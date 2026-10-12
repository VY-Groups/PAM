"""Session gateway & recording broker (plan phase 8a - the data plane).

The control-plane half of the gateway: zones, pools, registered nodes
(maker-checker), the session broker that dispatches a privileged session
onto a healthy node in the *target's* zone (failing clearly when none
exists), one-shot credential injection for the node's own token, the
recording store (gzip -> AES-256-GCM segments with per-recording envelope
keys, pointers + SHA-256 in the database, crypto-shreddable), playback,
retention, and the `gateway` ledger trail.

Boundaries kept honest:
- the target credential travels exactly once - vault -> API -> the
  approved node's one-shot connect-args, never to a browser or operator;
  the admin token is refused on connect-args by design;
- the database stores recording *pointers + hashes*, never bytes;
- destroying a recording key makes its segments unreadable even from an
  old file copy (crypto-shredding); rows stay as evidence;
- the guacd wire protocol lives in `guacd.py` and is verified against
  guacamole-server's own sources.

The daemon process (`gateway_daemon.py`) is the node side: it polls work,
performs the real guacd handshake, records the instruction stream and
reports progress back with its node token.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import secrets as pysecrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import Config
from errors import APIError, Conflict, Forbidden, NotFound, Unauthorized, ValidationFailed
from extensions import db
from models import (
    AssetZoneBinding,
    CommandIncident,
    DiscoveredAsset,
    GatewayEvent,
    GatewayNode,
    GatewayPool,
    GatewaySession,
    GATEWAY_TIERS,
    JitRequest,
    PrivilegedSession,
    RecordingKey,
    RecordingSegment,
    VaultItem,
    VaultSecretVersion,
    Zone,
)

# the node's API credential: issued once per node, sha256 at rest, and
# never waived in open/dev mode (a node credential is not an admin one).
GATEWAY_NODE_TOKEN_PREFIX = "vypam-gwn1"

# protocols guacd proxies natively in 8a (RDP/SSH/VNC/telnet); the DB wire
# proxy and the browser viewer are the following boundaries.
GATEWAY_PROTOCOLS = ("rdp", "ssh", "vnc", "telnet")
DEFAULT_TARGET_PORTS = {"ssh": 22, "rdp": 3389, "vnc": 5900, "telnet": 23}

# guacd connection parameters the daemon may need beyond the basics; the
# client maps whatever guacd's `args` asks for out of this superset.
GUACD_EXTRA_PARAMS = {
    "ignore-cert": "true",
    "resize-method": "display-update",
    "enable-wallpaper": "false",
    "create-drive-path": "false",
    "color-depth": "16",
}

GATEWAY_SESSION_STATES_LIVE = ("pending", "connecting", "active", "paused")
_STATE_ORDER = ("pending", "connecting", "active", "paused", "ended")

# settings defaults (the `gateway` group is validated by service; this
# reader merges stored values over the same defaults).
GATEWAY_SETTINGS_DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "require_zone": False,
    "guacd_host": "127.0.0.1",
    "guacd_port": 4822,
    "segment_seconds": 60,
    "recording_failure_policy": "block",  # block | flag
    "spool_alert_threshold_pct": 70,
    "spool_full_threshold_pct": 85,
    "spool_max_bytes": 10 * 1024 * 1024 * 1024,
    "retention_default_days": 90,
    "retention_overrides": "{}",  # JSON map protocol -> days
    "node_heartbeat_ttl_seconds": 90,
}


def gateway_settings() -> Dict[str, Any]:
    """The `gateway` policy group with schema defaults merged in."""
    from models import SettingGroup

    row = SettingGroup.query.filter(SettingGroup.group_name == "gateway").first()
    values: Dict[str, Any] = dict(row.value) if row is not None and row.value else {}
    out: Dict[str, Any] = {}
    for field, default in GATEWAY_SETTINGS_DEFAULTS.items():
        raw = values.get(field, default)
        if isinstance(default, bool):
            out[field] = bool(raw)
        elif isinstance(default, int):
            out[field] = int(raw)
        else:
            out[field] = raw if raw is not None else default
    return out


# ---------------------------------------------------------------------------
# ledger trail (the 21st source: `gateway`)
# ---------------------------------------------------------------------------
def gateway_event(
    action: str,
    *,
    actor: str,
    gateway_session_id: Optional[int] = None,
    node_id: Optional[int] = None,
    **detail: Any,
) -> GatewayEvent:
    """Record one gateway action. The row fans into the ledger through the
    audit listener; key material and credentials never enter `detail`."""
    event = GatewayEvent(
        action=action,
        actor=actor,
        gateway_session_id=gateway_session_id,
        node_id=node_id,
        detail={k: v for k, v in detail.items() if v is not None},
    )
    db.session.add(event)
    return event


# ---------------------------------------------------------------------------
# zones
# ---------------------------------------------------------------------------
def list_zones() -> List[Dict[str, Any]]:
    zones = Zone.query.order_by(Zone.name).all()
    out: List[Dict[str, Any]] = []
    for zone in zones:
        row = zone.to_dict()
        row["node_count"] = GatewayNode.query.filter_by(zone_id=zone.id).count()
        row["asset_count"] = AssetZoneBinding.query.filter_by(zone_id=zone.id).count()
        out.append(row)
    return out


def create_zone(payload: Any, *, actor: str) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed("'name' is required", {"field": "name"})
    name = name.strip()
    if len(name) > 80:
        raise ValidationFailed("'name' must be at most 80 characters")
    description = payload.get("description") or ""
    if not isinstance(description, str) or len(description) > 255:
        raise ValidationFailed("'description' must be at most 255 characters")
    if Zone.query.filter_by(name=name).first() is not None:
        raise Conflict("Zone name already exists", {"field": "name"})
    zone = Zone(name=name, description=description, created_by=actor)
    db.session.add(zone)
    db.session.flush()
    gateway_event("zone-created", actor=actor, zone_id=zone.id, name=name)
    db.session.commit()
    return zone.to_dict()


def get_zone(zone_id: int) -> Zone:
    zone = Zone.query.filter_by(id=zone_id).first()
    if zone is None:
        raise NotFound("Zone not found")
    return zone


def zone_detail(zone_id: int) -> Dict[str, Any]:
    zone = get_zone(zone_id)
    row = zone.to_dict()
    row["nodes"] = [
        node_view(n) for n in GatewayNode.query.filter_by(zone_id=zone.id).all()
    ]
    bindings = AssetZoneBinding.query.filter_by(zone_id=zone.id).all()
    row["assets"] = [
        {
            "asset_id": b.asset_id,
            "hostname": (
                DiscoveredAsset.query.filter_by(id=b.asset_id).first().hostname
                if DiscoveredAsset.query.filter_by(id=b.asset_id).first()
                else None
            ),
            "bound_by": b.created_by,
            "bound_at": b.created_at.isoformat(),
        }
        for b in bindings
    ]
    row["pools"] = [p.to_dict() for p in GatewayPool.query.filter_by(zone_id=zone.id).all()]
    return row


def delete_zone(zone_id: int, *, actor: str) -> Dict[str, Any]:
    zone = get_zone(zone_id)
    # terminal node rows (denied / revoked) are history, not residents: only
    # a live node still claims the zone. The revoked row keeps zone_id as
    # evidence of where the node once lived.
    node_count = GatewayNode.query.filter(
        GatewayNode.zone_id == zone.id,
        GatewayNode.status.notin_(("denied", "revoked")),
    ).count()
    if node_count:
        raise Conflict(
            "Zone still has gateway nodes",
            {"node_count": node_count, "hint": "revoke or move the nodes first"},
        )
    binding_count = AssetZoneBinding.query.filter_by(zone_id=zone.id).count()
    if binding_count:
        raise Conflict(
            "Zone still has asset bindings",
            {"asset_count": binding_count, "hint": "unbind the assets first"},
        )
    pool_count = GatewayPool.query.filter_by(zone_id=zone.id).count()
    if pool_count:
        raise Conflict("Zone still has gateway pools", {"pool_count": pool_count})
    name = zone.name
    db.session.delete(zone)
    gateway_event("zone-deleted", actor=actor, zone_id=zone_id, name=name)
    db.session.commit()
    return {"deleted": True, "zone_id": zone_id, "name": name}


def set_asset_zone(asset_id: int, payload: Any, *, actor: str) -> Dict[str, Any]:
    """Bind a discovered asset to a zone (or unbind with zone_id: null)."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    asset = DiscoveredAsset.query.filter_by(id=asset_id).first()
    if asset is None:
        raise NotFound("Asset not found")
    zone_id = payload.get("zone_id")
    existing = AssetZoneBinding.query.filter_by(asset_id=asset_id).first()
    if zone_id is None:
        if existing is None:
            raise NotFound("Asset is not bound to any zone")
        db.session.delete(existing)
        gateway_event(
            "asset-zone-unbound", actor=actor, asset_id=asset_id, hostname=asset.hostname
        )
        db.session.commit()
        return {"asset_id": asset_id, "zone_id": None, "bound": False}
    if not isinstance(zone_id, int):
        raise ValidationFailed("'zone_id' must be an integer or null")
    zone = get_zone(zone_id)
    if existing is not None:
        previous = existing.zone_id
        existing.zone_id = zone.id
        existing.created_by = actor
        existing.created_at = datetime.now()
    else:
        db.session.add(
            AssetZoneBinding(asset_id=asset_id, zone_id=zone.id, created_by=actor)
        )
    gateway_event(
        "asset-zone-bound",
        actor=actor,
        asset_id=asset_id,
        zone_id=zone.id,
        hostname=asset.hostname,
    )
    db.session.commit()
    return {"asset_id": asset_id, "zone_id": zone.id, "bound": True}


# ---------------------------------------------------------------------------
# pools
# ---------------------------------------------------------------------------
LB_POLICIES = ("least-loaded", "round-robin")


def list_pools() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for pool in GatewayPool.query.order_by(GatewayPool.name).all():
        row = pool.to_dict()
        row["node_count"] = GatewayNode.query.filter_by(pool_id=pool.id).count()
        out.append(row)
    return out


def create_pool(payload: Any, *, actor: str) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    name = payload.get("name")
    zone_id = payload.get("zone_id")
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed("'name' is required", {"field": "name"})
    name = name.strip()
    if not isinstance(zone_id, int):
        raise ValidationFailed("'zone_id' is required", {"field": "zone_id"})
    get_zone(zone_id)
    lb_policy = payload.get("lb_policy", "least-loaded")
    if lb_policy not in LB_POLICIES:
        raise ValidationFailed(
            "Unknown lb_policy",
            {"field": "lb_policy", "allowed": list(LB_POLICIES)},
        )
    if GatewayPool.query.filter_by(name=name).first() is not None:
        raise Conflict("Pool name already exists", {"field": "name"})
    pool = GatewayPool(name=name, zone_id=zone_id, lb_policy=lb_policy, created_by=actor)
    db.session.add(pool)
    db.session.flush()
    gateway_event("pool-created", actor=actor, pool_id=pool.id, name=name, zone_id=zone_id)
    db.session.commit()
    return pool.to_dict()


def delete_pool(pool_id: int, *, actor: str) -> Dict[str, Any]:
    pool = GatewayPool.query.filter_by(id=pool_id).first()
    if pool is None:
        raise NotFound("Pool not found")
    node_count = GatewayNode.query.filter_by(pool_id=pool.id).count()
    if node_count:
        raise Conflict(
            "Pool still has nodes", {"node_count": node_count}
        )
    name = pool.name
    db.session.delete(pool)
    gateway_event("pool-deleted", actor=actor, pool_id=pool_id, name=name)
    db.session.commit()
    return {"deleted": True, "pool_id": pool_id, "name": name}


# ---------------------------------------------------------------------------
# nodes: registration (maker-checker), liveness, capacity
# ---------------------------------------------------------------------------
def _heartbeat_ttl_seconds() -> int:
    return max(5, int(gateway_settings()["node_heartbeat_ttl_seconds"]))


def node_state(node: GatewayNode) -> str:
    """The stored status, with `offline` derived honestly from a stale
    heartbeat - it is never written to the row."""
    if node.status != "active":
        return node.status
    if node.last_heartbeat_at is None:
        return "offline"
    age = datetime.now() - node.last_heartbeat_at
    if age > timedelta(seconds=_heartbeat_ttl_seconds()):
        return "offline"
    return "active"


def node_view(node: GatewayNode) -> Dict[str, Any]:
    row = node.to_dict()
    state = node_state(node)
    row["state"] = state
    row["online"] = state in ("active", "draining")
    row["heartbeat_age_seconds"] = (
        int((datetime.now() - node.last_heartbeat_at).total_seconds())
        if node.last_heartbeat_at is not None
        else None
    )
    row["live_sessions"] = GatewaySession.query.filter(
        GatewaySession.gateway_node_id == node.id,
        GatewaySession.state.in_(GATEWAY_SESSION_STATES_LIVE),
    ).count()
    return row


def list_nodes() -> List[Dict[str, Any]]:
    return [
        node_view(n)
        for n in GatewayNode.query.order_by(GatewayNode.id).all()
    ]


def get_node(node_id: int) -> GatewayNode:
    node = GatewayNode.query.filter_by(id=node_id).first()
    if node is None:
        raise NotFound("Gateway node not found")
    return node


def register_node(payload: Any, *, actor: str) -> Tuple[Dict[str, Any], str]:
    """Register a node: created `pending`, token shown once. A distinct
    approver activates it - the requester never may (maker-checker)."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    name = payload.get("name")
    zone_id = payload.get("zone_id")
    endpoint_host = payload.get("endpoint_host")
    endpoint_port = payload.get("endpoint_port", 4822)
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed("'name' is required", {"field": "name"})
    name = name.strip()
    if not isinstance(zone_id, int):
        raise ValidationFailed("'zone_id' is required", {"field": "zone_id"})
    get_zone(zone_id)
    pool_id = payload.get("pool_id")
    if pool_id is not None:
        if not isinstance(pool_id, int):
            raise ValidationFailed("'pool_id' must be an integer")
        pool = GatewayPool.query.filter_by(id=pool_id).first()
        if pool is None:
            raise NotFound("Pool not found")
        if pool.zone_id != zone_id:
            raise ValidationFailed(
                "Pool belongs to a different zone",
                {"field": "pool_id", "pool_zone_id": pool.zone_id},
            )
    if not isinstance(endpoint_host, str) or not endpoint_host.strip():
        raise ValidationFailed("'endpoint_host' is required", {"field": "endpoint_host"})
    if not isinstance(endpoint_port, int) or not (0 < endpoint_port < 65536):
        raise ValidationFailed(
            "'endpoint_port' must be a TCP port", {"field": "endpoint_port"}
        )
    # terminal rows (revoked / denied) are history, not occupants: the name
    # frees for a replacement node while a live row keeps it reserved
    if (
        GatewayNode.query.filter(
            GatewayNode.name == name,
            GatewayNode.status.notin_(("revoked", "denied")),
        ).first()
        is not None
    ):
        raise Conflict("Node name already exists", {"field": "name"})

    secret = pysecrets.token_hex(32)
    node = GatewayNode(
        node_ref=f"gwn-{pysecrets.token_hex(6)}",
        name=name,
        zone_id=zone_id,
        pool_id=pool_id,
        endpoint_host=endpoint_host.strip(),
        endpoint_port=endpoint_port,
        status="pending",
        token_sha256=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        registered_by=actor,
    )
    db.session.add(node)
    db.session.flush()
    # the stored prefix names the node's id, exactly as the issued token
    # reads (vypam-gwn1.<id>.<secret>) - never a label that does not prefix
    node.token_prefix = f"{GATEWAY_NODE_TOKEN_PREFIX}.{node.id}."
    gateway_event(
        "node-registered",
        actor=actor,
        node_id=node.id,
        name=name,
        zone_id=zone_id,
        status="pending",
    )
    db.session.commit()
    token = f"{node.token_prefix}{secret}"
    return node_view(node), token


def approve_node(node_id: int, payload: Any, *, actor: str) -> Dict[str, Any]:
    """The checker half of maker-checker: approve or deny a pending node.
    The requester may never approve their own registration."""
    node = get_node(node_id)
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    decision = payload.get("decision")
    if decision not in ("approve", "deny"):
        raise ValidationFailed(
            "'decision' must be 'approve' or 'deny'", {"field": "decision"}
        )
    note = payload.get("note") or ""
    if not isinstance(note, str) or len(note) > 255:
        raise ValidationFailed("'note' must be at most 255 characters")
    if node.status != "pending":
        raise Conflict(
            "Node is not pending", {"node_id": node.id, "status": node.status}
        )
    if hmac.compare_digest(node.registered_by or "", actor or ""):
        raise Forbidden(
            "The requester may never approve their own gateway registration",
            {"registered_by": node.registered_by},
        )
    node.approved_by = actor
    node.approved_at = datetime.now()
    node.decision_note = note
    if decision == "approve":
        node.status = "active"
        action = "node-approved"
    else:
        node.status = "denied"
        action = "node-denied"
    gateway_event(
        action,
        actor=actor,
        node_id=node.id,
        name=node.name,
        registered_by=node.registered_by,
        note=note or None,
    )
    db.session.commit()
    return node_view(node)


def drain_node(node_id: int, *, actor: str) -> Dict[str, Any]:
    node = get_node(node_id)
    if node.status != "active":
        raise Conflict(
            "Only an active node can be drained", {"status": node.status}
        )
    node.status = "draining"
    gateway_event("node-draining", actor=actor, node_id=node.id, name=node.name)
    db.session.commit()
    return node_view(node)


def revoke_node(node_id: int, *, actor: str) -> Dict[str, Any]:
    """Revoke a node: its token dies and its live sessions are terminated."""
    node = get_node(node_id)
    live = GatewaySession.query.filter(
        GatewaySession.gateway_node_id == node.id,
        GatewaySession.state.in_(GATEWAY_SESSION_STATES_LIVE),
    ).all()
    import service

    ended = 0
    for gws in live:
        gws.state = "ended"
        gws.ended_at = datetime.now()
        gws.end_reason = "node-revoked"
        try:
            service.end_session(
                gws.privileged_session_id,
                actor=f"gateway:{node.name}",
                outcome="terminated",
                payload={"reason": "gateway node revoked"},
            )
            ended += 1
        except (ValidationFailed, NotFound):
            pass  # already terminal elsewhere; the gws row still records it
    node.status = "revoked"
    node.token_sha256 = None
    gateway_event(
        "node-revoked",
        actor=actor,
        node_id=node.id,
        name=node.name,
        sessions_terminated=ended,
    )
    db.session.commit()
    view = node_view(node)
    view["sessions_terminated"] = ended
    return view


def verify_node_token(token: Any) -> GatewayNode:
    """Authenticate a gateway node by its token. Constant-time comparison;
    pending/revoked/denied nodes do not authenticate (a pending node has
    not passed its checker yet)."""
    if not isinstance(token, str) or not token.strip():
        raise Unauthorized(
            "Gateway node token required "
            "(Authorization: Bearer vypam-gwn1.<id>.<secret>)"
        )
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != GATEWAY_NODE_TOKEN_PREFIX:
        raise Unauthorized(
            "Not a gateway node token (expected vypam-gwn1.<id>.<secret>)"
        )
    raw_id, secret = parts[1], parts[2]
    node = (
        GatewayNode.query.filter_by(id=int(raw_id)).first()
        if raw_id.isdigit()
        else None
    )
    if node is None or node.token_sha256 is None:
        raise Unauthorized("Unknown gateway node token")
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, node.token_sha256):
        raise Unauthorized("Unknown gateway node token")
    if node.status == "pending":
        raise Unauthorized("Gateway node is awaiting approval")
    if node.status in ("revoked", "denied"):
        raise Unauthorized(f"Gateway node is {node.status}")
    return node


def heartbeat(node: GatewayNode, payload: Any) -> Dict[str, Any]:
    """Liveness + capacity; the reply carries control directives so pause
    and terminate reach the node without any inbound port."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    capacity_active = payload.get("capacity_active", 0)
    if not isinstance(capacity_active, int) or capacity_active < 0:
        raise ValidationFailed(
            "'capacity_active' must be a non-negative integer"
        )
    version = payload.get("version") or ""
    if not isinstance(version, str) or len(version) > 32:
        raise ValidationFailed("'version' must be at most 32 characters")
    node.last_heartbeat_at = datetime.now()
    node.capacity_active = capacity_active
    node.version = version
    directives: List[str] = []
    terminate: List[int] = []
    if node.status == "draining":
        directives.append("drain")
    for gws in _live_sessions(node.id):
        privileged = (
            PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
        )
        if privileged is not None and privileged.status in ("terminated", "completed"):
            terminate.append(gws.id)
        elif privileged is not None and privileged.status in ("paused", "locked"):
            directives.append("pause")
    db.session.commit()
    return {
        "status": node.status,
        "directives": sorted(set(directives)),
        "terminate": terminate,
    }


def _live_sessions(node_id: int) -> List[GatewaySession]:
    return GatewaySession.query.filter(
        GatewaySession.gateway_node_id == node_id,
        GatewaySession.state.in_(GATEWAY_SESSION_STATES_LIVE),
    ).all()


def node_work(node: GatewayNode) -> Dict[str, Any]:
    """The node's queue: pending sessions to start + live control state."""
    pending = GatewaySession.query.filter_by(
        gateway_node_id=node.id, state="pending"
    ).all()
    live: List[Dict[str, Any]] = []
    for gws in _live_sessions(node.id):
        if gws.state == "pending":
            continue
        privileged = (
            PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
        )
        control = "run"
        if privileged is not None and privileged.status in ("paused", "locked"):
            control = "pause"
        live.append(
            {
                "gateway_session_id": gws.id,
                "privileged_session_id": gws.privileged_session_id,
                "state": gws.state,
                "control": control,
                "session_status": privileged.status if privileged else None,
            }
        )
    return {
        "pending": [_pending_work(gws) for gws in pending],
        "live": live,
    }


def _pending_work(gws: GatewaySession) -> Dict[str, Any]:
    privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
    from guacd import DEFAULT_GUACD_PORT

    settings = gateway_settings()
    return {
        "gateway_session_id": gws.id,
        "privileged_session_id": gws.privileged_session_id,
        "session_ref": privileged.session_ref if privileged else None,
        "protocol": privileged.protocol if privileged else None,
        "target_host": gws.target_host,
        "target_port": gws.target_port,
        "username": gws.username,
        "record": bool(privileged.record) if privileged else False,
        "watermark": bool(privileged.watermark) if privileged else False,
        "clipboard_allowed": bool(privileged.clipboard_allowed) if privileged else False,
        "upload_allowed": bool(privileged.upload_allowed) if privileged else False,
        "download_allowed": bool(privileged.download_allowed) if privileged else False,
        "guacd": {
            "host": settings["guacd_host"],
            "port": int(settings["guacd_port"] or DEFAULT_GUACD_PORT),
        },
    }


# ---------------------------------------------------------------------------
# the broker: dispatch a session onto a node in the target's zone
# ---------------------------------------------------------------------------
def _parse_target(protocol: str, target: str) -> Tuple[str, int]:
    """`host` or `host:port`; the default port is the protocol's."""
    host, port = target.strip(), DEFAULT_TARGET_PORTS.get(protocol, 0)
    if ":" in target:
        candidate_host, _, candidate_port = target.rpartition(":")
        if candidate_port.isdigit() and 0 < int(candidate_port) < 65536:
            host, port = candidate_host.strip(), int(candidate_port)
    if not host:
        raise ValidationFailed(
            "Session target must be a host or host:port", {"field": "target"}
        )
    return host, port


def _resolve_zone(host: str) -> Optional[Zone]:
    """The target's zone via its discovered asset binding, if any."""
    for asset in DiscoveredAsset.query.filter_by(hostname=host).all():
        binding = AssetZoneBinding.query.filter_by(asset_id=asset.id).first()
        if binding is not None:
            zone = Zone.query.filter_by(id=binding.zone_id).first()
            if zone is not None:
                return zone
    return None


def _pick_node(zone_id: int) -> Optional[GatewayNode]:
    """The least-loaded healthy node in the zone: approved, heartbeating,
    under capacity. Draining/pending/offline nodes never take new work."""
    ttl = timedelta(seconds=_heartbeat_ttl_seconds())
    now = datetime.now()
    candidates = [
        node
        for node in GatewayNode.query.filter_by(zone_id=zone_id, status="active").all()
        if node.last_heartbeat_at is not None
        and now - node.last_heartbeat_at <= ttl
        and node.capacity_active < node.capacity_max
    ]
    if not candidates:
        return None

    def live_count(node: GatewayNode) -> int:
        return GatewaySession.query.filter(
            GatewaySession.gateway_node_id == node.id,
            GatewaySession.state.in_(GATEWAY_SESSION_STATES_LIVE),
        ).count()

    return sorted(candidates, key=lambda n: (live_count(n), n.id))[0]


def _injection_item(privileged: PrivilegedSession) -> Optional[VaultItem]:
    """The vault credential this session rides: its own checkout, or the
    item behind its JIT grant."""
    if privileged.item_id is not None:
        return VaultItem.query.filter_by(id=privileged.item_id).first()
    if privileged.jit_request_id is not None:
        grant = JitRequest.query.filter_by(id=privileged.jit_request_id).first()
        if grant is not None and grant.item_id is not None:
            return VaultItem.query.filter_by(id=grant.item_id).first()
    return None


def attach_to_session(
    privileged: PrivilegedSession, payload: Any, *, actor: str
) -> Optional[Dict[str, Any]]:
    """Called from `service.create_session` inside its transaction.

    Returns the `gateway` object for the response, or None when the
    gateway is off. Raises 503 (rolling the whole start back) when the
    target sits in a zone that currently has no healthy node - a session
    that must be recorded never starts unrecorded.
    """
    settings = gateway_settings()
    if not settings["enabled"]:
        return None
    protocol = privileged.protocol
    if protocol not in GATEWAY_PROTOCOLS:
        return {
            "required": False,
            "reason": "protocol-not-gateway-capable",
            "protocols": list(GATEWAY_PROTOCOLS),
        }
    host, port = _parse_target(protocol, privileged.target)
    zone = _resolve_zone(host)
    if zone is None:
        if settings["require_zone"]:
            raise APIError(
                503,
                "Target is not mapped to any gateway zone",
                details={
                    "target": host,
                    "hint": "bind the asset to a zone (PUT /discovery/assets/<id>/zone)",
                },
            )
        return {"required": False, "reason": "target-not-mapped-to-a-zone"}

    # a gateway-brokered session exists to inject a credential: refuse to
    # start one without a vault secret to inject.
    if _injection_item(privileged) is None:
        raise APIError(
            503,
            "Gateway-brokered sessions require a vault credential",
            details={
                "target": host,
                "hint": "start the session against a vault item (item_id)",
            },
        )

    node = _pick_node(zone.id)
    if node is None:
        raise APIError(
            503,
            f"No healthy gateway node in zone '{zone.name}'",
            details={
                "zone": zone.name,
                "hint": "register + approve a node and let it heartbeat",
            },
        )

    principal = ""
    item = _injection_item(privileged)
    if item is not None and item.principal:
        principal = item.principal
    elif isinstance(payload, dict) and isinstance(payload.get("username"), str):
        principal = payload["username"]

    gws = GatewaySession(
        privileged_session_id=privileged.id,
        gateway_node_id=node.id,
        state="pending",
        target_host=host,
        target_port=port,
        username=principal,
    )
    db.session.add(gws)
    db.session.flush()

    recording_key = None
    if privileged.record:
        # a random per-recording data key, wrapped by the master key;
        # crypto-shredding later destroys only this wrap.
        data_key = os.urandom(32)
        wrapped = _wrap_recording_key(gws.id, data_key)
        recording_key = RecordingKey(
            gateway_session_id=gws.id,
            wrapped_key=json.dumps(wrapped),
        )
        db.session.add(recording_key)
    node.capacity_active = (node.capacity_active or 0) + 1
    gateway_event(
        "session-brokered",
        actor=actor,
        gateway_session_id=gws.id,
        node_id=node.id,
        zone=zone.name,
        protocol=protocol,
        target=host,
        port=port,
        recording=bool(privileged.record),
    )
    return {
        "required": True,
        "gateway_session_id": gws.id,
        "node": {"id": node.id, "name": node.name, "zone": zone.name},
        "state": gws.state,
        "credential_injected": False,
        "recording": bool(privileged.record),
    }


# ---------------------------------------------------------------------------
# node-side: one-shot connect args (credential injection) + progress
# ---------------------------------------------------------------------------
def get_gateway_session(gateway_session_id: int) -> GatewaySession:
    gws = GatewaySession.query.filter_by(id=gateway_session_id).first()
    if gws is None:
        raise NotFound("Gateway session not found")
    return gws


def _owned_session(gateway_session_id: int, node: GatewayNode) -> GatewaySession:
    gws = get_gateway_session(gateway_session_id)
    if gws.gateway_node_id != node.id:
        # never confirm another node's session exists
        raise NotFound("Gateway session not found")
    return gws


def connect_args(gateway_session_id: int, node: GatewayNode) -> Dict[str, Any]:
    """The one place the target credential travels: vault -> this response,
    to the approved node's own token, exactly once. The admin token is
    refused on this route by design."""
    gws = _owned_session(gateway_session_id, node)
    privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
    if privileged is None:
        raise NotFound("Privileged session not found")
    if gws.credential_fetched_at is not None:
        raise Conflict(
            "Connect args already consumed (single use)",
            {"gateway_session_id": gws.id},
        )
    if gws.state not in ("pending", "connecting"):
        raise Conflict(
            "Gateway session is not awaiting connection",
            {"gateway_session_id": gws.id, "state": gws.state},
        )
    if privileged.status not in ("active", "paused"):
        raise Conflict(
            "Privileged session is no longer live",
            {"privileged_session_id": privileged.id, "status": privileged.status},
        )
    item = _injection_item(privileged)
    if item is None or not item.secret_version:
        raise Conflict(
            "No stored vault secret for this session",
            {"privileged_session_id": privileged.id},
        )
    row = VaultSecretVersion.query.filter_by(
        item_id=item.id, version=item.secret_version
    ).first()
    if row is None:
        raise Conflict("No stored vault secret for this session", {"item_id": item.id})

    import service
    from secrets_store import unseal

    plaintext = unseal(row.blob, item.id, service._vault_config())

    params = {
        "hostname": gws.target_host,
        "port": str(gws.target_port or DEFAULT_TARGET_PORTS.get(privileged.protocol, 0)),
        "username": gws.username or item.principal or "",
        "password": plaintext,
    }
    params.update(GUACD_EXTRA_PARAMS)

    settings = gateway_settings()
    gws.credential_fetched_at = datetime.now()
    gws.credential_injected = True
    response: Dict[str, Any] = {
        "gateway_session_id": gws.id,
        "privileged_session_id": privileged.id,
        "protocol": privileged.protocol,
        "params": params,
        "recording": None,
    }
    if privileged.record:
        key = RecordingKey.query.filter_by(gateway_session_id=gws.id).first()
        if key is None or key.destroyed:
            raise Conflict(
                "Recording key unavailable for this session",
                {"gateway_session_id": gws.id},
            )
        data_key = _unwrap_recording_key(gws.id, key)
        response["recording"] = {
            "data_key": data_key.hex(),
            "segment_seconds": max(5, int(settings["segment_seconds"])),
            "storage_subdir": _segment_subdir(gws.id),
            "format": "guacd-native",
        }
    gateway_event(
        "credential-injected",
        actor=f"gateway:{node.name}",
        gateway_session_id=gws.id,
        node_id=node.id,
        item_id=item.id,
        username=params["username"],
        secret_version=row.version,
    )
    db.session.commit()
    return response


def progress(gateway_session_id: int, node: GatewayNode, payload: Any) -> Dict[str, Any]:
    """The daemon reports lifecycle transitions, sealed segments and the
    end; the reply carries the control directives back."""
    gws = _owned_session(gateway_session_id, node)
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    state = payload.get("state")
    if state is not None:
        if state not in _STATE_ORDER:
            raise ValidationFailed(
                "Unknown state",
                {"field": "state", "allowed": list(_STATE_ORDER)},
            )
        current = _STATE_ORDER.index(gws.state)
        target = _STATE_ORDER.index(state)
        if target < current:
            # backward movement is a lie; `ended` is terminal
            raise Conflict(
                "Illegal gateway session state transition",
                {"from": gws.state, "to": state},
            )
        if target > current:
            gws.state = state
            gateway_event(
                "session-state",
                actor=f"gateway:{node.name}",
                gateway_session_id=gws.id,
                node_id=node.id,
                state=state,
            )

    # sealed recording segments: pointer + hash + size, never bytes
    segments = payload.get("segments") or []
    if not isinstance(segments, list):
        raise ValidationFailed("'segments' must be a list")
    sealed: List[Dict[str, Any]] = []
    for entry in segments:
        if not isinstance(entry, dict):
            raise ValidationFailed("Each segment must be a JSON object")
        seq = entry.get("seq")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        duration = entry.get("duration_seconds")
        tier = entry.get("tier", "hot")
        if not isinstance(seq, int) or seq < 0:
            raise ValidationFailed("Segment 'seq' must be a non-negative integer")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValidationFailed("Segment 'sha256' must be a 64-char hex digest")
        if not isinstance(size_bytes, int) or size_bytes < 0:
            raise ValidationFailed("Segment 'size_bytes' must be a non-negative integer")
        if not isinstance(duration, (int, float)) or duration < 0:
            raise ValidationFailed(
                "Segment 'duration_seconds' must be a non-negative number"
            )
        if tier not in GATEWAY_TIERS:
            raise ValidationFailed(
                "Unknown segment tier", {"field": "tier", "allowed": list(GATEWAY_TIERS)}
            )
        if RecordingSegment.query.filter_by(
            gateway_session_id=gws.id, seq=seq
        ).first() is not None:
            raise Conflict("Segment seq already sealed", {"seq": seq})
        rel_path = f"{_segment_subdir(gws.id)}/seg-{seq:05d}.json"
        db.session.add(
            RecordingSegment(
                gateway_session_id=gws.id,
                seq=seq,
                storage_tier=tier,
                path=rel_path,
                size_bytes=size_bytes,
                sha256=sha256.lower(),
                duration_seconds=float(duration),
                format="guacd-native",
            )
        )
        sealed.append({"seq": seq, "size_bytes": size_bytes, "tier": tier})
    if sealed:
        gateway_event(
            "recording-segment-sealed",
            actor=f"gateway:{node.name}",
            gateway_session_id=gws.id,
            node_id=node.id,
            segments=len(sealed),
            bytes=sum(s["size_bytes"] for s in sealed),
        )

    # terminal report: end the privileged session through the normal path
    # (checkout release + rotation-on-close run exactly once, as in 4c)
    if state == "ended":
        end_reason = payload.get("end_reason") or "closed"
        if not isinstance(end_reason, str) or len(end_reason) > 32:
            raise ValidationFailed("'end_reason' must be at most 32 characters")
        gws.state = "ended"
        gws.ended_at = datetime.now()
        gws.end_reason = end_reason
        privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
        outcome = "terminated" if end_reason == "terminated" else "completed"
        rotated = False
        if privileged is not None and privileged.status in ("active", "paused", "locked"):
            import service

            try:
                _session, detail = service.end_session(
                    privileged.id,
                    actor=f"gateway:{node.name}",
                    outcome=outcome,
                    payload={"reason": f"gateway session ended: {end_reason}"},
                )
                rotated = bool(detail.get("rotated"))
            except (ValidationFailed, NotFound):
                pass  # already terminal elsewhere
        gateway_event(
            "session-ended",
            actor=f"gateway:{node.name}",
            gateway_session_id=gws.id,
            node_id=node.id,
            end_reason=end_reason,
            rotated=rotated,
        )

    # events the daemon observed (terminal content arrives as notes; the
    # command-indexing pipeline that decodes terminal text is phase 14)
    events = payload.get("events") or []
    if not isinstance(events, list):
        raise ValidationFailed("'events' must be a list")
    for entry in events[:200]:
        if not isinstance(entry, dict):
            continue
        content = entry.get("content")
        if not isinstance(content, str) or not content:
            continue
        etype = entry.get("type", "note")
        if etype not in ("note", "status", "command", "file_upload", "file_download"):
            etype = "note"
        try:
            import service

            service.post_session_event(
                gws.privileged_session_id,
                {"type": etype, "content": content[:2000]},
                actor=f"gateway:{node.name}",
            )
        except (ValidationFailed, NotFound):
            pass

    db.session.commit()

    # directives back to the node
    directives: List[str] = []
    terminate: List[int] = []
    privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
    if gws.state != "ended":
        if privileged is not None and privileged.status in ("terminated", "completed"):
            terminate.append(gws.id)
            gws.state = "ended"
            gws.ended_at = gws.ended_at or datetime.now()
            gws.end_reason = gws.end_reason or "admin-terminated"
            db.session.commit()
        elif privileged is not None and privileged.status in ("paused", "locked"):
            directives.append("pause")
    return {
        "status": gws.state,
        "directives": directives,
        "terminate": terminate,
    }


def control_directives(gateway_session_id: int, node: GatewayNode) -> Dict[str, Any]:
    """The current control state for one live session (used by heartbeat
    work polling and by the daemon between progress calls)."""
    gws = _owned_session(gateway_session_id, node)
    privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
    terminate = (
        privileged is not None and privileged.status in ("terminated", "completed")
    )
    pause = privileged is not None and privileged.status in ("paused", "locked")
    return {
        "state": gws.state,
        "terminate": bool(terminate or gws.state == "ended" and gws.end_reason == "terminated"),
        "pause": bool(pause),
    }


# ---------------------------------------------------------------------------
# recordings: metadata, playback, retention (crypto-shredding)
# ---------------------------------------------------------------------------
def recording_meta(gateway_session_id: int) -> Dict[str, Any]:
    gws = get_gateway_session(gateway_session_id)
    privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
    key = RecordingKey.query.filter_by(gateway_session_id=gws.id).first()
    segments = (
        RecordingSegment.query.filter_by(gateway_session_id=gws.id)
        .order_by(RecordingSegment.seq)
        .all()
    )
    return {
        "gateway_session_id": gws.id,
        "privileged_session_id": gws.privileged_session_id,
        "session_ref": privileged.session_ref if privileged else None,
        "protocol": privileged.protocol if privileged else None,
        "recorded": bool(privileged.record) if privileged else False,
        "state": gws.state,
        "started_at": gws.started_at.isoformat(),
        "ended_at": gws.ended_at.isoformat() if gws.ended_at else None,
        "key": key.to_dict() if key else None,
        "segment_count": len(segments),
        "total_bytes": sum(s.size_bytes for s in segments),
        "segments": [s.to_dict() for s in segments],
    }


def playback_segment(gateway_session_id: int, seq: int, *, actor: str) -> Dict[str, Any]:
    """Decrypt + decompress one segment's native stream. A destroyed key
    answers 410 - the rows stay as evidence, the bytes are gone."""
    gws = get_gateway_session(gateway_session_id)
    segment = RecordingSegment.query.filter_by(
        gateway_session_id=gws.id, seq=seq
    ).first()
    if segment is None:
        raise NotFound("Recording segment not found")
    key = RecordingKey.query.filter_by(gateway_session_id=gws.id).first()
    if key is None or key.destroyed:
        raise APIError(
            410,
            "Recording key destroyed (crypto-shredded)",
            details={"gateway_session_id": gws.id, "destroyed_at": (
                key.destroyed_at.isoformat() if key and key.destroyed_at else None
            )},
        )
    if segment.deleted_at is not None:
        raise APIError(
            410,
            "Segment file was pruned by retention",
            details={"seq": seq, "deleted_at": segment.deleted_at.isoformat()},
        )
    path = segment_path(segment.path)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError as exc:
        raise APIError(
            500,
            "Segment row exists but its file is missing from storage",
            details={"seq": seq, "path": segment.path},
        ) from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != segment.sha256:
        raise APIError(
            500,
            "Segment failed its SHA-256 integrity check",
            details={"seq": seq, "expected": segment.sha256, "actual": digest},
        )
    try:
        wire = json.loads(raw.decode("utf-8"))
        nonce = base64.b64decode(wire["nonce"], validate=True)
        ciphertext = base64.b64decode(wire["ct"], validate=True)
    except (ValueError, KeyError) as exc:
        raise APIError(500, "Segment file is malformed") from exc
    data_key = _unwrap_recording_key(gws.id, key)
    try:
        plaintext = AESGCM(data_key).decrypt(
            nonce, ciphertext, _segment_aad(gws.id, seq)
        )
    except InvalidTag as exc:
        raise APIError(
            500, "Segment failed its integrity check (wrong key or tampered data)"
        ) from exc
    try:
        stream_bytes = gzip.decompress(plaintext)
    except OSError as exc:
        raise APIError(500, "Segment did not decompress") from exc
    gateway_event(
        "recording-played",
        actor=actor,
        gateway_session_id=gws.id,
        seq=seq,
        bytes=len(stream_bytes),
    )
    db.session.commit()
    return {
        "seq": seq,
        "sha256": segment.sha256,
        "format": segment.format,
        "duration_seconds": segment.duration_seconds,
        "bytes": len(stream_bytes),
        "stream": stream_bytes.decode("utf-8", errors="replace"),
    }


def _retention_days_for(protocol: Optional[str], settings: Dict[str, Any]) -> int:
    overrides = {}
    raw = settings.get("retention_overrides") or "{}"
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            overrides = {str(k): int(v) for k, v in parsed.items()}
    except (ValueError, TypeError):
        overrides = {}
    if protocol and protocol in overrides:
        return max(1, overrides[protocol])
    return max(1, int(settings["retention_default_days"]))


def run_retention(payload: Any, *, actor: str) -> Dict[str, Any]:
    """Apply recording retention: delete files, destroy keys (crypto-shred),
    record `retention-expired`. Sessions linked to a command incident are
    never pruned - that linkage is the hold."""
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    dry_run = bool(payload.get("dry_run", False))
    settings = gateway_settings()
    now = datetime.now()
    pruned: List[Dict[str, Any]] = []
    bytes_freed = 0
    skipped_hold = 0
    for gws in GatewaySession.query.filter(
        GatewaySession.state == "ended"
    ).all():
        key = RecordingKey.query.filter_by(gateway_session_id=gws.id).first()
        if key is None or key.destroyed:
            continue  # nothing stored, or already shredded
        privileged = PrivilegedSession.query.filter_by(id=gws.privileged_session_id).first()
        protocol = privileged.protocol if privileged else None
        age_from = gws.ended_at or gws.started_at
        days = _retention_days_for(protocol, settings)
        if now - age_from <= timedelta(days=days):
            continue
        if CommandIncident.query.filter_by(
            session_id=gws.privileged_session_id
        ).first() is not None:
            skipped_hold += 1
            continue
        segments = RecordingSegment.query.filter_by(
            gateway_session_id=gws.id, deleted_at=None
        ).all()
        freed = sum(s.size_bytes for s in segments)
        entry = {
            "gateway_session_id": gws.id,
            "privileged_session_id": gws.privileged_session_id,
            "protocol": protocol,
            "retention_days": days,
            "segments": len(segments),
            "bytes": freed,
        }
        if dry_run:
            pruned.append(entry)
            continue
        for segment in segments:
            path = segment_path(segment.path)
            try:
                os.remove(path)
            except FileNotFoundError:
                pass  # the row still records the file was expected
            segment.deleted_at = now
        key.destroyed_at = now
        key.destroy_reason = "retention-expired"
        gws_end = gws.ended_at or gws.started_at
        entry["age_days"] = (now - gws_end).days
        pruned.append(entry)
        bytes_freed += freed
        gateway_event(
            "retention-expired",
            actor=actor,
            gateway_session_id=gws.id,
            segments=entry["segments"],
            bytes=freed,
            retention_days=days,
        )
    if not dry_run:
        db.session.commit()
    return {
        "dry_run": dry_run,
        "pruned": len(pruned),
        "sessions": pruned,
        "bytes_freed": bytes_freed,
        "skipped_under_incident_hold": skipped_hold,
    }


def stats() -> Dict[str, Any]:
    """Gateway posture for the dashboard: nodes, sessions, storage bytes by
    tier, and spool alerts measured against the configured volume size."""
    settings = gateway_settings()
    nodes = list_nodes()
    by_state: Dict[str, int] = {}
    for node in nodes:
        by_state[node["state"]] = by_state.get(node["state"], 0) + 1
    sessions_by_state: Dict[str, int] = {}
    for state, count in (
        db.session.query(GatewaySession.state, db.func.count(GatewaySession.id))
        .group_by(GatewaySession.state)
        .all()
    ):
        sessions_by_state[state] = int(count)

    bytes_by_tier: Dict[str, int] = {tier: 0 for tier in GATEWAY_TIERS}
    count_by_tier: Dict[str, int] = {tier: 0 for tier in GATEWAY_TIERS}
    for tier, total, count in (
        db.session.query(
            RecordingSegment.storage_tier,
            db.func.sum(RecordingSegment.size_bytes),
            db.func.count(RecordingSegment.id),
        )
        .filter(RecordingSegment.deleted_at.is_(None))
        .group_by(RecordingSegment.storage_tier)
        .all()
    ):
        bytes_by_tier[tier] = int(total or 0)
        count_by_tier[tier] = int(count or 0)
    hot_bytes = bytes_by_tier.get("hot", 0)
    max_bytes = max(1, int(settings["spool_max_bytes"]))
    usage_pct = round(hot_bytes * 100.0 / max_bytes, 2)
    destroyed = RecordingKey.query.filter(
        RecordingKey.destroyed_at.isnot(None)
    ).count()
    return {
        "enabled": bool(settings["enabled"]),
        "nodes": {"total": len(nodes), "by_state": by_state},
        "sessions": {
            "total": sum(sessions_by_state.values()),
            "by_state": sessions_by_state,
        },
        "recordings": {
            "segments": sum(count_by_tier.values()),
            "bytes_by_tier": bytes_by_tier,
            "segments_by_tier": count_by_tier,
            "keys_destroyed": destroyed,
        },
        "spool": {
            "hot_bytes": hot_bytes,
            "max_bytes": max_bytes,
            "usage_pct": usage_pct,
            "alert": usage_pct >= settings["spool_alert_threshold_pct"],
            "full": usage_pct >= settings["spool_full_threshold_pct"],
        },
        "retention_default_days": settings["retention_default_days"],
        "require_zone": bool(settings["require_zone"]),
    }


def states_for_sessions(session_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """Compact gateway state for a page of sessions (one query, not N)."""
    out: Dict[int, Dict[str, Any]] = {}
    if not session_ids:
        return out
    rows = GatewaySession.query.filter(
        GatewaySession.privileged_session_id.in_(list(session_ids))
    ).all()
    node_ids = {row.gateway_node_id for row in rows}
    nodes = (
        {
            node.id: node
            for node in GatewayNode.query.filter(GatewayNode.id.in_(node_ids)).all()
        }
        if node_ids
        else {}
    )
    for row in rows:
        node = nodes.get(row.gateway_node_id)
        out[row.privileged_session_id] = {
            "gateway_session_id": row.id,
            "state": row.state,
            "node": (
                {"id": node.id, "name": node.name, "state": node_state(node)}
                if node
                else None
            ),
            "credential_injected": row.credential_injected,
        }
    return out


def enrich_session_detail(detail: Dict[str, Any], session: PrivilegedSession) -> Dict[str, Any]:
    """Add the gateway view to a privileged-session detail (the Live Session
    Hub watermark finally reports real gateway state instead of
    'not connected')."""
    gws = GatewaySession.query.filter_by(privileged_session_id=session.id).first()
    if gws is None:
        detail["gateway"] = None
        return detail
    node = GatewayNode.query.filter_by(id=gws.gateway_node_id).first()
    key = RecordingKey.query.filter_by(gateway_session_id=gws.id).first()
    segment_count = RecordingSegment.query.filter_by(gateway_session_id=gws.id).count()
    detail["gateway"] = {
        "gateway_session_id": gws.id,
        "state": gws.state,
        "node": (
            {"id": node.id, "name": node.name, "state": node_state(node)}
            if node
            else None
        ),
        "target_host": gws.target_host,
        "target_port": gws.target_port,
        "credential_injected": gws.credential_injected,
        "recording": {
            "segments": segment_count,
            "key_state": key.to_dict()["state"] if key else None,
        },
        "end_reason": gws.end_reason,
    }
    return detail


def _segment_subdir(gateway_session_id: int) -> str:
    return f"gws-{gateway_session_id}"


def _recording_aad(gateway_session_id: int) -> bytes:
    return f"recording:{gateway_session_id}".encode("utf-8")


def _segment_aad(gateway_session_id: int, seq: int) -> bytes:
    return f"recording_segment:{gateway_session_id}:{seq}".encode("utf-8")


def _wrap_recording_key(gateway_session_id: int, data_key: bytes) -> Dict[str, Any]:
    from secrets_store import seal_with_aad

    import service

    return seal_with_aad(
        data_key.hex(), _recording_aad(gateway_session_id), service._vault_config()
    )


def _unwrap_recording_key(gateway_session_id: int, key: RecordingKey) -> bytes:
    from secrets_store import unseal_with_aad

    import service

    wrapped = json.loads(key.wrapped_key)
    return bytes.fromhex(
        unseal_with_aad(wrapped, _recording_aad(gateway_session_id), service._vault_config())
    )


def _storage_root() -> Config:
    import service

    return service._vault_config()


def segment_path(rel_path: str) -> str:
    """Resolve a stored relative segment pointer under the storage root."""
    root = _storage_root().recording_storage_dir
    full = os.path.normpath(os.path.join(root, rel_path))
    if not full.startswith(os.path.normpath(root)):
        raise APIError(500, "Segment pointer escapes the storage root")
    return full
