"""Immutable audit ledger (architecture section 19).

One append-only, hash-chained store for every module event:

    module event -> audit_events row -> sha256(prev_hash + payload)
    -> timestamp -> SQLite append-only triggers -> SIEM export (NDJSON)

- A ``before_flush`` listener copies each new event row into the ledger in
  the same transaction, so an event cannot be committed unaudited.
- When a SIEM webhook is configured (section 20), each committed batch is
  POSTed after_commit as HMAC-signed NDJSON - the same records
  ``GET /api/v1/audit/export`` emits; a failed push is recorded honestly
  and never breaks the request that committed it.
- ``event_hash`` links seq N to N-1; ``GET /api/v1/audit/verify`` walks the
  whole chain and reports the first break (gap, re-link or content change).
- SQLite ``BEFORE UPDATE``/``BEFORE DELETE`` triggers make the rows
  immutable even for someone with direct database access, and the API has
  no route that writes or deletes them.
- Channel content (keystrokes, file payloads) stays in the append-only
  session recording; the ledger stores *actions* - lifecycle transitions,
  commands, approval decisions and escalations.

Imported by ``service`` and ``app``; verify via ``GET /api/v1/audit/verify``.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import event, func, text
from sqlalchemy.orm import Session, sessionmaker

from extensions import db
from models import (
    AUDIT_GENESIS_HASH,
    AgentEvent,
    AnomalyEvent,
    AuditEvent,
    BreakGlassEvent,
    BrokerEvent,
    BypassEvent,
    CloudEvent,
    ClusterEvent,
    CommandIncident,
    DiscoveryEvent,
    IntegrationEvent,
    JitEvent,
    LicenseEvent,
    PrivilegedSession,
    RiskEvent,
    SessionEvent,
    SettingGroup,
    SettingsEvent,
    VaultEvent,
    VendorEvent,
)

# the sixteen trails folded into the ledger (the unified feed reads these)
AUDIT_SOURCES = (
    "license",
    "settings",
    "vault",
    "discovery",
    "jit",
    "session",
    "command",
    "risk",
    "bypass",
    "break-glass",
    "integration",
    "vendor",
    "cloud",
    "broker",
    "agent",
    "cluster",
)
SOURCE_RANK = {name: index for index, name in enumerate(AUDIT_SOURCES)}

# session recording rows the ledger takes (actions), versus channel content
# (keystroke / file / clipboard / screenshot) that stays in the recording
_SESSION_LEDGER_TYPES = ("status", "note")
_COMMAND_LEDGER_TYPES = ("command", "approval")

_TRIGGERS = {
    "audit_events_no_update": (
        "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only (architecture 19)'); END"
    ),
    "audit_events_no_delete": (
        "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only (architecture 19)'); END"
    ),
}


def compute_hash(
    *,
    seq: int,
    created_at: datetime,
    event_ref: str,
    source: str,
    action: str,
    actor: str,
    subject: str,
    detail: Dict[str, Any],
    prev_hash: str,
) -> str:
    """sha256 over the canonical record plus the previous hash."""
    payload = json.dumps(
        {
            "seq": seq,
            "created_at": created_at.isoformat(),
            "event_ref": event_ref,
            "source": source,
            "action": action,
            "actor": actor,
            "subject": subject,
            "detail": detail,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _row_hash(row: AuditEvent) -> str:
    return compute_hash(
        seq=row.seq,
        created_at=row.created_at,
        event_ref=row.event_ref,
        source=row.source,
        action=row.action,
        actor=row.actor,
        subject=row.subject,
        detail=row.detail or {},
        prev_hash=row.prev_hash,
    )


def _entry(
    *,
    source: str,
    event_ref: str,
    action: str,
    actor: str,
    subject: str,
    detail: Dict[str, Any],
    created_at: datetime,
    sort_id: int,
) -> Dict[str, Any]:
    return {
        "source": source,
        "event_ref": event_ref,
        "action": action,
        "actor": actor,
        "subject": subject,
        "detail": detail or {},
        "created_at": created_at,
        "sort_id": sort_id,
    }


def _value(obj: Any, name: str) -> Any:
    """Read a column the way it will be stored: pending rows still carry
    None where the INSERT will apply the column default, so mirror it."""
    value = getattr(obj, name, None)
    if value is not None:
        return value
    column = type(obj).__table__.c.get(name)
    default = column.default if column is not None else None
    if default is None:
        return None
    arg = default.arg
    return arg() if callable(arg) else arg


# --- source mappers: one per event model -----------------------------------
def _map_license(event: LicenseEvent, db_session) -> Dict[str, Any]:
    return _entry(
        source="license",
        event_ref=f"license:{event.id}",
        action=event.action,
        actor="system",
        subject=event.license_key,
        detail=event.detail or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_settings(event: SettingsEvent, db_session) -> Dict[str, Any]:
    return _entry(
        source="settings",
        event_ref=f"settings:{event.id}",
        action=event.action,
        actor=_value(event, "actor"),
        subject=event.group_name,
        detail=event.changes or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_vault(event: VaultEvent, db_session) -> Dict[str, Any]:
    return _entry(
        source="vault",
        event_ref=f"vault:{event.id}",
        action=event.action,
        actor=_value(event, "actor"),
        subject=event.item_name,
        detail=event.detail or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_discovery(event: DiscoveryEvent, db_session) -> Dict[str, Any]:
    return _entry(
        source="discovery",
        event_ref=f"discovery:{event.id}",
        action=event.action,
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=event.detail or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_jit(event: JitEvent, db_session) -> Dict[str, Any]:
    return _entry(
        source="jit",
        event_ref=f"jit:{event.id}",
        action=event.action,
        actor=_value(event, "actor"),
        subject=f"request {event.request_id}",
        detail=event.detail or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_session(event: SessionEvent, db_session) -> Optional[Dict[str, Any]]:
    """Lifecycle/notes land under `session`, command decisions (and their
    approval resolutions) under `command`. Channel content stays out."""
    if event.type in _COMMAND_LEDGER_TYPES:
        source, event_ref = "command", f"command:{event.id}"
    elif event.type in _SESSION_LEDGER_TYPES:
        source, event_ref = "session", f"session:{event.id}"
    else:
        return None
    session = None
    if db_session is not None and event.session_id is not None:
        with db_session.no_autoflush:
            session = db_session.get(PrivilegedSession, event.session_id)
    subject = session.session_ref if session is not None else f"session-{event.session_id}"
    return _entry(
        source=source,
        event_ref=event_ref,
        action=event.type,
        actor=_value(event, "actor"),
        subject=subject,
        detail={
            "type": event.type,
            "content": event.content,
            "allowed": _value(event, "allowed"),
            "blocked_reason": event.blocked_reason,
            "withheld": _value(event, "withheld"),
            "decision": event.decision,
            "rule_id": event.rule_id,
            "ref_seq": event.ref_seq,
            "session_id": event.session_id,
            "seq": event.seq,
            "watermark": event.watermark,
        },
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_incident(event: CommandIncident, db_session) -> Dict[str, Any]:
    return _entry(
        source="command",
        event_ref=f"incident:{event.id}",
        action="escalated",
        actor=_value(event, "actor"),
        subject=event.incident_ref,
        detail={
            "command": event.command,
            "target": _value(event, "target"),
            "session_id": event.session_id,
            "event_seq": event.event_seq,
            "rule_id": event.rule_id,
            "rule_name": _value(event, "rule_name"),
            "rule_pattern": _value(event, "rule_pattern"),
            "status": _value(event, "status"),
        },
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_risk_evaluation(event: RiskEvent, db_session) -> Dict[str, Any]:
    """The decision (allow/mfa/approval/block) and the points that produced
    it, under the `risk` trail - refusals are SOC evidence."""
    return _entry(
        source="risk",
        event_ref=f"risk:{event.id}",
        action=_value(event, "decision"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail={
            "score": _value(event, "score"),
            "band": _value(event, "band"),
            "decision": _value(event, "decision"),
            "result": _value(event, "result"),
            "context": _value(event, "context"),
            "target": _value(event, "target"),
            "device": _value(event, "device"),
            "source_ip": _value(event, "source_ip"),
            "ticket": _value(event, "ticket"),
            "command": _value(event, "command"),
            "components": _value(event, "components"),
        },
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_anomaly(event: AnomalyEvent, db_session) -> Dict[str, Any]:
    """A section-11 UEBA incident: the named deviations, the response the
    chain executed (sessions ended, rotations) and the evaluation it came
    from - under the `risk` trail, right next to that evaluation."""
    return _entry(
        source="risk",
        event_ref=f"anom:{event.id}",
        action="anomaly-incident",
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail={
            "incident_ref": _value(event, "incident_ref"),
            "evaluation_id": _value(event, "evaluation_id"),
            "target": _value(event, "target"),
            "score": _value(event, "score"),
            "band": _value(event, "band"),
            "reasons": _value(event, "reasons"),
            "actions": _value(event, "actions"),
        },
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_bypass(event: BypassEvent, db_session) -> Dict[str, Any]:
    """Ingestions, correlation scans, detections and closes under the ninth
    trail `bypass` (architecture section 10) - the SOC evidence trail for
    direct access that skipped PAM."""
    return _entry(
        source="bypass",
        event_ref=f"bypass:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_break_glass(event: BreakGlassEvent, db_session) -> Dict[str, Any]:
    """Requests, approval signatures, denials, unseals and closes under the
    tenth trail `break-glass` (architecture section 17) - the auditable
    trail of the emergency process itself."""
    return _entry(
        source="break-glass",
        event_ref=f"break-glass:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_integration(event: IntegrationEvent, db_session) -> Dict[str, Any]:
    """MFA verifications, the medium-band MFA gate, ITSM ticket checks,
    LDAP logins and SIEM push failures under the eleventh trail
    `integration` (architecture section 20) - what the product did against
    an external system, without the secrets it did it with."""
    return _entry(
        source="integration",
        event_ref=f"integration:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_vendor(event: VendorEvent, db_session) -> Dict[str, Any]:
    """Invites, step verifications, approvals, denials, revocations, scope
    refusals and automatic expiry under the twelfth trail `vendor`
    (architecture section 13) - the auditable trail of the third-party
    lifecycle itself, never the TOTP seed or a submitted code."""
    return _entry(
        source="vendor",
        event_ref=f"vendor:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_cloud(event: CloudEvent, db_session) -> Dict[str, Any]:
    """Connector lifecycle, real probe outcomes, inventory runs, Kubernetes
    RBAC grant requests and applied/removed ephemeral bindings under the
    thirteenth trail `cloud` (architecture section 14) - the auditable
    trail of the cloud PAM lifecycle itself, never the credential used for
    a call, only its outcome."""
    return _entry(
        source="cloud",
        event_ref=f"cloud:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_broker(event: BrokerEvent, db_session) -> Dict[str, Any]:
    """Pipeline identity lifecycle, credential requests, approvals, denials,
    releases, closes, expiry and scope refusals under the fourteenth trail
    `broker` (architecture section 15) - the auditable trail of the CI/CD
    credential broker itself, never the API token or the released secret,
    only the outcome."""
    return _entry(
        source="broker",
        event_ref=f"broker:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_agent(event: AgentEvent, db_session) -> Dict[str, Any]:
    """AI-agent identity lifecycle, task-scope changes, access requests and
    their refusals, opens and closes under the fifteenth trail `agent`
    (architecture section 16) - the auditable trail of agent privilege
    itself, never the API token, only the outcome."""
    return _entry(
        source="agent",
        event_ref=f"agent:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


def _map_cluster(event: ClusterEvent, db_session) -> Dict[str, Any]:
    """HA/DC/DR node lifecycle under the sixteenth trail `cluster`
    (architecture section 18): registrations, health-probe state changes,
    replication syncs, role flips and backups - the auditable trail of the
    cluster's own topology and trust, never a secret, never a sealed blob."""
    return _entry(
        source="cluster",
        event_ref=f"cluster:{event.id}",
        action=_value(event, "action"),
        actor=_value(event, "actor"),
        subject=_value(event, "subject"),
        detail=_value(event, "detail") or {},
        created_at=event.created_at,
        sort_id=event.id,
    )


# every event model that must reach the ledger, in a stable backfill order
LEDGER_MODELS = (
    LicenseEvent,
    SettingsEvent,
    VaultEvent,
    DiscoveryEvent,
    JitEvent,
    SessionEvent,
    CommandIncident,
    RiskEvent,
    BypassEvent,
    BreakGlassEvent,
    IntegrationEvent,
    AnomalyEvent,
    VendorEvent,
    CloudEvent,
    BrokerEvent,
    AgentEvent,
    ClusterEvent,
)

MAPPERS = {
    LicenseEvent: _map_license,
    SettingsEvent: _map_settings,
    VaultEvent: _map_vault,
    DiscoveryEvent: _map_discovery,
    JitEvent: _map_jit,
    SessionEvent: _map_session,
    CommandIncident: _map_incident,
    RiskEvent: _map_risk_evaluation,
    BypassEvent: _map_bypass,
    BreakGlassEvent: _map_break_glass,
    IntegrationEvent: _map_integration,
    AnomalyEvent: _map_anomaly,
    VendorEvent: _map_vendor,
    CloudEvent: _map_cloud,
    BrokerEvent: _map_broker,
    AgentEvent: _map_agent,
    ClusterEvent: _map_cluster,
}


def append_entries(entries: List[Dict[str, Any]], db_session) -> List[AuditEvent]:
    """Chain a batch of mapped entries onto the ledger and add them to the
    session (the caller's transaction owns the commit)."""
    if not entries:
        return []
    with db_session.no_autoflush:
        last = (
            db_session.query(AuditEvent)
            .order_by(AuditEvent.seq.desc())
            .first()
        )
    seq = last.seq if last is not None else 0
    prev_hash = last.event_hash if last is not None else AUDIT_GENESIS_HASH
    rows: List[AuditEvent] = []
    for entry in entries:
        seq += 1
        row = AuditEvent(
            seq=seq,
            event_ref=entry["event_ref"],
            source=entry["source"],
            action=entry["action"],
            actor=entry["actor"],
            subject=entry["subject"],
            detail=entry["detail"],
            created_at=entry["created_at"],
            prev_hash=prev_hash,
        )
        row.event_hash = _row_hash(row)
        db_session.add(row)
        prev_hash = row.event_hash
        rows.append(row)
    # queue the export form of this batch for the SIEM drain: the push
    # happens after_commit (a rolled-back transaction discards its own
    # pending records in after_rollback - evidence never ships uncommitted)
    _PENDING_PUSH.extend(row.to_dict() for row in rows)
    return rows


# ---------------------------------------------------------------------------
# SIEM outbound: every committed ledger batch, NDJSON + HMAC-SHA256
# ---------------------------------------------------------------------------
# The queue holds the exact records `GET /audit/export` would emit, staged
# during append and drained once the transaction that wrote them commits.
_PENDING_PUSH: List[Dict[str, Any]] = []

# last drain outcome, surfaced by GET /integrations/status (honest about
# "never pushed" before the first configured batch)
_SIEM_STATUS: Dict[str, Any] = {
    "last_push_at": None,
    "last_push_status": "never",  # never | ok | error
    "last_http_status": None,
    "last_error": None,
    "batches_ok": 0,
    "batches_failed": 0,
    "records_pushed": 0,
}

# re-entrancy guard: the push-failure event commits its own ledger row from
# inside a drain, and that row must not be pushed (a dead endpoint would
# otherwise fail, emit, push, fail, ...)
_SIEM_DRAINING = False


def siem_status() -> Dict[str, Any]:
    """A copy of the last drain outcome (settings live in the service)."""
    return dict(_SIEM_STATUS)


def _post_commit_session() -> Session:
    """A dedicated Session for work performed inside `after_commit`.

    The listener fires while the writing session is in SQLAlchemy's
    `committed` state, which refuses any new SQL until its `commit()`
    returns - so the settings read and the push-failure event run on a
    session of their own (same engine, post-commit data visible).
    """
    return sessionmaker(bind=db.engine)()


def _siem_settings() -> Tuple[Optional[str], Optional[str], bool, float]:
    """Read the `siem` group post-commit: (webhook, secret, enabled, t/o).

    Deferred imports: service imports this module at the top level.
    """
    from service import _setting_aad, _vault_config
    from secrets_store import unseal_with_aad

    session = _post_commit_session()
    try:
        row = session.query(SettingGroup).filter_by(group_name="siem").first()
        values = dict(row.value) if row is not None and row.value else {}
    finally:
        session.close()

    webhook = (values.get("webhook_url") or "").strip()
    enabled = bool(values.get("enabled"))
    raw = values.get("signing_secret")
    if not raw:
        secret = ""
    elif isinstance(raw, str):
        secret = raw  # never sealed in the first place - pass through
    else:
        secret = unseal_with_aad(raw, _setting_aad("siem", "signing_secret"), _vault_config())
    timeout = float(values.get("timeout_seconds") or 5)
    return webhook, secret, enabled, timeout


def _siem_drain() -> None:
    """Push the committed batch when a webhook is configured; record the
    outcome honestly, including a ledger event for a failed push."""
    global _SIEM_DRAINING
    records = list(_PENDING_PUSH)
    _PENDING_PUSH.clear()
    if not records:
        return

    try:
        webhook, secret, enabled, timeout = _siem_settings()
    except Exception:  # settings unreadable: nothing configured to push to
        return
    if not enabled or not webhook:
        return

    import integrations  # stdlib-only, cycle-free

    result = integrations.siem_push(
        records, webhook_url=webhook, signing_secret=secret or "", timeout=timeout
    )
    _SIEM_STATUS["last_push_at"] = datetime.now().isoformat()
    _SIEM_STATUS["last_http_status"] = result.get("http_status")
    if result.get("ok"):
        _SIEM_STATUS["last_push_status"] = "ok"
        _SIEM_STATUS["last_error"] = None
        _SIEM_STATUS["batches_ok"] += 1
        _SIEM_STATUS["records_pushed"] += int(result.get("records", 0))
        return

    detail = result.get("detail") or "push failed"
    _SIEM_STATUS["last_push_status"] = "error"
    _SIEM_STATUS["last_error"] = detail
    _SIEM_STATUS["batches_failed"] += 1

    # the failed push is itself auditable - under the re-entrancy guard, so
    # this event's ledger row is never pushed back at the dead endpoint.
    # It commits on its own session: we are inside `after_commit`, where
    # the writing session refuses SQL (see `_post_commit_session`).
    try:
        _SIEM_DRAINING = True
        session = _post_commit_session()
        try:
            session.add(
                IntegrationEvent(
                    action="siem-push-failed",
                    actor="system",
                    subject=f"{len(records)} record(s)",
                    detail={"error": detail, "records": len(records)},
                )
            )
            session.commit()
        finally:
            session.close()
    except Exception:
        pass
    finally:
        _SIEM_DRAINING = False
        _PENDING_PUSH.clear()


def _after_commit(_session: Session) -> None:
    """Drain the SIEM queue once the writing transaction committed."""
    if _SIEM_DRAINING:
        # the failure event's own commit: its records are for the chain,
        # not for the endpoint that just failed
        _PENDING_PUSH.clear()
        return
    try:
        if _PENDING_PUSH:
            _siem_drain()
    except Exception as exc:  # never let a push break the request that committed
        _PENDING_PUSH.clear()
        _SIEM_STATUS["last_push_status"] = "error"
        _SIEM_STATUS["last_error"] = f"{type(exc).__name__}: {exc}"


def _after_rollback(_session: Session) -> None:
    """A rolled-back transaction's records never reached the ledger: drop
    them so a later commit cannot ship uncommitted evidence."""
    if not _SIEM_DRAINING:
        _PENDING_PUSH.clear()


def append_explicit(
    *,
    event_ref: str,
    source: str,
    action: str,
    actor: str,
    subject: str,
    detail: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Audit a state change that has no new module row of its own (for
    example an incident being closed). The caller commits."""
    if source not in AUDIT_SOURCES:
        raise ValueError(f"unknown audit source '{source}'")
    rows = append_entries(
        [
            _entry(
                source=source,
                event_ref=event_ref,
                action=action,
                actor=actor,
                subject=subject,
                detail=detail or {},
                created_at=datetime.now(),
                sort_id=0,
            )
        ],
        db.session,
    )
    return rows[0]


def _ensure_id(db_session, obj: Any, pending: Dict[Any, List[int]]) -> None:
    """Assign the source id up front so the ledger ref ("vault:3") exists
    before the row is inserted (single-writer sqlite: max+1, like the
    session seq counter)."""
    if obj.id is not None:
        return
    cls = type(obj)
    with db_session.no_autoflush:
        current = db_session.query(func.max(cls.id)).scalar()
    floor = int(current or 0)
    assigned = pending.setdefault(cls, [])
    if assigned:
        floor = max(floor, max(assigned))
    obj.id = floor + 1
    assigned.append(obj.id)


def _before_flush(db_session, flush_context, instances) -> None:
    """Same-transaction fan-in: every new event row lands in the ledger."""
    pending: Dict[Any, List[int]] = {}
    entries: List[Dict[str, Any]] = []
    for obj in list(db_session.new):
        mapper = MAPPERS.get(type(obj))
        if mapper is None:
            continue
        _ensure_id(db_session, obj, pending)
        if obj.created_at is None:
            # the column default runs at INSERT; stamp it now so the source
            # row and its ledger record share the exact same timestamp
            obj.created_at = datetime.now()
        entry = mapper(obj, db_session)
        if entry is not None:
            entries.append(entry)
    if not entries:
        return
    entries.sort(
        key=lambda e: (e["created_at"], SOURCE_RANK.get(e["source"], len(SOURCE_RANK)), e["sort_id"])
    )
    append_entries(entries, db_session)


_LISTENER_INSTALLED = False


def install_listener() -> bool:
    """Register the flush + SIEM drain listeners once (idempotent)."""
    global _LISTENER_INSTALLED
    if _LISTENER_INSTALLED:
        return False
    event.listen(Session, "before_flush", _before_flush)
    event.listen(Session, "after_commit", _after_commit)
    event.listen(Session, "after_rollback", _after_rollback)
    _LISTENER_INSTALLED = True
    return True


install_listener()


def _install_triggers(engine) -> bool:
    """Create the append-only triggers when they are missing (sqlite only)."""
    if engine.dialect.name != "sqlite":
        return False
    with engine.begin() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    "AND name LIKE 'audit_events_%'"
                )
            )
        }
        for name, sql in _TRIGGERS.items():
            if name not in existing:
                conn.execute(text(sql))
    return True


def triggers_installed(engine) -> bool:
    """True when both immutability triggers are live in the database."""
    if engine.dialect.name != "sqlite":
        return False
    with engine.connect() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    "AND name LIKE 'audit_events_%'"
                )
            )
        }
    return set(_TRIGGERS) <= existing


def ensure_audit_chain() -> int:
    """Install the triggers and backfill any pre-existing history, oldest
    first, chaining onto whatever is already recorded. Returns the number
    of rows added (0 when the ledger is already current)."""
    _install_triggers(db.engine)
    with db.session.no_autoflush:
        existing = {
            ref for (ref,) in db.session.query(AuditEvent.event_ref).all()
        }
    entries: List[Dict[str, Any]] = []
    for cls in LEDGER_MODELS:
        mapper = MAPPERS[cls]
        for obj in (
            db.session.query(cls).order_by(cls.created_at, cls.id).all()
        ):
            entry = mapper(obj, db.session)
            if entry is not None and entry["event_ref"] not in existing:
                entries.append(entry)
    entries.sort(
        key=lambda e: (e["created_at"], SOURCE_RANK.get(e["source"], len(SOURCE_RANK)), e["sort_id"])
    )
    rows = append_entries(entries, db.session)
    db.session.commit()
    return len(rows)


def verify_chain() -> Dict[str, Any]:
    """Walk the whole ledger in chain order and report the first break."""
    rows = AuditEvent.query.order_by(AuditEvent.seq).all()
    prev_hash = AUDIT_GENESIS_HASH
    expected = 1
    checked = 0
    for row in rows:
        if row.seq != expected:
            return {
                "intact": False,
                "checked": checked,
                "total": len(rows),
                "last_seq": row.seq - 1 if row.seq > 1 else 0,
                "head_hash": prev_hash if checked else "",
                "broken_at": expected,
                "reason": (
                    f"sequence gap: expected seq {expected}, found {row.seq} "
                    "(a record was removed or reordered)"
                ),
            }
        if row.prev_hash != prev_hash:
            return {
                "intact": False,
                "checked": checked,
                "total": len(rows),
                "last_seq": row.seq - 1,
                "head_hash": prev_hash if checked else "",
                "broken_at": row.seq,
                "reason": f"chain link broken at seq {row.seq} (prev_hash does not match)",
            }
        if _row_hash(row) != row.event_hash:
            return {
                "intact": False,
                "checked": checked,
                "total": len(rows),
                "last_seq": row.seq - 1,
                "head_hash": prev_hash if checked else "",
                "broken_at": row.seq,
                "reason": f"content hash mismatch at seq {row.seq} (record altered)",
            }
        prev_hash = row.event_hash
        expected = row.seq + 1
        checked += 1
    return {
        "intact": True,
        "checked": checked,
        "total": len(rows),
        "last_seq": rows[-1].seq if rows else 0,
        "head_hash": prev_hash if checked else "",
        "broken_at": None,
        "reason": None,
    }


def chain_stats() -> Dict[str, Any]:
    """Real aggregates over the ledger (the screen's digest card)."""
    total = AuditEvent.query.count()
    counts = dict(
        db.session.query(AuditEvent.source, func.count(AuditEvent.id))
        .group_by(AuditEvent.source)
        .all()
    )
    newest = AuditEvent.query.order_by(AuditEvent.seq.desc()).first()
    oldest = AuditEvent.query.order_by(AuditEvent.seq.asc()).first()
    return {
        "total": total,
        "by_source": {name: int(counts.get(name, 0)) for name in AUDIT_SOURCES},
        "last_seq": newest.seq if newest is not None else 0,
        "head_hash": newest.event_hash if newest is not None else "",
        "oldest_at": oldest.created_at.isoformat() if oldest is not None else None,
        "newest_at": newest.created_at.isoformat() if newest is not None else None,
        "trigger_protection": triggers_installed(db.engine),
    }
