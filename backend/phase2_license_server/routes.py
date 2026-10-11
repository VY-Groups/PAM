"""HTTP routes for the Phase 2 license server."""
from __future__ import annotations

import fnmatch
import hmac
import json
import re
from functools import wraps
from typing import Any, Dict, Optional

from flask import Blueprint, Response, current_app, g, jsonify, request

import service
from config import Config
from errors import Conflict, Forbidden, Unauthorized, ValidationFailed
from licensing_bridge import sig

api = Blueprint("api", __name__, url_prefix="/api/v1")

MAX_PAGE_SIZE = 200


@api.before_request
def _passive_node_gate():
    """HA / DC / DR (architecture section 18): while this node's registry
    role is `passive`, every write outside the cluster module itself is
    refused with 409.

    That is what active-passive honestly means for this product: a passive
    DR node answers reads (the screens, the ledger, the evidence - that is
    what a standby is for) and runs its own cluster operations (probe,
    sync, backup, promote - a standby must be able to prove its peers are
    dead and take over), but it never takes a product write: not vault, not
    sessions, not settings, not licenses, not agent tasks. The gate is
    method-based and deliberately blunt - every POST/PUT/PATCH/DELETE
    outside those exemptions, including read-shaped ones like license
    validation: the load balancer keeps traffic on the active node, and a
    request that reaches the standby is told the truth (promote it) rather
    than answered from state this node does not replicate (licenses are
    not part of the pull replication - only the audit chain, the sealed
    vault and session metadata are).

    Two exemptions, both deliberate:
    - `/api/v1/auth/*` is how a caller proves who they are, and reads need
      credentials in token mode - gating authentication would lock
      operators out of the very node they must inspect (or promote), and
      6c's SSO login lands here too.
    - Cluster operations stay writable because they are the standby's own
      job: evidence, backups and the promote action itself.

    The check runs before auth on purpose: it consults nothing but this
    node's own row, and a 409 naming the promote route leaks no data - it
    tells a caller exactly why the write was refused and how to lift it.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.path.startswith(("/api/v1/cluster/", "/api/v1/auth/")):
        return None
    if service.cluster_self_role() != "passive":
        return None
    return (
        jsonify(
            {
                "error": (
                    "This node is passive (DR standby): every write outside "
                    "/api/v1/cluster/* (authentication excepted) is refused "
                    "until it is promoted"
                ),
                "details": {
                    "role": "passive",
                    "promote": "POST /api/v1/cluster/failover",
                },
            }
        ),
        409,
    )


def _config() -> Config:
    return current_app.config["LICENSE_CONFIG"]


def _json_body(*, required: bool = True) -> Dict[str, Any]:
    data = request.get_json(silent=True)
    if data is None:
        if required:
            raise ValidationFailed("Request body must be valid JSON")
        return {}
    if not isinstance(data, dict):
        raise ValidationFailed("Request body must be a JSON object")
    return data


def _int_param(name: str, default: int, *, minimum: int = 0) -> int:
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationFailed(f"Query parameter '{name}' must be an integer") from None
    if value < minimum:
        raise ValidationFailed(f"Query parameter '{name}' must be >= {minimum}")
    return value


_RULE_PARAM = re.compile(r"<(?:[a-z_][a-z0-9_]*:)?([a-z_][a-z0-9_]*)>")


def _operation_rule() -> str:
    """The request's URL rule in contract form: Flask writes path params
    as `/x/<int:item_id>`, the openapi document (and ROLE_OPERATIONS) as
    `/x/{item_id}` - the two must be the same key for the role policy to
    match what the contract documents."""
    rule = request.url_rule.rule if request.url_rule is not None else request.path
    return _RULE_PARAM.sub(r"{\1}", rule)


def _presented_credential() -> str:
    """The token this request presents as its admin-side credential: the
    X-Admin-Token header, or the Authorization bearer value when present."""
    token = request.headers.get("X-Admin-Token")
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    return (token or "").strip()


def _unbound_principal_error(principal: Dict[str, Any]) -> Forbidden:
    """The honest refusal for a directory identity with no role binding."""
    return Forbidden(
        f"Directory identity '{principal['principal']}' has no role "
        "binding - an admin must grant one (POST /api/v1/role-bindings)",
        {"principal": principal["principal"], "role_required": True},
    )


def _require_admin_credential() -> None:
    """Raise Unauthorized unless a valid admin-side credential is presented,
    and Forbidden unless that credential's role may call this operation
    (RBAC/ABAC, architecture section 10).

    Three credentials are accepted in token mode. The admin token is
    `admin` - every operation. A role binding's `vypam-rbac1.<id>.<secret>`
    token is its binding's role - exactly the operations ROLE_OPERATIONS
    grants it. A signed LDAP login ticket (minted by POST /api/v1/auth/ldap
    after a real bind) authenticates the directory username - and a role
    binding decides what that username may do, so an unbound directory
    identity is refused instead of silently holding the admin token. The
    acting principal is left on `g.rbac_principal` for the audit actor and
    the attribute checks. When LICENSE_ADMIN_TOKEN is unset the server runs
    in open/dev mode and every route is allowed (the response header
    reports this).
    """
    config = _config()
    if not config.admin_token:
        return
    principal = service.resolve_principal(_presented_credential(), config=config)
    if principal is None:
        raise Unauthorized(
            "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
        )
    if principal.get("unbound"):
        raise _unbound_principal_error(principal)
    g.rbac_principal = principal
    role = principal["role"]
    rule = _operation_rule()
    if not service.role_allows(role, request.method, rule):
        raise Forbidden(
            f"Role '{role}' may not call {request.method} {rule}",
            {"role": role, "operation": f"{request.method.lower()} {rule}"},
        )


def _require_scope(*, item_id: Optional[int] = None, target: Optional[str] = None) -> None:
    """ABAC (architecture section 10): enforce the acting principal's
    binding scope on a vault item operation or a session target. The admin
    role and unscoped bindings are unrestricted; a scoped binding only
    reaches the vault items and target patterns its admin granted it."""
    principal = getattr(g, "rbac_principal", None)
    if principal is None or principal.get("role") == "admin":
        return
    scope = principal.get("scope") or {}
    if item_id is not None:
        allowed_items = scope.get("vault_items") or []
        if allowed_items and item_id not in allowed_items:
            raise Forbidden(
                f"Role binding '{principal['principal']}' is not scoped to "
                f"vault item {item_id}",
                {"scope": scope, "item_id": item_id},
            )
    if target is not None:
        patterns = scope.get("targets") or []
        if patterns and not any(fnmatch.fnmatch(target, pattern) for pattern in patterns):
            raise Forbidden(
                f"Role binding '{principal['principal']}' is not scoped to "
                f"target '{target}'",
                {"scope": scope, "target": target},
            )


def require_admin(view):
    """Reject the request unless a valid admin credential is presented and
    its role may call this operation (see _require_admin_credential)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        _require_admin_credential()
        return view(*args, **kwargs)

    return wrapped


def _pipeline_token() -> str:
    """A pipeline's broker API token: the X-Broker-Token header, or a
    `vypam-ci1.` bearer value in Authorization - a plain bearer token stays
    the admin credential, so the two are never confused on dual-auth
    routes."""
    token = (request.headers.get("X-Broker-Token") or "").strip()
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer.startswith(service.BROKER_TOKEN_PREFIX + "."):
            return bearer
    return ""


def require_pipeline(view):
    """Reject the request unless a valid broker API token authenticates the
    pipeline (architecture section 15). Unlike the admin token this is
    never waived in open/dev mode: the machine identity is the point - the
    pipeline *is* its policy row, and X-Actor is not consulted."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.broker_policy = service.verify_broker_token(_pipeline_token())
        return view(*args, **kwargs)

    return wrapped


def _agent_token() -> str:
    """An AI agent's API token: the X-Agent-Token header, or a
    `vypam-agt1.` bearer value in Authorization - a plain bearer token
    stays the admin credential, so the two are never confused on dual-auth
    routes."""
    token = (request.headers.get("X-Agent-Token") or "").strip()
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer.startswith(service.AGENT_TOKEN_PREFIX + "."):
            return bearer
    return ""


def require_agent(view):
    """Reject the request unless a valid agent API token authenticates the
    agent (architecture section 16). Like the pipeline token this is never
    waived in open/dev mode: the agent identity is the point, X-Actor is
    not consulted, and the actor on every record is the identity's name."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.agent_identity = service.verify_agent_token(_agent_token())
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# installing vendor-signed licenses
# ---------------------------------------------------------------------------
@api.post("/licenses/import")
@require_admin
def import_license():
    """Install the vendor-signed .lic from the delivery bundle.

    The shipped server verifies the signature and records the claims — it
    never signs (issuing belongs to PAM-MASTER).
    """
    body = _json_body()
    record, license_file = service.import_license(_config(), body)
    return (
        jsonify(
            {
                "license": record.to_dict(),
                "license_file": license_file,
                "token": license_file.get("token"),
                "message": "License imported",
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------
@api.get("/meta")
def server_meta():
    """Capabilities: algorithms, formats, tier names, entitlement catalog."""
    return jsonify(service.meta())


@api.get("/licenses")
def list_licenses():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    records, total = service.list_licenses(
        status=request.args.get("status"),
        license_type=request.args.get("license_type"),
        issued_to=request.args.get("issued_to"),
        tier=request.args.get("tier"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "licenses": [record.to_dict() for record in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/licenses/<string:license_key>")
def get_license(license_key: str):
    record = service.get_record(license_key)
    payload = record.to_dict(include_events=True)
    payload["usage"] = record.usage_summary()
    return jsonify({"license": payload})


@api.get("/licenses/<string:license_key>/file")
@require_admin
def download_license_file(license_key: str):
    record = service.get_record(license_key)
    fmt = request.args.get("format", record.signature_format or sig.FORMAT_JSON)
    if fmt not in sig.SUPPORTED_FORMATS:
        raise ValidationFailed(
            f"Unknown format '{fmt}'",
            {"field": "format", "allowed": list(sig.SUPPORTED_FORMATS)},
        )

    if fmt == sig.FORMAT_JWT:
        payload = record.license_token()
        mimetype = "text/plain"
    else:
        payload = json.dumps(record.license_file(), indent=2)
        mimetype = "application/json"

    response = current_app.response_class(payload, mimetype=mimetype)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="license_{record.license_key}.{fmt}"'
    )
    return response


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------
@api.post("/licenses/<string:license_key>/revoke")
@require_admin
def revoke_license(license_key: str):
    body = _json_body(required=False)
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ValidationFailed("'reason' must be a string", {"field": "reason"})

    record = service.revoke_license(license_key, reason)
    return jsonify({"license": record.to_dict(), "message": "License revoked"})


@api.post("/licenses/<string:license_key>/restore")
@require_admin
def restore_license(license_key: str):
    record = service.restore_license(license_key)
    return jsonify({"license": record.to_dict(), "message": "License restored"})


# ---------------------------------------------------------------------------
# runtime usage reporting (admin)
# ---------------------------------------------------------------------------
@api.post("/licenses/<string:license_key>/usage")
@require_admin
def report_license_usage(license_key: str):
    record = service.report_usage(license_key, _json_body())
    return (
        jsonify(
            {
                "license": record.to_dict(),
                "usage": record.usage_summary(),
                "message": "Usage recorded",
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# validation (public)
# ---------------------------------------------------------------------------
@api.post("/licenses/validate")
def validate_license():
    """
    Validate a license payload.

    Accepts a JSON envelope, ``{"license": ...}`` / ``{"token": ...}`` wrappers,
    or a compact token sent as a raw string body (curl --data-binary @file.lic).
    """
    payload = request.get_json(silent=True)
    if payload is None:
        raw = request.get_data(as_text=True).strip()
        # A compact token is three dot-separated segments; anything else that
        # is not valid JSON is a bad request rather than a malformed license.
        if not raw or raw.startswith("{") or len(raw.split(".")) != 3:
            raise ValidationFailed(
                "Request body must be a valid JSON license envelope "
                "or a compact token (header.payload.signature)"
            )
        payload = raw
    return jsonify(service.validate_license_payload(_config(), payload))


@api.post("/licenses/<string:license_key>/check")
def check_license_access(license_key: str):
    body = _json_body()
    result = service.check_access(
        license_key,
        feature=body.get("feature"),
        module_id=body.get("module_id"),
        limit_type=body.get("limit_type"),
        current_usage=body.get("current_usage"),
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# platform settings (Platform Settings screen)
# ---------------------------------------------------------------------------
@api.get("/settings")
def get_platform_settings():
    """Every settings group (defaults merged in) plus the render schema."""
    return jsonify(
        {"settings": service.get_settings(), "schema": service.settings_schema()}
    )


@api.get("/settings/audit")
def get_settings_audit():
    """Config audit changelog: which fields changed, by whom, and when."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.settings_audit(limit))


@api.put("/settings/<string:group>")
@require_admin
def put_platform_settings(group: str):
    """Replace fields in one settings group (validated, audited, committed)."""
    body = _json_body()
    actor = (request.headers.get("X-Actor") or "admin").strip()[:64] or "admin"
    return jsonify(service.update_settings(group, body, actor=actor))


# ---------------------------------------------------------------------------
# dashboard (Command Center + Compliance screens)
# ---------------------------------------------------------------------------
def _actor(default: str = "admin") -> str:
    """Who is acting: a bound principal's own name (its credential is the
    identity - X-Actor is not consulted, as for pipeline and agent tokens),
    else the X-Actor header, else the configured default. The admin token
    keeps the X-Actor convention."""
    principal = getattr(g, "rbac_principal", None)
    if principal is not None and principal.get("kind") != "admin-token":
        return str(principal.get("principal") or default)[:64] or default
    return (request.headers.get("X-Actor") or default).strip()[:64] or default


@api.get("/overview")
def get_overview():
    """One aggregate: health, license posture, vault, settings, activity."""
    return jsonify(service.overview())


@api.get("/events")
def get_events():
    """Recent entries from the immutable audit ledger (architecture 19),
    across every trail, newest first."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.unified_events(source=request.args.get("source"), limit=limit))


# ---------------------------------------------------------------------------
# enterprise integrations (architecture section 20: MFA / ITSM / SIEM / LDAP)
# ---------------------------------------------------------------------------
@api.get("/integrations/status")
def get_integrations_status():
    """Every connector's real state - MFA factor, ITSM, SIEM outbound
    push, LDAP - plus the last push result. `not connected` is a measured
    fact here, never a placeholder."""
    return jsonify(service.integrations_status())


@api.post("/mfa/enroll")
@require_admin
def enroll_mfa_factor():
    """Generate this operator's TOTP factor (RFC 6238). The secret is
    returned exactly once, for the authenticator app, and stored sealed."""
    body = _json_body(required=False)
    return jsonify(service.mfa_enroll(body, actor=_actor())), 201


@api.post("/mfa/verify")
@require_admin
def verify_mfa_code():
    """Check a 6-digit code against the enrolled factor for real."""
    return jsonify(service.mfa_verify(_json_body(), actor=_actor()))


@api.post("/itsm/verify")
@require_admin
def verify_itsm_ticket():
    """Ask the configured ITSM instance whether a ticket exists - a real
    HTTP GET, 409 when no instance is configured."""
    body = _json_body()
    ticket = body.get("ticket")
    if not isinstance(ticket, str) or not ticket.strip():
        raise ValidationFailed("'ticket' is required", {"field": "ticket"})
    ticket = ticket.strip()
    if len(ticket) > 64:
        raise ValidationFailed(
            "'ticket' must be at most 64 characters",
            {"field": "ticket", "max_length": 64},
        )
    outcome = service.itsm_verify_ticket(ticket, actor=_actor())
    if not outcome["configured"]:
        raise Conflict(
            "ITSM is not configured",
            {"field": "itsm", "configured": False, "detail": outcome["detail"]},
        )
    return jsonify(outcome)


@api.post("/auth/ldap")
def ldap_login():
    """Verify credentials with a real LDAP bind (section 20 IAM). In token
    mode a successful bind returns a short-lived ticket the admin routes
    accept beside the admin token - and a role binding (kind `ldap`) decides
    what that directory username may do with it; in open dev mode there is
    nothing to grant and the response says so."""
    result = service.ldap_login(
        _json_body(), actor=_actor(default=""), config=_config()
    )
    return jsonify(result)


@api.get("/auth/whoami")
def whoami():
    """Who the caller is and what their role may call (section 10): open
    mode, the admin token, a role binding's token, or a directory login
    ticket. Honest 401 without a credential, honest 403 for a directory
    identity that has no binding."""
    config = _config()
    if not config.admin_token:
        return jsonify(
            {
                "mode": "open",
                "principal": "open-dev-mode",
                "role": "admin",
                "kind": "open",
                "scope": None,
                "operations": "all",
                "operations_count": len(service.ADMIN_OPERATIONS),
            }
        )
    principal = service.resolve_principal(_presented_credential(), config=config)
    if principal is None:
        raise Unauthorized(
            "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
        )
    if principal.get("unbound"):
        raise _unbound_principal_error(principal)
    operations = service.operations_for_role(principal["role"])
    return jsonify(
        {
            "mode": "token",
            "principal": principal["principal"],
            "role": principal["role"],
            "kind": principal["kind"],
            "scope": principal.get("scope"),
            "operations": operations,
            "operations_count": len(operations),
        }
    )


# ---------------------------------------------------------------------------
# immutable audit ledger (architecture 19, Compliance screen)
# ---------------------------------------------------------------------------
@api.get("/audit/stats")
def audit_stats():
    """Ledger aggregates: totals by source, chain head, trigger protection."""
    return jsonify(service.audit_stats())


@api.get("/audit/verify")
def audit_verify():
    """Walk the whole hash chain and report the first break, if any."""
    return jsonify(service.audit_verify())


@api.get("/audit/export")
def audit_export():
    """The full ledger in chain order as newline-delimited JSON (NDJSON) -
    the same records a SIEM would ingest."""
    # evaluated inside the request context; the generator only serialises it
    records = service.audit_export_rows()

    def generate():
        for row in records:
            yield json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="vy-pam-audit.ndjson"'
        },
    )


# ---------------------------------------------------------------------------
# credential vault (Credential Vault screen)
# ---------------------------------------------------------------------------
@api.get("/vault/stats")
def get_vault_stats():
    """Inventory aggregates: totals by type/status, rotation compliance."""
    return jsonify(service.vault_stats())


@api.get("/vault/items")
def list_vault_items():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_vault_items(
        q=request.args.get("q"),
        secret_type=request.args.get("type"),
        status=request.args.get("status"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/vault/items/<int:item_id>")
def get_vault_item(item_id: int):
    item = service.get_vault_item(item_id)
    payload = item.to_dict()
    payload["events"] = [
        event.to_dict() for event in service.vault_item_events(item_id, limit=10)
    ]
    return jsonify({"item": payload})


@api.post("/vault/items")
@require_admin
def create_vault_item():
    item = service.onboard_vault_item(_json_body(), actor=_actor())
    return jsonify({"item": item.to_dict(), "message": "Credential onboarded"}), 201


@api.post("/vault/items/<int:item_id>/checkout")
@require_admin
def checkout_vault_item(item_id: int):
    _require_scope(item_id=item_id)
    body = _json_body(required=False)
    item = service.checkout_vault_item(
        item_id, actor=_actor(), reason=body.get("reason")
    )
    return jsonify({"item": item.to_dict(), "message": "Credential checked out"})


@api.post("/vault/items/<int:item_id>/revoke")
@require_admin
def revoke_vault_checkout(item_id: int):
    _require_scope(item_id=item_id)
    item = service.revoke_vault_checkout(item_id, actor=_actor())
    return jsonify({"item": item.to_dict(), "message": "Checkout revoked"})


@api.get("/vault/items/<int:item_id>/secret")
@require_admin
def reveal_vault_secret(item_id: int):
    """Decrypt and return the current secret version (admin-only reveal);
    the reveal itself is an audited ledger event."""
    _require_scope(item_id=item_id)
    return jsonify(service.reveal_vault_secret(item_id, actor=_actor()))


@api.post("/vault/items/<int:item_id>/rotate")
@require_admin
def rotate_vault_item(item_id: int):
    _require_scope(item_id=item_id)
    item, detail = service.rotate_vault_item(item_id, actor=_actor())
    return jsonify(
        {"item": item.to_dict(), "rotation": detail, "message": "Rotation recorded"}
    )


@api.get("/vault/events")
def get_vault_events():
    """Vault audit trail (onboarding, checkouts, rotations), newest first."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.vault_events(limit, action=request.args.get("action")))


# ---------------------------------------------------------------------------
# rotation engine (module 5: scheduled + event-based password rotation)
# ---------------------------------------------------------------------------
@api.post("/rotation/run")
@require_admin
def run_rotations():
    """Run the engine over due credentials (or explicit `item_ids`)."""
    return jsonify(service.run_rotations(_json_body(required=False), actor=_actor()))


@api.post("/rotation/session-end")
@require_admin
def rotation_session_end():
    """Event-based trigger: a checkout's session ended -> rotate now."""
    item, detail = service.rotation_session_end(_json_body(), actor=_actor())
    return jsonify(
        {
            "item": item.to_dict(),
            "rotation": detail,
            "message": "Session-end rotation recorded",
        }
    )


# ---------------------------------------------------------------------------
# JIT / JEA access (module 6: request -> risk -> approvals -> grant -> expiry)
# ---------------------------------------------------------------------------
@api.get("/jit/stats")
def jit_stats():
    """Real queue counts: totals, per-status, per-risk."""
    return jsonify(service.jit_stats())


@api.get("/jit/requests")
def list_jit_requests():
    """JIT queue, newest first (status/requester filters, pagination)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_jit_requests(
        status=request.args.get("status"),
        requester=request.args.get("requester"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/jit/requests")
@require_admin
def create_jit_request():
    """File one access request: risk is evaluated over real context."""
    item = service.create_jit_request(_json_body(), actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Request filed"}), 201


@api.get("/jit/requests/<int:request_id>")
def get_jit_request(request_id: int):
    """One request with its audit trail (evaluates expiry on the way)."""
    return jsonify(service.jit_request_detail(request_id))


@api.post("/jit/requests/<int:request_id>/approve")
@require_admin
def approve_jit_request(request_id: int):
    """Record a manager/security approval (403 for self-approval)."""
    item = service.approve_jit_request(
        request_id, actor=_actor(), payload=_json_body()
    )
    return jsonify({"request": item.to_dict(), "message": "Approval recorded"})


@api.post("/jit/requests/<int:request_id>/deny")
@require_admin
def deny_jit_request(request_id: int):
    """Reject a pending or policy-blocked request (audited)."""
    item = service.deny_jit_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify({"request": item.to_dict(), "message": "Request denied"})


@api.post("/jit/requests/<int:request_id>/consume")
@require_admin
def consume_jit_request(request_id: int):
    """Grant an approved request: credential checked out until expires_at."""
    item = service.consume_jit_request(request_id, actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Access granted"})


@api.post("/jit/requests/<int:request_id>/close")
@require_admin
def close_jit_request(request_id: int):
    """End an active grant early: release the checkout and rotate."""
    item = service.close_jit_request(request_id, actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Access closed and credential rotated"})


# ---------------------------------------------------------------------------
# privileged session management (module 8: record -> monitor -> control)
# ---------------------------------------------------------------------------
@api.get("/sessions/stats")
def session_stats():
    """Real monitoring aggregates: per-status counts and recording totals."""
    return jsonify(service.session_stats())


@api.get("/sessions")
def list_sessions():
    """Live session list, newest first (status/protocol/search filters)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_sessions(
        status=request.args.get("status"),
        protocol=request.args.get("protocol"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/sessions")
@require_admin
def create_session():
    """Start a session: protocol + target, optional checkout or JIT grant.
    The request is scored first (architecture 7); CRITICAL/HIGH-without-
    approval answers 403 with the evaluation that refused it."""
    body = _json_body()
    if body.get("target"):
        _require_scope(target=str(body["target"]))
    session, risk = service.create_session(body, actor=_actor())
    return (
        jsonify(
            {
                "session": session.to_dict(),
                "risk": risk.to_dict(),
                "message": "Session started",
            }
        ),
        201,
    )


@api.get("/sessions/<int:session_id>")
def get_session(session_id: int):
    """One session with its latest recorded events (evaluates grant expiry)."""
    return jsonify(service.session_detail(session_id))


@api.get("/sessions/<int:session_id>/events")
def get_session_events(session_id: int):
    """Playback: the recording in sequence order (asc by default)."""
    limit = min(_int_param("limit", 500), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_session_events(
        session_id,
        limit=limit,
        offset=offset,
        event_type=request.args.get("type"),
        order=request.args.get("order", "asc"),
    )
    return jsonify(
        {
            "events": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/sessions/<int:session_id>/events")
@require_admin
def post_session_event(session_id: int):
    """Record one channel event; controls are enforced for real and command
    events carry their policy decision (an escalated block also returns the
    incident it raised)."""
    event, escalation = service.post_session_event(
        session_id, _json_body(), actor=_actor()
    )
    body = {"event": event.to_dict(), "message": "Event recorded"}
    if escalation is not None:
        body["escalation"] = escalation
    return jsonify(body), 201


@api.post("/sessions/<int:session_id>/controls")
@require_admin
def update_session_controls(session_id: int):
    """Flip control flags (record, watermark, clipboard, transfer...)."""
    session = service.update_session_controls(
        session_id, _json_body(), actor=_actor()
    )
    return jsonify({"session": session.to_dict(), "message": "Controls updated"})


@api.post("/sessions/<int:session_id>/pause")
@require_admin
def pause_session(session_id: int):
    """Supervisor pause: the channel refuses events until resumed."""
    session = service.pause_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session paused"})


@api.post("/sessions/<int:session_id>/lock")
@require_admin
def lock_session(session_id: int):
    """Lock pending review: events refused until resumed."""
    session = service.lock_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session locked"})


@api.post("/sessions/<int:session_id>/resume")
@require_admin
def resume_session(session_id: int):
    """Resume a paused or locked session."""
    session = service.resume_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session resumed"})


@api.post("/sessions/<int:session_id>/terminate")
@require_admin
def terminate_session(session_id: int):
    """Kill switch: end the session, release its checkout, rotate once."""
    session, detail = service.end_session(
        session_id,
        actor=_actor(),
        outcome="terminated",
        payload=_json_body(required=False),
    )
    return jsonify(
        {
            "session": session.to_dict(),
            "cascade": detail,
            "message": "Session terminated",
        }
    )


@api.post("/sessions/<int:session_id>/complete")
@require_admin
def complete_session(session_id: int):
    """Natural end: same release-and-rotate cascade as terminate."""
    session, detail = service.end_session(
        session_id,
        actor=_actor(),
        outcome="completed",
        payload=_json_body(required=False),
    )
    return jsonify(
        {
            "session": session.to_dict(),
            "cascade": detail,
            "message": "Session completed",
        }
    )


# ---------------------------------------------------------------------------
# command control (module 9: policy rules, dry-run, approvals, incidents)
# ---------------------------------------------------------------------------
@api.get("/command-control/stats")
def command_control_stats():
    """Real aggregates: rule counts, today's intercepts, approval queue,
    incident posture and a content hash of the current policy."""
    return jsonify(service.command_control_stats())


@api.get("/command-control/rules")
def list_command_rules():
    """Every rule in evaluation order with its real match counts."""
    raw_enabled = request.args.get("enabled")
    enabled = None
    if raw_enabled is not None:
        if raw_enabled not in ("true", "false", "1", "0"):
            raise ValidationFailed(
                "Query parameter 'enabled' must be true or false",
                {"field": "enabled"},
            )
        enabled = raw_enabled in ("true", "1")
    return jsonify(
        service.list_command_rules(
            action=request.args.get("action"),
            q=request.args.get("q"),
            enabled=enabled,
        )
    )


@api.post("/command-control/rules")
@require_admin
def create_command_rule():
    """Add a policy rule (name, pattern, action, optional target scope)."""
    rule = service.create_command_rule(_json_body(), actor=_actor())
    return jsonify({"rule": rule.to_dict(), "message": "Rule created"}), 201


@api.put("/command-control/rules/<int:rule_id>")
@require_admin
def update_command_rule(rule_id: int):
    """Edit a rule in place (partial update: send only what changed)."""
    rule = service.update_command_rule(rule_id, _json_body(), actor=_actor())
    return jsonify({"rule": rule.to_dict(), "message": "Rule updated"})


@api.delete("/command-control/rules/<int:rule_id>")
@require_admin
def delete_command_rule(rule_id: int):
    """Remove a rule; recorded events keep their rule_id as history."""
    result = service.delete_command_rule(rule_id)
    return jsonify({"deleted": result["deleted"], "message": "Rule deleted"})


@api.post("/command-control/evaluate")
def evaluate_command():
    """Dry-run one command line against the live policy - no state changes."""
    payload = _json_body()
    command = payload.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValidationFailed("'command' is required", {"field": "command"})
    if len(command) > 4096:
        raise ValidationFailed(
            "'command' must be at most 4096 characters", {"field": "command"}
        )
    target = payload.get("target", "")
    if target is None:
        target = ""
    if not isinstance(target, str) or len(target) > 255:
        raise ValidationFailed(
            "'target' must be a string of at most 255 characters",
            {"field": "target"},
        )
    return jsonify({"result": service.evaluate_command(command, target)})


@api.get("/command-control/approvals")
def pending_command_approvals():
    """Held commands awaiting a decision (active sessions only)."""
    return jsonify(service.pending_command_approvals())


@api.get("/command-control/incidents")
def list_command_incidents():
    """Escalation incidents, newest first (status: open/closed/all)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    return jsonify(
        service.list_command_incidents(
            status=request.args.get("status"), limit=limit, offset=offset
        )
    )


@api.get("/command-control/incidents/<int:incident_id>")
def get_command_incident(incident_id: int):
    """One incident with its preserved evidence."""
    return jsonify({"incident": service.get_command_incident(incident_id).to_dict()})


@api.post("/command-control/incidents/<int:incident_id>/close")
@require_admin
def close_command_incident(incident_id: int):
    """Close an incident after review (note optional, recorded with who/when)."""
    incident = service.close_command_incident(
        incident_id, _json_body(required=False), actor=_actor()
    )
    return jsonify({"incident": incident.to_dict(), "message": "Incident closed"})


@api.post("/sessions/<int:session_id>/events/<int:seq>/approve")
@require_admin
def approve_session_command(session_id: int, seq: int):
    """Release a held command: the recording gets an `approved` row that
    references it (append-only - the hold itself is never edited)."""
    original, resolution = service.resolve_command_approval(
        session_id, seq, approve=True, actor=_actor()
    )
    return jsonify(
        {
            "event": original.to_dict(),
            "resolution": resolution.to_dict(),
            "message": "Command approved",
        }
    )


@api.post("/sessions/<int:session_id>/events/<int:seq>/deny")
@require_admin
def deny_session_command(session_id: int, seq: int):
    """Deny a held command: an append-only `denied` row records the decision."""
    original, resolution = service.resolve_command_approval(
        session_id, seq, approve=False, actor=_actor()
    )
    return jsonify(
        {
            "event": original.to_dict(),
            "resolution": resolution.to_dict(),
            "message": "Command denied",
        }
    )


# ---------------------------------------------------------------------------
# discovery engine (Discovery / Target Infrastructure screen)
# ---------------------------------------------------------------------------
@api.get("/discovery/stats")
def get_discovery_stats():
    """Aggregate counts: total assets, per-type/risk/status, last scan."""
    return jsonify(service.discovery_stats())


@api.get("/discovery/assets")
def list_discovered_assets():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    assets, total = service.list_discovered_assets(
        q=request.args.get("q"),
        asset_type=request.args.get("type"),
        risk=request.args.get("risk"),
        pam_status=request.args.get("pam_status"),
        limit=limit,
        offset=offset,
    )
    counts = service.vault_counts_by_target([asset.address for asset in assets])
    return jsonify(
        {
            "assets": [
                dict(asset.to_dict(), vault_count=counts.get(asset.address, 0))
                for asset in assets
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/discovery/assets")
@require_admin
def onboard_discovered_asset():
    """Manual target registration + vault ingestion in one call."""
    asset, item = service.onboard_asset(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "asset": asset.to_dict(),
                "vault_item": item.to_dict(),
                "message": "Target onboarded",
            }
        ),
        201,
    )


@api.patch("/discovery/assets/<int:asset_id>")
@require_admin
def patch_discovered_asset(asset_id: int):
    """Operator overrides: pam_status (ignore/restore), reclassification."""
    asset = service.update_asset(asset_id, _json_body(), actor=_actor())
    return jsonify({"asset": asset.to_dict(), "message": "Asset updated"})


@api.post("/discovery/assets/<int:asset_id>/onboard")
@require_admin
def adopt_discovered_asset(asset_id: int):
    """Adopt a discovered asset: mark managed + ingest its admin account."""
    asset, item = service.adopt_asset(asset_id, _json_body(), actor=_actor())
    return (
        jsonify(
            {
                "asset": asset.to_dict(),
                "vault_item": item.to_dict(),
                "message": "Target onboarded",
            }
        ),
        201,
    )


@api.get("/discovery/accounts")
def list_discovered_accounts():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    accounts, total = service.list_discovered_accounts(
        q=request.args.get("q"),
        kind=request.args.get("kind"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "accounts": [account.to_dict() for account in accounts],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/discovery/scans")
def list_discovery_scans():
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    scans, total = service.list_scans(limit=limit)
    return jsonify(
        {
            "scans": [scan.to_dict() for scan in scans],
            "total": total,
            "limit": limit,
        }
    )


@api.post("/discovery/scans")
@require_admin
def start_discovery_scan():
    """Run a real TCP-connect scan (bounded, single-flight, synchronous)."""
    scan = service.start_scan(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "scan": scan.to_dict(),
                "message": (
                    f"Scan finished: {scan.hosts_open}/{scan.hosts_probed} hosts "
                    f"open, {scan.findings} new asset(s)"
                ),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# risk-based access engine (architecture section 7, Policy screen)
# ---------------------------------------------------------------------------
@api.post("/risk/evaluate")
@require_admin
def evaluate_risk():
    """Score one access request over the eight components (user, device,
    asset, time, location, behavior, ticket, command) - every point traces
    to a measured input - and record the evaluation."""
    evaluation = service.evaluate_risk(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "evaluation": evaluation.to_dict(),
                "message": (
                    f"Scored {evaluation.score}/100 - {evaluation.band} "
                    f"({evaluation.decision})"
                ),
            }
        ),
        201,
    )


@api.get("/risk/evaluations")
def list_risk_evaluations():
    """The recorded evaluations, newest first (band/context filters)."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_risk_evaluations(
        band=request.args.get("band"),
        context=request.args.get("context"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "evaluations": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/risk/stats")
def risk_stats():
    """Real aggregates over the evaluations: bands, decisions, refusals."""
    return jsonify(service.risk_stats())


# ---------------------------------------------------------------------------
# UEBA behavior baselines and anomaly incidents (architecture section 11)
# ---------------------------------------------------------------------------


@api.get("/risk/baselines")
def list_risk_baselines():
    """Trained per-principal behavior baselines (hours, devices, source
    IPs, targets, command verbs, privilege verbs, cadence) - learned only
    from real history rows inside the rolling window."""
    return jsonify(service.list_behavior_baselines())


@api.post("/risk/baselines/train")
@require_admin
def train_risk_baselines():
    """Learn or refresh baselines from the product's own history: every
    principal in the window, or just `subject` when the body names one.
    No history, no baseline - normality is never invented."""
    payload = _json_body(required=False)
    rows = service.train_behavior_baselines(
        subject=payload.get("subject"), actor=_actor()
    )
    return (
        jsonify(
            {
                "trained": len(rows),
                "baselines": [row.to_dict() for row in rows],
                "message": (
                    f"Trained {len(rows)} baseline(s) from real history"
                ),
            }
        ),
        200,
    )


@api.get("/risk/anomalies")
def list_risk_anomalies():
    """Recorded UEBA incidents (architecture section 11), newest first:
    the evaluation, the named deviations and the response chain it ran."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    return jsonify(
        service.list_anomaly_events(
            subject=request.args.get("subject"), limit=limit, offset=offset
        )
    )


# ---------------------------------------------------------------------------
# PAM bypass detection (architecture section 10, Command Center screen)
# ---------------------------------------------------------------------------
@api.post("/bypass/ingest")
@require_admin
def ingest_bypass_signals():
    """Parse a real log bundle (auth.log / Windows / EDR export) into
    connection observations - evidence only, no verdicts yet."""
    detail = service.ingest_bypass_signals(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "ingest": detail,
                "message": (
                    f"Stored {detail['stored']}/{detail['lines']} line(s) from "
                    f"{detail['origin']} ({detail['malformed']} malformed, "
                    f"{detail['duplicates']} duplicate)"
                ),
            }
        ),
        201,
    )


@api.get("/bypass/signals")
def list_bypass_signals():
    """Parsed observations, newest first (status + text-search filters)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_bypass_signals(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "signals": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/bypass/scans")
@require_admin
def scan_bypass_signals():
    """Correlate every unscanned observation: managed target + no covering
    session opens an incident with the section-10 ACTION block."""
    result = service.scan_bypass_signals(actor=_actor())
    return (
        jsonify(
            {
                "scan": result,
                "message": (
                    f"Correlated {result['scanned']}: {result['covered']} covered, "
                    f"{result['out_of_scope']} out of scope, "
                    f"{result['incidents']} new incident(s), "
                    f"{result['rotations_forced']} forced rotation(s)"
                ),
            }
        ),
        201,
    )


@api.get("/bypass/incidents")
def list_bypass_incidents():
    """Detected direct-access incidents, newest first (open/closed/all)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_bypass_incidents(
        status=request.args.get("status"), limit=limit, offset=offset
    )
    return jsonify(
        {
            "incidents": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/bypass/incidents/<int:incident_id>")
def get_bypass_incident(incident_id: int):
    """One incident with its parsed log-line evidence."""
    incident, signal = service.get_bypass_incident(incident_id)
    return jsonify(
        {"incident": incident.to_dict(), "evidence": signal.to_dict() if signal else None}
    )


@api.post("/bypass/incidents/<int:incident_id>/close")
@require_admin
def close_bypass_incident(incident_id: int):
    """Analyst closure - recorded on the `bypass` trail in the same commit."""
    incident = service.close_bypass_incident(
        incident_id, _json_body(required=False), actor=_actor()
    )
    return jsonify(
        {
            "incident": incident.to_dict(),
            "message": f"Incident {incident.incident_ref} closed",
        }
    )


@api.get("/bypass/stats")
def bypass_stats():
    """Real aggregates: signal states, open incidents, forced rotations."""
    return jsonify(service.bypass_stats())


# ---------------------------------------------------------------------------
# break glass (architecture section 17)
# ---------------------------------------------------------------------------
@api.post("/break-glass/requests")
@require_admin
def create_break_glass_request():
    """File one emergency request: reason + severity + target, awaiting two
    distinct approvals before any credential is released."""
    req = service.create_break_glass_request(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "request": service.break_glass_view(req),
                "message": (
                    f"Emergency request {req.request_ref} filed "
                    "(2 distinct approvals required)"
                ),
            }
        ),
        201,
    )


@api.get("/break-glass/requests")
def list_break_glass_requests():
    """Emergency requests, newest first (status filter + paging)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_break_glass_requests(
        status=request.args.get("status"), limit=limit, offset=offset
    )
    return jsonify(
        {
            "requests": [service.break_glass_view(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/break-glass/requests/<int:request_id>")
def get_break_glass_request(request_id: int):
    """One request with its approval snapshots and its recorded session."""
    return jsonify(service.get_break_glass_detail(request_id))


@api.post("/break-glass/requests/<int:request_id>/approve")
@require_admin
def approve_break_glass_request(request_id: int):
    """Record one approval signature (1/2, then 2/2 flips to approved)."""
    view = service.approve_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    signed = view["approvals_signed"]
    message = (
        f"Dual approval complete for {view['request_ref']} (2/2)"
        if signed >= 2
        else f"Approval {signed}/2 recorded for {view['request_ref']}"
    )
    return jsonify({"request": view, "message": message})


@api.post("/break-glass/requests/<int:request_id>/deny")
@require_admin
def deny_break_glass_request(request_id: int):
    """Turn the request down before anything was released."""
    view = service.deny_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "request": view,
            "message": (
                f"Request {view['request_ref']} denied by {view['denied_by']}"
            ),
        }
    )


@api.post("/break-glass/requests/<int:request_id>/open")
@require_admin
def open_break_glass_request(request_id: int):
    """Release the emergency credential through the real vault checkout and
    start the mandatory recorded session (record=true forced)."""
    result = service.open_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return (
        jsonify(
            {
                **result,
                "message": (
                    f"Emergency credential released; recorded session "
                    f"{result['session']['session_ref']} is open"
                ),
            }
        ),
        201,
    )


@api.post("/break-glass/requests/<int:request_id>/close")
@require_admin
def close_break_glass_request(request_id: int):
    """End the emergency: session stopped, credential rotated, post-incident
    review note filed (the note is required)."""
    result = service.close_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    rotation = result["rotation"]
    return jsonify(
        {
            **result,
            "message": (
                f"Emergency {result['request']['request_ref']} closed; "
                f"rotation {rotation.get('status')}"
            ),
        }
    )


@api.get("/break-glass/stats")
def break_glass_stats():
    """Real aggregates: request states, approval signatures, ledger actions."""
    return jsonify(service.break_glass_stats())



# ---------------------------------------------------------------------------
# third-party / vendor PAM (architecture section 13)
# ---------------------------------------------------------------------------
@api.post("/vendors")
@require_admin
def invite_vendor():
    """Invite a third-party vendor (201): the account starts `invited` and
    the TOTP seed + otpauth URI come back once, here, never again."""
    view = service.invite_vendor(_json_body(), actor=_actor())
    name = view["vendor"]["name"]
    return (
        jsonify(
            {
                **view,
                "message": (
                    f"Vendor {name} invited - MFA secret shown once"
                ),
            }
        ),
        201,
    )


@api.get("/vendors")
def list_vendors():
    """Vendor accounts, newest first (status filter + search + paging)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_vendors(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "vendors": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/vendors/<int:vendor_id>")
def get_vendor(vendor_id: int):
    """The vendor dashboard payload: chain steps, access/denied lists,
    valid window, recording state, grants raised and the recent trail."""
    return jsonify(service.vendor_detail(vendor_id))


@api.patch("/vendors/<int:vendor_id>")
@require_admin
def update_vendor(vendor_id: int):
    """Edit contact and access scope (allowed/denied targets, valid window,
    recording, expiry) on an invited or approved account."""
    view = service.update_vendor(vendor_id, _json_body(), actor=_actor())
    return jsonify({"vendor": view, "message": f"Vendor {view['name']} updated"})


@api.post("/vendors/<int:vendor_id>/mfa")
@require_admin
def verify_vendor_mfa(vendor_id: int):
    """Step 1 - verify the vendor's TOTP code (real RFC-6238)."""
    view = service.verify_vendor_mfa(vendor_id, _json_body(), actor=_actor())
    return jsonify(
        {"vendor": view, "message": f"MFA verified for {view['name']}"}
    )


@api.post("/vendors/<int:vendor_id>/nda")
@require_admin
def sign_vendor_nda(vendor_id: int):
    """Step 2 - record the NDA/agreement acceptance."""
    view = service.sign_vendor_nda(vendor_id, _json_body(required=False), actor=_actor())
    ref = view["nda"]["ref"]
    return jsonify(
        {
            "vendor": view,
            "message": (
                f"NDA signed for {view['name']}"
                + (f" ({ref})" if ref else "")
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/ticket")
@require_admin
def verify_vendor_ticket(vendor_id: int):
    """Step 3 - verify the ITSM ticket for real (409 while ITSM is not
    configured; the upstream's own answer on a failed check)."""
    view = service.verify_vendor_ticket(vendor_id, _json_body(), actor=_actor())
    return jsonify(
        {
            "vendor": view,
            "message": f"Ticket {view['ticket']} verified against ITSM",
        }
    )


@api.post("/vendors/<int:vendor_id>/approve")
@require_admin
def approve_vendor(vendor_id: int):
    """Step 4 - approve, refused with the exact steps still outstanding."""
    view = service.approve_vendor(vendor_id, actor=_actor())
    return jsonify(
        {
            "vendor": view,
            "message": (
                f"Vendor {view['name']} approved - access enabled inside its scope"
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/deny")
@require_admin
def deny_vendor(vendor_id: int):
    """Refuse the invite outright (the name may be re-invited later)."""
    view = service.deny_vendor(vendor_id, _json_body(required=False), actor=_actor())
    return jsonify({"vendor": view, "message": f"Vendor {view['name']} denied"})


@api.post("/vendors/<int:vendor_id>/revoke")
@require_admin
def revoke_vendor(vendor_id: int):
    """Withdraw the vendor: active grants close (credential rotated, live
    sessions ended) and the account turns `revoked`."""
    view = service.revoke_vendor(vendor_id, _json_body(required=False), actor=_actor())
    ended = view["grants_ended"]
    return jsonify(
        {
            "vendor": view["vendor"],
            "grants_ended": ended,
            "message": (
                f"Vendor {view['vendor']['name']} revoked"
                + (
                    f"; {len(ended)} grant(s) closed"
                    if ended
                    else ""
                )
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/requests")
@require_admin
def create_vendor_jit_request(vendor_id: int):
    """The vendor requests access inside its scope (201): the normal
    section-6 JIT request, linked to this account, ticket defaulting to
    the vendor's verified ITSM reference."""
    view = service.create_vendor_jit_request(
        vendor_id, _json_body(), actor=_actor()
    )
    return (
        jsonify(
            {
                "request": view,
                "message": (
                    f"Access request #{view['id']} filed for this vendor "
                    f"(risk: {view['risk']['level']}, status: {view['status']})"
                ),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# cloud PAM (architecture section 14: AWS / Azure / GCP / Kubernetes)
# ---------------------------------------------------------------------------
@api.post("/cloud/connectors")
@require_admin
def create_cloud_connector():
    """Register a cloud account/cluster (201): the credential stays in the
    vault and the row starts honest - `not connected`/`configured`, never
    `connected` before a real probe."""
    view = service.create_cloud_connector(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "connector": view,
                "message": (
                    f"Cloud connector {view['name']} registered "
                    f"({view['provider']}, {view['status']})"
                ),
            }
        ),
        201,
    )


@api.get("/cloud/connectors")
def list_cloud_connectors():
    """Cloud connectors, newest first (provider/status filters + search)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_cloud_connectors(
        provider=request.args.get("provider"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "connectors": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/cloud/connectors/<int:connector_id>")
def get_cloud_connector(connector_id: int):
    """The cloud console payload: connector, recent section-14 trail, RBAC
    grants raised through it, last inventory run."""
    return jsonify(service.cloud_connector_detail(connector_id))


@api.patch("/cloud/connectors/<int:connector_id>")
@require_admin
def update_cloud_connector(connector_id: int):
    """Edit the configuration; changing the endpoint drops the connector
    back to `configured` (the old probe described the old endpoint)."""
    view = service.update_cloud_connector(
        connector_id, _json_body(), actor=_actor()
    )
    return jsonify(
        {"connector": view, "message": f"Cloud connector {view['name']} updated"}
    )


@api.delete("/cloud/connectors/<int:connector_id>")
@require_admin
def delete_cloud_connector(connector_id: int):
    """Remove a connector (409 while open RBAC grants still ride it)."""
    return jsonify(service.delete_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/test")
@require_admin
def test_cloud_connector(connector_id: int):
    """A real reachability probe: GET the endpoint (with the vault
    credential when one is bound) and record what happened - 2xx makes it
    `connected`, anything else `error` with the honest reason."""
    return jsonify(service.test_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/discover")
@require_admin
def discover_cloud_connector(connector_id: int):
    """Inventory the cloud for real: the cloud's own API answers, new
    assets land under the `cloud` discovery source, and a failed run
    records the honest reason instead of inventing anything."""
    return jsonify(service.discover_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/rbac/requests")
@require_admin
def create_cloud_rbac_request(connector_id: int):
    """Kubernetes -> RBAC -> JIT -> ephemeral privilege -> audit (201):
    raise a section-6 JIT request whose grant applies a real RoleBinding
    for exactly the requested window; close/expiry removes it."""
    view = service.create_cloud_rbac_request(
        connector_id, _json_body(), actor=_actor()
    )
    return (
        jsonify(
            {
                "request": view["request"],
                "connector": view["connector"],
                "message": view["message"],
            }
        ),
        201,
    )


@api.get("/cloud/stats")
def cloud_stats():
    """Real aggregates: connectors by provider and state, the section-14
    trail's size, RBAC grants, cloud-discovered assets."""
    return jsonify(service.cloud_stats())


# ---------------------------------------------------------------------------
# CI/CD credential broker (architecture section 15: pipelines request
# short-lived credentials with an API token - no static secrets in CI)
# ---------------------------------------------------------------------------
@api.post("/broker/policies")
@require_admin
def create_broker_policy():
    """Register a pipeline identity (201). The API token is returned
    exactly once - it is stored as a sha256 hash and cannot be recovered."""
    policy, token = service.create_broker_policy(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "policy": policy.to_dict(),
                "token": token,
                "message": (
                    f"Broker policy {policy.name} registered "
                    f"({policy.ci_system}, {policy.approval_mode} approval) - "
                    "the API token is shown once"
                ),
            }
        ),
        201,
    )


@api.get("/broker/policies")
@require_admin
def list_broker_policies():
    """Pipeline identities and their policies, newest first."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_broker_policies(
        ci_system=request.args.get("ci_system"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "policies": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/broker/policies/<int:policy_id>")
@require_admin
def broker_policy_detail(policy_id: int):
    """One policy with its open credential count and latest trail."""
    return jsonify(service.broker_policy_detail(policy_id))


@api.patch("/broker/policies/<int:policy_id>")
@require_admin
def update_broker_policy(policy_id: int):
    """Edit the policy knobs (approval mode, TTL cap, scope, contact,
    expiry); a revoked policy's settings are frozen."""
    view = service.update_broker_policy(policy_id, _json_body(), actor=_actor())
    return jsonify(
        {"policy": view, "message": f"Broker policy {view['name']} updated"}
    )


@api.delete("/broker/policies/<int:policy_id>")
@require_admin
def revoke_broker_policy(policy_id: int):
    """Withdraw the identity: open credentials are closed first (released
    grants rotate like a JIT expiry), then the token stops authenticating."""
    view = service.revoke_broker_policy(
        policy_id, actor=_actor(), payload=_json_body(required=False)
    )
    closed_count = view.pop("credentials_closed", 0)
    return jsonify(
        {
            "policy": view,
            "credentials_closed": closed_count,
            "message": (
                f"Broker policy {view['name']} revoked "
                f"({closed_count} credential(s) closed)"
            ),
        }
    )


@api.post("/broker/credentials")
@require_pipeline
def create_broker_credential():
    """One credential request from the pipeline (201). An `auto` policy
    releases the secret in this same response; a `manual` policy lands the
    request in the approval queue and the pipeline releases it later."""
    policy = g.broker_policy
    credential, auto = service.create_broker_credential(_json_body(), policy=policy)
    if auto:
        released = service.release_broker_credential(credential.id, policy=policy)
        return (
            jsonify(
                {
                    "credential": released["credential"],
                    "secret": released["secret"],
                    "message": (
                        f"Credential {credential.id} approved by policy and "
                        "released once - it expires at the timestamp above"
                    ),
                }
            ),
            201,
        )
    return (
        jsonify(
            {
                "credential": credential.to_dict(),
                "message": (
                    f"Credential {credential.id} requested - awaiting admin approval"
                ),
            }
        ),
        201,
    )


@api.get("/broker/credentials")
@require_admin
def list_broker_credentials():
    """Every pipeline credential, newest first (never the secret - the
    row records only that it was released)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    policy_id = None
    if request.args.get("policy_id") is not None:
        policy_id = _int_param("policy_id", 0)
    rows, total = service.list_broker_credentials(
        status=request.args.get("status"),
        policy_id=policy_id,
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "credentials": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/broker/credentials/<int:credential_id>")
@require_admin
def broker_credential_detail(credential_id: int):
    """One credential with its policy and full trail."""
    return jsonify(service.broker_credential_detail(credential_id))


@api.post("/broker/credentials/<int:credential_id>/approve")
@require_admin
def approve_broker_credential(credential_id: int):
    """Sign off a queued request; the pipeline then releases it."""
    view = service.approve_broker_credential(
        credential_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "credential": view.to_dict(),
            "message": (
                f"Credential {view.id} approved - the pipeline can now release it"
            ),
        }
    )


@api.post("/broker/credentials/<int:credential_id>/deny")
@require_admin
def deny_broker_credential(credential_id: int):
    """Refuse a queued request; nothing was released."""
    view = service.deny_broker_credential(
        credential_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {"credential": view.to_dict(), "message": f"Credential {view.id} denied"}
    )


@api.post("/broker/credentials/<int:credential_id>/release")
@require_pipeline
def release_broker_credential(credential_id: int):
    """The pipeline fetches its approved credential: the secret appears in
    this response exactly once and expires at the timestamp returned."""
    released = service.release_broker_credential(
        credential_id, policy=g.broker_policy
    )
    return jsonify(
        {
            "credential": released["credential"],
            "secret": released["secret"],
            "message": "Credential released once - it expires at the timestamp above",
        }
    )


@api.post("/broker/credentials/<int:credential_id>/close")
def close_broker_credential(credential_id: int):
    """End the grant early (deploy finished or cancelled). The pipeline
    closes its own credential with its API token; an admin closes any."""
    token = _pipeline_token()
    if token:
        policy = service.verify_broker_token(token)
        view = service.close_broker_credential(
            credential_id, actor=policy.name, policy=policy
        )
    else:
        _require_admin_credential()
        view = service.close_broker_credential(credential_id, actor=_actor())
    return jsonify(
        {
            "credential": view.to_dict(),
            "message": f"Credential {view.id} {view.status}",
        }
    )


@api.get("/broker/stats")
def broker_stats():
    """Real aggregates: policies by state and CI system, credentials by
    state, the section-15 trail's size."""
    return jsonify(service.broker_stats())


# ---------------------------------------------------------------------------
# AI-agent PAM (architecture section 16: the agent is a first-class
# principal - identity -> task -> risk -> JIT credential -> task-scoped
# command restrictions -> monitored session -> expiry)
# ---------------------------------------------------------------------------
@api.post("/agents")
@require_admin
def create_agent_identity():
    """Register an AI-agent identity (201). The API token is returned
    exactly once - it is stored as a sha256 hash and cannot be recovered."""
    agent, token = service.create_agent_identity(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "agent": agent.to_dict(),
                "token": token,
                "message": (
                    f"Agent identity {agent.name} registered "
                    f"({agent.max_ttl_minutes} min cap) - "
                    "the API token is shown once"
                ),
            }
        ),
        201,
    )


@api.get("/agents")
@require_admin
def list_agent_identities():
    """AI-agent identities, newest first."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_agent_identities(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "agents": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/agents/<int:agent_id>")
@require_admin
def agent_identity_detail(agent_id: int):
    """One identity with its task scopes, open access and latest trail."""
    return jsonify(service.agent_identity_detail(agent_id))


@api.patch("/agents/<int:agent_id>")
@require_admin
def update_agent_identity(agent_id: int):
    """Edit the identity knobs (description, contact, window cap,
    enable/disable); the name and token are never editable and a revoked
    identity's settings are frozen."""
    view = service.update_agent_identity(agent_id, _json_body(), actor=_actor())
    return jsonify(
        {"agent": view, "message": f"Agent identity {view['name']} updated"}
    )


@api.delete("/agents/<int:agent_id>")
@require_admin
def revoke_agent_identity(agent_id: int):
    """Withdraw the identity: open access is closed first (active grants
    release and rotate like a JIT expiry), then the token stops
    authenticating."""
    agent, closed = service.revoke_agent_identity(
        agent_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "agent": agent.to_dict(),
            "grants_closed": closed,
            "message": (
                f"Agent identity {agent.name} revoked "
                f"({closed} access request(s) closed)"
            ),
        }
    )


@api.get("/agents/<int:agent_id>/tasks")
@require_admin
def list_agent_tasks(agent_id: int):
    """The declared task scopes under one identity."""
    rows = service.list_agent_tasks(agent_id)
    return jsonify({"tasks": [row.to_dict() for row in rows], "total": len(rows)})


@api.post("/agents/<int:agent_id>/tasks")
@require_admin
def create_agent_task(agent_id: int):
    """Declare one task the agent may perform (201): the exhaustive
    allowed-command list, an optional target scope and the window cap."""
    task = service.create_agent_task(agent_id, _json_body(), actor=_actor())
    return (
        jsonify(
            {
                "task": task.to_dict(),
                "message": (
                    f"Task {task.name} declared with "
                    f"{len(task.allowed_commands)} allowed command(s), "
                    f"{task.max_minutes} min cap"
                ),
            }
        ),
        201,
    )


@api.patch("/agents/<int:agent_id>/tasks/<int:task_id>")
@require_admin
def update_agent_task(agent_id: int, task_id: int):
    """Edit a declared task (allow-list, targets, cap, description); the
    name stays put because access requests reference it."""
    task = service.update_agent_task(agent_id, task_id, _json_body(), actor=_actor())
    return jsonify({"task": task.to_dict(), "message": f"Task {task.name} updated"})


@api.delete("/agents/<int:agent_id>/tasks/<int:task_id>")
@require_admin
def delete_agent_task(agent_id: int, task_id: int):
    """Withdraw the task: access riding it ends first, then the scope goes."""
    view, closed = service.delete_agent_task(agent_id, task_id, actor=_actor())
    return jsonify(
        {
            "task": view,
            "grants_closed": closed,
            "message": (
                f"Task {view['name']} removed "
                f"({closed} access request(s) closed)"
            ),
        }
    )


@api.post("/agent-access/requests")
@require_agent
def request_agent_access():
    """The agent files a task-scoped access request (201): the declared
    task is verified first, then the section-7 risk evaluation decides the
    state it lands in (low auto-approved, medium/high queued for sign-off,
    critical blocked)."""
    item = service.request_agent_access(_json_body(), agent=g.agent_identity)
    binding = item.agent_binding or {}
    return (
        jsonify(
            {
                "request": item.to_dict(),
                "message": (
                    f"Request #{item.id} filed for task '{binding.get('task')}' "
                    f"- risk {item.risk_level} (score {item.risk_score}), "
                    f"status {item.status}"
                ),
            }
        ),
        201,
    )


@api.get("/agent-access/requests")
@require_admin
def list_agent_access():
    """Every agent-raised access request, newest first (never a secret)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    agent_id = None
    if request.args.get("agent_id") is not None:
        agent_id = _int_param("agent_id", 0)
    rows, total = service.list_agent_access(
        status=request.args.get("status"),
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/agent-access/requests/<int:request_id>")
@require_admin
def agent_access_detail(request_id: int):
    """One agent access request with the identity it rides and its
    section-16 trail."""
    return jsonify(service.agent_access_detail(request_id))


@api.post("/agent-access/requests/<int:request_id>/open")
@require_agent
def open_agent_access(request_id: int):
    """The agent's JIT credential: the approved request is consumed (real
    vault checkout under the identity) and a mandatory recorded session is
    started against the grant - task-restricted, monitored, expiring with
    the grant. The raw secret is never returned."""
    opened = service.open_agent_access(
        request_id, agent=g.agent_identity, payload=_json_body(required=False)
    )
    return jsonify(opened), 201


@api.post("/agent-access/requests/<int:request_id>/close")
def close_agent_access(request_id: int):
    """End an active agent grant early. The agent closes its own access
    with its API token; an admin closes any."""
    token = _agent_token()
    if token:
        agent = service.verify_agent_token(token)
        view = service.close_agent_access(
            request_id, actor=agent.name, agent=agent
        )
    else:
        _require_admin_credential()
        view = service.close_agent_access(request_id, actor=_actor())
    return jsonify(
        {
            "request": view.to_dict(),
            "message": "Access closed and credential rotated",
        }
    )


@api.get("/agent-access/stats")
def agent_stats():
    """Real aggregates: identities by state, declared tasks, agent access
    requests by state with the open count, the section-16 trail's size."""
    return jsonify(service.agent_stats())


# ---------------------------------------------------------------------------
# HA / DC / DR (architecture section 18): node registry with real health
# probes, pull replication (hash-verified audit chain, sealed vault
# ciphertext, session metadata), role-enforced failover, backups.
# ---------------------------------------------------------------------------
@api.get("/cluster")
@require_admin
def cluster_overview_route():
    """One aggregate for the cluster screen: this node's identity and role,
    the peer table with each node's last real probe, replica posture (what
    this DR node holds and how much of it verified) and the backup ledger."""
    return jsonify(service.cluster_overview())


@api.get("/cluster/nodes")
@require_admin
def list_cluster_nodes_route():
    """Every registered node - this one first, then peers by name - each
    with the honest health state of its last real probe."""
    return jsonify({"nodes": [node.to_dict() for node in service.list_cluster_nodes()]})


@api.post("/cluster/nodes")
@require_admin
def register_cluster_node_route():
    """Register a peer node (201): its site (dc/dr), its role in the
    topology (active/passive) and where its /health answers. The node is
    `unknown` until the first real probe - health is never assumed."""
    node = service.register_cluster_node(_json_body(), actor=_actor())
    return jsonify({"node": node.to_dict(), "message": "Node registered"}), 201


@api.get("/cluster/nodes/<int:node_id>")
@require_admin
def get_cluster_node_route(node_id: int):
    """One registered node with its last probe state."""
    return jsonify({"node": service.get_cluster_node(node_id).to_dict()})


@api.patch("/cluster/nodes/<int:node_id>")
@require_admin
def update_cluster_node_route(node_id: int):
    """Update a registered node's topology (site, role, base_url, name).
    Each change lands on the cluster trail with the value it replaced."""
    node = service.update_cluster_node(node_id, _json_body(), actor=_actor())
    return jsonify({"node": node.to_dict(), "message": "Node updated"})


@api.delete("/cluster/nodes/<int:node_id>")
@require_admin
def delete_cluster_node_route(node_id: int):
    """Unregister a peer. Replicated evidence stays (it is this node's own
    DR record); the response says exactly how much stays behind."""
    return jsonify(service.delete_cluster_node(node_id, actor=_actor()))


@api.post("/cluster/nodes/<int:node_id>/probe")
@require_admin
def probe_cluster_node_route(node_id: int):
    """Probe the peer's real /health now: measured latency, honest
    unreachable (with the transport error verbatim) or degraded. The
    cluster trail only records health *changes*."""
    return jsonify(service.probe_cluster_node(node_id, actor=_actor()))


@api.post("/cluster/nodes/<int:node_id>/sync")
@require_admin
def sync_cluster_node_route(node_id: int):
    """Pull replication from the peer: its immutable audit chain (re-hashed
    record by record here), its sealed vault ciphertext and its session
    metadata. A `peer_token` body field authenticates the outbound calls
    only - never stored, never echoed, never on the trail. The response is
    the honest per-kind result, including a broken peer chain or the
    transport error verbatim."""
    return jsonify(
        service.sync_cluster_node(node_id, _json_body(required=False), actor=_actor())
    )


@api.get("/cluster/replicas")
@require_admin
def cluster_replicas_route():
    """Replica posture per peer: audit records held and how many verified
    locally, replicated secrets (and whether this node's own key could
    open them), sessions mirrored, last sync time."""
    return jsonify(service.cluster_replica_summary())


@api.post("/cluster/failover")
@require_admin
def cluster_failover_route():
    """Promote or demote THIS node (section 18's failover): a real role
    flip on the own registry row, recorded with the role it replaced.
    While passive, the app-level gate refuses every write outside
    /api/v1/cluster/* with 409 - the role is enforced, not decorative."""
    body = _json_body(required=False)
    action = body.get("action", "promote")
    if not isinstance(action, str) or action not in ("promote", "demote"):
        raise ValidationFailed(
            "'action' must be 'promote' or 'demote'", {"field": "action"}
        )
    return jsonify(service.failover_cluster(action, body, actor=_actor()))


@api.post("/cluster/monitor/tick")
@require_admin
def cluster_monitor_tick_route():
    """Run one automatic-failover tick synchronously (the CLUSTER_MONITOR
    thread runs this same function): while this node is passive, probe
    every registered active peer; when all of them have failed enough real
    consecutive probes, promote with those failures as the reason."""
    return jsonify(service.run_cluster_monitor(actor=_actor(default="admin-monitor")))


@api.get("/cluster/backups")
@require_admin
def list_cluster_backups_route():
    """Every recorded backup of this node's database, newest first - path,
    sha256, size, ledger head at backup time and the re-walk verdict."""
    return jsonify({"backups": [b.to_dict() for b in service.list_cluster_backups()]})


@api.post("/cluster/backups")
@require_admin
def create_cluster_backup_route():
    """Take a real backup now (201): SQLite's online backup API copies the
    live file without stopping writes, the copy is hashed and re-opened
    read-only to re-walk its audit chain - a backup that cannot be
    verified says why, honestly."""
    backup = service.create_cluster_backup(actor=_actor())
    return jsonify({"backup": backup.to_dict(), "message": "Backup created"}), 201


@api.get("/cluster/export/vault")
@require_admin
def cluster_export_vault_route():
    """This node's sealed vault ciphertext for a peer's replication pull:
    each item's current version with the blob exactly as stored. The
    plaintext never crosses this endpoint - only the AES-GCM wire form."""
    return jsonify(service.export_vault_secrets())


@api.get("/cluster/export/sessions")
@require_admin
def cluster_export_sessions_route():
    """This node's session metadata for a peer's replication pull: who had
    access to what, when, and how it ended."""
    return jsonify(service.export_sessions())


# ---------------------------------------------------------------------------
# RBAC / ABAC (architecture section 10: roles + attribute rules)
# ---------------------------------------------------------------------------
@api.get("/roles")
@require_admin
def list_roles():
    """The five built-in roles with the exact number of admin operations
    each may call - the policy is computed, never a stale copy."""
    return jsonify({"roles": service.list_roles_with_operations()})


@api.get("/role-bindings")
@require_admin
def list_role_bindings_route():
    """Who holds a role: active bindings by default, revoked rows kept as
    evidence behind ?include_revoked=1. The token itself is shown once at
    creation and never again - only whether a credential exists."""
    include_revoked = (
        (request.args.get("include_revoked") or "").strip().lower()
        in ("1", "true", "yes")
    )
    return jsonify(
        {"bindings": service.list_role_bindings(include_revoked=include_revoked)}
    )


@api.post("/role-bindings")
@require_admin
def create_role_binding_route():
    """Create a role binding: a `local` principal receives its API token
    once (`vypam-rbac1.<id>.<secret>` - sha256 at rest, never recoverable);
    an `ldap` principal is a directory username that a signed login ticket
    will carry. Optional `scope` carries the ABAC attribute rules."""
    binding, token = service.create_role_binding(_json_body(), actor=_actor())
    payload: Dict[str, Any] = {
        "binding": binding,
        "message": "Role binding created",
    }
    if token is not None:
        payload["token"] = token
        payload["token_notice"] = (
            "Shown once - store it now; it cannot be recovered."
        )
    return jsonify(payload), 201


@api.delete("/role-bindings/<int:binding_id>")
@require_admin
def delete_role_binding_route(binding_id: int):
    """Revoke a role binding: its token stops working immediately and a
    directory binding stops counting; the row stays as evidence."""
    binding = service.revoke_role_binding(binding_id, actor=_actor())
    return jsonify({"binding": binding, "message": "Role binding revoked"})
