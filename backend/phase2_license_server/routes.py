"""HTTP routes for the Phase 2 license server."""
from __future__ import annotations

import hmac
import json
from functools import wraps
from typing import Any, Dict

from flask import Blueprint, Response, current_app, jsonify, request

import service
from config import Config
from errors import Unauthorized, ValidationFailed
from licensing_bridge import sig

api = Blueprint("api", __name__, url_prefix="/api/v1")

MAX_PAGE_SIZE = 200


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


def require_admin(view):
    """Reject the request unless a valid admin token is presented.

    When LICENSE_ADMIN_TOKEN is unset the server runs in open/dev mode and
    every route is allowed (the response header reports this).
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        config = _config()
        if config.admin_token:
            token = request.headers.get("X-Admin-Token")
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            if not token or not hmac.compare_digest(token, config.admin_token):
                raise Unauthorized(
                    "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
                )
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
    """Who is acting: X-Actor header, else the configured default."""
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
    body = _json_body(required=False)
    item = service.checkout_vault_item(
        item_id, actor=_actor(), reason=body.get("reason")
    )
    return jsonify({"item": item.to_dict(), "message": "Credential checked out"})


@api.post("/vault/items/<int:item_id>/revoke")
@require_admin
def revoke_vault_checkout(item_id: int):
    item = service.revoke_vault_checkout(item_id, actor=_actor())
    return jsonify({"item": item.to_dict(), "message": "Checkout revoked"})


@api.get("/vault/items/<int:item_id>/secret")
@require_admin
def reveal_vault_secret(item_id: int):
    """Decrypt and return the current secret version (admin-only reveal);
    the reveal itself is an audited ledger event."""
    return jsonify(service.reveal_vault_secret(item_id, actor=_actor()))


@api.post("/vault/items/<int:item_id>/rotate")
@require_admin
def rotate_vault_item(item_id: int):
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
    session, risk = service.create_session(_json_body(), actor=_actor())
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
