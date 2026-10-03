"""HTTP routes for the Phase 2 license server."""
from __future__ import annotations

import hmac
import json
from functools import wraps
from typing import Any, Dict

from flask import Blueprint, current_app, jsonify, request

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
# issuing
# ---------------------------------------------------------------------------
@api.post("/licenses")
@require_admin
def create_license():
    body = _json_body()

    license_type = body.get("license_type")
    if not isinstance(license_type, str) or not license_type:
        raise ValidationFailed("'license_type' is required", {"field": "license_type"})

    record, license_file = service.issue_license(
        _config(),
        license_type=license_type,
        issued_to=body.get("issued_to", ""),
        trial_days=body.get("trial_days"),
        features=body.get("features"),
        usage_limits=body.get("usage_limits"),
        metadata=body.get("metadata"),
        tier=body.get("tier"),
        plan=body.get("plan"),
        license_id=body.get("license_id"),
        subject_entity=body.get("subject_entity"),
        classification=body.get("classification"),
        issuer=body.get("issuer"),
        enclave_binding=body.get("enclave_binding"),
        quotas=body.get("quotas"),
        modules=body.get("modules"),
        account=body.get("account"),
        environment=body.get("environment"),
        signature_algorithm=body.get("algorithm", sig.DEFAULT_ALGORITHM),
        file_format=body.get("format", sig.FORMAT_JSON),
    )
    return (
        jsonify(
            {
                "license": record.to_dict(),
                "license_file": license_file,
                "token": license_file.get("token"),
                "message": "License issued",
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
