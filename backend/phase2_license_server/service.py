"""
Business logic for the Phase 2 license server.

Routes stay thin: they parse/serialise HTTP, this module does the work.
Cryptographic signing and verification are delegated to the Phase 1 library
via licensing_bridge.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from config import Config
from errors import APIError, Conflict, NotFound, Unauthorized, ValidationFailed
from licensing_bridge import (
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    License,
    LicenseType,
    get_validator,
    sig,
)
from extensions import db
from models import (
    ACCOUNT_KINDS,
    ASSET_PAM_STATUSES,
    ASSET_RISKS,
    ASSET_SECRET_TYPES,
    ASSET_TYPES,
    BASE_RISK,
    BREAK_GLASS_ACTIONS,
    BREAK_GLASS_SEVERITIES,
    BREAK_GLASS_STATUSES,
    BYPASS_INCIDENT_STATUSES,
    BYPASS_SIGNAL_CANDIDATE,
    BYPASS_SIGNAL_COVERED,
    BYPASS_SIGNAL_OBSERVED,
    BYPASS_SIGNAL_OUT_OF_SCOPE,
    BYPASS_SIGNAL_STATUSES,
    COMMAND_ACTIONS,
    DISCOVERY_ACTION_ASSET_DISCOVERED,
    DISCOVERY_ACTION_ASSET_ONBOARDED,
    DISCOVERY_ACTION_ASSET_UPDATED,
    DISCOVERY_ACTION_SCAN_COMPLETED,
    DISCOVERY_ACTION_SCAN_FAILED,
    DISCOVERY_ACTION_SCAN_STARTED,
    DISCOVERY_METHOD_MANUAL,
    DISCOVERY_METHOD_PROBE,
    DISCOVERY_SCAN_COMPLETED,
    DISCOVERY_SCAN_FAILED,
    DISCOVERY_SCAN_RUNNING,
    DISCOVERY_SOURCE_MANUAL,
    DISCOVERY_SOURCE_SCAN,
    EVENT_IMPORTED,
    EVENT_RESTORED,
    EVENT_REVOKED,
    EVENT_USAGE_REPORTED,
    JIT_ROLES,
    JIT_STATUSES,
    RISK_CONTEXT_MANUAL,
    RISK_CONTEXT_SESSION_START,
    RISK_CONTEXTS,
    RISK_DECISIONS,
    RISK_DECISION_BY_BAND,
    RISK_LEVELS,
    RISK_RESULTS,
    SESSION_EVENT_TYPES,
    SESSION_PROTOCOLS,
    SESSION_STATUSES,
    SESSION_TERMINAL_STATUSES,
    SETTINGS_ACTION_UPDATED,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    VAULT_ACTION_CHECKED_OUT,
    VAULT_ACTION_ONBOARDED,
    VAULT_ACTION_REVOKED,
    VAULT_ACTION_REVEALED,
    VAULT_ACTION_ROTATED,
    VAULT_ACTION_ROTATION_FAILED,
    VAULT_STATUS_AVAILABLE,
    VAULT_STATUS_CHECKED_OUT,
    VAULT_STATUS_FAILED,
    VAULT_STATUS_ROTATING,
    VAULT_STATUS_ROTATION_DUE,
    VAULT_STATUSES,
    VAULT_TYPES,
    DiscoveredAccount,
    DiscoveredAsset,
    DiscoveryEvent,
    DiscoveryScan,
    IntegrationEvent,
    JitEvent,
    JitRequest,
    LicenseEvent,
    LicenseRecord,
    PrivilegedSession,
    RiskEvent,
    SessionEvent,
    SettingGroup,
    SettingsEvent,
    VaultEvent,
    VaultItem,
    VaultSecretVersion,
    AnomalyEvent,
    AuditEvent,
    BehaviorBaseline,
    BreakGlassApproval,
    BreakGlassEvent,
    BreakGlassRequest,
    BypassEvent,
    BypassIncident,
    BypassSignal,
    classify_account_kind,
    CommandIncident,
    CommandRule,
    log_event,
)
from secrets_store import (
    approximate_entropy_bits,
    generate_secret,
    generated_secret_is_valid,
    seal,
    seal_with_aad,
    unseal,
    unseal_with_aad,
)

import audit
import integrations

_QUOTA_SCALARS = (
    "nodes",
    "concurrent_sessions",
    "bastion_tunnels",
    "max_lease_hours",
    "worm_retention_days",
)
_USAGE_FIELDS = ("nodes_consumed", "sessions_active", "bastion_tunnels_used")


# ---------------------------------------------------------------------------
# installing vendor-signed licenses
# ---------------------------------------------------------------------------
def import_license(config: Config, payload: Any) -> Tuple[LicenseRecord, Dict[str, Any]]:
    """Install a signed license file — the ``.lic`` from the delivery bundle.

    PAM-MASTER signs; this server only verifies and records. Claims are stored
    exactly as signed (what validates is what you imported): malformed,
    wrongly-signed, expired, structurally invalid and already-installed files
    are refused with 400/409.
    """
    envelope = sig.parse_envelope(payload)
    if envelope is None:
        raise ValidationFailed(
            "Body must be a signed license envelope (the .lic file from the "
            'delivery bundle, or {"token": ...} for a compact token)'
        )

    algorithm = envelope.get("algorithm") or sig.DEFAULT_ALGORITHM
    if algorithm not in sig.SUPPORTED_ALGORITHMS:
        raise ValidationFailed(
            f"Unknown signature algorithm '{algorithm}'",
            {"field": "algorithm", "allowed": list(sig.SUPPORTED_ALGORITHMS)},
        )
    if envelope.get("format") not in sig.SUPPORTED_FORMATS:
        raise ValidationFailed(
            f"Unknown license file format '{envelope.get('format')}'",
            {"field": "format", "allowed": list(sig.SUPPORTED_FORMATS)},
        )

    validator = get_validator(config)
    if not validator.verify_envelope(envelope):
        raise ValidationFailed(
            "Signature verification failed — the file was not signed with "
            "this deployment's trusted vendor key"
        )

    license_data = envelope["license_data"]
    _validate_import_claims(license_data)

    try:
        license_obj = License.from_dict(license_data)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationFailed(f"License claims could not be parsed: {exc}") from None

    if license_obj.is_expired():
        raise ValidationFailed(
            f"License expired on {license_obj.expires_on.date()} — nothing to import",
            {"field": "expires_on", "expires_on": license_obj.expires_on.isoformat()},
        )

    existing = LicenseRecord.query.filter_by(
        license_key=license_obj.license_key
    ).first()
    if existing is not None:
        raise Conflict(
            f"License {license_obj.license_key} is already installed",
            {"license_key": existing.license_key, "status": existing.status},
        )

    # parse_envelope descends into compact-token documents, which strips the
    # envelope's own `token` and `fingerprint`. Restore the caller's token and
    # derive the fingerprint from the verified signature, so the stored record
    # matches the file the vendor shipped.
    echo = dict(envelope)
    if isinstance(payload, dict):
        raw_token = payload.get("token")
        if isinstance(raw_token, str) and "token" not in echo:
            echo["token"] = raw_token
    if not echo.get("fingerprint"):
        try:
            echo["fingerprint"] = sig.fingerprint(base64.b64decode(echo["signature"]))
        except (ValueError, TypeError):  # pragma: no cover - verify already decoded it
            echo["fingerprint"] = None

    record = LicenseRecord(
        license_key=license_data["license_key"],
        license_type=license_data["license_type"],
        issued_to=license_data["issued_to"],
        issued_date=license_obj.issued_date,
        expires_on=license_obj.expires_on,
        features=license_data.get("features") or [],
        usage_limits=license_data.get("usage_limits") or {},
        license_metadata=license_data.get("metadata") or {},
        license_id=license_data.get("license_id"),
        tier=license_data.get("tier"),
        plan=license_data.get("plan"),
        subject_entity=license_data.get("subject_entity"),
        classification=license_data.get("classification"),
        issuer=license_data.get("issuer"),
        enclave_binding=license_data.get("enclave_binding"),
        quotas=license_data.get("quotas") or {},
        modules=license_data.get("modules") or [],
        account=license_data.get("account") or {},
        status=STATUS_ACTIVE,
        signature=envelope["signature"],
        algorithm=algorithm,
        signature_format=envelope.get("format") or sig.FORMAT_JSON,
        fingerprint=echo.get("fingerprint"),
    )
    db.session.add(record)
    log_event(
        record.license_key,
        EVENT_IMPORTED,
        {
            "issued_to": record.issued_to,
            "license_type": record.license_type,
            "algorithm": algorithm,
            "format": record.signature_format,
            "license_id": record.license_id,
        },
    )
    db.session.commit()
    return record, public_envelope(echo)


def _validate_import_claims(claims: Dict[str, Any]) -> None:
    """Refuse claims this server could not serve — checked, never rewritten.

    These are the form-level rules the old self-issue endpoint enforced, now
    applied where vendor files are installed. The stored record must match the
    signature byte for byte, so validation rejects instead of normalising.
    """
    license_type = claims.get("license_type")
    try:
        LicenseType(license_type)
    except (TypeError, ValueError):
        raise ValidationFailed(
            f"Unknown license_type '{license_type}'",
            {"field": "license_type", "allowed": [t.value for t in LicenseType]},
        ) from None

    for field, max_length in (
        ("license_key", 64),
        ("issued_to", 255),
        ("tier", 64),
        ("plan", 64),
        ("license_id", 64),
        ("subject_entity", 255),
        ("classification", 64),
        ("issuer", 255),
        ("environment", 32),
    ):
        value = claims.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValidationFailed(f"'{field}' must be a string", {"field": field})
        if len(value) > max_length:
            raise ValidationFailed(
                f"'{field}' must be at most {max_length} characters",
                {"field": field},
            )

    for required in ("license_key", "issued_to"):
        if not (claims.get(required) or "").strip():
            raise ValidationFailed(f"'{required}' is required", {"field": required})
    key = claims.get("license_key")
    if isinstance(key, str) and key != key.upper():
        raise ValidationFailed(
            "'license_key' must be uppercase", {"field": "license_key"}
        )

    metadata = claims.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValidationFailed("'metadata' must be an object", {"field": "metadata"})

    features = claims.get("features")
    if features is not None and (
        not isinstance(features, list)
        or not all(isinstance(feature, str) for feature in features)
    ):
        raise ValidationFailed(
            "'features' must be a list of strings", {"field": "features"}
        )

    limits = claims.get("usage_limits")
    if limits is not None:
        if not isinstance(limits, dict):
            raise ValidationFailed(
                "'usage_limits' must be an object", {"field": "usage_limits"}
            )
        for key, value in limits.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, int)
                or isinstance(value, bool)
            ):
                raise ValidationFailed(
                    "'usage_limits' must map string keys to integer values",
                    {"field": "usage_limits", "key": key},
                )

    quotas = claims.get("quotas")
    if quotas is not None:
        _validate_import_quotas(quotas)

    modules = claims.get("modules")
    if modules is not None:
        _validate_import_modules(modules)

    account = claims.get("account")
    if account is not None:
        if not isinstance(account, dict):
            raise ValidationFailed("'account' must be an object", {"field": "account"})
        for key, value in account.items():
            if not isinstance(key, str):
                raise ValidationFailed(
                    "'account' keys must be strings", {"field": "account"}
                )
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise ValidationFailed(
                    f"'account.{key}' must be a string or integer",
                    {"field": "account"},
                )
            if isinstance(value, str) and len(value) > 255:
                raise ValidationFailed(
                    f"'account.{key}' must be at most 255 characters",
                    {"field": "account"},
                )


def _validate_import_quotas(raw: Any) -> None:
    """Validate the node/session/tunnel quota block and its pool breakdown."""
    if not isinstance(raw, dict):
        raise ValidationFailed("'quotas' must be an object", {"field": "quotas"})
    for key, value in raw.items():
        if key == "pools":
            continue
        if key not in _QUOTA_SCALARS:
            raise ValidationFailed(
                f"Unknown quota '{key}'",
                {"field": "quotas", "allowed": list(_QUOTA_SCALARS) + ["pools"]},
            )
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationFailed(
                f"'quotas.{key}' must be a non-negative integer",
                {"field": f"quotas.{key}"},
            )

    pools_raw = raw.get("pools", [])
    if pools_raw is None:
        pools_raw = []
    if not isinstance(pools_raw, list):
        raise ValidationFailed(
            "'quotas.pools' must be a list", {"field": "quotas.pools"}
        )
    seen = set()
    for entry in pools_raw:
        if not isinstance(entry, dict):
            raise ValidationFailed(
                "'quotas.pools' entries must be objects", {"field": "quotas.pools"}
            )
        pool_id = entry.get("id")
        if not isinstance(pool_id, str) or not pool_id.strip() or len(pool_id) > 64:
            raise ValidationFailed(
                "Each node pool needs an 'id'", {"field": "quotas.pools"}
            )
        if pool_id in seen:
            raise ValidationFailed(
                f"Duplicate node pool '{pool_id}'", {"field": "quotas.pools"}
            )
        seen.add(pool_id)
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise ValidationFailed(
                "Each node pool needs 'id' and 'name'", {"field": "quotas.pools"}
            )
        quota_nodes = entry.get("quota_nodes")
        if (
            not isinstance(quota_nodes, int)
            or isinstance(quota_nodes, bool)
            or quota_nodes < 0
        ):
            raise ValidationFailed(
                f"'quotas.pools.{pool_id}.quota_nodes' must be a non-negative integer",
                {"field": "quotas.pools"},
            )
        enforcement = entry.get("enforcement", "audit-log")
        if enforcement not in ENFORCEMENT_LEVELS:
            raise ValidationFailed(
                f"Unknown enforcement level '{enforcement}'",
                {"field": "quotas.pools", "allowed": list(ENFORCEMENT_LEVELS)},
            )
        regions = entry.get("regions", [])
        if not isinstance(regions, list) or not all(
            isinstance(region, str) for region in regions
        ):
            raise ValidationFailed(
                f"'quotas.pools.{pool_id}.regions' must be a list of strings",
                {"field": "quotas.pools"},
            )


def _validate_import_modules(raw: Any) -> None:
    """Validate granted entitlement modules against the catalog."""
    if not isinstance(raw, list):
        raise ValidationFailed("'modules' must be a list", {"field": "modules"})
    seen = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValidationFailed(
                "'modules' entries must be objects", {"field": "modules"}
            )
        module_id = entry.get("id")
        if not isinstance(module_id, str) or not module_id:
            raise ValidationFailed("Each module needs an 'id'", {"field": "modules"})
        if module_id not in MODULE_IDS:
            raise ValidationFailed(
                f"Unknown module '{module_id}'",
                {"field": "modules", "allowed": MODULE_IDS},
            )
        if module_id in seen:
            raise ValidationFailed(
                f"Duplicate module '{module_id}'", {"field": "modules"}
            )
        seen.add(module_id)
        status = entry.get("status", "entitled")
        if status not in ("entitled", "not_entitled"):
            raise ValidationFailed(
                f"Unknown module status '{status}'",
                {"field": "modules", "allowed": ["entitled", "not_entitled"]},
            )


def public_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Envelope as served over HTTP: claims + signature, minus signing inputs."""
    return {
        key: value
        for key, value in envelope.items()
        if key not in ("signing_input", "header")
    }


# ---------------------------------------------------------------------------
# querying
# ---------------------------------------------------------------------------
def get_record(license_key: str) -> LicenseRecord:
    """Fetch a license by key or raise 404."""
    record = LicenseRecord.query.filter(
        db.or_(
            LicenseRecord.license_key == license_key.upper(),
            LicenseRecord.license_id == license_key,
        )
    ).first()
    if record is None:
        raise NotFound(f"No license with key {license_key}")
    return record


def list_licenses(
    *,
    status: Optional[str] = None,
    license_type: Optional[str] = None,
    issued_to: Optional[str] = None,
    tier: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[LicenseRecord], int]:
    """
    List licenses with optional filters, newest first.

    `status` accepts 'active' (not revoked), 'revoked', 'valid' (active and
    unexpired) and 'expired'. Expiry is evaluated in Python because the
    datetime columns are naive local time, which SQLite's date functions
    would compare against UTC.
    """
    allowed_statuses = {STATUS_ACTIVE, STATUS_REVOKED, "valid", "expired"}
    if status and status not in allowed_statuses:
        raise ValidationFailed(
            f"Unknown status '{status}'",
            {"field": "status", "allowed": sorted(allowed_statuses)},
        )

    query = LicenseRecord.query
    if license_type:
        query = query.filter(LicenseRecord.license_type == license_type)
    if issued_to:
        query = query.filter(LicenseRecord.issued_to.ilike(f"%{issued_to}%"))
    if tier:
        query = query.filter(LicenseRecord.tier.ilike(f"%{tier}%"))
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                LicenseRecord.license_key.ilike(pattern),
                LicenseRecord.license_id.ilike(pattern),
                LicenseRecord.issued_to.ilike(pattern),
                LicenseRecord.tier.ilike(pattern),
            )
        )

    records = query.order_by(LicenseRecord.created_at.desc()).all()

    if status == STATUS_ACTIVE:
        records = [r for r in records if r.status == STATUS_ACTIVE]
    elif status == STATUS_REVOKED:
        records = [r for r in records if r.status == STATUS_REVOKED]
    elif status == "valid":
        records = [r for r in records if r.effective_status() == "valid"]
    elif status == "expired":
        records = [r for r in records if r.effective_status() == "expired"]

    return _paginate(records, limit, offset)


def _paginate(records: List[LicenseRecord], limit: int, offset: int) -> Tuple[List[LicenseRecord], int]:
    return records[offset : offset + limit], len(records)


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------
def revoke_license(license_key: str, reason: Optional[str] = None) -> LicenseRecord:
    record = get_record(license_key)
    if record.status == STATUS_REVOKED:
        raise ValidationFailed("License is already revoked", {"license_key": record.license_key})

    record.status = STATUS_REVOKED
    record.revoked_at = datetime.now()
    record.revoked_reason = reason
    log_event(record.license_key, EVENT_REVOKED, {"reason": reason})
    db.session.commit()
    return record


def restore_license(license_key: str) -> LicenseRecord:
    record = get_record(license_key)
    if record.status != STATUS_REVOKED:
        raise ValidationFailed("License is not revoked", {"license_key": record.license_key})

    record.status = STATUS_ACTIVE
    record.revoked_at = None
    record.revoked_reason = None
    log_event(record.license_key, EVENT_RESTORED, {})
    db.session.commit()
    return record


# ---------------------------------------------------------------------------
# usage reporting (runtime consumption against the signed ceilings)
# ---------------------------------------------------------------------------
def report_usage(license_key: str, payload: Any) -> LicenseRecord:
    """Record runtime consumption reported by a deployed instance."""
    if not isinstance(payload, dict):
        raise ValidationFailed(
            "Usage body must be an object", {"field": "usage"}
        )

    record = get_record(license_key)
    unknown = set(payload) - set(_USAGE_FIELDS) - {"pools"}
    if unknown:
        raise ValidationFailed(
            f"Unknown usage field(s): {', '.join(sorted(unknown))}",
            {"field": "usage", "allowed": list(_USAGE_FIELDS) + ["pools"]},
        )

    usage: Dict[str, Any] = {}
    for field in _USAGE_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationFailed(
                f"'{field}' must be a non-negative integer", {"field": field}
            )
        usage[field] = value

    pools_raw = payload.get("pools", [])
    if pools_raw is None:
        pools_raw = []
    if not isinstance(pools_raw, list):
        raise ValidationFailed("'pools' must be a list", {"field": "pools"})

    configured = {
        pool.get("id")
        for pool in (record.quotas or {}).get("pools", [])
        if isinstance(pool, dict)
    }
    pools: List[Dict[str, Any]] = []
    for entry in pools_raw:
        if not isinstance(entry, dict):
            raise ValidationFailed("'pools' entries must be objects", {"field": "pools"})
        pool_id = entry.get("id")
        if pool_id not in configured:
            raise ValidationFailed(
                f"Unknown node pool '{pool_id}'",
                {"field": "pools", "allowed": sorted(configured)},
            )
        consumed = entry.get("nodes_consumed")
        if not isinstance(consumed, int) or isinstance(consumed, bool) or consumed < 0:
            raise ValidationFailed(
                f"'pools.{pool_id}.nodes_consumed' must be a non-negative integer",
                {"field": "pools"},
            )
        pools.append({"id": pool_id, "nodes_consumed": consumed})
    if pools:
        usage["pools"] = pools

    record.reported_usage = usage
    record.last_reported_at = datetime.now()
    log_event(record.license_key, EVENT_USAGE_REPORTED, {"usage": usage})
    db.session.commit()
    return record


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def validate_license_payload(config: Config, payload: Any) -> Dict[str, Any]:
    """
    Fully validate a signed license.

    Accepts a JSON envelope, a compact ``.lic`` / ``.jwt`` token (raw string or
    wrapped in ``{"token": ...}`` / ``{"license": ...}``) and checks:
    structure -> cryptographic signature -> revocation list -> expiry.
    """
    envelope = sig.parse_envelope(payload)
    if envelope is None:
        return _result(
            valid=False,
            status="malformed",
            signature_valid=False,
            registered=False,
            reason="License payload must be a JSON object, a {license: ...} "
            "wrapper, or a compact token string",
        )

    license_data = envelope["license_data"]
    validator = get_validator(config)
    if not validator.verify_envelope(envelope):
        return _result(
            valid=False,
            status="signature_invalid",
            signature_valid=False,
            registered=license_key_of(license_data) is not None,
            reason="Signature does not match the signed license data",
            algorithm=envelope.get("algorithm"),
            file_format=envelope.get("format"),
        )

    try:
        license_obj = License.from_dict(license_data)
    except (KeyError, ValueError, TypeError) as exc:
        return _result(
            valid=False,
            status="malformed",
            signature_valid=True,
            registered=False,
            reason=f"License data could not be parsed: {exc}",
            algorithm=envelope.get("algorithm"),
            file_format=envelope.get("format"),
        )

    record = LicenseRecord.query.filter_by(license_key=license_obj.license_key).first()
    registered = record is not None
    revoked = registered and record.status == STATUS_REVOKED
    expired = license_obj.is_expired()
    matches_record = record.signature == envelope["signature"] if registered else None

    if revoked:
        status, valid = "revoked", False
    elif expired:
        status, valid = "expired", False
    else:
        status, valid = "valid", True

    info = validator.get_license_info(license_obj)
    return {
        "valid": valid,
        "status": status,
        "signature_valid": True,
        "registered": registered,
        "revoked": revoked,
        "expired": expired,
        "matches_registered_record": matches_record,
        "reason": None
        if valid
        else ("License has been revoked" if revoked else "License has expired"),
        "license": info,
        "revoked_reason": record.revoked_reason if revoked else None,
        "algorithm": envelope.get("algorithm"),
        "format": envelope.get("format"),
        "fingerprint": sig.fingerprint(base64.b64decode(envelope["signature"])),
    }


def license_key_of(license_data: Any) -> Optional[str]:
    if isinstance(license_data, dict):
        key = license_data.get("license_key")
        if isinstance(key, str):
            return key
    return None


def _result(
    *,
    valid: bool,
    status: str,
    signature_valid: bool,
    registered: bool,
    reason: str,
    algorithm: Optional[str] = None,
    file_format: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "valid": valid,
        "status": status,
        "signature_valid": signature_valid,
        "registered": registered,
        "revoked": False,
        "expired": False,
        "matches_registered_record": None,
        "reason": reason,
        "license": None,
        "revoked_reason": None,
        "algorithm": algorithm,
        "format": file_format,
        "fingerprint": None,
    }


# ---------------------------------------------------------------------------
# feature / module / usage checks
# ---------------------------------------------------------------------------
def check_access(
    license_key: str,
    *,
    feature: Optional[str] = None,
    module_id: Optional[str] = None,
    limit_type: Optional[str] = None,
    current_usage: Optional[int] = None,
) -> Dict[str, Any]:
    """Check a registered license for feature/module access and/or usage limits."""
    if feature is None and module_id is None and limit_type is None:
        raise ValidationFailed(
            "Provide 'feature', 'module_id' and/or 'limit_type' to check",
            {"fields": ["feature", "module_id", "limit_type"]},
        )

    record = get_record(license_key)
    entitled = [module.get("id") for module in (record.modules or [])]
    response: Dict[str, Any] = {
        "license_key": record.license_key,
        "license_id": record.license_id,
        "status": record.effective_status(),
        "active": record.status == STATUS_ACTIVE and not record.is_expired,
    }

    if feature is not None:
        response["feature"] = feature
        response["feature_allowed"] = response["active"] and feature in (record.features or [])

    if module_id is not None:
        if module_id not in MODULE_IDS:
            raise ValidationFailed(
                f"Unknown module '{module_id}'",
                {"field": "module_id", "allowed": MODULE_IDS},
            )
        response["module_id"] = module_id
        response["module_allowed"] = response["active"] and module_id in entitled

    if limit_type is not None:
        if current_usage is None or not isinstance(current_usage, int) or isinstance(current_usage, bool):
            raise ValidationFailed(
                "'current_usage' must be an integer when checking a limit",
                {"field": "current_usage"},
            )
        limits = {**(record.usage_limits or {}), **(record.quotas or {})}
        limit = limits.get(limit_type)
        allowed = response["active"] and (limit is None or current_usage <= limit)
        response.update(
            {
                "limit_type": limit_type,
                "current_usage": current_usage,
                "limit": limit,
                "limit_allowed": allowed,
            }
        )

    return response


def meta() -> Dict[str, Any]:
    """Static license-server capabilities (drives the console's pickers)."""
    return {
        "algorithms": list(sig.SUPPORTED_ALGORITHMS),
        "formats": list(sig.SUPPORTED_FORMATS),
        "license_types": [t.value for t in LicenseType],
        "enforcement_levels": list(ENFORCEMENT_LEVELS),
        "tiers": sorted(set(DEFAULT_TIERS.values())),
        "modules": MODULE_CATALOG,
        "quota_fields": list(_QUOTA_SCALARS),
        "usage_fields": list(_USAGE_FIELDS),
    }


# ---------------------------------------------------------------------------
# platform settings (SSO / HSM / ZSP / WORM + the section-20 connectors:
# MFA / ITSM / SIEM / LDAP)
#
# Every field is validated server-side against SETTINGS_SCHEMA; unknown groups
# and unknown/ill-typed/out-of-range fields are rejected before anything is
# stored, and each accepted change is written to the config audit changelog.
# Two field kinds carry material:
#   - `secret` fields (ITSM token, SIEM signing secret, the TOTP factor) are
#     sealed with AES-256-GCM (`secrets_store`), never returned by the API
#     (`<set>` on read) and never written to the changelog in plaintext;
#   - `readonly` fields (the TOTP factor state) reject PUT /settings outright:
#     they are managed by their own endpoints (/mfa/enroll, /mfa/verify).
# Plain fields stay what they always were: references and configuration.
# ---------------------------------------------------------------------------
_IDP_PROVIDERS = ("okta", "entra", "ping-federate", "adfs", "keycloak")
_HSM_PROVIDERS = (
    "aws-cloudhsm",
    "azure-dedicated-hsm",
    "gcp-cloud-hsm",
    "hashicorp-vault",
    "local-pkcs11",
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")

SETTINGS_SCHEMA: Dict[str, Dict[str, Dict[str, Any]]] = {
    "sso": {
        "primary_provider": {"type": "enum", "choices": _IDP_PROVIDERS, "default": "okta"},
        "primary_metadata_url": {
            "type": "url",
            "default": "https://aegispam.okta.com/app/aegis-sso/sso/saml/metadata",
        },
        "primary_entity_id": {
            "type": "str",
            "max_length": 255,
            "default": "urn:aegispam.internal:sp:primary",
        },
        "secondary_provider": {
            "type": "enum",
            "choices": _IDP_PROVIDERS + ("disabled",),
            "default": "entra",
        },
        "secondary_metadata_url": {
            "type": "url",
            "allow_empty": True,
            "default": "https://login.microsoftonline.com/8c1f2a64-3d77-4b1e-9f5a-2e6b0d4c7a91"
            "/federationmetadata/2.000/federationmetadata.xml",
        },
        "enforce_sso": {"type": "bool", "default": True},
        "jit_provisioning": {"type": "bool", "default": True},
        "require_mfa": {"type": "bool", "default": True},
        "session_ttl_minutes": {"type": "int", "min": 5, "max": 1440, "default": 480},
    },
    "hsm": {
        "provider": {"type": "enum", "choices": _HSM_PROVIDERS, "default": "aws-cloudhsm"},
        "cluster_id": {"type": "str", "max_length": 64, "default": "hsm-cluster-k10-east"},
        "region": {"type": "str", "max_length": 32, "default": "us-east-1"},
        "kms_endpoint": {
            "type": "url",
            "default": "https://hsm-cluster-k10-east.prod.aegis.internal:443",
        },
        "master_key_label": {"type": "str", "max_length": 64, "default": "aegispam-root-lmk"},
        "pin_reference": {
            "type": "str",
            "max_length": 255,
            "default": "vault://kv/pam/hsm",
        },
        "key_rotation_hours": {"type": "int", "min": 1, "max": 720, "default": 24},
        "seal_delay_seconds": {"type": "int", "min": 0, "max": 120, "default": 18},
        "fips_profile": {
            "type": "enum",
            "choices": ("fips-140-2-level-3", "fips-140-2-level-4", "fips-140-3-level-1"),
            "default": "fips-140-2-level-4",
        },
    },
    "zsp": {
        "default_jit_ttl_minutes": {"type": "int", "min": 1, "max": 1440, "default": 60},
        "max_ttl_extension_minutes": {"type": "int", "min": 0, "max": 4320, "default": 120},
        "tier0_quorum_approvers": {"type": "int", "min": 1, "max": 10, "default": 2},
        "session_inactivity_timeout_minutes": {"type": "int", "min": 1, "max": 240, "default": 15},
    },
    "worm": {
        "destination": {
            "type": "enum",
            "choices": ("s3-object-lock", "azure-blob-immutability", "gcs-locked", "offline-archive"),
            "default": "s3-object-lock",
        },
        "bucket": {"type": "slug", "default": "aegispam-immutable-worm-audit-prod-01"},
        "region": {"type": "str", "max_length": 32, "default": "us-east-1"},
        "retention_days": {"type": "int", "min": 30, "max": 3650, "default": 2555},
        "object_lock_mode": {"type": "enum", "choices": ("COMPLIANCE", "GOVERNANCE"), "default": "COMPLIANCE"},
        "immutability_enabled": {"type": "bool", "default": True},
    },
    # --- section 20: enterprise integrations (every connector either works
    # for real or honestly reports `not connected`) -----------------------
    "mfa": {
        # the TOTP factor: enrolled through POST /mfa/enroll, verified
        # through POST /mfa/verify / the medium-band session-start gate.
        # Read-only here - PUT /settings/mfa rejects these fields.
        "factor_enrolled_for": {
            "type": "str",
            "max_length": 64,
            "allow_empty": True,
            "default": "",
            "readonly": True,
        },
        "factor_secret": {
            "type": "secret",
            "max_length": 4096,
            "allow_empty": True,
            "default": "",
            "readonly": True,
        },
        "factor_created_at": {
            "type": "str",
            "max_length": 32,
            "allow_empty": True,
            "default": "",
            "readonly": True,
        },
        "factor_last_verified_at": {
            "type": "str",
            "max_length": 32,
            "allow_empty": True,
            "default": "",
            "readonly": True,
        },
    },
    "itsm": {
        "vendor": {
            "type": "enum",
            "choices": integrations.ITSM_VENDORS,
            "default": "servicenow",
        },
        "base_url": {
            "type": "url",
            "allow_empty": True,
            "allow_http": True,  # internal Jira/Elastic instances often are
            "default": "",
        },
        "username": {"type": "str", "max_length": 128, "allow_empty": True, "default": ""},
        "api_token": {"type": "secret", "max_length": 4096, "allow_empty": True, "default": ""},
        "path_template": {
            "type": "str",
            "max_length": 255,
            "allow_empty": True,
            "default": "",
        },
        "timeout_seconds": {"type": "int", "min": 1, "max": 30, "default": 5},
    },
    "siem": {
        "webhook_url": {
            "type": "url",
            "allow_empty": True,
            "allow_http": True,  # HEC collectors sit on plain http internally
            "default": "",
        },
        "signing_secret": {"type": "secret", "max_length": 4096, "allow_empty": True, "default": ""},
        "enabled": {"type": "bool", "default": False},
        "timeout_seconds": {"type": "int", "min": 1, "max": 30, "default": 5},
    },
    "ldap": {
        "server": {"type": "str", "max_length": 255, "allow_empty": True, "default": ""},
        "port": {"type": "int", "min": 1, "max": 65535, "default": 389},
        "use_ssl": {"type": "bool", "default": False},
        # DN/UPN the user's own password is tried against, e.g.
        # `uid={user},ou=people,dc=example,dc=com` or `{user}@corp.example`
        "user_bind_template": {
            "type": "str",
            "max_length": 255,
            "allow_empty": True,
            "default": "",
        },
        "timeout_seconds": {"type": "int", "min": 1, "max": 30, "default": 5},
        "ticket_ttl_seconds": {"type": "int", "min": 60, "max": 86400, "default": 900},
    },
}

SETTINGS_GROUPS = tuple(SETTINGS_SCHEMA)


def settings_schema() -> Dict[str, Any]:
    """Field metadata (types, choices, ranges, defaults) for the settings UI."""
    return {
        group: {
            name: {
                key: (list(value) if isinstance(value, tuple) else value)
                for key, value in spec.items()
            }
            for name, spec in fields.items()
        }
        for group, fields in SETTINGS_SCHEMA.items()
    }


def _validate_setting(group: str, field: str, spec: Dict[str, Any], value: Any) -> Any:
    where = f"{group}.{field}"
    ftype = spec["type"]

    if ftype == "bool":
        if not isinstance(value, bool):
            raise ValidationFailed(f"'{where}' must be true or false", {"field": where})
        return value

    if ftype == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationFailed(f"'{where}' must be an integer", {"field": where})
        low, high = spec.get("min"), spec.get("max")
        if low is not None and value < low:
            raise ValidationFailed(
                f"'{where}' must be >= {low}", {"field": where, "min": low}
            )
        if high is not None and value > high:
            raise ValidationFailed(
                f"'{where}' must be <= {high}", {"field": where, "max": high}
            )
        return value

    if not isinstance(value, str):
        raise ValidationFailed(f"'{where}' must be a string", {"field": where})
    value = value.strip()

    if ftype == "enum":
        if value not in spec["choices"]:
            raise ValidationFailed(
                f"'{where}' must be one of {', '.join(spec['choices'])}",
                {"field": where, "allowed": list(spec["choices"])},
            )
        return value

    if len(value) > spec.get("max_length", 255):
        raise ValidationFailed(
            f"'{where}' must be at most {spec.get('max_length', 255)} characters",
            {"field": where, "max_length": spec.get("max_length", 255)},
        )

    if ftype == "secret":
        # plaintext in - `update_settings` seals it before storage and the
        # changelog only ever records `<set>` / `<cleared>`; empty clears
        return value

    if ftype == "url":
        if not value:
            if spec.get("allow_empty"):
                return ""
            raise ValidationFailed(f"'{where}' is required", {"field": where})
        allowed = ("https://", "http://") if spec.get("allow_http") else ("https://",)
        host = value.split("://", 1)[1] if "://" in value else ""
        if not value.startswith(allowed) or not host:
            message = (
                f"'{where}' must be an http(s) URL"
                if len(allowed) > 1
                else f"'{where}' must be an https URL"
            )
            raise ValidationFailed(
                message, {"field": where, "scheme": allowed[0][:-3]}
            )
        return value

    if ftype == "slug":
        if not _BUCKET_RE.match(value):
            raise ValidationFailed(
                f"'{where}' must be a DNS-style name (lowercase letters, digits, dots, dashes)",
                {"field": where},
            )
        return value

    # plain string
    if not value and not spec.get("allow_empty"):
        raise ValidationFailed(f"'{where}' is required", {"field": where})
    return value


def _settings_row(group: str) -> Dict[str, Any]:
    """Stored values for one group, merged over the schema defaults."""
    fields = SETTINGS_SCHEMA[group]
    row = SettingGroup.query.filter_by(group_name=group).first()
    saved = dict(row.value or {}) if row else {}
    merged = {
        name: saved[name] if name in saved else spec["default"]
        for name, spec in fields.items()
    }
    if row is None:
        return {
            "group": group,
            "values": merged,
            "stored": False,
            "updated_at": None,
            "updated_by": None,
        }
    return row.to_dict(merged)


def _redact_settings_values(group: str, values: Dict[str, Any]) -> Dict[str, Any]:
    """API-facing copy of a group's values: a secret field reads `<set>`
    when material exists and `` when it does not - never the ciphertext."""
    out = dict(values)
    for name, spec in SETTINGS_SCHEMA[group].items():
        if spec.get("type") == "secret":
            out[name] = "<set>" if out.get(name) else ""
    return out


def _setting_aad(group: str, field: str) -> bytes:
    """AAD: a settings ciphertext belongs to exactly one field."""
    return f"settings:{group}:{field}".encode("utf-8")


def seal_setting_secret(group: str, field: str, plaintext: str) -> Dict[str, Any]:
    """Seal one settings secret for storage (AES-256-GCM, field-bound)."""
    return seal_with_aad(plaintext, _setting_aad(group, field), _vault_config())


def unseal_setting_secret(group: str, field: str) -> str:
    """Unseal one settings secret; `` when never set. An unsealed plaintext
    string (never sealed in the first place) passes through unchanged."""
    raw = _settings_row(group)["values"].get(field)
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw
    return unseal_with_aad(raw, _setting_aad(group, field), _vault_config())


def get_settings() -> Dict[str, Any]:
    """All settings groups (defaults merged in, secrets redacted)."""
    out: Dict[str, Any] = {}
    for group in SETTINGS_GROUPS:
        data = _settings_row(group)
        data["values"] = _redact_settings_values(group, data["values"])
        out[group] = data
    return out


def update_settings(group: str, payload: Any, actor: str = "admin") -> Dict[str, Any]:
    """Validate and persist one settings group, then log the audit entry."""
    fields = SETTINGS_SCHEMA.get(group)
    if fields is None:
        raise NotFound(f"Unknown settings group '{group}'")

    if not isinstance(payload, dict):
        raise ValidationFailed(
            "Settings payload must be a JSON object",
            {"field": "values", "allowed": sorted(fields)},
        )

    unknown = sorted(name for name in payload if name not in fields)
    if unknown:
        raise ValidationFailed(
            f"Unknown field(s) in '{group}'",
            {"group": group, "fields": unknown, "allowed": sorted(fields)},
        )
    if not payload:
        raise ValidationFailed(
            f"Provide at least one '{group}' field to update",
            {"group": group, "allowed": sorted(fields)},
        )

    readonly = sorted(name for name in payload if fields[name].get("readonly"))
    if readonly:
        raise ValidationFailed(
            f"'{group}' field(s) are read-only in settings",
            {
                "group": group,
                "fields": readonly,
                "hint": "managed by their own endpoint (POST /api/v1/mfa/enroll, /mfa/verify)",
            },
        )

    current = _settings_row(group)["values"]
    changes: Dict[str, Dict[str, Any]] = {}
    stored: Dict[str, Any] = {}
    for name, raw in payload.items():
        spec = fields[name]
        new_value = _validate_setting(group, name, spec, raw)
        old_value = current.get(name)
        if spec.get("type") == "secret":
            # plaintext never reaches the changelog or the response: the
            # row gets ciphertext, the event gets `<set>` / `<cleared>`
            if new_value:
                changes[name] = {"old": "<set>" if old_value else "", "new": "<set>"}
                stored[name] = seal_setting_secret(group, name, new_value)
            elif old_value:
                changes[name] = {"old": "<set>", "new": ""}
                stored[name] = ""
            continue
        if new_value != old_value:
            changes[name] = {"old": old_value, "new": new_value}
            stored[name] = new_value

    if not changes:
        return {
            "group": group,
            "values": _redact_settings_values(group, current),
            "changes": {},
            "changed_fields": [],
            "message": "No changes",
        }

    return _persist_settings(group, changes, stored, actor)


def _persist_settings(
    group: str,
    changes: Dict[str, Dict[str, Any]],
    stored: Dict[str, Any],
    actor: str,
) -> Dict[str, Any]:
    """Merge validated changes into the row, write the changelog entry and
    commit. `changes` is already sanitized for the changelog; `stored` holds
    what goes to the row (ciphertext for secret fields). Also used by the
    MFA factor endpoints, which manage read-only fields through their own
    flow but keep the same changelog discipline."""
    current = _settings_row(group)["values"]
    merged = {**current, **stored}
    now = datetime.now()
    row = SettingGroup.query.filter_by(group_name=group).first()
    if row is None:
        row = SettingGroup(
            group_name=group, value=merged, updated_at=now, updated_by=actor
        )
        db.session.add(row)
    else:
        row.value = merged
        row.updated_at = now
        row.updated_by = actor
    db.session.add(
        SettingsEvent(
            group_name=group,
            action=SETTINGS_ACTION_UPDATED,
            changes=changes,
            actor=actor,
        )
    )
    db.session.commit()

    return {
        "group": group,
        "values": _redact_settings_values(group, merged),
        "changes": changes,
        "changed_fields": sorted(changes),
        "message": "Settings stored",
        "stored": True,
        "updated_at": now.isoformat(),
        "updated_by": actor,
    }


def settings_audit(limit: int = 20) -> Dict[str, Any]:
    """Recent config-audit entries, newest first."""
    total = SettingsEvent.query.count()
    events = (
        SettingsEvent.query.order_by(
            SettingsEvent.created_at.desc(), SettingsEvent.id.desc()
        )
        .limit(limit)
        .all()
    )
    return {
        "events": [event.to_dict() for event in events],
        "total": total,
        "limit": limit,
    }


# ---------------------------------------------------------------------------
# enterprise integrations foundation (architecture section 20): MFA
# (RFC-6238 TOTP), ITSM ticket verification, SIEM outbound push, LDAP bind
# ---------------------------------------------------------------------------
# Every connector either works for real or honestly reports `not
# connected`; nothing here simulates an external system, and no secret ever
# enters a response, a changelog entry or a ledger `detail`.


def _integration_event(
    action: str, subject: str, actor: str, detail: Dict[str, Any]
) -> IntegrationEvent:
    """Queue one section-20 action record; the flush listener folds it into
    the audit ledger under the eleventh source `integration` in the same
    commit - MFA verifications, the medium-band gate, ITSM checks, LDAP
    logins and SIEM push failures."""
    event = IntegrationEvent(action=action, actor=actor, subject=subject, detail=detail)
    db.session.add(event)
    return event


# --- MFA: TOTP (RFC 6238) -------------------------------------------------
def mfa_status() -> Dict[str, Any]:
    """Honest factor state: `configured` only when a factor is enrolled."""
    values = _settings_row("mfa")["values"]
    configured = bool(values.get("factor_secret") and values.get("factor_enrolled_for"))
    return {
        "configured": configured,
        "enrolled_for": values.get("factor_enrolled_for") or "",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "created_at": values.get("factor_created_at") or None,
        "last_verified_at": values.get("factor_last_verified_at") or None,
        "gate": (
            "medium-risk (mfa-decision) session starts require a valid code"
            if configured
            else "not configured - the mfa band stays advisory"
        ),
    }


def mfa_enroll(payload: Any, *, actor: str) -> Dict[str, Any]:
    """Generate a real TOTP factor for the acting operator.

    The plaintext secret appears exactly once - in this response, which is
    what an authenticator app scans or types - and is sealed AES-256-GCM at
    rest. Re-enrolling replaces the factor; the changelog records the
    replacement, never the material."""
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    secret = integrations.generate_totp_secret()
    now = datetime.now().isoformat()
    current = _settings_row("mfa")["values"]
    had_factor = bool(current.get("factor_secret"))
    _integration_event(
        "mfa-enrolled",
        actor,
        actor,
        {
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "replaced_existing": had_factor,
        },
    )
    _persist_settings(
        "mfa",
        {
            "factor_enrolled_for": {
                "old": current.get("factor_enrolled_for") or "",
                "new": actor,
            },
            "factor_secret": {
                "old": "<set>" if had_factor else "",
                "new": "<set>",
            },
            "factor_created_at": {
                "old": current.get("factor_created_at") or "",
                "new": now,
            },
            "factor_last_verified_at": {
                "old": current.get("factor_last_verified_at") or "",
                "new": "",
            },
        },
        {
            "factor_enrolled_for": actor,
            "factor_secret": seal_setting_secret("mfa", "factor_secret", secret),
            "factor_created_at": now,
            "factor_last_verified_at": "",
        },
        actor,
    )
    return {
        "factor": mfa_status(),
        "otpauth_uri": integrations.otpauth_uri(secret, account=actor),
        "secret": secret,
        "message": "Factor enrolled - add it to your authenticator app; the secret is shown once",
    }


def mfa_verify(payload: Any, *, actor: str) -> Dict[str, Any]:
    """Check a code against the enrolled factor (explicit verification)."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    code = payload.get("code")
    status = mfa_status()
    if not status["configured"]:
        raise Conflict(
            "MFA factor is not configured",
            {"field": "factor", "hint": "POST /api/v1/mfa/enroll first"},
        )
    if not isinstance(code, str) or not code.strip():
        raise ValidationFailed("'code' is required (6-digit TOTP)", {"field": "code"})

    if integrations.verify_totp(unseal_setting_secret("mfa", "factor_secret"), code):
        verified_at = datetime.now().isoformat()
        _integration_event(
            "mfa-verified",
            actor,
            actor,
            {"enrolled_for": status["enrolled_for"], "method": "totp"},
        )
        _persist_settings(
            "mfa",
            {
                "factor_last_verified_at": {
                    "old": status["last_verified_at"],
                    "new": verified_at,
                }
            },
            {"factor_last_verified_at": verified_at},
            actor,
        )
        return {"verified": True, "verified_at": verified_at, "factor": mfa_status()}

    _integration_event(
        "mfa-verify-failed",
        actor,
        actor,
        {
            "enrolled_for": status["enrolled_for"],
            "reason": "invalid or expired TOTP code",
        },
    )
    db.session.commit()
    raise Unauthorized(
        "Invalid or expired TOTP code",
        {"field": "code", "verified": False},
    )


def _mfa_gate(mfa_code: Any) -> Tuple[bool, str, str]:
    """The medium-band session-start gate (architecture section 7's `mfa`
    decision made actionable by section 20): with a factor enrolled, only a
    valid TOTP code passes. Without a factor there is nothing to verify -
    honest advisory, never a fake challenge. Returns
    `(passed, outcome, reason)` where outcome is `verified` / `no-factor` /
    `refused`; pure over its input, so the evaluator, the session gate and
    the break-glass open can all derive the same verdict."""
    status = mfa_status()
    if not status["configured"]:
        return True, "no-factor", "no TOTP factor enrolled - mfa band is advisory"
    if not isinstance(mfa_code, str) or not mfa_code.strip():
        return False, "refused", "TOTP code required - a factor is enrolled"
    if integrations.verify_totp(unseal_setting_secret("mfa", "factor_secret"), mfa_code):
        return True, "verified", "TOTP code verified"
    return False, "refused", "invalid or expired TOTP code"


# --- ITSM: real ticket verification ---------------------------------------
def itsm_status() -> Dict[str, Any]:
    """Honest connector state: configured only when an instance URL is set."""
    values = _settings_row("itsm")["values"]
    configured = bool((values.get("base_url") or "").strip())
    return {
        "configured": configured,
        "vendor": values.get("vendor") or "servicenow",
        "base_url": values.get("base_url") or "",
        "username": values.get("username") or "",
        "credentials_configured": bool(values.get("api_token")),
        "path_template": values.get("path_template") or "",
        "timeout_seconds": values.get("timeout_seconds") or 5,
        "detail": None if configured else "not connected - set itsm.base_url",
    }


def itsm_verify_ticket(
    ticket: str, *, actor: str, record: bool = True
) -> Dict[str, Any]:
    """Ask the configured ITSM instance whether `ticket` exists - a real
    HTTP GET, never a simulation. `record=False` lets the risk scorer fold
    the verdict into its components instead of writing a ledger event of
    its own (every evaluation already is one)."""
    status = itsm_status()
    if not status["configured"]:
        return {
            "ticket": ticket,
            "configured": False,
            "verified": False,
            "detail": "itsm is not configured",
        }
    values = _settings_row("itsm")["values"]
    result = integrations.verify_itsm_ticket(
        base_url=values.get("base_url") or "",
        vendor=values.get("vendor") or "servicenow",
        path_template=values.get("path_template") or "",
        username=values.get("username") or "",
        token=unseal_setting_secret("itsm", "api_token"),
        ticket=ticket,
        timeout=float(values.get("timeout_seconds") or 5),
    )
    outcome: Dict[str, Any] = {
        "ticket": ticket,
        "configured": True,
        "verified": bool(result.get("verified")),
        "vendor": status["vendor"],
        "http_status": result.get("http_status"),
        "detail": result.get("detail") or "",
        "checked_at": datetime.now().isoformat(),
    }
    if record:
        _integration_event(
            "itsm-verified" if outcome["verified"] else "itsm-verify-failed",
            actor,
            ticket,
            {
                "vendor": outcome["vendor"],
                "http_status": outcome["http_status"],
                "detail": outcome["detail"],
            },
        )
        db.session.commit()
    return outcome


# --- LDAP: real bind as an optional admin auth backend ---------------------
_LDAP_TICKET_PREFIX = "vypam-ldap1."


def mint_ldap_ticket(username: str, ttl_seconds: int, config: Config) -> str:
    """A signed, expiring bearer ticket proving an LDAP bind succeeded."""
    payload = json.dumps(
        {"u": username, "exp": int(time.time()) + int(ttl_seconds)},
        sort_keys=True,
        separators=(",", ":"),
    )
    body = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    signed = _LDAP_TICKET_PREFIX + body
    signature = hmac.new(
        config.secret_key.encode("utf-8"), signed.encode("ascii"), hashlib.sha256
    ).digest()
    sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{signed}.{sig}"


def verify_ldap_ticket(token: Any, *, config: Config) -> Optional[Dict[str, Any]]:
    """The ticket's username when signature and expiry both hold, else None
    (tampered, malformed or expired - all indistinguishable to the caller)."""
    if not isinstance(token, str) or not token.startswith(_LDAP_TICKET_PREFIX):
        return None
    body, dot, signature = token[len(_LDAP_TICKET_PREFIX) :].partition(".")
    if not dot or not body:
        return None
    signed = _LDAP_TICKET_PREFIX + body
    expected = base64.urlsafe_b64encode(
        hmac.new(
            config.secret_key.encode("utf-8"), signed.encode("ascii"), hashlib.sha256
        ).digest()
    ).decode("ascii").rstrip("=")
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        data = json.loads(raw)
        expires = int(data["exp"])
        username = data["u"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(username, str) or not username:
        return None
    if expires < time.time():
        return None
    return {"username": username, "expires_at": expires}


def ldap_status() -> Dict[str, Any]:
    """Honest connector state: server + user template both set to connect."""
    values = _settings_row("ldap")["values"]
    server = (values.get("server") or "").strip()
    template = (values.get("user_bind_template") or "").strip()
    configured = bool(server and template)
    return {
        "configured": configured,
        "server": server,
        "port": values.get("port") or 389,
        "use_ssl": bool(values.get("use_ssl")),
        "user_bind_template": template,
        "timeout_seconds": values.get("timeout_seconds") or 5,
        "ticket_ttl_seconds": values.get("ticket_ttl_seconds") or 900,
        "detail": None if configured else "not connected - set ldap.server and ldap.user_bind_template",
    }


def ldap_login(payload: Any, *, actor: str, config: Config) -> Dict[str, Any]:
    """Verify username/password with a real LDAP bind (section 20 IAM) and,
    in token mode, mint a short-lived admin ticket the routes accept beside
    the admin token. The password travels only inside the BindRequest; it is
    never stored, logged or echoed."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    username = payload.get("username")
    if not isinstance(username, str) or not username.strip():
        raise ValidationFailed("'username' is required", {"field": "username"})
    username = username.strip()
    if len(username) > 64:
        raise ValidationFailed(
            "'username' must be at most 64 characters",
            {"field": "username", "max_length": 64},
        )
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        raise ValidationFailed("'password' is required", {"field": "password"})
    if len(password) > 1024:
        raise ValidationFailed(
            "'password' must be at most 1024 characters",
            {"field": "password", "max_length": 1024},
        )

    status = ldap_status()
    if not status["configured"]:
        raise Conflict(
            "LDAP is not configured",
            {"field": "ldap", "configured": False, "detail": status["detail"]},
        )

    dn = status["user_bind_template"].replace("{user}", username)
    result = integrations.ldap_bind(
        server=status["server"],
        port=status["port"],
        use_ssl=status["use_ssl"],
        dn=dn,
        password=password,
        timeout=float(status["timeout_seconds"]),
    )
    if not result["ok"]:
        _integration_event(
            "ldap-login-failed",
            actor or username,
            username,
            {"detail": result.get("detail") or "bind failed", "result_code": result.get("result_code")},
        )
        db.session.commit()
        raise Unauthorized(
            "LDAP bind failed",
            {"detail": result.get("detail") or "bind failed", "configured": True},
        )

    ttl = status["ticket_ttl_seconds"]
    ticket = mint_ldap_ticket(username, ttl, config) if config.admin_token else None
    _integration_event(
        "ldap-login",
        actor or username,
        username,
        {
            "dn": dn,
            "mode": "token" if ticket else "open",
            "ticket_ttl_seconds": ttl if ticket else None,
        },
    )
    db.session.commit()
    return {
        "username": username,
        "verified": True,
        "ticket": ticket,
        "expires_in": ttl if ticket else None,
        "mode": "token" if ticket else "open",
        "note": (
            None
            if ticket
            else "open dev mode - no admin token configured, nothing to grant"
        ),
    }


# --- one aggregate for the Integrations cards and the SIEM chip -----------
def integrations_status() -> Dict[str, Any]:
    """Every connector's real state plus the last outbound push result."""
    siem_values = _settings_row("siem")["values"]
    siem_url = (siem_values.get("webhook_url") or "").strip()
    siem_secret_set = bool(siem_values.get("signing_secret"))
    siem_enabled = bool(siem_values.get("enabled"))
    push = audit.siem_status()
    if not (siem_url and siem_secret_set and siem_enabled):
        siem_state = "not connected"
        siem_detail = "not connected - set siem.webhook_url, a signing secret and enabled=true"
    elif push["last_push_status"] == "ok":
        siem_state = "connected"
        siem_detail = None
    elif push["last_push_status"] == "error":
        siem_state = "error"
        siem_detail = push.get("last_error")
    else:
        siem_state = "configured"
        siem_detail = "configured - awaiting the first committed ledger batch"
    return {
        "mfa": mfa_status(),
        "itsm": itsm_status(),
        "siem": {
            "configured": bool(siem_url and siem_secret_set and siem_enabled),
            "state": siem_state,
            "detail": siem_detail,
            "webhook_url": siem_url,
            "enabled": siem_enabled,
            "signing_secret_set": siem_secret_set,
            "last_push": push,
        },
        "ldap": ldap_status(),
    }


# ---------------------------------------------------------------------------
# credential vault (Credential Vault screen: inventory, rotation, checkouts)
# ---------------------------------------------------------------------------


def _rotation_due(item: VaultItem, now: datetime) -> bool:
    hours = item.rotation_interval_hours or 0
    if hours <= 0 or item.last_rotated_at is None:
        return False
    return (now - item.last_rotated_at).total_seconds() / 3600.0 >= hours


def refresh_vault_statuses() -> None:
    """Persist rotation_due once an item passes its SLA (cheap, dev-scale)."""
    now = datetime.now()
    changed = False
    pending = VaultItem.query.filter(
        VaultItem.status.in_([VAULT_STATUS_AVAILABLE, VAULT_STATUS_ROTATION_DUE])
    ).all()
    for item in pending:
        target = (
            VAULT_STATUS_ROTATION_DUE if _rotation_due(item, now) else VAULT_STATUS_AVAILABLE
        )
        if item.status != target:
            item.status = target
            changed = True
    if changed:
        db.session.commit()


def get_vault_item(item_id: int) -> VaultItem:
    """Fetch one inventory row or raise 404."""
    item = VaultItem.query.filter_by(id=item_id).first()
    if item is None:
        raise NotFound(f"No vault item with id {item_id}")
    return item


def list_vault_items(
    *,
    q: Optional[str] = None,
    secret_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[VaultItem], int]:
    """Inventory rows with the screen's type/status/free-text filters."""
    if secret_type and secret_type not in VAULT_TYPES:
        raise ValidationFailed(
            f"Unknown vault type '{secret_type}'",
            {"field": "type", "allowed": list(VAULT_TYPES)},
        )
    if status and status not in VAULT_STATUSES:
        raise ValidationFailed(
            f"Unknown vault status '{status}'",
            {"field": "status", "allowed": list(VAULT_STATUSES)},
        )

    refresh_vault_statuses()
    query = VaultItem.query
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                VaultItem.name.ilike(pattern),
                VaultItem.description.ilike(pattern),
                VaultItem.target.ilike(pattern),
                VaultItem.principal.ilike(pattern),
            )
        )
    if secret_type:
        query = query.filter(VaultItem.secret_type == secret_type)
    if status:
        query = query.filter(VaultItem.status == status)
    total = query.count()
    items = (
        query.order_by(VaultItem.id.asc()).offset(offset).limit(limit).all()
    )
    return items, total


def vault_stats() -> Dict[str, Any]:
    """Aggregates for the Credential Vault screen's tiles and filters."""
    refresh_vault_statuses()
    items = VaultItem.query.all()
    by_type = {kind: 0 for kind in VAULT_TYPES}
    by_status = {state: 0 for state in VAULT_STATUSES}
    on_demand = 0
    for item in items:
        by_type[item.secret_type] = by_type.get(item.secret_type, 0) + 1
        by_status[item.status] = by_status.get(item.status, 0) + 1
        if (item.rotation_interval_hours or 0) <= 0:
            on_demand += 1

    total = len(items)
    due = by_status.get(VAULT_STATUS_ROTATION_DUE, 0)
    failed = by_status.get(VAULT_STATUS_FAILED, 0)
    in_policy = total - due - failed

    midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    checkouts_today = VaultEvent.query.filter(
        VaultEvent.action == VAULT_ACTION_CHECKED_OUT,
        VaultEvent.created_at >= midnight,
    ).count()
    rotations_today = VaultEvent.query.filter(
        VaultEvent.action == VAULT_ACTION_ROTATED,
        VaultEvent.created_at >= midnight,
    ).count()

    return {
        "total": total,
        "by_type": by_type,
        "by_status": by_status,
        "rotation": {
            "compliance_pct": round(100.0 * in_policy / total, 2) if total else 100.0,
            "due": due,
            "on_demand": on_demand,
        },
        "secrets": {
            "managed": sum(1 for item in items if item.secret_version),
            "unmanaged": total - sum(1 for item in items if item.secret_version),
            "versions": VaultSecretVersion.query.count(),
        },
        "attention": {"failed": failed},
        "checked_out": by_status.get(VAULT_STATUS_CHECKED_OUT, 0),
        "events_today": {"checkouts": checkouts_today, "rotations": rotations_today},
    }


def _log_vault_event(
    item: VaultItem, action: str, actor: str, detail: Optional[Dict[str, Any]] = None
) -> None:
    db.session.add(
        VaultEvent(
            item_id=item.id,
            item_name=item.name,
            action=action,
            actor=actor,
            detail=detail or {},
        )
    )


def checkout_vault_item(
    item_id: int, *, actor: str, reason: Optional[str] = None
) -> VaultItem:
    item = get_vault_item(item_id)
    if item.status == VAULT_STATUS_CHECKED_OUT:
        raise ValidationFailed(
            "Credential is already checked out",
            {"field": "status", "status": item.status},
        )
    if item.status == VAULT_STATUS_ROTATING:
        raise ValidationFailed(
            "Rotation is in progress",
            {"field": "status", "status": item.status},
        )
    item.status = VAULT_STATUS_CHECKED_OUT
    item.checked_out_by = actor
    item.checked_out_at = datetime.now()
    _log_vault_event(
        item, VAULT_ACTION_CHECKED_OUT, actor, {"reason": reason} if reason else {}
    )
    db.session.commit()
    return item


def revoke_vault_checkout(item_id: int, *, actor: str) -> VaultItem:
    item = get_vault_item(item_id)
    if item.status != VAULT_STATUS_CHECKED_OUT:
        raise ValidationFailed(
            "Credential is not checked out",
            {"field": "status", "status": item.status},
        )
    detail = {"checked_out_by": item.checked_out_by}
    item.status = VAULT_STATUS_AVAILABLE
    item.checked_out_by = None
    item.checked_out_at = None
    _log_vault_event(item, VAULT_ACTION_REVOKED, actor, detail)
    db.session.commit()
    return item


def _vault_config() -> Config:
    """Runtime config for at-rest crypto (works in request and app context)."""
    from flask import current_app

    return current_app.config["LICENSE_CONFIG"]


def _store_secret(
    item: VaultItem,
    blob: Dict[str, Any],
    *,
    source: str,
    trigger: str,
    actor: str,
) -> VaultSecretVersion:
    """Append the next secret version and point the item at it."""
    version = (item.secret_version or 0) + 1
    row = VaultSecretVersion(
        item_id=item.id,
        version=version,
        blob=blob,
        source=source,
        trigger=trigger,
        created_by=actor,
    )
    db.session.add(row)
    db.session.flush()
    item.secret_version = version
    item.secret_updated_at = row.created_at
    return row


def _validate_stored_secret(
    item: VaultItem, plaintext: str, row: VaultSecretVersion, *, config: Config
) -> Dict[str, Any]:
    """Local round-trip: decrypt the row we just wrote and check the value.

    This validates what this deployment controls (storage integrity). It makes
    no claim about the credential working on a remote target — nothing here
    can reach one, and inventing such a claim would be a lie.
    """
    decrypted = unseal(row.blob, item.id, config)
    checks = {"decrypt": True, "plaintext_match": decrypted == plaintext}
    if row.source == "generated":
        checks["type_format"] = generated_secret_is_valid(item.secret_type, plaintext)
    failed = [name for name, ok in checks.items() if not ok]
    result: Dict[str, Any] = {
        "method": "local_roundtrip",
        "passed": not failed,
        "checks": sorted(checks),
    }
    if failed:
        raise APIError(
            500,
            "Rotation validation failed: " + ", ".join(failed),
            {"checks": result},
        )
    return result


def _mark_rotation_failed(
    item: VaultItem, *, trigger: str, actor: str, error: Exception,
    session_ref: Optional[str] = None,
) -> None:
    detail: Dict[str, Any] = {"trigger": trigger, "error": str(error)[:255]}
    if session_ref:
        detail["session_ref"] = session_ref
    try:
        item.status = VAULT_STATUS_FAILED
        _log_vault_event(item, VAULT_ACTION_ROTATION_FAILED, actor, detail)
        db.session.commit()
    except Exception:  # pragma: no cover - only when the DB itself fails
        db.session.rollback()


def _update_dependents(
    item: VaultItem, *, actor: str, trigger: str
) -> Dict[str, Any]:
    """Event-based step 2 of the architecture flow: after the primary value
    rotates, bring every other managed credential on the same target forward.

    Siblings that cannot rotate right now (checked out / mid-rotation) are
    reported with the real reason instead of being silently skipped.
    """
    siblings = (
        VaultItem.query.filter(
            VaultItem.target == item.target, VaultItem.id != item.id
        )
        .order_by(VaultItem.id.asc())
        .all()
    )
    rotated: List[str] = []
    skipped: List[Dict[str, str]] = []
    for sibling in siblings:
        try:
            rotate_vault_item(
                sibling.id, actor=actor, trigger=trigger, cascade=False
            )
            rotated.append(sibling.name)
        except APIError as exc:
            # Guard rejections and real failures are both auditable reasons;
            # real pipeline failures already wrote the sibling's own event.
            skipped.append({"name": sibling.name, "reason": exc.message})
    return {"considered": len(siblings), "rotated": rotated, "skipped": skipped}


def rotate_vault_item(
    item_id: int,
    *,
    actor: str,
    trigger: str = "manual",
    session_ref: Optional[str] = None,
    cascade: bool = False,
    extra_detail: Optional[Dict[str, Any]] = None,
) -> Tuple[VaultItem, Dict[str, Any]]:
    """Run one real rotation for one credential.

    Architecture order (module 5): mint+store the new value -> update
    dependent systems -> validate -> emit the audit event. The value itself is
    generated with the OS CSPRNG for the credential's type, sealed with
    AES-256-GCM under the vault key and kept versioned; nothing about the
    operation is simulated.
    """
    item = get_vault_item(item_id)
    if item.status == VAULT_STATUS_ROTATING:
        raise ValidationFailed(
            "Rotation is already in progress",
            {"field": "status", "status": item.status},
        )
    if item.status == VAULT_STATUS_CHECKED_OUT:
        raise ValidationFailed(
            "Revoke the checkout before rotating",
            {"field": "status", "status": item.status},
        )
    previous = item.status
    started = time.monotonic()
    config = _vault_config()

    # Mint + seal before any state change: a missing vault key must fail the
    # request without leaving the item stuck in `rotating`.
    plaintext = generate_secret(item.secret_type)
    blob = seal(plaintext, item.id, config)

    item.status = VAULT_STATUS_ROTATING
    db.session.flush()
    try:
        row = _store_secret(
            item, blob, source="generated", trigger=trigger, actor=actor
        )
        dependents = (
            _update_dependents(item, actor=actor, trigger=trigger)
            if cascade
            else {"considered": 0, "rotated": [], "skipped": []}
        )
        validation = _validate_stored_secret(item, plaintext, row, config=config)
        detail: Dict[str, Any] = {
            "trigger": trigger,
            "previous_status": previous,
            "interval_hours": item.rotation_interval_hours,
            "secret_version": row.version,
            "validation": validation,
            "dependents": dependents,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if session_ref:
            detail["session_ref"] = session_ref
        if extra_detail:
            detail.update(extra_detail)
        item.status = VAULT_STATUS_AVAILABLE
        item.last_rotated_at = datetime.now()
        item.checked_out_by = None
        item.checked_out_at = None
        _log_vault_event(item, VAULT_ACTION_ROTATED, actor, detail)
        db.session.commit()
        return item, detail
    except Exception as exc:
        _mark_rotation_failed(
            item, trigger=trigger, actor=actor, error=exc, session_ref=session_ref
        )
        if isinstance(exc, APIError):
            raise
        raise APIError(500, f"Rotation failed for '{item.name}': {exc}") from exc


def reveal_vault_secret(item_id: int, *, actor: str = "system") -> Dict[str, Any]:
    """Decrypt the current secret version for an admin reveal (route-gated).
    Every successful reveal is an audited event - without the secret."""
    item = get_vault_item(item_id)
    if not item.secret_version:
        raise NotFound("No stored secret for this credential (metadata-only record)")
    row = VaultSecretVersion.query.filter_by(
        item_id=item.id, version=item.secret_version
    ).first()
    if row is None:
        raise NotFound("No stored secret for this credential (metadata-only record)")
    config = _vault_config()
    plaintext = unseal(row.blob, item.id, config)
    _log_vault_event(
        item,
        VAULT_ACTION_REVEALED,
        actor,
        {"version": row.version, "source": row.source},
    )
    db.session.commit()
    return {
        "item_id": item.id,
        "item_name": item.name,
        "version": row.version,
        "secret": plaintext,
        "entropy_bits": approximate_entropy_bits(plaintext),
        "alg": (row.blob or {}).get("alg"),
        "source": row.source,
        "rotated_at": row.created_at.isoformat(),
    }


def run_rotations(
    payload: Any,
    *,
    actor: str,
    trigger: str = "bulk",
    include_failed: bool = True,
) -> Dict[str, Any]:
    """Run the rotation engine over due credentials (or explicit ids).

    `item_ids` absent = every credential whose SLA window has elapsed (plus
    failed ones when `include_failed`, so the screen's Retry semantics hold).
    With `cascade` (default) each rotation also updates its same-target
    dependents, and those are not rotated twice in one run.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    cascade = payload.get("cascade", True)
    if not isinstance(cascade, bool):
        raise ValidationFailed("'cascade' must be a boolean", {"field": "cascade"})

    raw_ids = payload.get("item_ids")
    if raw_ids is None:
        refresh_vault_statuses()
        wanted = [VAULT_STATUS_ROTATION_DUE]
        if include_failed:
            wanted.append(VAULT_STATUS_FAILED)
        targets = (
            VaultItem.query.filter(VaultItem.status.in_(wanted))
            .order_by(VaultItem.id.asc())
            .all()
        )
    else:
        if not isinstance(raw_ids, list) or not raw_ids:
            raise ValidationFailed(
                "'item_ids' must be a non-empty array of vault item ids",
                {"field": "item_ids"},
            )
        ids: List[int] = []
        for raw in raw_ids:
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValidationFailed(
                    "'item_ids' must contain integers only", {"field": "item_ids"}
                )
            ids.append(raw)
        missing = [
            item_id
            for item_id in ids
            if VaultItem.query.filter_by(id=item_id).first() is None
        ]
        if missing:
            raise ValidationFailed(
                "No vault item with id " + ", ".join(str(x) for x in missing),
                {"field": "item_ids", "missing": missing},
            )
        targets = [get_vault_item(item_id) for item_id in ids]

    processed: set = set()
    rotated: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    dependents_rotated = 0
    dependents_skipped: List[Dict[str, str]] = []

    for item in targets:
        if item.id in processed:
            continue
        target = item.target
        try:
            _, detail = rotate_vault_item(
                item.id, actor=actor, trigger=trigger, cascade=cascade
            )
            processed.add(item.id)
            dependents_rotated += len(detail["dependents"]["rotated"])
            dependents_skipped.extend(detail["dependents"]["skipped"])
            if cascade:
                # Dependents on this target were rotated (or legitimately
                # skipped) as part of this run — don't run them again.
                for (sibling_id,) in VaultItem.query.with_entities(
                    VaultItem.id
                ).filter(VaultItem.target == target):
                    processed.add(sibling_id)
            rotated.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "secret_version": detail["secret_version"],
                    "dependents": len(detail["dependents"]["rotated"]),
                }
            )
        except ValidationFailed as exc:
            processed.add(item.id)
            skipped.append({"id": item.id, "name": item.name, "reason": exc.message})
        except APIError as exc:
            processed.add(item.id)
            failed.append({"id": item.id, "name": item.name, "error": exc.message})

    refresh_vault_statuses()
    return {
        "trigger": trigger,
        "targets": len(targets),
        "rotated": rotated,
        "skipped": skipped,
        "failed": failed,
        "dependents_rotated": dependents_rotated,
        "dependents_skipped": dependents_skipped,
        "due_remaining": VaultItem.query.filter_by(
            status=VAULT_STATUS_ROTATION_DUE
        ).count(),
        "failed_remaining": VaultItem.query.filter_by(
            status=VAULT_STATUS_FAILED
        ).count(),
    }


def rotation_session_end(payload: Any, *, actor: str) -> Tuple[VaultItem, Dict[str, Any]]:
    """Event-based rotation (architecture 5): a checkout's session ended.

    Releases the checkout if one is held, then rotates the credential with
    `trigger=session_end` and updates its same-target dependents — the
    "checks out -> session ends -> rotate -> update dependents -> validate ->
    audit" flow, driven by the event instead of the clock.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    raw = payload.get("item_id")
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValidationFailed("'item_id' is required", {"field": "item_id"})
    session_ref = payload.get("session_id")
    if session_ref is not None:
        if not isinstance(session_ref, str) or not session_ref.strip():
            raise ValidationFailed(
                "'session_id' must be a non-empty string", {"field": "session_id"}
            )
        session_ref = session_ref.strip()[:64]

    item = get_vault_item(raw)
    released: Optional[Dict[str, Any]] = None
    if item.status == VAULT_STATUS_CHECKED_OUT:
        released = {
            "checked_out_by": item.checked_out_by,
            "reason": "session ended",
        }
        if session_ref:
            released["session_ref"] = session_ref
        item.status = VAULT_STATUS_AVAILABLE
        item.checked_out_by = None
        item.checked_out_at = None
        _log_vault_event(item, VAULT_ACTION_REVOKED, actor, released)

    return rotate_vault_item(
        item.id,
        actor=actor,
        trigger="session_end",
        session_ref=session_ref,
        cascade=True,
        extra_detail={"checkout_released": released is not None},
    )


def onboard_vault_item(payload: Any, *, actor: str) -> VaultItem:
    """Add a credential to the inventory after strict validation."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValidationFailed("'name' is required", {"field": "name"})
    name = name.strip()[:120]
    if VaultItem.query.filter_by(name=name).first() is not None:
        raise ValidationFailed(
            f"A credential named '{name}' already exists", {"field": "name"}
        )

    secret_type = payload.get("secret_type")
    if secret_type not in VAULT_TYPES:
        raise ValidationFailed(
            "'secret_type' must be one of the vault types",
            {"field": "secret_type", "allowed": list(VAULT_TYPES)},
        )

    def required_text(field: str, max_length: int) -> str:
        raw = payload.get(field)
        if not isinstance(raw, str) or not raw.strip():
            raise ValidationFailed(f"'{field}' is required", {"field": field})
        return raw.strip()[:max_length]

    target = required_text("target", 255)
    principal = required_text("principal", 128)

    interval = payload.get("rotation_interval_hours", 24)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 0 <= interval <= 8760:
        raise ValidationFailed(
            "'rotation_interval_hours' must be an integer between 0 and 8760",
            {"field": "rotation_interval_hours"},
        )

    tier = payload.get("access_tier", "Tier-2")
    if tier not in ("Tier-0", "Tier-1", "Tier-2"):
        raise ValidationFailed(
            "'access_tier' must be Tier-0, Tier-1 or Tier-2",
            {"field": "access_tier", "allowed": ["Tier-0", "Tier-1", "Tier-2"]},
        )

    auth_method = payload.get("auth_method", "Password")
    if not isinstance(auth_method, str) or not auth_method.strip():
        raise ValidationFailed("'auth_method' must be a non-empty string",
                               {"field": "auth_method"})
    auth_method = auth_method.strip()[:32]

    description = payload.get("description", "")
    target_detail = payload.get("target_detail", "")
    for field, value in (("description", description), ("target_detail", target_detail)):
        if not isinstance(value, str):
            raise ValidationFailed(f"'{field}' must be a string", {"field": field})

    now = datetime.now()
    item = VaultItem(
        name=name,
        secret_type=secret_type,
        description=description.strip()[:255],
        target=target,
        target_detail=target_detail.strip()[:255],
        principal=principal,
        access_tier=tier,
        auth_method=auth_method,
        rotation_interval_hours=interval,
        last_rotated_at=now,
        status=VAULT_STATUS_AVAILABLE,
    )
    db.session.add(item)
    db.session.flush()  # assign the id first: the secret AAD binds to it

    # Store the credential value: operator-supplied, or minted for the type.
    provided = payload.get("secret", None)
    if provided is not None and not isinstance(provided, str):
        raise ValidationFailed("'secret' must be a string", {"field": "secret"})
    if isinstance(provided, str):
        if not provided.strip():
            raise ValidationFailed(
                "'secret' must be a non-empty string", {"field": "secret"}
            )
        if len(provided) > 65536:
            raise ValidationFailed(
                "'secret' must be at most 65536 characters", {"field": "secret"}
            )
        plaintext, source = provided, "operator"
    else:
        plaintext, source = generate_secret(secret_type), "generated"
    blob = seal(plaintext, item.id, _vault_config())
    row = _store_secret(
        item, blob, source=source, trigger="onboarded", actor=actor
    )
    _validate_stored_secret(item, plaintext, row, config=_vault_config())

    _log_vault_event(
        item,
        VAULT_ACTION_ONBOARDED,
        actor,
        {"rotation_interval_hours": interval, "secret_source": source},
    )
    db.session.commit()
    return item


def vault_item_events(item_id: int, limit: int = 10) -> List[VaultEvent]:
    return (
        VaultEvent.query.filter_by(item_id=item_id)
        .order_by(VaultEvent.created_at.desc(), VaultEvent.id.desc())
        .limit(limit)
        .all()
    )


_VAULT_EVENT_ACTIONS = (
    VAULT_ACTION_ONBOARDED,
    VAULT_ACTION_CHECKED_OUT,
    VAULT_ACTION_REVOKED,
    VAULT_ACTION_ROTATED,
    VAULT_ACTION_ROTATION_FAILED,
)


def vault_events(limit: int = 20, *, action: Optional[str] = None) -> Dict[str, Any]:
    """Vault audit trail, newest first; optionally one action type."""
    query = VaultEvent.query
    if action is not None:
        if action not in _VAULT_EVENT_ACTIONS:
            raise ValidationFailed(
                f"Unknown vault action '{action}'",
                {"field": "action", "allowed": list(_VAULT_EVENT_ACTIONS)},
            )
        query = query.filter(VaultEvent.action == action)
    total = query.count()
    events = (
        query.order_by(VaultEvent.created_at.desc(), VaultEvent.id.desc())
        .limit(limit)
        .all()
    )
    payload: Dict[str, Any] = {
        "events": [event.to_dict() for event in events],
        "total": total,
        "limit": limit,
    }
    if action is not None:
        payload["action"] = action
    return payload


# ---------------------------------------------------------------------------
# JIT / JEA access (module 6: request -> risk -> approvals -> grant -> expiry)
# ---------------------------------------------------------------------------
# How many approvals each risk band demands (architecture: LOW allow,
# MEDIUM a manager sign-off, HIGH manager + security, CRITICAL block).
_JIT_REQUIRED_APPROVALS: Dict[str, Tuple[str, ...]] = {
    "low": (),
    "medium": ("manager",),
    "high": ("manager", "security"),
    "critical": (),
}
_TIER_POINTS = {"Tier-0": 30, "Tier-1": 15, "Tier-2": 0}
_JIT_MIN_MINUTES = 1
_JIT_MAX_MINUTES = 480
_JIT_TICKET_RE = re.compile(r"^[A-Za-z]{2,10}-\d{2,10}$")


def _jit_level(score: int) -> str:
    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def _jit_risk(
    item: VaultItem, requester: str, minutes: int, ticket: str, now: datetime
) -> Tuple[int, str, List[Dict[str, Any]]]:
    """Evaluate this request for real: every point traces to a measured input
    (target tier, requested duration, local clock, the requester's own
    24h history, ticket shape, credential health) - factors are returned so
    the console can show exactly why a decision came out the way it did."""
    factors: List[Dict[str, Any]] = []
    score = 0

    def add(name: str, points: int, detail: str) -> None:
        nonlocal score
        if points:
            factors.append({"factor": name, "points": points, "detail": detail})
            score += points

    add("target_tier", _TIER_POINTS.get(item.access_tier, 0), item.access_tier)
    duration = (
        20 if minutes > 120
        else 15 if minutes > 60
        else 10 if minutes > 30
        else 5 if minutes > 15
        else 0
    )
    add("duration", duration, f"{minutes} minutes requested")
    if now.weekday() >= 5 or now.hour < 8 or now.hour >= 18:
        add("off_hours", 20, now.strftime("%A %H:%M local"))
    prior = (
        JitRequest.query.filter(
            JitRequest.requester == requester,
            JitRequest.created_at >= now - timedelta(hours=24),
        )
        .count()
    )
    if prior:
        add(
            "repeat_requests",
            min(15, 5 * prior),
            f"{prior} request(s) by this requester in the last 24h",
        )
    if not _JIT_TICKET_RE.match(ticket or ""):
        add("ticket_shape", 10, "ticket is not an ITSM-style reference")
    if item.status == VAULT_STATUS_FAILED:
        add("credential_health", 10, "credential is in failed rotation state")
    return score, _jit_level(score), factors


def _log_jit_event(
    request: JitRequest, action: str, actor: str, detail: Optional[Dict[str, Any]] = None
) -> None:
    db.session.add(
        JitEvent(
            request_id=request.id,
            action=action,
            actor=actor,
            detail=detail or {},
        )
    )


def get_jit_request(request_id: int) -> JitRequest:
    request = JitRequest.query.filter_by(id=request_id).first()
    if request is None:
        raise NotFound(f"No JIT request with id {request_id}")
    return request


def create_jit_request(payload: Any, *, actor: str) -> JitRequest:
    """File one access request: validates context, evaluates risk against the
    real clock/history and lands in the state that risk implies."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    item_id = payload.get("item_id")
    if isinstance(item_id, bool) or not isinstance(item_id, int):
        raise ValidationFailed("'item_id' is required", {"field": "item_id"})
    item = get_vault_item(item_id)

    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValidationFailed("'reason' is required", {"field": "reason"})
    reason = reason.strip()[:255]
    if len(reason) < 8:
        raise ValidationFailed(
            "'reason' must be at least 8 characters", {"field": "reason"}
        )
    ticket = payload.get("ticket")
    if not isinstance(ticket, str) or not ticket.strip():
        raise ValidationFailed(
            "'ticket' is required (an ITSM reference such as INC-23891)",
            {"field": "ticket"},
        )
    ticket = ticket.strip()[:64]
    minutes = payload.get("minutes", 15)
    if (
        isinstance(minutes, bool)
        or not isinstance(minutes, int)
        or not _JIT_MIN_MINUTES <= minutes <= _JIT_MAX_MINUTES
    ):
        raise ValidationFailed(
            f"'minutes' must be an integer between {_JIT_MIN_MINUTES} and {_JIT_MAX_MINUTES}",
            {"field": "minutes", "min": _JIT_MIN_MINUTES, "max": _JIT_MAX_MINUTES},
        )
    requester = payload.get("requester") or actor
    if not isinstance(requester, str) or not requester.strip():
        raise ValidationFailed(
            "'requester' must be a non-empty string", {"field": "requester"}
        )
    requester = requester.strip()[:64]

    score, level, factors = _jit_risk(item, requester, minutes, ticket, datetime.now())
    required = _JIT_REQUIRED_APPROVALS[level]
    if level == "critical":
        status = "blocked"
    elif not required:
        status = "approved"  # low risk: policy grants without sign-off
    else:
        status = "pending"

    request = JitRequest(
        item_id=item.id,
        requester=requester,
        reason=reason,
        ticket=ticket,
        minutes=minutes,
        risk_score=score,
        risk_level=level,
        risk_factors=factors,
        status=status,
    )
    db.session.add(request)
    db.session.flush()
    _log_jit_event(
        request,
        "requested",
        actor,
        {
            "risk_score": score,
            "risk_level": level,
            "required_approvals": list(required),
            "minutes": minutes,
        },
    )
    if status == "approved":
        _log_jit_event(
            request,
            "approved",
            "risk-policy",
            {"auto": True, "reason": f"low risk (score {score}) - no sign-off required"},
        )
    elif status == "blocked":
        _log_jit_event(
            request,
            "blocked",
            "risk-policy",
            {"risk_score": score, "reason": "critical risk - policy blocks this request"},
        )
    db.session.commit()
    return request


def approve_jit_request(
    request_id: int, *, actor: str, payload: Any
) -> JitRequest:
    request = get_jit_request(request_id)
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    role = payload.get("role")
    if role not in JIT_ROLES:
        raise ValidationFailed(
            "'role' must be 'manager' or 'security'",
            {"field": "role", "allowed": list(JIT_ROLES)},
        )
    if request.status == "blocked":
        raise ValidationFailed(
            "Risk is critical: policy blocks this request (deny it instead)",
            {"field": "status", "status": request.status},
        )
    if request.status != "pending":
        raise ValidationFailed(
            f"Request is {request.status}, not awaiting approvals",
            {"field": "status", "status": request.status},
        )
    if actor == request.requester:
        raise APIError(403, "Requesters cannot approve their own access")
    required = _JIT_REQUIRED_APPROVALS[request.risk_level]
    if role not in required:
        raise ValidationFailed(
            f"{request.risk_level} risk does not require {role} approval",
            {"field": "role", "required": list(required)},
        )
    snapshot = {"actor": actor, "at": datetime.now().isoformat(), "role": role}
    if role == "manager":
        if request.manager_approval:
            raise ValidationFailed("Manager approval already recorded", {"field": "role"})
        request.manager_approval = snapshot
    else:
        if request.security_approval:
            raise ValidationFailed("Security approval already recorded", {"field": "role"})
        request.security_approval = snapshot
    _log_jit_event(request, "approved", actor, {"role": role})
    recorded = {
        role_name
        for role_name, snapshot in (
            ("manager", request.manager_approval),
            ("security", request.security_approval),
        )
        if snapshot
    }
    if set(required) <= recorded:
        request.status = "approved"
    db.session.commit()
    return request


def deny_jit_request(request_id: int, *, actor: str, payload: Any) -> JitRequest:
    request = get_jit_request(request_id)
    if request.status not in ("pending", "blocked"):
        raise ValidationFailed(
            f"Request is {request.status} and cannot be denied",
            {"field": "status", "status": request.status},
        )
    detail: Dict[str, Any] = {}
    if isinstance(payload, dict):
        note = payload.get("reason")
        if note is not None:
            if not isinstance(note, str) or not note.strip():
                raise ValidationFailed(
                    "'reason' must be a non-empty string when present",
                    {"field": "reason"},
                )
            detail["reason"] = note.strip()[:255]
    elif payload is not None:
        raise ValidationFailed("Request body must be a JSON object")
    request.status = "denied"
    _log_jit_event(request, "denied", actor, detail)
    db.session.commit()
    return request


def consume_jit_request(request_id: int, *, actor: str) -> JitRequest:
    """Grant the access: check the credential out under the requester for the
    requested window (session_ref = jit-<id>), so expiry can find it again."""
    request = get_jit_request(request_id)
    if request.status != "approved":
        raise ValidationFailed(
            f"Request is {request.status}; only an approved request can be granted",
            {"field": "status", "status": request.status},
        )
    checkout_vault_item(
        request.item_id,
        actor=request.requester,
        reason=f"JIT request #{request.id} ({request.ticket})",
    )
    now = datetime.now()
    request.status = "active"
    request.granted_at = now
    request.expires_at = now + timedelta(minutes=request.minutes)
    request.session_ref = f"jit-{request.id}"
    _log_jit_event(
        request,
        "granted",
        actor,
        {
            "session_ref": request.session_ref,
            "minutes": request.minutes,
            "expires_at": request.expires_at.isoformat(),
        },
    )
    db.session.commit()
    return request


def _end_jit_grant(request: JitRequest, *, actor: str, action: str) -> JitRequest:
    """Shared close/expiry path: release our checkout, then rotate the
    credential (architecture: session ends -> rotate -> audit)."""
    item = get_vault_item(request.item_id)
    detail: Dict[str, Any] = {"session_ref": request.session_ref}
    try:
        if item.status == VAULT_STATUS_CHECKED_OUT and item.checked_out_by == request.requester:
            _, rotation = rotation_session_end(
                {"item_id": item.id, "session_id": request.session_ref}, actor=actor
            )
            detail["checkout_released"] = True
        else:
            _, rotation = rotate_vault_item(
                item.id,
                actor=actor,
                trigger="session_end",
                session_ref=request.session_ref,
            )
            detail["checkout_released"] = False
        detail["rotated"] = True
        detail["secret_version"] = rotation["secret_version"]
    except APIError as exc:
        # The credential may be held by someone else or mid-rotation; the
        # grant still ends, and the reason is recorded instead of hidden.
        detail["rotated"] = False
        detail["rotation_error"] = exc.message
    request.status = "expired" if action == "expired" else "closed"
    request.closed_at = datetime.now()
    _log_jit_event(request, action, actor, detail)
    # a live session riding this grant ends with it (one cascade, one commit)
    _end_sessions_for_grant(request, actor=actor, action=action)
    db.session.commit()
    return request


def refresh_jit_requests() -> int:
    """Evaluate the real clock over active grants: elapsed windows end the
    access and rotate the credential. Called from every JIT read and from
    scheduler ticks, so expiry never depends on someone remembering."""
    now = datetime.now()
    expired = 0
    for request in JitRequest.query.filter_by(status="active").all():
        if request.expires_at is not None and request.expires_at <= now:
            _end_jit_grant(request, actor="system", action="expired")
            expired += 1
    return expired


def close_jit_request(request_id: int, *, actor: str) -> JitRequest:
    request = get_jit_request(request_id)
    if request.status != "active":
        raise ValidationFailed(
            f"Request is {request.status}; only an active grant can be closed",
            {"field": "status", "status": request.status},
        )
    return _end_jit_grant(request, actor=actor, action="closed")


def list_jit_requests(
    *,
    status: Optional[str] = None,
    requester: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[JitRequest], int]:
    if status is not None and status not in JIT_STATUSES:
        raise ValidationFailed(
            f"Unknown JIT status '{status}'",
            {"field": "status", "allowed": list(JIT_STATUSES)},
        )
    refresh_jit_requests()
    query = JitRequest.query
    if status:
        query = query.filter(JitRequest.status == status)
    if requester:
        query = query.filter(JitRequest.requester.ilike(f"%{requester}%"))
    total = query.count()
    items = (
        query.order_by(JitRequest.id.desc()).limit(limit).offset(offset).all()
    )
    return items, total


def jit_request_detail(request_id: int) -> Dict[str, Any]:
    refresh_jit_requests()
    request = get_jit_request(request_id)
    events = (
        JitEvent.query.filter_by(request_id=request.id)
        .order_by(JitEvent.created_at.desc(), JitEvent.id.desc())
        .all()
    )
    return {"request": request.to_dict(), "events": [event.to_dict() for event in events]}


def jit_stats() -> Dict[str, Any]:
    """Real queue counts; nothing is precomputed or invented."""
    refresh_jit_requests()
    by_status = {
        status: JitRequest.query.filter_by(status=status).count()
        for status in JIT_STATUSES
    }
    by_risk = {
        level: JitRequest.query.filter_by(risk_level=level).count()
        for level in ("low", "medium", "high", "critical")
    }
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "by_risk": by_risk,
        "active": by_status["active"],
        "pending": by_status["pending"],
    }


# ---------------------------------------------------------------------------
# privileged session management (module 8: record -> monitor -> control)
# ---------------------------------------------------------------------------
SESSION_CONTROL_FIELDS = (
    "record",
    "keystroke_log",
    "watermark",
    "clipboard_allowed",
    "upload_allowed",
    "download_allowed",
    "screenshot_allowed",
)
# content events are capped so one recording can never blow up the store
_MAX_EVENT_CONTENT = 4096


def get_privileged_session(session_id: int) -> PrivilegedSession:
    """Fetch one session row or raise 404."""
    session = PrivilegedSession.query.filter_by(id=session_id).first()
    if session is None:
        raise NotFound(f"No session with id {session_id}")
    return session


def _next_session_seq(session_id: int) -> int:
    # append-only table (rows are never deleted) -> count + 1 is stable
    return SessionEvent.query.filter_by(session_id=session_id).count() + 1


def _session_watermark(session: PrivilegedSession, actor: str) -> str:
    return f"{session.session_ref} | {actor} | {datetime.now().isoformat(timespec='seconds')}"


def _append_session_status(
    session: PrivilegedSession, *, actor: str, content: str
) -> SessionEvent:
    """Server-written lifecycle marker so playback shows every control action."""
    event = SessionEvent(
        session_id=session.id,
        seq=_next_session_seq(session.id),
        type="status",
        content=content,
        actor=actor,
        watermark=_session_watermark(session, actor) if session.watermark else None,
    )
    db.session.add(event)
    return event


def create_session(
    payload: Any, *, actor: str
) -> Tuple[PrivilegedSession, RiskEvent]:
    """Start a privileged session: protocol + target, optionally against a
    vault credential (checked out for the session) or riding an active JIT
    grant (attached, no second checkout).

    The request is scored first (architecture section 7): CRITICAL is
    refused, HIGH needs the approval an active JIT grant represents and
    MEDIUM needs a valid TOTP code when a factor is enrolled (section 20,
    threaded through as `mfa_code`), and the evaluation is recorded either
    way.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    protocol = payload.get("protocol")
    if not isinstance(protocol, str) or protocol.strip().lower() not in SESSION_PROTOCOLS:
        raise ValidationFailed(
            "Unknown protocol",
            {"field": "protocol", "allowed": list(SESSION_PROTOCOLS)},
        )
    protocol = protocol.strip().lower()

    target = payload.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValidationFailed("'target' is required", {"field": "target"})
    target = target.strip()
    if len(target) > 255:
        raise ValidationFailed(
            "'target' must be at most 255 characters", {"field": "target"}
        )

    def _opt_int(field: str) -> Optional[int]:
        if field not in payload or payload[field] is None:
            return None
        raw = payload[field]
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValidationFailed(f"'{field}' must be an integer id", {"field": field})
        return raw

    item_id = _opt_int("item_id")
    jit_request_id = _opt_int("jit_request_id")

    controls: Dict[str, Any] = {}
    for key in SESSION_CONTROL_FIELDS:
        if key in payload:
            value = payload[key]
            if not isinstance(value, bool):
                raise ValidationFailed(
                    f"'{key}' must be true or false", {"field": key}
                )
            controls[key] = value

    grant: Optional[JitRequest] = None
    if jit_request_id is not None:
        grant = get_jit_request(jit_request_id)  # 404 for unknown ids
        if grant.status != "active":
            raise ValidationFailed(
                f"Request is {grant.status}; a session needs an active grant",
                {"field": "jit_request_id", "status": grant.status},
            )
        if item_id is not None and item_id != grant.item_id:
            raise ValidationFailed(
                "item_id does not match the credential this grant checks out",
                {"field": "item_id", "expected": grant.item_id},
            )
        item_id = grant.item_id
        live = (
            PrivilegedSession.query.filter_by(jit_request_id=grant.id)
            .filter(~PrivilegedSession.status.in_(SESSION_TERMINAL_STATUSES))
            .first()
        )
        if live is not None:
            raise Conflict(
                "This grant already has a live session",
                {"field": "jit_request_id", "session_id": live.id},
            )

    own_checkout = False
    if item_id is not None:
        item = get_vault_item(item_id)  # 404 for unknown ids
        if grant is None:
            if item.status == VAULT_STATUS_CHECKED_OUT:
                raise Conflict(
                    "Credential is already checked out",
                    {"field": "status", "status": item.status},
                )
            if item.status == VAULT_STATUS_ROTATING:
                raise Conflict(
                    "Rotation is in progress",
                    {"field": "status", "status": item.status},
                )
            own_checkout = True

    # architecture section 7: score this request before it runs. The band
    # drives policy - CRITICAL is refused outright, HIGH needs the approval
    # of an active JIT grant, MEDIUM needs a valid TOTP code when a factor
    # is enrolled (section 20) - and the evaluation commits on its own so a
    # refusal is still recorded (SOC evidence in the audit ledger).
    risk = evaluate_risk(
        {
            "subject": actor,
            "target": target,
            "device": payload.get("device"),
            "source_ip": payload.get("source_ip"),
            "mfa_code": payload.get("mfa_code"),
        },
        actor=actor,
        context=RISK_CONTEXT_SESSION_START,
        approved_grant=grant,
    )
    if risk.result == "refused":
        details: Dict[str, Any] = {"risk": risk.to_dict()}
        if risk.decision == "mfa":
            # the medium band refused through the factor gate: name why
            # (same pure check the evaluator ran, moments ago)
            _passed, _outcome, reason = _mfa_gate(payload.get("mfa_code"))
            details["mfa"] = reason
        if risk.band == "critical" and _evaluation_reasons(risk):
            # section 11: a critical *deviation* runs the response chain -
            # end the principal's other active sessions (release-and-rotate),
            # rotate the credential this request sought, record the incident
            details["anomaly"] = _anomaly_response(
                risk, actor=actor, item_id=item_id
            )
        raise APIError(
            403,
            "Risk policy refuses this session start",
            details,
        )

    session = PrivilegedSession(
        session_ref=f"sess-{secrets.token_hex(4)}",
        protocol=protocol,
        target=target,
        actor=actor,
        item_id=item_id,
        jit_request_id=grant.id if grant is not None else None,
        **controls,
    )
    db.session.add(session)
    try:
        db.session.flush()  # assign the id before the status event references it
        _append_session_status(session, actor=actor, content="session started")
        if own_checkout:
            # commits session + status event together with the checkout
            checkout_vault_item(
                item_id, actor=actor, reason=f"session {session.session_ref}"
            )
        else:
            db.session.commit()
    except APIError:
        db.session.rollback()
        raise
    return session, risk


def list_sessions(
    *,
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[PrivilegedSession], int]:
    """Live monitoring list (filters + pagination), newest first."""
    refresh_jit_requests()  # a linked grant may have expired -> session ended
    if status is not None and status not in SESSION_STATUSES:
        raise ValidationFailed(
            f"Unknown status '{status}'",
            {"field": "status", "allowed": list(SESSION_STATUSES)},
        )
    if protocol is not None and protocol not in SESSION_PROTOCOLS:
        raise ValidationFailed(
            f"Unknown protocol '{protocol}'",
            {"field": "protocol", "allowed": list(SESSION_PROTOCOLS)},
        )
    query = PrivilegedSession.query
    if status is not None:
        query = query.filter_by(status=status)
    if protocol is not None:
        query = query.filter_by(protocol=protocol)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(
            db.or_(
                PrivilegedSession.target.ilike(pattern),
                PrivilegedSession.actor.ilike(pattern),
                PrivilegedSession.session_ref.ilike(pattern),
            )
        )
    total = query.count()
    items = (
        query.order_by(PrivilegedSession.id.desc()).limit(limit).offset(offset).all()
    )
    return items, total


def session_detail(session_id: int) -> Dict[str, Any]:
    """One session with its latest recorded events and real counters."""
    refresh_jit_requests()
    session = get_privileged_session(session_id)
    events = (
        SessionEvent.query.filter_by(session_id=session.id)
        .order_by(SessionEvent.id.desc())
        .limit(20)
        .all()
    )
    total = SessionEvent.query.filter_by(session_id=session.id).count()
    blocked = SessionEvent.query.filter_by(
        session_id=session.id, allowed=False
    ).count()
    return {
        "session": session.to_dict(),
        "events": [event.to_dict() for event in events],
        "event_count": total,
        "blocked_count": blocked,
    }


def session_stats() -> Dict[str, Any]:
    """Real monitoring aggregates over the session and recording tables."""
    refresh_jit_requests()
    by_status = {
        value: PrivilegedSession.query.filter_by(status=value).count()
        for value in SESSION_STATUSES
    }
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "active": by_status["active"],
        "paused": by_status["paused"],
        "locked": by_status["locked"],
        "ended": by_status["terminated"] + by_status["completed"],
        "events_total": SessionEvent.query.count(),
        "events_blocked": SessionEvent.query.filter_by(allowed=False).count(),
        "events_withheld": SessionEvent.query.filter_by(withheld=True).count(),
    }


def list_session_events(
    session_id: int,
    *,
    limit: int = 500,
    offset: int = 0,
    event_type: Optional[str] = None,
    order: str = "asc",
) -> Tuple[List[SessionEvent], int]:
    """Playback: the recording in sequence order (desc for live tails)."""
    session = get_privileged_session(session_id)
    if event_type is not None and event_type not in SESSION_EVENT_TYPES:
        raise ValidationFailed(
            f"Unknown event type '{event_type}'",
            {"field": "type", "allowed": list(SESSION_EVENT_TYPES)},
        )
    if order not in ("asc", "desc"):
        raise ValidationFailed(
            f"Unknown order '{order}'", {"field": "order", "allowed": ["asc", "desc"]}
        )
    query = SessionEvent.query.filter_by(session_id=session.id)
    if event_type is not None:
        query = query.filter_by(type=event_type)
    total = query.count()
    if order == "desc":
        rows = (
            query.order_by(SessionEvent.seq.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
    else:
        rows = (
            query.order_by(SessionEvent.seq.asc())
            .limit(limit)
            .offset(offset)
            .all()
        )
    return rows, total


def post_session_event(
    session_id: int, payload: Any, *, actor: str
) -> Tuple[SessionEvent, Optional[Dict[str, Any]]]:
    """Record one channel event. Controls are enforced for real: a gated-off
    transfer/clipboard/screenshot is stored with allowed=false as evidence,
    keystrokes are content-withheld when logging is off, and a paused/locked/
    ended session refuses events outright. `command` rows are additionally run
    through command control (module 9): the matched rule decides allow /
    approval-hold / block, and an escalated block raises its incident and
    terminates the session - returned as the second value."""
    session = get_privileged_session(session_id)
    if session.status in SESSION_TERMINAL_STATUSES:
        raise Conflict(
            f"Session already {session.status}",
            {"field": "status", "status": session.status},
        )
    if session.status in ("paused", "locked"):
        raise Conflict(
            f"Session is {session.status}; resume it before posting events",
            {"field": "status", "status": session.status},
        )
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    event_type = payload.get("type")
    if not isinstance(event_type, str) or event_type not in SESSION_EVENT_TYPES:
        raise ValidationFailed(
            "Unknown event type",
            {"field": "type", "allowed": list(SESSION_EVENT_TYPES)},
        )
    content = payload.get("content")
    if content is None:
        content = ""
    if not isinstance(content, str):
        raise ValidationFailed("'content' must be a string", {"field": "content"})
    if len(content) > _MAX_EVENT_CONTENT:
        raise ValidationFailed(
            f"'content' must be at most {_MAX_EVENT_CONTENT} characters",
            {"field": "content"},
        )
    # the safety channel is never silenced by the recording flag
    if event_type not in ("command", "status") and not session.record:
        raise ValidationFailed(
            "Recording is off for this session; content events are refused",
            {"field": "type", "record": False},
        )
    allowed = True
    blocked_reason = None
    withheld = False
    stored = content
    gates = {
        "file_upload": (session.upload_allowed, "upload_not_allowed"),
        "file_download": (session.download_allowed, "download_not_allowed"),
        "clipboard": (session.clipboard_allowed, "clipboard_not_allowed"),
        "screenshot": (session.screenshot_allowed, "screenshot_not_allowed"),
    }
    if event_type in gates:
        gate_ok, why = gates[event_type]
        if not gate_ok:
            # keep the attempt as evidence, marked as blocked
            allowed = False
            blocked_reason = why
    if event_type == "keystroke" and not session.keystroke_log:
        # policy says do not capture: the row records that input happened,
        # never what was typed
        withheld = True
        stored = None
    decision = None
    rule_id = None
    verdict = None
    if event_type == "command":
        # command control (module 9): the policy decides before the row lands
        verdict = evaluate_command(content, session.target)
        decision = verdict["decision"]
        rule_id = verdict["rule"]["id"] if verdict["rule"] else None
        if decision == "approval":
            allowed = False
            blocked_reason = "approval_required"
        elif decision == "block":
            allowed = False
            blocked_reason = "command_blocked"
    event = SessionEvent(
        session_id=session.id,
        seq=_next_session_seq(session.id),
        type=event_type,
        content=stored,
        allowed=allowed,
        blocked_reason=blocked_reason,
        withheld=withheld,
        decision=decision,
        rule_id=rule_id,
        watermark=_session_watermark(session, actor) if session.watermark else None,
        actor=actor,
    )
    db.session.add(event)
    db.session.flush()
    escalation = None
    if verdict is not None and verdict["terminate"]:
        escalation = _escalate_blocked_command(
            session, event, verdict, actor=actor
        )
    db.session.commit()
    return event, escalation


def update_session_controls(
    session_id: int, payload: Any, *, actor: str
) -> PrivilegedSession:
    """Flip control flags on a live session (audited as a status event)."""
    session = get_privileged_session(session_id)
    if session.status in SESSION_TERMINAL_STATUSES:
        raise ValidationFailed(
            f"Session already {session.status}",
            {"field": "status", "status": session.status},
        )
    if not isinstance(payload, dict) or not payload:
        raise ValidationFailed(
            "Request body must set at least one control", {"field": "controls"}
        )
    changed = []
    for key, value in payload.items():
        if key not in SESSION_CONTROL_FIELDS:
            raise ValidationFailed(
                f"Unknown control '{key}'",
                {"field": key, "allowed": list(SESSION_CONTROL_FIELDS)},
            )
        if not isinstance(value, bool):
            raise ValidationFailed(f"'{key}' must be true or false", {"field": key})
        setattr(session, key, value)
        changed.append(f"{key}={'on' if value else 'off'}")
    _append_session_status(
        session, actor=actor, content="controls updated: " + ", ".join(changed)
    )
    db.session.commit()
    return session


def _session_transition(
    session_id: int, *, actor: str, action: str
) -> PrivilegedSession:
    """pause / lock / resume — each transition is validated and recorded."""
    session = get_privileged_session(session_id)
    if session.status in SESSION_TERMINAL_STATUSES:
        raise ValidationFailed(
            f"Session already {session.status}",
            {"field": "status", "status": session.status},
        )
    if action == "pause":
        if session.status != "active":
            raise ValidationFailed(
                "Only an active session can be paused",
                {"field": "status", "status": session.status},
            )
        session.status = "paused"
        label = "session paused"
    elif action == "lock":
        if session.status not in ("active", "paused"):
            raise ValidationFailed(
                "Only a running or paused session can be locked",
                {"field": "status", "status": session.status},
            )
        session.status = "locked"
        label = "session locked"
    else:  # resume
        if session.status not in ("paused", "locked"):
            raise ValidationFailed(
                "Only a paused or locked session can be resumed",
                {"field": "status", "status": session.status},
            )
        session.status = "active"
        label = "session resumed"
    _append_session_status(session, actor=actor, content=label)
    db.session.commit()
    return session


def pause_session(session_id: int, *, actor: str) -> PrivilegedSession:
    return _session_transition(session_id, actor=actor, action="pause")


def lock_session(session_id: int, *, actor: str) -> PrivilegedSession:
    return _session_transition(session_id, actor=actor, action="lock")


def resume_session(session_id: int, *, actor: str) -> PrivilegedSession:
    return _session_transition(session_id, actor=actor, action="resume")


def end_session(
    session_id: int,
    *,
    actor: str,
    outcome: str = "terminated",
    payload: Any = None,
) -> Tuple[PrivilegedSession, Dict[str, Any]]:
    """Stop a session (kill switch or natural completion). If it holds a
    vault checkout or rides a JIT grant, the release-and-rotate cascade runs
    exactly once."""
    if outcome not in SESSION_TERMINAL_STATUSES:
        raise ValidationFailed(
            f"Unknown outcome '{outcome}'",
            {"field": "outcome", "allowed": list(SESSION_TERMINAL_STATUSES)},
        )
    reason = None
    if payload is not None:
        if not isinstance(payload, dict):
            raise ValidationFailed("Request body must be a JSON object")
        reason = payload.get("reason")
        if reason is not None:
            if not isinstance(reason, str):
                raise ValidationFailed(
                    "'reason' must be a string", {"field": "reason"}
                )
            if len(reason) > 500:
                raise ValidationFailed(
                    "'reason' must be at most 500 characters", {"field": "reason"}
                )
    session = get_privileged_session(session_id)
    if session.status in SESSION_TERMINAL_STATUSES:
        raise ValidationFailed(
            f"Session already {session.status}",
            {"field": "status", "status": session.status},
        )
    content = f"session {outcome}"
    if reason:
        content += f": {reason}"
    session.status = outcome
    session.ended_at = datetime.now()
    session.end_reason = outcome
    _append_session_status(session, actor=actor, content=content)

    detail: Dict[str, Any] = {
        "session_ref": session.session_ref,
        "outcome": outcome,
        "rotated": False,
        "checkout_released": False,
    }

    grant = None
    if session.jit_request_id is not None:
        grant = JitRequest.query.filter_by(id=session.jit_request_id).first()
    if grant is not None and grant.status == "active":
        # closing the grant releases + rotates once; its hook then sees this
        # session is already terminal and leaves it alone
        close_jit_request(grant.id, actor=actor)
        last = (
            JitEvent.query.filter_by(request_id=grant.id)
            .order_by(JitEvent.id.desc())
            .first()
        )
        detail["grant_closed"] = True
        detail["rotated"] = bool(last and last.detail.get("rotated"))
        detail["checkout_released"] = bool(
            last and last.detail.get("checkout_released")
        )
        if last and last.detail.get("secret_version") is not None:
            detail["secret_version"] = last.detail["secret_version"]
        _append_session_status(
            session,
            actor=actor,
            content=f"JIT grant #{grant.id} closed with the session",
        )
    elif session.item_id is not None:
        item = VaultItem.query.filter_by(id=session.item_id).first()
        if (
            item is not None
            and item.status == VAULT_STATUS_CHECKED_OUT
            and item.checked_out_by == session.actor
        ):
            try:
                _, rotation = rotation_session_end(
                    {"item_id": item.id, "session_id": session.session_ref},
                    actor=actor,
                )
                detail["checkout_released"] = True
                detail["rotated"] = True
                detail["secret_version"] = rotation.get("secret_version")
                _append_session_status(
                    session,
                    actor=actor,
                    content="checkout released; credential rotated",
                )
            except APIError as exc:
                # still end the session; the real reason is recorded, not hidden
                detail["checkout_released"] = False
                detail["rotated"] = False
                detail["rotation_error"] = exc.message
                _append_session_status(
                    session, actor=actor, content=f"rotation not run: {exc.message}"
                )
        else:
            # nothing held (bare session or checkout already revoked)
            detail["rotated"] = False
            detail["checkout_released"] = False
    db.session.commit()
    return session, detail


def _end_sessions_for_grant(
    request: JitRequest, *, actor: str, action: str
) -> None:
    """Called from the JIT grant end path: any live session riding that grant
    ends with it — no second cascade, the grant path already rotated."""
    live = (
        PrivilegedSession.query.filter_by(jit_request_id=request.id)
        .filter(~PrivilegedSession.status.in_(SESSION_TERMINAL_STATUSES))
        .all()
    )
    for session in live:
        session.status = "terminated"
        session.ended_at = datetime.now()
        session.end_reason = "grant_expired" if action == "expired" else "grant_closed"
        _append_session_status(
            session,
            actor=actor,
            content=f"access grant ended ({action}); session terminated with it",
        )


# ---------------------------------------------------------------------------
# command control (module 9: dangerous-command policy + escalation)
# ---------------------------------------------------------------------------
# Shipped default policy = the architecture document's section 9 table:
# known-benign commands ALLOW, privileged mutations APPROVAL, destructive
# commands BLOCK - plus the rest of its dangerous-command list as BLOCK and
# the context-aware production escalation from its worked example. Patterns
# match case-insensitively anywhere in the command line (a deliberately
# simple deterministic engine): evaluation order is block -> approval ->
# allow; within an action the target-scoped rule wins, then the longer
# pattern, then the lowest id. No rule matched -> default allow.
# (name, pattern, action, target_pattern, terminate_on_match, description)
DEFAULT_COMMAND_RULES: Tuple[Tuple[str, str, str, str, bool, str], ...] = (
    ("Allow file listing", "ls", "allow", "", False,
     "Architecture 9 policy table: ls is allowed"),
    ("Allow disk usage report", "df -h", "allow", "", False,
     "Architecture 9 policy table: df -h is allowed"),
    ("Allow service status", "systemctl status", "allow", "", False,
     "Architecture 9 policy table: systemctl status is allowed"),
    ("Service restart needs approval", "systemctl restart", "approval", "",
     False, "Architecture 9 policy table: systemctl restart requires approval"),
    ("User creation needs approval", "useradd", "approval", "", False,
     "Architecture 9 policy table: useradd requires approval"),
    ("Password change needs approval", "passwd", "approval", "", False,
     "Architecture 9 policy table: passwd requires approval"),
    ("Recursive delete blocked", "rm -rf", "block", "", False,
     "Architecture 9 dangerous command list: rm -rf"),
    ("Database drop blocked", "DROP DATABASE", "block", "", False,
     "Architecture 9 dangerous command list: DROP DATABASE"),
    ("Firewall flush blocked", "iptables -F", "block", "", False,
     "Architecture 9 policy table: iptables -F is blocked"),
    ("Shutdown blocked", "shutdown", "block", "", False,
     "Architecture 9 dangerous command list: shutdown"),
    ("Reboot blocked", "reboot", "block", "", False,
     "Architecture 9 dangerous command list: reboot"),
    ("World-writable chmod blocked", "chmod 777", "block", "", False,
     "Architecture 9 dangerous command list: chmod 777"),
    ("Service stop blocked", "systemctl stop", "block", "", False,
     "Architecture 9 dangerous command list: systemctl stop"),
    ("Table truncate blocked", "TRUNCATE", "block", "", False,
     "Architecture 9 dangerous command list: TRUNCATE"),
    ("Production database drop kills the session", "DROP DATABASE", "block",
     "prod-*", True,
     "Architecture 9 context-aware example: production target -> block, "
     "terminate the session, raise the incident, preserve the evidence"),
)
COMMAND_RULE_ORDER = {"block": 0, "approval": 1, "allow": 2}


def ensure_command_rules() -> int:
    """Seed the shipped section-9 policy once (empty table only).

    Returns the number of rows added (0 when the policy already exists, so a
    deletion an admin made stays deleted).
    """
    if CommandRule.query.count() > 0:
        return 0
    now = datetime.now()
    for name, pattern, action, target, terminate, description in DEFAULT_COMMAND_RULES:
        db.session.add(
            CommandRule(
                name=name,
                pattern=pattern,
                action=action,
                target_pattern=target,
                terminate_on_match=terminate,
                description=description,
                created_at=now,
                updated_at=now,
            )
        )
    db.session.commit()
    return len(DEFAULT_COMMAND_RULES)


def _rule_order_key(rule: CommandRule) -> Tuple[int, int, int, int]:
    # security first (block > approval > allow), then target-scoped rules,
    # then the longer (more specific) pattern, then the stable id
    return (
        COMMAND_RULE_ORDER[rule.action],
        0 if rule.target_pattern else 1,
        -len(rule.pattern),
        rule.id,
    )


def _rule_matches(rule: CommandRule, command: str, target: str) -> bool:
    if rule.pattern.lower() not in command.lower():
        return False
    if rule.target_pattern and not fnmatch.fnmatchcase(
        (target or "").lower(), rule.target_pattern.lower()
    ):
        return False
    return True


def evaluate_command(command: str, target: str = "") -> Dict[str, Any]:
    """Deterministic policy decision for one command line (architecture 9):
    the first matching rule in evaluation order decides; no match -> default
    allow (this engine flags known-dangerous commands, it does not whitelist
    every safe command)."""
    rules = [r for r in CommandRule.query.filter_by(enabled=True).all()]
    rules.sort(key=_rule_order_key)
    for rule in rules:
        if _rule_matches(rule, command, target):
            return {
                "decision": rule.action,
                "matched": True,
                "terminate": bool(rule.terminate_on_match and rule.action == "block"),
                "rule": rule.to_dict(),
                "default": False,
            }
    return {
        "decision": "allow",
        "matched": False,
        "terminate": False,
        "rule": None,
        "default": True,
    }


def _rule_match_counts(*, blocked_only: bool = False) -> Dict[int, int]:
    query = db.session.query(
        SessionEvent.rule_id, db.func.count(SessionEvent.id)
    ).filter(SessionEvent.rule_id.isnot(None))
    if blocked_only:
        query = query.filter(SessionEvent.decision == "block")
    return {
        int(rule_id): int(count)
        for rule_id, count in query.group_by(SessionEvent.rule_id).all()
    }


def list_command_rules(
    *, action: Optional[str] = None, q: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Every rule in evaluation order, each with its real match count."""
    if action is not None and action not in COMMAND_ACTIONS:
        raise ValidationFailed(
            f"Unknown action '{action}'",
            {"field": "action", "allowed": list(COMMAND_ACTIONS)},
        )
    rules = CommandRule.query.all()
    if action is not None:
        rules = [r for r in rules if r.action == action]
    if enabled is not None:
        rules = [r for r in rules if r.enabled is bool(enabled)]
    if q:
        needle = q.strip().lower()
        rules = [
            r for r in rules
            if needle in " ".join(
                (r.name, r.pattern, r.description, r.target_pattern)
            ).lower()
        ]
    rules.sort(key=_rule_order_key)
    counts = _rule_match_counts()
    return {
        "items": [
            dict(rule.to_dict(), match_count=counts.get(rule.id, 0))
            for rule in rules
        ],
        "total": len(rules),
    }


def get_command_rule(rule_id: int) -> CommandRule:
    rule = CommandRule.query.filter_by(id=rule_id).first()
    if rule is None:
        raise NotFound(f"No command rule with id {rule_id}")
    return rule


def _validated_rule_fields(
    payload: Any, *, partial: bool, rule: Optional[CommandRule] = None
) -> Dict[str, Any]:
    """Validate a create/update payload; partial updates start from the row."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    if partial:
        if rule is None:  # pragma: no cover - callers always pass the row
            raise ValidationFailed("Request body must be a JSON object")
        fields = {
            "name": rule.name,
            "pattern": rule.pattern,
            "action": rule.action,
            "target_pattern": rule.target_pattern,
            "terminate_on_match": rule.terminate_on_match,
            "description": rule.description,
            "enabled": rule.enabled,
        }
    else:
        fields = {
            "name": None,
            "pattern": None,
            "action": "allow",
            "target_pattern": "",
            "terminate_on_match": False,
            "description": "",
            "enabled": True,
        }
    for key in list(fields):
        if key in payload:
            fields[key] = payload[key]
    name = _required_text(fields, "name", 120)
    pattern = _required_text(fields, "pattern", 160)
    action = fields["action"]
    if action not in COMMAND_ACTIONS:
        raise ValidationFailed(
            f"Unknown action '{action}'",
            {"field": "action", "allowed": list(COMMAND_ACTIONS)},
        )
    target_pattern = _optional_text(fields, "target_pattern", 120)
    description = _optional_text(fields, "description", 255)
    terminate = fields["terminate_on_match"]
    if not isinstance(terminate, bool):
        raise ValidationFailed(
            "'terminate_on_match' must be true or false",
            {"field": "terminate_on_match"},
        )
    enabled = fields["enabled"]
    if not isinstance(enabled, bool):
        raise ValidationFailed("'enabled' must be true or false", {"field": "enabled"})
    if terminate and action != "block":
        # session termination is the escalation response to a block
        raise ValidationFailed(
            "Escalation (terminate_on_match) only applies to block rules",
            {"field": "terminate_on_match", "action": action},
        )
    return {
        "name": name,
        "pattern": pattern,
        "action": action,
        "target_pattern": target_pattern,
        "terminate_on_match": terminate,
        "description": description,
        "enabled": enabled,
    }


def create_command_rule(payload: Any, *, actor: str) -> CommandRule:
    fields = _validated_rule_fields(payload, partial=False)
    rule = CommandRule(**fields, updated_by=actor)
    db.session.add(rule)
    db.session.commit()
    return rule


def update_command_rule(
    rule_id: int, payload: Any, *, actor: str
) -> CommandRule:
    rule = get_command_rule(rule_id)
    fields = _validated_rule_fields(payload, partial=True, rule=rule)
    for key, value in fields.items():
        setattr(rule, key, value)
    rule.updated_at = datetime.now()
    rule.updated_by = actor
    db.session.commit()
    return rule


def delete_command_rule(rule_id: int) -> Dict[str, Any]:
    """Remove a rule. Recorded events keep their rule_id as history (the
    incidents snapshot name/pattern too), so past decisions stay explainable."""
    rule = get_command_rule(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return {"deleted": rule_id}


def _pending_approval_events() -> List[SessionEvent]:
    held = SessionEvent.query.filter_by(type="command", decision="approval").all()
    resolved = {
        (row.session_id, row.ref_seq)
        for row in SessionEvent.query.filter_by(type="approval").all()
        if row.ref_seq is not None
    }
    return [row for row in held if (row.session_id, row.seq) not in resolved]


def pending_command_approvals() -> Dict[str, Any]:
    """Held commands an approver can still act on (active sessions only: a
    hold whose session ended can never be resolved and is only evidence)."""
    sessions = {s.id: s for s in PrivilegedSession.query.all()}
    items: List[Dict[str, Any]] = []
    held = sorted(
        _pending_approval_events(), key=lambda row: row.created_at, reverse=True
    )
    for row in held:
        session = sessions.get(row.session_id)
        if session is None or session.status != "active":
            continue
        items.append(
            {
                "event": row.to_dict(),
                "session": {
                    "id": session.id,
                    "session_ref": session.session_ref,
                    "protocol": session.protocol,
                    "target": session.target,
                    "actor": session.actor,
                    "status": session.status,
                },
            }
        )
    return {"items": items, "total": len(items)}


def resolve_command_approval(
    session_id: int, seq: int, *, approve: bool, actor: str
) -> Tuple[SessionEvent, SessionEvent]:
    """Approve or deny one held command: the append-only recording gets a new
    `approval` row referencing it (ref_seq); the hold itself is never edited."""
    session = get_privileged_session(session_id)
    original = SessionEvent.query.filter_by(
        session_id=session_id, seq=seq
    ).first()
    if original is None:
        raise NotFound(f"No event seq {seq} in session {session_id}")
    if original.type != "command" or original.decision != "approval":
        raise Conflict(
            "Event is not awaiting command approval",
            {"field": "seq", "seq": seq, "decision": original.decision},
        )
    if session.status in SESSION_TERMINAL_STATUSES:
        raise Conflict(
            f"Session already {session.status}",
            {"field": "status", "status": session.status},
        )
    already = SessionEvent.query.filter_by(
        session_id=session_id, type="approval", ref_seq=seq
    ).first()
    if already is not None:
        raise Conflict(
            "Approval already recorded",
            {"field": "seq", "seq": seq, "decision": already.decision},
        )
    resolution = SessionEvent(
        session_id=session.id,
        seq=_next_session_seq(session.id),
        type="approval",
        content=original.content,
        allowed=bool(approve),
        blocked_reason=None if approve else "approval_denied",
        withheld=False,
        decision="approved" if approve else "denied",
        rule_id=original.rule_id,
        ref_seq=seq,
        watermark=(
            _session_watermark(session, actor) if session.watermark else None
        ),
        actor=actor,
    )
    db.session.add(resolution)
    db.session.commit()
    return original, resolution


def command_control_stats() -> Dict[str, Any]:
    """Real aggregates for the command-control screen: rule counts, today's
    intercepts, the approval queue, incident posture, and a content hash of
    the current policy (changes when any rule changes)."""
    rules = CommandRule.query.all()
    day_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    commands_today = (
        SessionEvent.query.filter(
            SessionEvent.type == "command",
            SessionEvent.created_at >= day_start,
        )
        .count()
    )
    blocks_today = (
        SessionEvent.query.filter(
            SessionEvent.type == "command",
            SessionEvent.decision == "block",
            SessionEvent.created_at >= day_start,
        )
        .count()
    )
    commands_recorded = SessionEvent.query.filter_by(type="command").count()
    approved = SessionEvent.query.filter_by(
        type="approval", decision="approved"
    ).count()
    denied = SessionEvent.query.filter_by(
        type="approval", decision="denied"
    ).count()
    canonical = json.dumps(
        [
            {
                "id": rule.id,
                "pattern": rule.pattern,
                "action": rule.action,
                "target_pattern": rule.target_pattern,
                "terminate_on_match": bool(rule.terminate_on_match),
                "enabled": bool(rule.enabled),
            }
            for rule in sorted(rules, key=lambda r: r.id)
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    last_sync = max((r.updated_at for r in rules), default=None)
    last_sync_by = None
    if rules:
        last_sync_by = max(rules, key=lambda r: r.updated_at).updated_by
    return {
        "rules_total": len(rules),
        "rules_enabled": sum(1 for rule in rules if rule.enabled),
        "by_action": {
            action: sum(1 for rule in rules if rule.action == action)
            for action in COMMAND_ACTIONS
        },
        "intercepts_today": blocks_today,
        "commands_today": commands_today,
        "commands_recorded": commands_recorded,
        "approvals": {
            "pending": len(_pending_approval_events()),
            "approved": approved,
            "denied": denied,
        },
        "incidents": {
            "open": CommandIncident.query.filter_by(status="open").count(),
            "total": CommandIncident.query.count(),
        },
        "engine_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12],
        "last_sync": last_sync.isoformat() if last_sync else None,
        "last_sync_by": last_sync_by,
    }


def list_command_incidents(
    *, status: Optional[str] = None, limit: int = 50, offset: int = 0
) -> Dict[str, Any]:
    if status is None or status == "all":
        query = CommandIncident.query
    elif status in ("open", "closed"):
        query = CommandIncident.query.filter_by(status=status)
    else:
        raise ValidationFailed(
            f"Unknown status '{status}'",
            {"field": "status", "allowed": ["open", "closed", "all"]},
        )
    total = query.count()
    rows = query.order_by(
        CommandIncident.created_at.desc(), CommandIncident.id.desc()
    ).offset(offset).limit(limit).all()
    return {"items": [row.to_dict() for row in rows], "total": total,
            "limit": limit, "offset": offset}


def get_command_incident(incident_id: int) -> CommandIncident:
    incident = CommandIncident.query.filter_by(id=incident_id).first()
    if incident is None:
        raise NotFound(f"No incident with id {incident_id}")
    return incident


def close_command_incident(
    incident_id: int, payload: Any, *, actor: str
) -> CommandIncident:
    incident = get_command_incident(incident_id)
    if incident.status == "closed":
        raise Conflict(
            "Incident already closed",
            {"field": "status", "status": "closed"},
        )
    if payload is not None and not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    note = _optional_text(payload or {}, "note", 255)
    incident.status = "closed"
    incident.closed_by = actor
    incident.closed_at = datetime.now()
    incident.close_note = note
    # the close writes no new incident row of its own, so it gets its own
    # ledger record - same transaction, so the two commit together
    audit.append_explicit(
        event_ref=f"incident-closed:{incident.id}",
        source="command",
        action="closed",
        actor=actor,
        subject=incident.incident_ref,
        detail={
            "note": note,
            "session_id": incident.session_id,
            "rule_id": incident.rule_id,
            "status": "closed",
        },
    )
    db.session.commit()
    return incident


def _escalate_blocked_command(
    session: PrivilegedSession,
    event: SessionEvent,
    verdict: Dict[str, Any],
    *,
    actor: str,
) -> Dict[str, Any]:
    """Context-aware response (architecture 9): preserve the evidence as an
    incident, then end the session - which runs the normal release-and-rotate
    cascade. Any failure is reported, never hidden."""
    rule = verdict["rule"]
    incident = CommandIncident(
        incident_ref="inc-" + secrets.token_hex(4),
        session_id=session.id,
        event_seq=event.seq,
        rule_id=rule["id"],
        rule_name=rule["name"],
        rule_pattern=rule["pattern"],
        command=event.content or "",
        target=session.target,
        actor=actor,
    )
    db.session.add(incident)
    db.session.flush()
    escalation: Dict[str, Any] = {
        "incident": incident.to_dict(),
        "session_terminated": False,
    }
    try:
        _, cascade = end_session(
            session.id,
            actor=actor,
            outcome="terminated",
            payload={"reason": f"command-control: {rule['name']}"},
        )
        escalation["session_terminated"] = True
        escalation["cascade"] = cascade
    except APIError as exc:
        escalation["error"] = exc.message
    return escalation


# ---------------------------------------------------------------------------
# dashboard (Command Center + Compliance screens)
# ---------------------------------------------------------------------------
_AUDIT_SOURCES = audit.AUDIT_SOURCES  # the eight trails folded into section 19's ledger


def unified_events(
    *, source: Optional[str] = None, limit: int = 20
) -> Dict[str, Any]:
    """Recent entries from the immutable audit ledger (architecture 19):
    license, settings, vault, discovery, JIT, session lifecycle, command
    control and risk, newest first. Each row carries its chain seq and
    hash."""
    if source and source not in _AUDIT_SOURCES:
        raise ValidationFailed(
            f"Unknown event source '{source}'",
            {"field": "source", "allowed": list(_AUDIT_SOURCES)},
        )

    query = AuditEvent.query
    if source:
        query = query.filter_by(source=source)
    total = query.count()
    rows = query.order_by(
        AuditEvent.created_at.desc(), AuditEvent.seq.desc()
    ).limit(limit).all()
    events = [
        {
            "id": row.event_ref,
            "seq": row.seq,
            "source": row.source,
            "action": row.action,
            "subject": row.subject,
            "actor": row.actor,
            "detail": row.detail,
            "created_at": row.created_at.isoformat(),
            "event_hash": row.event_hash,
        }
        for row in rows
    ]
    return {
        "events": events,
        "total": total,
        "limit": limit,
        "source": source or "all",
    }


def audit_stats() -> Dict[str, Any]:
    """Ledger aggregates: totals by source, chain head, trigger protection."""
    return audit.chain_stats()


def audit_verify() -> Dict[str, Any]:
    """Walk the whole hash chain and report the first break, if any."""
    return audit.verify_chain()


def audit_export_rows() -> List[Dict[str, Any]]:
    """The full ledger in chain order (one dict per NDJSON export line)."""
    return [row.to_dict() for row in AuditEvent.query.order_by(AuditEvent.seq)]


def overview() -> Dict[str, Any]:
    """One aggregate powering the Command Center and Compliance screens."""
    now = datetime.now()

    # --- license posture (expiry evaluated in Python: naive local datetimes)
    rows = db.session.query(
        LicenseRecord.status, LicenseRecord.expires_on, LicenseRecord.tier
    ).all()
    counts = {
        "total": len(rows),
        "active": 0,
        "revoked": 0,
        "expired": 0,
        "expiring_soon": 0,
    }
    by_tier: Dict[str, int] = {}
    for status, expires_on, tier in rows:
        if status == STATUS_REVOKED:
            counts["revoked"] += 1
        elif expires_on is not None and now > expires_on:
            counts["expired"] += 1
        else:
            counts["active"] += 1
            if expires_on is not None:
                days = (expires_on.date() - now.date()).days
                if 0 <= days <= 30:
                    counts["expiring_soon"] += 1
        tier_key = tier or "unspecified"
        by_tier[tier_key] = by_tier.get(tier_key, 0) + 1

    usage = {"nodes": 0, "sessions": 0, "bastion_tunnels": 0, "reported_licenses": 0}
    for record in LicenseRecord.query.all():
        summary = record.usage_summary()
        if not summary["reported"]:
            continue
        usage["reported_licenses"] += 1
        usage["nodes"] += summary["nodes"]["consumed"]
        usage["sessions"] += summary["concurrent_sessions"]["consumed"]
        usage["bastion_tunnels"] += summary["bastion_tunnels"]["consumed"]

    # --- vault + settings posture
    vault = vault_stats()
    sso = _settings_row("sso")["values"]
    hsm = _settings_row("hsm")["values"]
    zsp = _settings_row("zsp")["values"]
    worm = _settings_row("worm")["values"]
    groups_stored = SettingGroup.query.count()

    license_events = LicenseEvent.query.count()
    settings_events = SettingsEvent.query.count()
    vault_events_total = VaultEvent.query.count()
    discovery_events_total = DiscoveryEvent.query.count()
    # the immutable ledger counts every trail (section 19), so that is the
    # number the footers show for "audit events"; the per-source counters
    # above stay the module tables' own rows
    total_events = AuditEvent.query.count()

    auth_mode = "token" if _overview_auth_mode() else "open"
    algorithms = list(sig.SUPPORTED_ALGORITHMS)

    # --- controls: each is a real, checkable fact about this deployment
    controls = [
        {
            "id": "worm_retention",
            "label": "Immutable WORM audit retention",
            "passed": bool(worm.get("immutability_enabled"))
            and int(worm.get("retention_days", 0)) >= 365,
            "evidence": f"{worm.get('object_lock_mode')} \u2022 {worm.get('retention_days')}d retention",
        },
        {
            "id": "audit_evidence",
            "label": "Audit evidence collected",
            "passed": total_events > 0,
            "evidence": f"{total_events} records",
        },
        {
            "id": "quantum_safe",
            "label": "Quantum-safe signature algorithms",
            "passed": {"ed25519", "rsa-pss-sha256"}
            <= {algorithm.lower() for algorithm in algorithms},
            "evidence": ", ".join(algorithms),
        },
        {
            "id": "rotation_sla",
            "label": "Secret rotation SLA compliance",
            "passed": vault["attention"]["failed"] == 0 and vault["rotation"]["due"] == 0,
            "evidence": f"{vault['rotation']['compliance_pct']}% in policy",
        },
        {
            "id": "sso_mfa",
            "label": "SSO + MFA enforced",
            "passed": bool(sso.get("enforce_sso")) and bool(sso.get("require_mfa")),
            "evidence": str(sso.get("primary_provider")),
        },
        {
            "id": "tier0_quorum",
            "label": "Tier-0 quorum approval",
            "passed": int(zsp.get("tier0_quorum_approvers", 0)) >= 2,
            "evidence": f"{zsp.get('tier0_quorum_approvers')}-party approval",
        },
        {
            "id": "admin_auth",
            "label": "Admin API authentication",
            "passed": auth_mode == "token",
            "evidence": (
                "admin token enforced" if auth_mode == "token" else "open dev mode"
            ),
        },
        {
            "id": "hsm_backed",
            "label": "HSM-backed master key",
            "passed": bool(hsm.get("cluster_id")) and bool(hsm.get("kms_endpoint")),
            "evidence": f"{hsm.get('provider')} \u2022 {hsm.get('cluster_id')}",
        },
    ]
    passed_controls = sum(1 for control in controls if control["passed"])

    return {
        "generated_at": now.isoformat(),
        "health": {
            "status": "ok",
            "auth": auth_mode,
            "algorithms": algorithms,
            "formats": list(sig.SUPPORTED_FORMATS),
        },
        "licenses": {
            **counts,
            "by_tier": by_tier,
            "usage": usage,
        },
        "vault": vault,
        "settings": {
            "groups": len(SETTINGS_GROUPS),
            "groups_stored": groups_stored,
            "worm_retention_days": worm.get("retention_days"),
            "worm_immutable": bool(worm.get("immutability_enabled")),
            "zsp_quorum_approvers": zsp.get("tier0_quorum_approvers"),
            "sso_provider": sso.get("primary_provider"),
        },
        "counters": {
            "license_events": license_events,
            "settings_events": settings_events,
            "vault_events": vault_events_total,
            "discovery_events": discovery_events_total,
            "total_events": total_events,
        },
        "posture": {
            "score": round(100.0 * passed_controls / len(controls), 1),
            "violations": len(controls) - passed_controls,
            "controls": controls,
        },
        "activity": unified_events(limit=6)["events"],
    }


def _overview_auth_mode() -> bool:
    """True when the admin token is enforced (False = open dev mode)."""
    from flask import current_app

    return bool(current_app.config["LICENSE_CONFIG"].admin_token)


# ---------------------------------------------------------------------------
# discovery engine (module 3): real TCP-connect probes, classify, onboard
# ---------------------------------------------------------------------------
DEFAULT_SCAN_PORTS = (
    22,
    88,
    135,
    389,
    443,
    445,
    636,
    1433,
    1521,
    2375,
    2379,
    27017,
    3306,
    3389,
    5432,
    5985,
    6379,
    6443,
)
MAX_SCAN_HOSTS = 256
MAX_SCAN_PORTS = 24
SCAN_CONNECT_TIMEOUT = 0.35
SCAN_BANNER_TIMEOUT = 0.2
_SCAN_THREADS = 64

_SERVICE_BY_PORT = {
    22: "SSH",
    88: "Kerberos",
    135: "MSRPC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    2375: "Docker API",
    2379: "etcd",
    27017: "MongoDB",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM",
    6379: "Redis",
    6443: "Kubernetes API",
}
_WINDOWS_PORTS = frozenset({88, 135, 389, 445, 636, 3389, 5985})
_DATABASE_PORTS = frozenset({1433, 1521, 3306, 5432, 6379, 27017})
_K8S_PORTS = frozenset({6443, 2379})
_DOCKER_PORTS = frozenset({2375})
_SSH_PORTS = frozenset({22})

_SCAN_LOCK = threading.Lock()


def _clean_banner(raw: bytes) -> str:
    """First banner line, printable only, capped for storage/display."""
    text = raw.decode("ascii", errors="replace").replace("\x00", " ")
    printable = "".join(ch for ch in text if ch.isprintable())
    return " ".join(printable.split())[:80]


def _probe_host(address: str, ports) -> List[Dict[str, Any]]:
    """TCP-connect probe: which ports are open, plus a short banner grab
    (greeting services answer immediately; others simply time out). Pure
    sockets - safe to call from worker threads."""
    found: List[Dict[str, Any]] = []
    for port in ports:
        try:
            with socket.create_connection(
                (address, port), timeout=SCAN_CONNECT_TIMEOUT
            ) as sock:
                banner = ""
                try:
                    sock.settimeout(SCAN_BANNER_TIMEOUT)
                    chunk = sock.recv(256)
                    if chunk:
                        banner = _clean_banner(chunk)
                except OSError:
                    banner = ""
                found.append(
                    {
                        "port": port,
                        "proto": "TCP",
                        "service": _SERVICE_BY_PORT.get(port, ""),
                        "banner": banner,
                    }
                )
        except OSError:
            continue
    return found


def _classify_service(entries: List[Dict[str, Any]]) -> Tuple[str, str]:
    """Open ports + greetings -> (asset_type, detail).

    Port-to-service mapping classifies the family; an SSH/MySQL greeting
    refines the OS where one was actually read. Anything unproven stays
    'unknown' rather than being guessed.
    """
    open_ports = {int(entry["port"]) for entry in entries}
    banners = {
        int(entry["port"]): entry.get("banner", "") for entry in entries
    }
    order = sorted(open_ports)

    def labels(port_set) -> str:
        names: List[str] = []
        for port in order:
            if port not in port_set:
                continue
            name = _SERVICE_BY_PORT.get(port, f"TCP/{port}")
            if name and name not in names:
                names.append(name)
            if len(names) == 2:
                break
        return " \u00b7 ".join(names)

    if _WINDOWS_PORTS & open_ports:
        return "windows", labels(_WINDOWS_PORTS)
    if _DATABASE_PORTS & open_ports:
        banner = next(
            (
                banners[port]
                for port in order
                if port in _DATABASE_PORTS and banners.get(port)
            ),
            "",
        )
        if banner:
            return "database", banner
        return "database", labels(_DATABASE_PORTS)
    if _K8S_PORTS & open_ports:
        return "kubernetes", labels(_K8S_PORTS)
    if _DOCKER_PORTS & open_ports:
        return "docker", labels(_DOCKER_PORTS)
    # SSH evidence: port 22 open, or a greeting that identifies SSH on any port.
    ssh_banner = banners.get(22, "") if _SSH_PORTS & open_ports else ""
    if not ssh_banner:
        ssh_banner = next(
            (
                banners[port]
                for port in order
                if banners.get(port, "").startswith("SSH-")
            ),
            "",
        )
    if _SSH_PORTS & open_ports or ssh_banner:
        lower = ssh_banner.lower()
        if "sun_ssh" in lower or "solaris" in lower:
            return "solaris", ssh_banner
        if "hp-ux" in lower:
            return "unix", ssh_banner
        if "aix" in lower:
            return "aix", ssh_banner
        if ssh_banner:
            return "linux", ssh_banner
        # SSH answered but no greeting was captured: do not guess the OS.
        return "unknown", labels(_SSH_PORTS)
    if order:
        return "unknown", labels(open_ports)
    return "unknown", ""


def _expand_scope(scope: str, *, field: str = "scope") -> List[str]:
    """Validated scan targets: single IPv4, IPv4 CIDR within the host cap, or
    a hostname. Refuses multicast, unspecified and broadcast addresses.
    `field` names the offending input in errors ('scope' for scans,
    'address' for onboarding)."""
    value = scope.strip()
    if not value:
        raise ValidationFailed(f"'{field}' is required", {"field": field})
    if len(value) > 64:
        raise ValidationFailed(f"'{field}' is too long", {"field": field})

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValidationFailed(
                f"'{value}' is not a valid IPv4 CIDR", {"field": field}
            ) from None
        if network.version != 4:
            raise ValidationFailed(
                "Only IPv4 scopes are supported", {"field": field}
            )
        if network.is_multicast or network.is_unspecified:
            raise ValidationFailed(
                "Multicast/unspecified scopes are refused", {"field": field}
            )
        # Count BEFORE materializing: a /8 would otherwise build 16M strings.
        if network.prefixlen >= 31:
            expected = network.num_addresses
        else:
            expected = network.num_addresses - 2  # network + broadcast
        if expected > MAX_SCAN_HOSTS:
            raise ValidationFailed(
                f"Scope covers {expected} hosts; the limit is {MAX_SCAN_HOSTS}",
                {"field": field, "max_hosts": MAX_SCAN_HOSTS},
            )
        hosts = [str(host) for host in network.hosts()]
        return hosts or [str(network.network_address)]

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise ValidationFailed(
                "Only IPv4 addresses are supported", {"field": field}
            )
        if (
            address.is_multicast
            or address.is_unspecified
            or str(address) == "255.255.255.255"
        ):
            raise ValidationFailed(
                "Multicast/unspecified addresses are refused", {"field": field}
            )
        return [str(address)]

    if (
        len(value) <= 253
        and re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?", value)
        and re.search(r"[A-Za-z]", value)
    ):
        return [value]
    raise ValidationFailed(
        f"'{field}' must be an IPv4 address, an IPv4 CIDR, or a hostname",
        {"field": field},
    )


def _log_discovery_event(
    action: str, subject: str, actor: str, detail: Dict[str, Any]
) -> None:
    db.session.add(
        DiscoveryEvent(
            action=action, subject=subject[:128], actor=actor, detail=detail
        )
    )


def _get_asset(asset_id: int) -> DiscoveredAsset:
    """Fetch one discovered asset or raise 404."""
    asset = DiscoveredAsset.query.filter_by(id=asset_id).first()
    if asset is None:
        raise NotFound(f"No asset with id {asset_id}")
    return asset


def _heal_stale_scans() -> None:
    """Mark abandoned 'running' rows failed (a crashed request never finished)."""
    cutoff = datetime.now() - timedelta(minutes=10)
    stale = (
        DiscoveryScan.query.filter_by(status=DISCOVERY_SCAN_RUNNING)
        .filter(DiscoveryScan.started_at <= cutoff)
        .update(
            {
                "status": DISCOVERY_SCAN_FAILED,
                "error": "interrupted",
                "finished_at": datetime.now(),
            },
            synchronize_session=False,
        )
    )
    if stale:
        db.session.commit()


def start_scan(payload: Any, *, actor: str) -> DiscoveryScan:
    """Run a real TCP-connect discovery scan over the requested scope.

    Single-flight (module lock), bounded (host/port caps) and synchronous:
    the request returns the finished scan with honest counters. Only scans
    an operator explicitly asks for - there is no default range.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    scope_raw = payload.get("scope")
    if not isinstance(scope_raw, str) or not scope_raw.strip():
        raise ValidationFailed("'scope' is required", {"field": "scope"})
    hosts = _expand_scope(scope_raw)

    ports_raw = payload.get("ports")
    if ports_raw is None:
        ports = list(DEFAULT_SCAN_PORTS)
    else:
        if not isinstance(ports_raw, list) or not ports_raw:
            raise ValidationFailed(
                "'ports' must be a non-empty list of port numbers",
                {"field": "ports"},
            )
        ports = []
        for entry in ports_raw:
            if (
                isinstance(entry, bool)
                or not isinstance(entry, int)
                or not 1 <= entry <= 65535
            ):
                raise ValidationFailed(
                    "Every port must be an integer between 1 and 65535",
                    {"field": "ports"},
                )
            if entry not in ports:
                ports.append(entry)
        if len(ports) > MAX_SCAN_PORTS:
            raise ValidationFailed(
                f"At most {MAX_SCAN_PORTS} ports per scan",
                {"field": "ports", "max_ports": MAX_SCAN_PORTS},
            )

    if not _SCAN_LOCK.acquire(blocking=False):
        raise ValidationFailed("A discovery scan is already running")
    scan_id: Optional[int] = None
    try:
        _heal_stale_scans()
        scan = DiscoveryScan(
            scope=scope_raw.strip()[:64],
            method=DISCOVERY_METHOD_PROBE,
            ports=ports,
            status=DISCOVERY_SCAN_RUNNING,
            triggered_by=actor,
        )
        db.session.add(scan)
        db.session.flush()
        scan_id = scan.id
        _log_discovery_event(
            DISCOVERY_ACTION_SCAN_STARTED,
            scan.scope,
            actor,
            {"hosts": len(hosts), "ports": ports},
        )
        db.session.commit()

        workers = min(_SCAN_THREADS, max(1, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            probed = list(
                pool.map(lambda host: (host, _probe_host(host, ports)), hosts)
            )

        hosts_open = 0
        services_found = 0
        findings = 0
        for host, entries in probed:
            if not entries:
                continue
            hosts_open += 1
            services_found += len(entries)
            asset_type, detail = _classify_service(entries)
            asset = DiscoveredAsset.query.filter_by(address=host).first()
            if asset is None:
                asset = DiscoveredAsset(
                    address=host,
                    asset_type=asset_type,
                    risk=BASE_RISK.get(asset_type, "LOW"),
                    pam_status="unmanaged",
                    detail=detail,
                    ports=entries,
                    source=DISCOVERY_SOURCE_SCAN,
                    method=DISCOVERY_METHOD_PROBE,
                )
                db.session.add(asset)
                db.session.flush()
                findings += 1
                _log_discovery_event(
                    DISCOVERY_ACTION_ASSET_DISCOVERED,
                    host,
                    actor,
                    {
                        "asset_type": asset_type,
                        "risk": asset.risk,
                        "ports": [entry["port"] for entry in entries],
                    },
                )
            else:
                asset.ports = entries
                asset.last_seen = datetime.now()
                if asset.pam_status != "managed":
                    # Machine-owned rows follow the probe; operator-classified
                    # (managed) rows keep the human's classification.
                    asset.asset_type = asset_type
                    asset.detail = detail
                    asset.risk = BASE_RISK.get(asset_type, "LOW")

        scan.hosts_probed = len(hosts)
        scan.hosts_open = hosts_open
        scan.services_found = services_found
        scan.findings = findings
        scan.status = DISCOVERY_SCAN_COMPLETED
        scan.finished_at = datetime.now()
        _log_discovery_event(
            DISCOVERY_ACTION_SCAN_COMPLETED,
            scan.scope,
            actor,
            {
                "hosts_probed": len(hosts),
                "hosts_open": hosts_open,
                "services_found": services_found,
                "findings": findings,
            },
        )
        db.session.commit()
        return scan
    except APIError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        db.session.rollback()
        if scan_id is not None:
            failed = DiscoveryScan.query.filter_by(id=scan_id).first()
            if failed is not None:
                failed.status = DISCOVERY_SCAN_FAILED
                failed.error = str(exc)[:255]
                failed.finished_at = datetime.now()
                _log_discovery_event(
                    DISCOVERY_ACTION_SCAN_FAILED,
                    failed.scope,
                    actor,
                    {"error": str(exc)[:255]},
                )
                db.session.commit()
        raise APIError(500, f"Discovery scan failed: {exc}")
    finally:
        _SCAN_LOCK.release()


def list_scans(*, limit: int = 20) -> Tuple[List[DiscoveryScan], int]:
    """Scan history, newest first."""
    total = DiscoveryScan.query.count()
    scans = DiscoveryScan.query.order_by(
        DiscoveryScan.id.desc(), DiscoveryScan.started_at.desc()
    ).limit(limit).all()
    return scans, total


def _vault_item_for_asset(
    asset: DiscoveredAsset, principal: str, *, actor: str, **options
) -> VaultItem:
    """Ingest an asset's admin account into the vault (metadata only)."""
    base = f"{asset.hostname or asset.address} {principal}".strip()
    name = base[:120]
    if VaultItem.query.filter_by(name=name).first() is not None:
        suffix = f" #{asset.id}"
        name = f"{base[:120 - len(suffix)]}{suffix}"
        if VaultItem.query.filter_by(name=name).first() is not None:
            raise ValidationFailed(
                f"A credential named '{name}' already exists",
                {"field": "principal"},
            )
    item = VaultItem(
        name=name,
        secret_type=ASSET_SECRET_TYPES.get(asset.asset_type, "service_account"),
        description=f"Admin credential for {asset.hostname or asset.address}"[:255],
        target=asset.address,
        target_detail=asset.hostname[:255],
        principal=principal,
        last_rotated_at=datetime.now(),
        status=VAULT_STATUS_AVAILABLE,
        **options,
    )
    db.session.add(item)
    db.session.flush()
    # A discovered admin account enters the vault as a real managed credential:
    # mint + seal its value now, rotation brings it forward later.
    plaintext = generate_secret(item.secret_type)
    blob = seal(plaintext, item.id, _vault_config())
    row = _store_secret(
        item, blob, source="generated", trigger="onboarded", actor=actor
    )
    _validate_stored_secret(item, plaintext, row, config=_vault_config())
    _log_vault_event(
        item,
        VAULT_ACTION_ONBOARDED,
        actor,
        {"via": "discovery", "asset_id": asset.id},
    )
    return item


def _record_account(
    asset: DiscoveredAsset, username: str, *, source: str
) -> DiscoveredAccount:
    existing = DiscoveredAccount.query.filter_by(
        asset_id=asset.id, username=username
    ).first()
    if existing is not None:
        return existing
    account = DiscoveredAccount(
        asset_id=asset.id,
        asset_address=asset.address,
        username=username[:128],
        kind=classify_account_kind(username),
        source=source,
    )
    db.session.add(account)
    db.session.flush()
    return account


def _required_text(payload: Dict[str, Any], field: str, max_length: int) -> str:
    raw = payload.get(field)
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationFailed(f"'{field}' is required", {"field": field})
    return raw.strip()[:max_length]


def _optional_text(
    payload: Dict[str, Any], field: str, max_length: int
) -> str:
    raw = payload.get(field, "")
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationFailed(f"'{field}' must be a string", {"field": field})
    return raw.strip()[:max_length]


def _vault_options(payload: Dict[str, Any]) -> Dict[str, Any]:
    interval = payload.get("rotation_interval_hours", 24)
    if (
        isinstance(interval, bool)
        or not isinstance(interval, int)
        or not 0 <= interval <= 8760
    ):
        raise ValidationFailed(
            "'rotation_interval_hours' must be an integer between 0 and 8760",
            {"field": "rotation_interval_hours"},
        )
    tier = payload.get("access_tier", "Tier-2")
    if tier not in ("Tier-0", "Tier-1", "Tier-2"):
        raise ValidationFailed(
            "'access_tier' must be Tier-0, Tier-1 or Tier-2",
            {"field": "access_tier", "allowed": ["Tier-0", "Tier-1", "Tier-2"]},
        )
    auth_method = payload.get("auth_method", "Password")
    if not isinstance(auth_method, str) or not auth_method.strip():
        raise ValidationFailed(
            "'auth_method' must be a non-empty string", {"field": "auth_method"}
        )
    return {
        "rotation_interval_hours": interval,
        "access_tier": tier,
        "auth_method": auth_method.strip()[:32],
    }


def onboard_asset(
    payload: Any, *, actor: str
) -> Tuple[DiscoveredAsset, VaultItem]:
    """Manually register + classify a target and ingest its admin account.

    The operator supplies the classification (asset_type) and the privileged
    principal; the asset lands as managed with a real vault credential.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    address = _required_text(payload, "address", 64)
    if "/" in address:
        raise ValidationFailed(
            "'address' must be a single IP address or hostname",
            {"field": "address"},
        )
    _expand_scope(address, field="address")  # shape validation (single host)
    if DiscoveredAsset.query.filter_by(address=address).first() is not None:
        raise ValidationFailed(
            f"An asset at '{address}' already exists", {"field": "address"}
        )

    asset_type = payload.get("asset_type", "unknown")
    if asset_type not in ASSET_TYPES:
        raise ValidationFailed(
            "'asset_type' must be one of the discovery types",
            {"field": "asset_type", "allowed": list(ASSET_TYPES)},
        )
    hostname = _optional_text(payload, "hostname", 255)
    detail = _optional_text(payload, "detail", 255)
    notes = _optional_text(payload, "notes", 255)
    principal = _required_text(payload, "principal", 128)
    options = _vault_options(payload)

    asset = DiscoveredAsset(
        address=address,
        hostname=hostname,
        asset_type=asset_type,
        risk=BASE_RISK.get(asset_type, "LOW"),
        pam_status="managed",
        detail=detail,
        ports=[],
        source=DISCOVERY_SOURCE_MANUAL,
        method=DISCOVERY_METHOD_MANUAL,
        notes=notes,
    )
    db.session.add(asset)
    db.session.flush()
    item = _vault_item_for_asset(asset, principal, actor=actor, **options)
    _record_account(asset, principal, source=DISCOVERY_SOURCE_MANUAL)
    _log_discovery_event(
        DISCOVERY_ACTION_ASSET_ONBOARDED,
        address,
        actor,
        {
            "asset_type": asset_type,
            "risk": asset.risk,
            "principal": principal,
            "vault_item_id": item.id,
        },
    )
    db.session.commit()
    return asset, item


def adopt_asset(
    asset_id: int, payload: Any, *, actor: str
) -> Tuple[DiscoveredAsset, VaultItem]:
    """Onboard an already-discovered asset: classify it as managed and ingest
    its admin account into the vault (Discover -> Recommend -> Auto-onboard)."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    asset = _get_asset(asset_id)
    if asset.pam_status == "managed":
        raise ValidationFailed("Asset is already managed")
    principal = _required_text(payload, "principal", 128)
    options = _vault_options(payload)

    asset.pam_status = "managed"
    item = _vault_item_for_asset(asset, principal, actor=actor, **options)
    _record_account(asset, principal, source=DISCOVERY_SOURCE_MANUAL)
    _log_discovery_event(
        DISCOVERY_ACTION_ASSET_ONBOARDED,
        asset.address,
        actor,
        {
            "asset_type": asset.asset_type,
            "risk": asset.risk,
            "principal": principal,
            "vault_item_id": item.id,
            "adopted": True,
        },
    )
    db.session.commit()
    return asset, item


def update_asset(asset_id: int, payload: Any, *, actor: str) -> DiscoveredAsset:
    """Operator overrides: PAM status (ignore/restore), reclassification,
    hostname/notes. Reclassification recomputes the risk score."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    asset = _get_asset(asset_id)
    changes: Dict[str, Any] = {}

    if "pam_status" in payload:
        status = payload["pam_status"]
        if status not in ASSET_PAM_STATUSES:
            raise ValidationFailed(
                "'pam_status' must be unmanaged, managed or ignored",
                {"field": "pam_status", "allowed": list(ASSET_PAM_STATUSES)},
            )
        if status != asset.pam_status:
            changes["pam_status"] = {"from": asset.pam_status, "to": status}
            asset.pam_status = status

    if "asset_type" in payload:
        asset_type = payload["asset_type"]
        if asset_type not in ASSET_TYPES:
            raise ValidationFailed(
                "'asset_type' must be one of the discovery types",
                {"field": "asset_type", "allowed": list(ASSET_TYPES)},
            )
        if asset_type != asset.asset_type:
            changes["asset_type"] = {
                "from": asset.asset_type,
                "to": asset_type,
            }
            changes["risk"] = {
                "from": asset.risk,
                "to": BASE_RISK.get(asset_type, "LOW"),
            }
            asset.asset_type = asset_type
            asset.risk = BASE_RISK.get(asset_type, "LOW")

    for field, max_length in (
        ("hostname", 255),
        ("detail", 255),
        ("notes", 255),
    ):
        if field in payload:
            value = _optional_text(payload, field, max_length)
            if value != getattr(asset, field):
                changes[field] = value
                setattr(asset, field, value)

    if not changes:
        raise ValidationFailed("No changes supplied", {"fields": sorted(payload)})

    _log_discovery_event(
        DISCOVERY_ACTION_ASSET_UPDATED, asset.address, actor, {"changes": changes}
    )
    db.session.commit()
    return asset


def list_discovered_assets(
    *,
    q: Optional[str] = None,
    asset_type: Optional[str] = None,
    risk: Optional[str] = None,
    pam_status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[DiscoveredAsset], int]:
    """Asset rows with the screen's type/risk/status/free-text filters."""
    if asset_type and asset_type not in ASSET_TYPES:
        raise ValidationFailed(
            f"Unknown asset type '{asset_type}'",
            {"field": "type", "allowed": list(ASSET_TYPES)},
        )
    if risk and risk not in ASSET_RISKS:
        raise ValidationFailed(
            f"Unknown risk '{risk}'",
            {"field": "risk", "allowed": list(ASSET_RISKS)},
        )
    if pam_status and pam_status not in ASSET_PAM_STATUSES:
        raise ValidationFailed(
            f"Unknown PAM status '{pam_status}'",
            {"field": "pam_status", "allowed": list(ASSET_PAM_STATUSES)},
        )

    query = DiscoveredAsset.query
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                DiscoveredAsset.address.ilike(pattern),
                DiscoveredAsset.hostname.ilike(pattern),
                DiscoveredAsset.detail.ilike(pattern),
                DiscoveredAsset.notes.ilike(pattern),
            )
        )
    if asset_type:
        query = query.filter(DiscoveredAsset.asset_type == asset_type)
    if risk:
        query = query.filter(DiscoveredAsset.risk == risk)
    if pam_status:
        query = query.filter(DiscoveredAsset.pam_status == pam_status)

    total = query.count()
    attention = db.case((DiscoveredAsset.pam_status == "unmanaged", 0), else_=1)
    risk_rank = db.case(
        (DiscoveredAsset.risk == "CRITICAL", 0),
        (DiscoveredAsset.risk == "HIGH", 1),
        (DiscoveredAsset.risk == "MEDIUM", 2),
        (DiscoveredAsset.risk == "LOW", 3),
        else_=4,
    )
    assets = (
        query.order_by(attention, risk_rank, DiscoveredAsset.address.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return assets, total


def vault_counts_by_target(targets: List[str]) -> Dict[str, int]:
    """Vault credentials per asset address (exact target match)."""
    if not targets:
        return {}
    rows = (
        db.session.query(VaultItem.target, db.func.count(VaultItem.id))
        .filter(VaultItem.target.in_(targets))
        .group_by(VaultItem.target)
        .all()
    )
    return {target: count for target, count in rows}


def list_discovered_accounts(
    *,
    q: Optional[str] = None,
    kind: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[DiscoveredAccount], int]:
    """Recorded privileged accounts (real rows only - recorded at onboarding)."""
    if kind and kind not in ACCOUNT_KINDS:
        raise ValidationFailed(
            f"Unknown account kind '{kind}'",
            {"field": "kind", "allowed": list(ACCOUNT_KINDS)},
        )
    query = DiscoveredAccount.query
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                DiscoveredAccount.username.ilike(pattern),
                DiscoveredAccount.asset_address.ilike(pattern),
            )
        )
    if kind:
        query = query.filter(DiscoveredAccount.kind == kind)
    total = query.count()
    accounts = (
        query.order_by(DiscoveredAccount.id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return accounts, total


def discovery_stats() -> Dict[str, Any]:
    """Counts powering the screen's tiles, posture pills and type tabs."""
    assets = DiscoveredAsset.query.all()
    by_type = {kind: 0 for kind in ASSET_TYPES}
    by_risk = {level: 0 for level in ASSET_RISKS}
    by_pam_status = {status: 0 for status in ASSET_PAM_STATUSES}
    for asset in assets:
        by_type[asset.asset_type] = by_type.get(asset.asset_type, 0) + 1
        by_risk[asset.risk] = by_risk.get(asset.risk, 0) + 1
        by_pam_status[asset.pam_status] = by_pam_status.get(asset.pam_status, 0) + 1
    last_scan = DiscoveryScan.query.order_by(DiscoveryScan.id.desc()).first()
    return {
        "total": len(assets),
        "by_type": by_type,
        "by_risk": by_risk,
        "by_pam_status": by_pam_status,
        "accounts_total": DiscoveredAccount.query.count(),
        "scans": {
            "total": DiscoveryScan.query.count(),
            "last": last_scan.to_dict() if last_scan else None,
        },
    }


# ---------------------------------------------------------------------------
# risk-based access engine (architecture section 7)
# ---------------------------------------------------------------------------
# RBAC + ABAC + risk: every request is scored over the eight components the
# architecture names, the total picks the band, and the band drives policy -
#
#     0-25    LOW      -> allow
#     26-50   MEDIUM   -> MFA
#     51-75   HIGH     -> approval
#     76-100  CRITICAL -> block (the refusal is kept as SOC evidence)
#
# Nothing is assigned: user, device, asset, time, location, behavior,
# ticket and command each read a measured input - the subject's own 24h
# history, the discovered inventory, the live command policy, the local
# clock, the source address (stdlib ipaddress, no geo feed is claimed),
# the ticket's shape - and every component returns its points with the
# detail that produced them. The caps add up to exactly 100, so the score
# is always the visible sum of its parts.
RISK_ASSET_POINTS = {"CRITICAL": 25, "HIGH": 20, "MEDIUM": 10, "LOW": 0}
RISK_UNMANAGED_POINTS = 5  # an asset outside PAM control is exposure (section 10)
RISK_DEVICE_UNKNOWN = 15
RISK_OFF_HOURS = 10
RISK_PUBLIC_SOURCE = 5
RISK_BEHAVIOR_BLOCKED = 10  # blocked commands by this subject in the last 24h
RISK_BEHAVIOR_DENIED = 5    # denied JIT requests by this subject in the last 24h
RISK_TICKET_SHAPE = 5
RISK_COMMAND_POINTS = {"block": 10, "approval": 5}
# section 11 (UEBA): one point block per named baseline deviation, five
# points each - six reasons ("unusual time" ... "unusual privilege") add 30
# to the behavior component, which is what turns an otherwise-normal request
# critical when the principal deviates from their own recorded profile.
RISK_ANOMALY_POINTS = 5
UEBA_WINDOW_DAYS = 30      # rolling window a baseline learns from
UEBA_MAX_DISTINCT = 128    # per-dimension cap; a truncated list skips its check
UEBA_PRIVILEGE_VERBS = {   # commands that raise privilege: "attempted sudo"
    "chown",
    "doas",
    "passwd",
    "pkexec",
    "su",
    "sudo",
    "useradd",
    "usermod",
    "visudo",
}


def _risk_band(score: int) -> str:
    """The architecture's bands (mirrors the thresholds _jit_level uses)."""
    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


def _risk_text(
    payload: Dict[str, Any], field: str, *, max_length: int, required: bool = False
) -> str:
    raw = payload.get(field)
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationFailed(f"'{field}' must be a string", {"field": field})
    value = raw.strip()
    if required and not value:
        raise ValidationFailed(f"'{field}' is required", {"field": field})
    if len(value) > max_length:
        raise ValidationFailed(
            f"'{field}' must be at most {max_length} characters",
            {"field": field, "max_length": max_length},
        )
    return value


def _target_host(target: str) -> str:
    """`web-01.prod:22` -> `web-01.prod` (bracketed IPv6 kept intact)."""
    raw = (target or "").strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            return raw[1:end]
    head, _, tail = raw.rpartition(":")
    if head and tail.isdigit() and raw.count(":") == 1:
        return head
    return raw


def _risk_asset(host: str) -> Optional[DiscoveredAsset]:
    if not host:
        return None
    needle = host.lower()
    return (
        DiscoveredAsset.query.filter(
            db.func.lower(DiscoveredAsset.address) == needle
        ).first()
        or DiscoveredAsset.query.filter(
            db.func.lower(DiscoveredAsset.hostname) == needle
        ).first()
    )


# ---------------------------------------------------------------------------
# behavior baselines and anomaly response (architecture section 11 / UEBA)
# ---------------------------------------------------------------------------


def _command_verb(command: Optional[str]) -> str:
    """`sudo systemctl restart nginx` -> `sudo` (the command class)."""
    raw = (command or "").strip()
    if not raw:
        return ""
    token = raw.split()[0].strip('"\'();&|')
    return token.rsplit("/", 1)[-1].lower()


def _distinct(values: Any) -> Tuple[List[str], bool]:
    """Deduplicated, sorted, capped list - the bool says it was truncated
    (past the cap the deviation check for that dimension stands down)."""
    uniq = sorted({str(v).strip() for v in values if v and str(v).strip()})
    return uniq[:UEBA_MAX_DISTINCT], len(uniq) > UEBA_MAX_DISTINCT


def _learn_behavior_profile(
    subject: str, *, now: datetime, window_days: int = UEBA_WINDOW_DAYS
) -> Dict[str, Any]:
    """One principal's rolling profile, learned only from real history rows:
    risk evaluations, privileged sessions, posted command events and command
    incidents inside the window. No rows, no profile - normality is never
    invented for a principal the product has not seen."""
    since = now - timedelta(days=window_days)
    risks = (
        RiskEvent.query.filter(
            RiskEvent.subject == subject, RiskEvent.created_at >= since
        ).all()
    )
    sessions = (
        PrivilegedSession.query.filter(
            PrivilegedSession.actor == subject,
            PrivilegedSession.started_at >= since,
        ).all()
    )
    commands = (
        SessionEvent.query.filter(
            SessionEvent.actor == subject,
            SessionEvent.type == "command",
            SessionEvent.created_at >= since,
        ).all()
    )
    incidents = (
        CommandIncident.query.filter(
            CommandIncident.actor == subject, CommandIncident.created_at >= since
        ).all()
    )
    samples = len(risks) + len(sessions) + len(commands) + len(incidents)
    if not samples:
        return {}

    hours = sorted(
        {row.created_at.hour for row in risks}
        | {row.started_at.hour for row in sessions}
        | {row.created_at.hour for row in commands}
        | {row.created_at.hour for row in incidents}
    )
    devices, devices_truncated = _distinct(row.device for row in risks)
    source_ips, ips_truncated = _distinct(row.source_ip for row in risks)
    targets, targets_truncated = _distinct(
        [_target_host(row.target) for row in risks]
        + [_target_host(row.target) for row in sessions]
    )
    protocols = sorted({row.protocol for row in sessions})
    verbs = {
        _command_verb(row.content) for row in commands
    } | {
        _command_verb(row.command) for row in risks
    } | {
        _command_verb(row.command) for row in incidents
    }
    verbs.discard("")
    command_verbs, verbs_truncated = _distinct(sorted(verbs))
    privilege_verbs = [v for v in command_verbs if v in UEBA_PRIVILEGE_VERBS]
    stamps = (
        [row.created_at for row in risks]
        + [row.started_at for row in sessions]
        + [row.created_at for row in commands]
        + [row.created_at for row in incidents]
    )
    first, last = min(stamps), max(stamps)
    days_span = max(1, min(window_days, (now - first).days + 1))
    return {
        "hours": hours,
        "devices": devices,
        "source_ips": source_ips,
        "targets": targets,
        "protocols": protocols,
        "command_verbs": command_verbs,
        "privilege_verbs": privilege_verbs,
        "devices_truncated": devices_truncated,
        "source_ips_truncated": ips_truncated,
        "targets_truncated": targets_truncated,
        "command_verbs_truncated": verbs_truncated,
        "sessions": len(sessions),
        "evaluations": len(risks),
        "incidents": len(incidents),
        "samples": samples,
        "sessions_per_day": round(len(sessions) / days_span, 2),
        "first_at": first.isoformat(),
        "last_at": last.isoformat(),
    }


def train_behavior_baselines(
    *, subject: Optional[str] = None, actor: str = "system"
) -> List[BehaviorBaseline]:
    """Learn (or refresh) behavior baselines from real history.

    Explicitly triggered - the endpoint and the tests - so evaluations stay
    deterministic: a principal's profile is what was recorded, not what the
    moment of scoring happens to look like. With no `subject`, every
    principal with history in the window is trained; principals whose rows
    all aged out lose their baseline rather than keep a stale claim."""
    now = datetime.now()
    since = now - timedelta(days=UEBA_WINDOW_DAYS)
    if subject is not None:
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or len(subject) > 160
        ):
            raise ValidationFailed(
                "'subject' must be a non-empty string (max 160 characters)",
                {"field": "subject"},
            )
        subjects = {subject.strip()}
    else:
        subjects = set(
            row[0]
            for row in db.session.query(RiskEvent.subject).filter(
                RiskEvent.created_at >= since
            )
        )
        subjects |= set(
            row[0]
            for row in db.session.query(PrivilegedSession.actor).filter(
                PrivilegedSession.started_at >= since
            )
        )
        subjects |= set(
            row[0]
            for row in db.session.query(SessionEvent.actor).filter(
                SessionEvent.created_at >= since, SessionEvent.type == "command"
            )
        )
        subjects |= set(
            row[0]
            for row in db.session.query(CommandIncident.actor).filter(
                CommandIncident.created_at >= since
            )
        )
        subjects = {name for name in subjects if name and name.strip()}

    trained: List[BehaviorBaseline] = []
    for name in sorted(subjects):
        profile = _learn_behavior_profile(name, now=now)
        row = BehaviorBaseline.query.filter_by(subject=name).first()
        if not profile:
            if row is not None:  # every learned row aged out of the window
                db.session.delete(row)
            continue
        if row is None:
            row = BehaviorBaseline(subject=name, created_at=now)
            db.session.add(row)
        row.window_days = UEBA_WINDOW_DAYS
        row.samples = int(profile["samples"])
        row.profile = profile
        row.trained_by = actor
        row.updated_at = now
        trained.append(row)
    db.session.commit()
    return trained


def list_behavior_baselines() -> Dict[str, Any]:
    """Every trained baseline, newest profile state first by subject."""
    rows = BehaviorBaseline.query.order_by(BehaviorBaseline.subject).all()
    return {
        "total": len(rows),
        "window_days": UEBA_WINDOW_DAYS,
        "baselines": [row.to_dict() for row in rows],
    }


def list_anomaly_events(
    *,
    subject: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Recorded UEBA incidents (architecture section 11), newest first."""
    if not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValidationFailed(
            "'limit' must be between 1 and 200", {"field": "limit"}
        )
    if not isinstance(offset, int) or offset < 0:
        raise ValidationFailed("'offset' must be >= 0", {"field": "offset"})
    query = AnomalyEvent.query
    if subject is not None:
        if not isinstance(subject, str) or not subject.strip():
            raise ValidationFailed(
                "'subject' must be a non-empty string", {"field": "subject"}
            )
        query = query.filter(AnomalyEvent.subject == subject.strip())
    total = query.count()
    rows = (
        query.order_by(AnomalyEvent.created_at.desc(), AnomalyEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {"total": total, "anomalies": [row.to_dict() for row in rows]}


def _behavior_deviations(
    profile: Dict[str, Any],
    *,
    now: datetime,
    device: str,
    source_ip: str,
    target_host: str,
    command: str,
) -> List[str]:
    """The section-11 "Reasons:" list: every dimension a trained profile
    knows is checked against the request; a dimension with no recorded data
    (or a truncated list) is skipped - no baseline data, no claim."""
    reasons: List[str] = []
    if profile.get("hours") and now.hour not in profile["hours"]:
        reasons.append("unusual time")
    if (
        device
        and profile.get("devices")
        and not profile.get("devices_truncated")
        and device.strip().lower() not in {d.lower() for d in profile["devices"]}
    ):
        reasons.append("unusual device")
    if (
        source_ip
        and profile.get("source_ips")
        and not profile.get("source_ips_truncated")
        and source_ip.strip() not in set(profile["source_ips"])
    ):
        reasons.append("unusual IP")
    if (
        target_host
        and profile.get("targets")
        and not profile.get("targets_truncated")
        and target_host.strip().lower() not in set(profile["targets"])
    ):
        reasons.append("unusual target")
    verb = _command_verb(command)
    if (
        verb
        and profile.get("command_verbs")
        and not profile.get("command_verbs_truncated")
        and verb not in set(profile["command_verbs"])
    ):
        reasons.append("unusual command")
    if (
        verb in UEBA_PRIVILEGE_VERBS
        and not profile.get("privilege_verbs")
        and not profile.get("command_verbs_truncated")
    ):
        reasons.append("unusual privilege")
    return reasons


def _evaluation_reasons(risk: RiskEvent) -> List[str]:
    """The named deviations recorded on an evaluation's behavior component."""
    for component in risk.components or []:
        if isinstance(component, dict) and component.get("component") == "behavior":
            return [str(reason) for reason in component.get("reasons") or []]
    return []


def _anomaly_response(
    risk: RiskEvent, *, actor: str, item_id: Optional[int] = None
) -> Dict[str, Any]:
    """The section-11 chain for a critical deviation evaluation. The start
    is already refused (BLOCK SESSION); the principal's other active
    sessions now end through the release-and-rotate cascade (ROTATE
    CREDENTIAL), the credential this request sought is rotated through the
    real module-5 pipeline, and the incident row is committed as evidence -
    its ledger fan-in (source `risk`, action `anomaly-incident`) is the SOC
    ALERT, reaching SIEM when section 20 is configured. Every failure is
    reported on the incident, never hidden."""
    reasons = _evaluation_reasons(risk)
    ref = f"anom-{secrets.token_hex(4)}"
    actions: Dict[str, Any] = {
        "blocked": True,
        "sessions_ended": [],
        "rotations": [],
        "notes": [],
    }
    others = (
        PrivilegedSession.query.filter(
            PrivilegedSession.actor == risk.subject,
            PrivilegedSession.status.notin_(SESSION_TERMINAL_STATUSES),
        )
        .order_by(PrivilegedSession.id)
        .all()
    )
    for other in others:
        try:
            _ended, cascade = end_session(
                other.id,
                actor=actor,
                outcome="terminated",
                payload={"reason": f"behavior anomaly {ref}"},
            )
            actions["sessions_ended"].append(other.session_ref)
            if cascade.get("rotated"):
                actions["rotations"].append(
                    {
                        "item_id": other.item_id,
                        "secret_version": cascade.get("secret_version"),
                        "via": f"session {other.session_ref}",
                    }
                )
        except APIError as exc:
            actions["notes"].append(
                f"session {other.session_ref} not ended: {exc.message}"
            )
    if item_id is not None:
        try:
            _item, rotation = rotate_vault_item(
                item_id,
                actor=actor,
                trigger="anomaly",
                extra_detail={"reason": f"behavior anomaly {ref}"},
            )
            actions["rotations"].append(
                {
                    "item_id": item_id,
                    "secret_version": rotation.get("secret_version"),
                    "via": "requested credential",
                }
            )
        except Exception as exc:  # noqa: BLE001 - a failed rotation is reported
            actions["notes"].append(f"credential {item_id} not rotated: {exc}")
    else:
        host = _target_host(risk.target)
        if host:
            forced = _force_target_rotation(
                host, actor=actor, trigger="anomaly", reason=f"behavior anomaly {ref}"
            )
            # `_force_target_rotation` reports its successes under `items`
            # (id/name/version); the incident records them beside the
            # cascade entries in the same `item_id`/`secret_version` shape,
            # so every rotation the chain actually performed is listed.
            actions["rotations"].extend(
                {
                    "item_id": entry.get("id"),
                    "secret_version": entry.get("version"),
                    "via": f"target {host}",
                }
                for entry in forced.get("items", [])
            )
            for skipped in forced.get("skipped", []):
                actions["notes"].append(
                    f"credential {skipped.get('id')} not rotated: "
                    f"{skipped.get('reason')}"
                )
            for failed in forced.get("failed", []):
                actions["notes"].append(
                    f"credential {failed.get('id')} not rotated: {failed.get('error')}"
                )
        else:
            actions["notes"].append("no credential linked to this request to rotate")
    incident = AnomalyEvent(
        incident_ref=ref,
        evaluation_id=risk.id,
        actor=actor,
        subject=risk.subject,
        target=risk.target or "",
        score=risk.score,
        band=risk.band,
        reasons=reasons,
        actions=actions,
        created_at=datetime.now(),
    )
    db.session.add(incident)
    db.session.commit()
    return incident.to_dict()


def _score_risk(
    *,
    subject: str,
    target: str,
    device: str,
    source_ip: str,
    ticket: str,
    command: str,
    now: datetime,
    baseline: Optional[Dict[str, Any]] = None,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Score one request: eight measured components, honest details, total.

    The behavior component carries the section-11 anomaly factor: when the
    subject has a trained baseline, every dimension the request deviates on
    (unusual time/device/IP/target/command/privilege) adds
    `RISK_ANOMALY_POINTS` and is named on the component's `reasons`."""
    components: List[Dict[str, Any]] = []
    total = 0

    def add(name: str, points: int, detail: str) -> None:
        nonlocal total
        components.append(
            {"component": name, "points": int(points), "detail": detail}
        )
        total += int(points)

    # user: the subject's own critical history (real evaluations, last 24h)
    prior_critical = (
        RiskEvent.query.filter(
            RiskEvent.subject == subject,
            RiskEvent.band == "critical",
            RiskEvent.created_at >= now - timedelta(hours=24),
        )
        .count()
    )
    add(
        "user",
        min(10, 5 * prior_critical),
        (
            f"{prior_critical} critical evaluation(s) for this subject in the last 24h"
            if prior_critical
            else "no critical history for this subject in the last 24h"
        ),
    )

    # device: known to discovery or not (no device reported scores nothing)
    if not device:
        add("device", 0, "no device reported for this request")
    else:
        known = _risk_asset(device) is not None
        add(
            "device",
            0 if known else RISK_DEVICE_UNKNOWN,
            (
                f"device '{device}' is in the discovered inventory"
                if known
                else f"device '{device}' is not in the discovered inventory"
            ),
        )

    # asset: the target resolved against the real inventory record
    host = _target_host(target)
    if not target:
        add("asset", 0, "no target supplied")
    else:
        asset = _risk_asset(host)
        if asset is None:
            add(
                "asset",
                0,
                f"target host '{host}' is not in the discovered inventory",
            )
        else:
            points = RISK_ASSET_POINTS.get(asset.risk, 0) + (
                RISK_UNMANAGED_POINTS if asset.pam_status == "unmanaged" else 0
            )
            add(
                "asset",
                points,
                (
                    f"{asset.asset_type} asset {asset.address} - risk "
                    f"{asset.risk}, {asset.pam_status}"
                ),
            )

    # time: the local clock (real - no simulated business hours)
    if now.weekday() >= 5 or now.hour < 8 or now.hour >= 18:
        add(
            "time",
            RISK_OFF_HOURS,
            f"{now.strftime('%A %H:%M')} local - outside business hours",
        )
    else:
        add("time", 0, f"{now.strftime('%A %H:%M')} local - business hours")

    # location: source address classification only (no geo feed is claimed)
    if not source_ip:
        add("location", 0, "no source address on this request")
    else:
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            add("location", 0, f"'{source_ip}' is not a valid IP address")
        else:
            add(
                "location",
                RISK_PUBLIC_SOURCE if address.is_global else 0,
                (
                    f"{source_ip} is outside the private ranges "
                    "(no geo feed configured)"
                    if address.is_global
                    else f"{source_ip} is in a private range"
                ),
            )

    # behavior: what this subject has actually done in the last 24h, plus
    # (section 11) how far this request deviates from their trained baseline
    blocked = (
        SessionEvent.query.filter(
            SessionEvent.actor == subject,
            SessionEvent.decision == "block",
            SessionEvent.created_at >= now - timedelta(hours=24),
        )
        .count()
    )
    denied = (
        JitRequest.query.filter(
            JitRequest.requester == subject,
            JitRequest.status == "denied",
            JitRequest.created_at >= now - timedelta(hours=24),
        )
        .count()
    )
    points = (RISK_BEHAVIOR_BLOCKED if blocked else 0) + (
        RISK_BEHAVIOR_DENIED if denied else 0
    )
    summary = (
        f"{blocked} blocked command(s) and {denied} denied request(s) "
        "by this subject in the last 24h"
    )
    # each named deviation against the baseline is worth RISK_ANOMALY_POINTS
    # and is listed verbatim on the component's `reasons`
    deviations = (
        _behavior_deviations(
            baseline,
            now=now,
            device=device,
            source_ip=source_ip,
            target_host=_target_host(target),
            command=command,
        )
        if baseline
        else []
    )
    if deviations:
        points += RISK_ANOMALY_POINTS * len(deviations)
        summary += (
            " · baseline deviation: "
            + ", ".join(f"+ {reason}" for reason in deviations)
            + f" ({RISK_ANOMALY_POINTS} points each)"
        )
    add("behavior", points, summary)
    if deviations:
        components[-1]["reasons"] = deviations

    # ticket: shape first, then - when an ITSM instance is configured (section
    # 20) - a real verification against it: the component gains a `verified`
    # flag, unconfigured stays shape-only and labelled so
    if not ticket:
        add("ticket", 0, "no ticket supplied")
    else:
        shape_ok = bool(_JIT_TICKET_RE.match(ticket))
        check = itsm_verify_ticket(ticket, actor="risk-engine", record=False)
        if not check["configured"]:
            if shape_ok:
                add("ticket", 0, f"'{ticket}' matches the ITSM reference shape")
            else:
                add("ticket", RISK_TICKET_SHAPE, "ticket is not an ITSM-style reference")
        elif check["verified"]:
            add(
                "ticket",
                0,
                f"'{ticket}' verified against {check['vendor']} ({check['detail']})",
            )
            components[-1]["verified"] = True
        elif shape_ok:
            add(
                "ticket",
                0,
                f"'{ticket}' matches the ITSM reference shape; "
                f"verification failed: {check['detail']}",
            )
            components[-1]["verified"] = False
        else:
            add(
                "ticket",
                RISK_TICKET_SHAPE,
                f"ticket is not an ITSM-style reference; "
                f"verification failed: {check['detail']}",
            )
            components[-1]["verified"] = False

    # command: the live command policy (the same engine judging session
    # commands) - a block is the strongest signal this component carries
    if not command:
        add("command", 0, "no command supplied")
    else:
        verdict = evaluate_command(command, target)
        rule = verdict.get("rule") or {}
        add(
            "command",
            RISK_COMMAND_POINTS.get(verdict["decision"], 0),
            (
                f"'{rule.get('name')}' returns {verdict['decision']} "
                "for this command"
                if verdict["matched"]
                else "no rule matches this command (default allow)"
            ),
        )

    # section 11: the behavior component can now carry baseline deviations
    # (up to 45 points), so the measured sum can exceed 100 - the score
    # clamps there (bands and the /100 display hold) and says so.
    if total > 100:
        measured = total
        total = 100
        for component in components:
            if component["component"] == "behavior":
                component["detail"] += (
                    f" · measured sum {measured}; score clamps at 100"
                )
    return total, components


def evaluate_risk(
    payload: Any,
    *,
    actor: str,
    context: str = RISK_CONTEXT_MANUAL,
    approved_grant: Optional[JitRequest] = None,
) -> RiskEvent:
    """Score one access request for real and record the evaluation.

    The row commits on its own: a refused session start keeps its
    evaluation (SOC evidence in the audit ledger) even though no session
    follows. Console evaluations (context `manual`) only advise; a session
    start is allowed or refused by its band - CRITICAL outright, HIGH on
    the approval of an active JIT grant, MEDIUM on a valid TOTP code when
    a factor is enrolled (section 20), each recorded with its reason on
    the `integration` trail.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    subject = _risk_text(payload, "subject", required=True, max_length=160)
    target = _risk_text(payload, "target", max_length=255)
    device = _risk_text(payload, "device", max_length=128)
    source_ip = _risk_text(payload, "source_ip", max_length=64)
    ticket = _risk_text(payload, "ticket", max_length=64)
    command = _risk_text(payload, "command", max_length=1000)
    mfa_code = _risk_text(payload, "mfa_code", max_length=32)

    now = datetime.now()
    # section 11: the subject's trained baseline, if one exists - evaluations
    # only ever diff against a stored profile, never a fresh guess
    baseline_row = BehaviorBaseline.query.filter_by(subject=subject).first()
    score, components = _score_risk(
        subject=subject,
        target=target,
        device=device,
        source_ip=source_ip,
        ticket=ticket,
        command=command,
        now=now,
        baseline=(baseline_row.profile or {}) if baseline_row is not None else None,
    )
    band = _risk_band(score)
    decision = RISK_DECISION_BY_BAND[band]

    gate: Optional[Dict[str, Any]] = None
    if context == RISK_CONTEXT_SESSION_START:
        if band == "critical":
            result = "refused"  # CRITICAL: block, no exceptions
        elif band == "high":
            # HIGH: approval - an active JIT grant (signed off by someone
            # other than the requester) is the approval this gate accepts
            result = (
                "allowed"
                if approved_grant is not None and approved_grant.status == "active"
                else "refused"
            )
        elif decision == "mfa":
            # MEDIUM: the section-20 factor judges the start - a valid
            # TOTP code when a factor is enrolled, honest advisory when
            # there is none
            passed, outcome, reason = _mfa_gate(mfa_code)
            result = "allowed" if passed else "refused"
            gate = {"outcome": outcome, "reason": reason}
        else:
            result = "allowed"
    else:
        result = "advisory"

    evaluation = RiskEvent(
        actor=actor,
        subject=subject,
        context=context,
        target=target,
        device=device,
        source_ip=source_ip,
        ticket=ticket,
        command=command,
        score=score,
        band=band,
        decision=decision,
        result=result,
        components=components,
    )
    db.session.add(evaluation)
    if gate is not None:
        # every medium-band start records how the factor judged it - the
        # evaluation row carries score/band/result, this carries the reason
        _integration_event(
            "mfa-gate",
            actor,
            subject,
            {**gate, "context": context, "target": target, "risk_result": result},
        )
    db.session.commit()
    return evaluation


def list_risk_evaluations(
    *,
    band: Optional[str] = None,
    context: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> Tuple[List[RiskEvent], int]:
    query = RiskEvent.query
    if band is not None and band not in RISK_LEVELS:
        raise ValidationFailed(
            f"Unknown risk band '{band}'",
            {"field": "band", "allowed": list(RISK_LEVELS)},
        )
    if context is not None and context not in RISK_CONTEXTS:
        raise ValidationFailed(
            f"Unknown risk context '{context}'",
            {"field": "context", "allowed": list(RISK_CONTEXTS)},
        )
    if band:
        query = query.filter_by(band=band)
    if context:
        query = query.filter_by(context=context)
    total = query.count()
    rows = (
        query.order_by(RiskEvent.created_at.desc(), RiskEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def risk_stats() -> Dict[str, Any]:
    """Real aggregates over the evaluations (the screen's risk cards)."""
    rows = RiskEvent.query.all()
    by_band = {name: 0 for name in RISK_LEVELS}
    by_decision = {name: 0 for name in RISK_DECISIONS}
    by_result = {name: 0 for name in RISK_RESULTS}
    by_context = {name: 0 for name in RISK_CONTEXTS}
    for row in rows:
        by_band[row.band] = by_band.get(row.band, 0) + 1
        by_decision[row.decision] = by_decision.get(row.decision, 0) + 1
        by_result[row.result] = by_result.get(row.result, 0) + 1
        by_context[row.context] = by_context.get(row.context, 0) + 1
    newest = RiskEvent.query.order_by(RiskEvent.id.desc()).first()
    return {
        "total": len(rows),
        "by_band": by_band,
        "by_decision": by_decision,
        "by_result": by_result,
        "by_context": by_context,
        "refused": by_result.get("refused", 0),
        "avg_score": (
            round(sum(row.score for row in rows) / len(rows), 1) if rows else None
        ),
        "last_evaluated_at": newest.created_at.isoformat() if newest else None,
    }


# ---------------------------------------------------------------------------
# PAM bypass detection (architecture section 10)
# ---------------------------------------------------------------------------
_BYPASS_MAX_CONTENT = 200_000
_BYPASS_MAX_RAW = 2_000
# OpenSSH auth line: "Accepted password for admin01 from 10.10.5.20 port 22"
_BYPASS_SSHD = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+\d+"
)


def _bypass_event(
    action: str, subject: str, actor: str, detail: Dict[str, Any]
) -> BypassEvent:
    """Queue one section-10 action record; the flush listener folds it into
    the audit ledger under the ninth source `bypass` in the same commit."""
    event = BypassEvent(action=action, actor=actor, subject=subject, detail=detail)
    db.session.add(event)
    return event


def _bypass_timestamp(raw: str, now: datetime) -> Tuple[datetime, str]:
    """The line's own timestamp when it has one (ISO 8601), otherwise the
    ingest time - which of the two it was is recorded as `at_source`."""
    if not raw:
        return now, "ingest_time"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return now, "ingest_time"
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed, "line"


def _parse_bypass_line(
    line: str, *, fallback_target: str, now: datetime
) -> Tuple[Optional[Dict[str, Any]], str]:
    """One log line -> signal fields, or the reason it was skipped.

    Two real formats are accepted: structured JSON records (Windows / EDR /
    network telemetry exports that carry their own target and timestamp) and
    OpenSSH `Accepted ...` auth lines (whose target is the host the log
    bundle came from, passed with the ingest). Anything else is counted as
    malformed and never invented into a signal.
    """
    stripped = line.strip()
    if not stripped:
        return None, "blank"
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            return None, "malformed"
        if not isinstance(obj, dict):
            return None, "malformed"
        user = str(obj.get("user") or obj.get("username") or "").strip()
        source_ip = str(
            obj.get("source_ip") or obj.get("source") or obj.get("ip") or ""
        ).strip()
        target = (
            str(obj.get("target") or obj.get("host") or "").strip()
            or fallback_target.strip()
        )
        if not user or not source_ip:
            return None, "malformed"
        if not target:
            return None, "untargeted"
        observed_at, at_source = _bypass_timestamp(
            str(obj.get("at") or obj.get("timestamp") or ""), now
        )
        return {
            "user": user[:128],
            "source_ip": source_ip[:64],
            "target": target[:255],
            "protocol": str(obj.get("protocol") or "unknown").strip().lower()[:16]
            or "unknown",
            "observed_at": observed_at,
            "at_source": at_source,
        }, None
    match = _BYPASS_SSHD.search(stripped)
    if match:
        target = fallback_target.strip()
        if not target:
            return None, "untargeted"
        return {
            "user": match.group("user")[:128],
            "source_ip": match.group("source_ip")[:64],
            "target": target[:255],
            "protocol": "ssh",
            "observed_at": now,
            "at_source": "ingest_time",
        }, None
    return None, "malformed"


def ingest_bypass_signals(payload: Any, *, actor: str) -> Dict[str, Any]:
    """Parse a real log bundle into connection observations (the section-10
    source material: Windows event logs, Linux auth.log, SSH/RDP logs ...).

    Nothing is correlated here - lines are kept as evidence with their
    original text, and a later scan decides what they mean.
    """
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    origin = _required_text(payload, "origin", 128)
    target = _optional_text(payload, "target", 255)
    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValidationFailed("Log content is required", {"field": "content"})
    if len(content) > _BYPASS_MAX_CONTENT:
        raise ValidationFailed(
            f"Log content exceeds {_BYPASS_MAX_CONTENT} characters",
            {"field": "content", "max": _BYPASS_MAX_CONTENT},
        )

    now = datetime.now()
    lines = content.splitlines()
    parsed = malformed = untargeted = duplicates = stored = 0
    batch: set = set()
    for line in lines:
        row, reason = _parse_bypass_line(
            line, fallback_target=target, now=now
        )
        if row is None:
            if reason == "malformed":
                malformed += 1
            elif reason == "untargeted":
                untargeted += 1
            continue
        parsed += 1
        raw = line.strip()[:_BYPASS_MAX_RAW]
        key = (row["user"], row["source_ip"], row["target"], raw)
        if key in batch:
            duplicates += 1
            continue
        batch.add(key)
        exists = BypassSignal.query.filter_by(
            origin=origin, target=row["target"], raw=raw
        ).first()
        if exists is not None:
            duplicates += 1
            continue
        db.session.add(
            BypassSignal(
                observed_at=row["observed_at"],
                user=row["user"],
                source_ip=row["source_ip"],
                target=row["target"],
                protocol=row["protocol"],
                origin=origin,
                raw=raw,
                detail={"at_source": row["at_source"]},
            )
        )
        stored += 1

    detail = {
        "origin": origin,
        "target": target,
        "lines": len(lines),
        "parsed": parsed,
        "stored": stored,
        "malformed": malformed,
        "untargeted": untargeted,
        "duplicates": duplicates,
    }
    _bypass_event("ingested", origin, actor, detail)
    db.session.commit()
    return detail


def list_bypass_signals(
    *,
    status: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[BypassSignal], int]:
    """Parsed observations, newest first (status filter + text search over
    user, source IP, target and origin)."""
    if status is not None and status not in BYPASS_SIGNAL_STATUSES:
        raise ValidationFailed(
            f"Unknown signal status '{status}'",
            {"field": "status", "allowed": list(BYPASS_SIGNAL_STATUSES)},
        )
    query = BypassSignal.query
    if status:
        query = query.filter(BypassSignal.status == status)
    if q:
        needle = f"%{q.lower()}%"
        query = query.filter(
            db.or_(
                db.func.lower(BypassSignal.user).like(needle),
                db.func.lower(BypassSignal.source_ip).like(needle),
                db.func.lower(BypassSignal.target).like(needle),
                db.func.lower(BypassSignal.origin).like(needle),
            )
        )
    total = query.count()
    rows = (
        query.order_by(BypassSignal.created_at.desc(), BypassSignal.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def _force_target_rotation(
    host: str, *, actor: str, trigger: str, reason: str
) -> Dict[str, Any]:
    """Force credential rotation for a target through the real module-5
    pipeline, never a simulated one - shared by the section-10 ACTION and
    the section-17 close step. One credential failing must not abort the
    pass, so every outcome is recorded and the loop continues."""
    rotated: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    for item in VaultItem.query.all():
        if _target_host(item.target).lower() != host.lower():
            continue
        if item.status == VAULT_STATUS_CHECKED_OUT:
            skipped.append({"id": item.id, "name": item.name, "reason": "checked_out"})
            continue
        if item.status == VAULT_STATUS_ROTATING:
            skipped.append(
                {"id": item.id, "name": item.name, "reason": "already_rotating"}
            )
            continue
        try:
            _, rotation = rotate_vault_item(
                item.id,
                actor=actor,
                trigger=trigger,
                extra_detail={"reason": reason},
            )
            rotated.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "version": rotation.get("secret_version"),
                }
            )
        except Exception as exc:  # noqa: BLE001 - keep the pass running
            failed.append({"id": item.id, "name": item.name, "error": str(exc)})
    if not rotated and not skipped and not failed:
        return {
            "status": "no_credential_on_file",
            "detail": "No vault credential is registered for this target",
            "items": [],
            "skipped": [],
            "failed": [],
        }
    return {
        "status": "rotated" if rotated else ("failed" if failed else "skipped"),
        "items": rotated,
        "skipped": skipped,
        "failed": failed,
    }


def _force_bypass_rotation(host: str, *, actor: str) -> Dict[str, Any]:
    """Section-10 ACTION: force credential rotation for the bypassed target."""
    return _force_target_rotation(
        host,
        actor=actor,
        trigger="bypass",
        reason="direct access to a managed target (architecture 10)",
    )


def _new_bypass_ref() -> str:
    for _ in range(6):
        ref = f"byp-{secrets.token_hex(4)}"
        if BypassIncident.query.filter_by(incident_ref=ref).first() is None:
            return ref
    raise APIError(500, "Could not allocate a unique incident reference")


def scan_bypass_signals(*, actor: str) -> Dict[str, Any]:
    """Correlate every unscanned observation against the managed inventory
    and the recorded sessions (architecture section 10).

    Outcomes per signal: target not a managed asset -> `out_of_scope`; a
    recorded session covering the same user, host and moment -> `covered`
    (it went through PAM); otherwise `candidate` - an incident opens with
    the architecture's ACTION block (alert SOC, force rotation, block
    source recorded honestly as not connected).
    """
    signals = (
        BypassSignal.query.filter_by(status=BYPASS_SIGNAL_OBSERVED)
        .order_by(BypassSignal.id.asc())
        .all()
    )
    scanned = len(signals)
    covered = out_of_scope = candidates = 0
    incidents = 0
    rotations_forced = 0

    for signal in signals:
        host = _target_host(signal.target).lower()
        asset = None
        if host:
            asset = (
                DiscoveredAsset.query.filter(
                    db.func.lower(DiscoveredAsset.address) == host,
                    DiscoveredAsset.pam_status == "managed",
                ).first()
                or DiscoveredAsset.query.filter(
                    db.func.lower(DiscoveredAsset.hostname) == host,
                    DiscoveredAsset.pam_status == "managed",
                ).first()
            )
        detail = dict(signal.detail or {})
        if asset is None:
            signal.status = BYPASS_SIGNAL_OUT_OF_SCOPE
            detail["reason"] = "target is not a managed PAM asset"
            detail["asset_id"] = None
            signal.detail = detail
            out_of_scope += 1
            continue

        observed_at = signal.observed_at or signal.created_at
        covering = None
        if signal.user:
            for session in PrivilegedSession.query.filter(
                PrivilegedSession.actor == signal.user
            ).all():
                if _target_host(session.target).lower() != host:
                    continue
                started = session.started_at or session.created_at
                if started > observed_at:
                    continue
                if session.ended_at is not None and session.ended_at < observed_at:
                    continue
                covering = session
                break
        if covering is not None:
            signal.status = BYPASS_SIGNAL_COVERED
            detail["reason"] = "covered by a recorded privileged session"
            detail["session_ref"] = covering.session_ref
            signal.detail = detail
            covered += 1
            continue

        rotation = _force_bypass_rotation(host, actor=actor)
        if rotation["status"] == "rotated":
            rotations_forced += 1
        signal.status = BYPASS_SIGNAL_CANDIDATE
        detail["reason"] = "managed target reached with no recorded session"
        detail["asset_id"] = asset.id
        detail["asset_address"] = asset.address
        signal.detail = detail

        incident = BypassIncident(
            incident_ref=_new_bypass_ref(),
            signal_id=signal.id,
            user=signal.user,
            source_ip=signal.source_ip,
            target=signal.target,
            protocol=signal.protocol,
            observed_at=observed_at,
            actions={
                "alert": {
                    "status": "recorded",
                    "detail": "SOC alert recorded in the audit ledger (source 'bypass')",
                },
                "rotation": rotation,
                "block_source": {
                    "status": "not_connected",
                    "detail": "No firewall/EDR enforcement connector is configured",
                },
            },
        )
        db.session.add(incident)
        _bypass_event(
            "detected",
            incident.incident_ref,
            actor,
            {
                "signal_id": signal.id,
                "user": signal.user,
                "source_ip": signal.source_ip,
                "target": signal.target,
                "protocol": signal.protocol,
                "asset_id": asset.id,
                "rotation": rotation["status"],
            },
        )
        candidates += 1
        incidents += 1

    _bypass_event(
        "scanned",
        "signals",
        actor,
        {
            "scanned": scanned,
            "covered": covered,
            "out_of_scope": out_of_scope,
            "candidates": candidates,
            "incidents": incidents,
            "rotations_forced": rotations_forced,
        },
    )
    db.session.commit()
    return {
        "scanned": scanned,
        "covered": covered,
        "out_of_scope": out_of_scope,
        "candidates": candidates,
        "incidents": incidents,
        "rotations_forced": rotations_forced,
    }


def list_bypass_incidents(
    *, status: Optional[str] = None, limit: int = 50, offset: int = 0
) -> Tuple[List[BypassIncident], int]:
    """Detected direct-access incidents, newest first."""
    if status is not None and status not in ("open", "closed", "all"):
        raise ValidationFailed(
            f"Unknown incident status '{status}'",
            {"field": "status", "allowed": ["open", "closed", "all"]},
        )
    query = BypassIncident.query
    if status in BYPASS_INCIDENT_STATUSES:
        query = query.filter(BypassIncident.status == status)
    total = query.count()
    rows = (
        query.order_by(BypassIncident.created_at.desc(), BypassIncident.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def get_bypass_incident(
    incident_id: int,
) -> Tuple[BypassIncident, Optional[BypassSignal]]:
    incident = BypassIncident.query.filter_by(id=incident_id).first()
    if incident is None:
        raise NotFound(f"No bypass incident with id {incident_id}")
    signal = BypassSignal.query.filter_by(id=incident.signal_id).first()
    return incident, signal


def close_bypass_incident(
    incident_id: int, payload: Any, *, actor: str
) -> BypassIncident:
    """Analyst closure - the close writes no incident row of its own, so it
    gets its own ledger record in the same transaction."""
    incident, _ = get_bypass_incident(incident_id)
    if incident.status == "closed":
        raise Conflict(
            "Incident already closed",
            {"field": "status", "status": "closed"},
        )
    if payload is not None and not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    note = _optional_text(payload or {}, "note", 255)
    incident.status = "closed"
    incident.closed_by = actor
    incident.closed_at = datetime.now()
    incident.close_note = note
    _bypass_event(
        "closed",
        incident.incident_ref,
        actor,
        {
            "note": note,
            "user": incident.user,
            "source_ip": incident.source_ip,
            "target": incident.target,
        },
    )
    db.session.commit()
    return incident


def bypass_stats() -> Dict[str, Any]:
    """Real aggregates over signals, incidents and the module's ledger
    actions (the Command Center bypass cards)."""
    signals = {"total": 0}
    for status in BYPASS_SIGNAL_STATUSES:
        signals[status] = 0
    for status, count in (
        db.session.query(BypassSignal.status, db.func.count(BypassSignal.id))
        .group_by(BypassSignal.status)
        .all()
    ):
        signals[status] = int(count)
        signals["total"] += int(count)

    incidents = {"total": 0, "open": 0, "closed": 0}
    for status, count in (
        db.session.query(BypassIncident.status, db.func.count(BypassIncident.id))
        .group_by(BypassIncident.status)
        .all()
    ):
        incidents[status] = int(count)
        incidents["total"] += int(count)

    rotations_forced = sum(
        1
        for (actions,) in db.session.query(BypassIncident.actions).all()
        if ((actions or {}).get("rotation") or {}).get("status") == "rotated"
    )

    actions = {"ingested": 0, "scanned": 0, "detected": 0, "closed": 0}
    last_ingest = last_scan = None
    for action, count, latest in db.session.query(
        BypassEvent.action,
        db.func.count(BypassEvent.id),
        db.func.max(BypassEvent.created_at),
    ).group_by(BypassEvent.action).all():
        actions[action] = int(count)
        if action == "ingested":
            last_ingest = latest
        elif action == "scanned":
            last_scan = latest

    return {
        "signals": signals,
        "incidents": incidents,
        "rotations_forced": rotations_forced,
        "actions": actions,
        "last_ingest_at": last_ingest.isoformat() if last_ingest else None,
        "last_scan_at": last_scan.isoformat() if last_scan else None,
    }


# ---------------------------------------------------------------------------
# break glass (architecture section 17)
# ---------------------------------------------------------------------------
def _break_glass_event(
    action: str, subject: str, actor: str, detail: Dict[str, Any]
) -> BreakGlassEvent:
    """Queue one section-17 action record; the flush listener folds it into
    the audit ledger under the tenth source `break-glass` in the same
    commit - the emergency process itself is auditable."""
    event = BreakGlassEvent(action=action, actor=actor, subject=subject, detail=detail)
    db.session.add(event)
    return event


def _new_break_glass_ref() -> str:
    for _ in range(6):
        ref = f"bg-{secrets.token_hex(4)}"
        if BreakGlassRequest.query.filter_by(request_ref=ref).first() is None:
            return ref
    raise APIError(500, "Could not allocate a break-glass request reference")


def get_break_glass_request(request_id: int) -> BreakGlassRequest:
    """Fetch one request row or raise 404."""
    request = BreakGlassRequest.query.filter_by(id=request_id).first()
    if request is None:
        raise NotFound(f"No break-glass request with id {request_id}")
    return request


def list_break_glass_approvals(request_id: int) -> List[BreakGlassApproval]:
    """The append-only signatures recorded on one request."""
    return (
        BreakGlassApproval.query.filter_by(request_id=request_id)
        .order_by(BreakGlassApproval.id.asc())
        .all()
    )


def break_glass_view(request: BreakGlassRequest) -> Dict[str, Any]:
    """The row the screens read: request fields plus its approval snapshots
    and the dual-approval progress."""
    approvals = list_break_glass_approvals(request.id)
    data = request.to_dict()
    data["approvals"] = [row.to_dict() for row in approvals]
    data["approvals_required"] = 2
    data["approvals_signed"] = len(approvals)
    return data


def create_break_glass_request(payload: Any, *, actor: str) -> BreakGlassRequest:
    """File one emergency request (architecture section 17).

    The operator's reason, severity and target are recorded verbatim and
    the request waits for two distinct approvals. MFA is recorded exactly
    as it stands: `not configured` without a factor, `required at open`
    when one is enrolled (the release will demand a valid code - section
    20), never a fake challenge."""
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")

    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValidationFailed("'reason' is required", {"field": "reason"})
    reason = reason.strip()
    if len(reason) > 1000:
        raise ValidationFailed(
            "'reason' must be at most 1000 characters",
            {"field": "reason", "max_length": 1000},
        )

    target = payload.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValidationFailed("'target' is required", {"field": "target"})
    target = target.strip()
    if len(target) > 255:
        raise ValidationFailed(
            "'target' must be at most 255 characters", {"field": "target"}
        )

    severity = payload.get("severity", "sev1")
    if severity not in BREAK_GLASS_SEVERITIES:
        raise ValidationFailed(
            f"Unknown severity '{severity}'",
            {"field": "severity", "allowed": list(BREAK_GLASS_SEVERITIES)},
        )

    protocol = payload.get("protocol", "ssh")
    if not isinstance(protocol, str):
        raise ValidationFailed("'protocol' must be a string", {"field": "protocol"})
    protocol = protocol.strip().lower()
    if protocol not in SESSION_PROTOCOLS:
        raise ValidationFailed(
            "Unknown protocol",
            {"field": "protocol", "allowed": list(SESSION_PROTOCOLS)},
        )

    request = BreakGlassRequest(
        request_ref=_new_break_glass_ref(),
        reason=reason,
        severity=severity,
        target=target,
        protocol=protocol,
        requested_by=actor,
        mfa="required at open" if mfa_status()["configured"] else "not configured",
    )
    db.session.add(request)
    db.session.flush()
    _break_glass_event(
        "requested",
        request.request_ref,
        actor,
        {
            "ref": request.request_ref,
            "target": target,
            "severity": severity,
            "protocol": protocol,
            "reason": reason,
            "mfa": request.mfa,
        },
    )
    db.session.commit()
    return request


def list_break_glass_requests(
    *, status: Optional[str] = None, limit: int = 50, offset: int = 0
) -> Tuple[List[BreakGlassRequest], int]:
    """Requests newest first, optionally filtered by one lifecycle status."""
    query = BreakGlassRequest.query
    if status is not None:
        if status not in BREAK_GLASS_STATUSES:
            raise ValidationFailed(
                f"Unknown status '{status}'",
                {"field": "status", "allowed": list(BREAK_GLASS_STATUSES)},
            )
        query = query.filter_by(status=status)
    total = query.count()
    rows = query.order_by(BreakGlassRequest.id.desc()).limit(limit).offset(offset).all()
    return rows, total


def get_break_glass_detail(request_id: int) -> Dict[str, Any]:
    """One request with its signatures and the recorded session it opened
    (null until the emergency credential is released)."""
    request = get_break_glass_request(request_id)
    session = None
    if request.session_id is not None:
        session = PrivilegedSession.query.filter_by(id=request.session_id).first()
    return {
        "request": break_glass_view(request),
        "session": session.to_dict() if session is not None else None,
    }


def approve_break_glass_request(
    request_id: int, *, actor: str, payload: Any = None
) -> Dict[str, Any]:
    """Record one approval signature (architecture section 17, dual
    approval): the requester cannot sign their own emergency, the second
    signature must come from someone else, and two signatures flip the
    request to `approved` - all enforced, never assumed."""
    request = get_break_glass_request(request_id)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    if request.status != "pending":
        raise ValidationFailed(
            f"Request is {request.status}, not awaiting approvals",
            {"field": "status", "status": request.status},
        )
    if actor == request.requested_by:
        raise APIError(403, "Requesters cannot approve their own emergency request")
    existing = list_break_glass_approvals(request.id)
    if any(row.approver == actor for row in existing):
        raise ValidationFailed(
            "This approver has already signed this request",
            {"field": "approver", "approver": actor},
        )

    note = payload.get("note") or ""
    if not isinstance(note, str):
        raise ValidationFailed("'note' must be a string", {"field": "note"})
    note = note.strip()
    if len(note) > 500:
        raise ValidationFailed(
            "'note' must be at most 500 characters",
            {"field": "note", "max_length": 500},
        )

    db.session.add(BreakGlassApproval(request_id=request.id, approver=actor, note=note))
    signed = len(existing) + 1
    if signed >= 2:
        request.status = "approved"
    _break_glass_event(
        "approved",
        request.request_ref,
        actor,
        {
            "ref": request.request_ref,
            "approver": actor,
            "approvals_signed": signed,
            "approvals_required": 2,
            "status": request.status,
        },
    )
    db.session.commit()
    return break_glass_view(request)


def deny_break_glass_request(
    request_id: int, *, actor: str, payload: Any = None
) -> Dict[str, Any]:
    """Turn the request down before anything was released - recorded with
    who/when and (when given) the note, on the `break-glass` trail."""
    request = get_break_glass_request(request_id)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    if request.status != "pending":
        raise ValidationFailed(
            f"Request is {request.status}, not awaiting approvals",
            {"field": "status", "status": request.status},
        )

    note = payload.get("note") or ""
    if not isinstance(note, str):
        raise ValidationFailed("'note' must be a string", {"field": "note"})
    note = note.strip()
    if len(note) > 500:
        raise ValidationFailed(
            "'note' must be at most 500 characters",
            {"field": "note", "max_length": 500},
        )

    request.status = "denied"
    request.denied_by = actor
    request.denied_at = datetime.now()
    request.deny_note = note
    _break_glass_event(
        "denied",
        request.request_ref,
        actor,
        {"ref": request.request_ref, "denied_by": actor, "note": note},
    )
    db.session.commit()
    return break_glass_view(request)


def _break_glass_credential(request: BreakGlassRequest) -> VaultItem:
    """The emergency credential for this target: a free vault item on the
    same host. Nothing is released when the target has no credential or
    none of them is free - the real state, said plainly."""
    host = _target_host(request.target).lower()
    available: List[VaultItem] = []
    blocked: List[Dict[str, Any]] = []
    for item in VaultItem.query.order_by(VaultItem.id.asc()).all():
        if _target_host(item.target).lower() != host:
            continue
        if item.status == VAULT_STATUS_AVAILABLE:
            available.append(item)
        else:
            blocked.append({"id": item.id, "name": item.name, "status": item.status})
    if not available:
        if blocked:
            raise Conflict(
                "No credential for this target is free for emergency use",
                {"field": "item_id", "credentials": blocked},
            )
        raise ValidationFailed(
            "No vault credential is registered for this target",
            {"field": "target", "target": request.target},
        )
    return available[0]


def open_break_glass_request(
    request_id: int, *, actor: str, payload: Any = None
) -> Dict[str, Any]:
    """Release the emergency credential and start its session (architecture
    section 17: unseal -> session recorded -> automatic alert).

    Section-20 emergency authentication first: with a TOTP factor enrolled
    the release demands a valid code before anything is unsealed (recorded
    as `mfa: verified` on the request), without one there is nothing to
    verify - `not configured` stays honest. The credential then goes
    through the real vault checkout and the session runs with `record=true`
    forced - recording is not an operator preference here. The section-7
    risk gate still judges the start and its evaluation commits either
    way: a refusal keeps the request `approved` and releases nothing, and
    the `opened` ledger record it writes (the section-17 automatic alert)
    is the SOC's evidence trail."""
    request = get_break_glass_request(request_id)
    if request.status == "used":
        raise ValidationFailed(
            "The emergency session for this request is already open",
            {"field": "status", "status": request.status},
        )
    if request.status != "approved":
        raise ValidationFailed(
            f"Request is {request.status}; two distinct approvals are "
            "required before opening",
            {"field": "status", "status": request.status},
        )

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    mfa_code = payload.get("mfa_code")
    passed, outcome, reason = _mfa_gate(mfa_code)
    if not passed:
        # refused before anything is unsealed - the refusal itself is SOC
        # evidence on the integration trail
        _integration_event(
            "mfa-gate",
            actor,
            request.request_ref,
            {"outcome": outcome, "reason": reason, "flow": "break-glass-open"},
        )
        db.session.commit()
        raise Unauthorized(
            "Break-glass release requires a valid TOTP code",
            {"field": "mfa_code", "mfa": reason},
        )
    factor_verified = outcome == "verified"

    item = _break_glass_credential(request)
    session, risk = create_session(
        {
            "protocol": request.protocol,
            "target": request.target,
            "item_id": item.id,
            "record": True,
            "mfa_code": mfa_code,
        },
        actor=actor,
    )
    request.status = "used"
    request.session_id = session.id
    request.opened_by = actor
    request.opened_at = datetime.now()
    request.opened_item_id = item.id
    request.opened_secret_version = item.secret_version
    if factor_verified:
        request.mfa = "verified"
    _break_glass_event(
        "opened",
        request.request_ref,
        actor,
        {
            "ref": request.request_ref,
            "session_id": session.id,
            "session_ref": session.session_ref,
            "item_id": item.id,
            "record": True,
            "mfa": request.mfa,
            "risk": {"score": risk.score, "band": risk.band, "result": risk.result},
        },
    )
    db.session.commit()
    return {
        "request": break_glass_view(request),
        "session": session.to_dict(),
        "risk": risk.to_dict(),
    }


def _break_glass_rotation(
    request: BreakGlassRequest, *, actor: str
) -> Dict[str, Any]:
    """Section-17 close step: the credential released for the emergency
    must end this flow rotated. The session-end cascade normally does it;
    this compares the current secret version against the one carried at
    release - unchanged means the rotation is still owed and is forced
    through the real module-5 pipeline now."""
    item = None
    if request.opened_item_id is not None:
        item = VaultItem.query.filter_by(id=request.opened_item_id).first()
    if item is None:
        return {
            "status": "not_applicable",
            "detail": "No emergency credential was released for this request",
        }
    if item.secret_version != request.opened_secret_version:
        return {
            "status": "rotated",
            "performed": "at session end",
            "secret_version": item.secret_version,
        }
    return _force_target_rotation(
        _target_host(request.target),
        actor=actor,
        trigger="break-glass",
        reason="break-glass emergency closed (architecture 17)",
    )


def close_break_glass_request(
    request_id: int, *, actor: str, payload: Any
) -> Dict[str, Any]:
    """Close the emergency (architecture section 17, final steps): end the
    recorded session if it is still running - its release-and-rotate
    cascade fires - guarantee the released credential ends up rotated, and
    file the post-incident review note. The note is required: an emergency
    that is not reviewed is not closed."""
    request = get_break_glass_request(request_id)
    if request.status != "used":
        raise ValidationFailed(
            f"Request is {request.status}; only an open emergency can be closed",
            {"field": "status", "status": request.status},
        )
    if not isinstance(payload, dict):
        raise ValidationFailed("Request body must be a JSON object")
    review = payload.get("review")
    if not isinstance(review, str) or not review.strip():
        raise ValidationFailed(
            "A post-incident review note is required to close the emergency",
            {"field": "review"},
        )
    review = review.strip()
    if len(review) > 1000:
        raise ValidationFailed(
            "'review' must be at most 1000 characters",
            {"field": "review", "max_length": 1000},
        )

    session = None
    if request.session_id is not None:
        session = PrivilegedSession.query.filter_by(id=request.session_id).first()
        if session is not None and session.status not in SESSION_TERMINAL_STATUSES:
            session, _ = end_session(
                session.id,
                actor=actor,
                outcome="completed",
                payload={"reason": "break-glass closed"},
            )

    rotation = _break_glass_rotation(request, actor=actor)

    request.status = "closed"
    request.closed_by = actor
    request.closed_at = datetime.now()
    request.review = review
    _break_glass_event(
        "closed",
        request.request_ref,
        actor,
        {
            "ref": request.request_ref,
            "review": review,
            "rotation": rotation,
            "session_ref": session.session_ref if session is not None else None,
            "session_status": session.status if session is not None else None,
        },
    )
    db.session.commit()
    return {
        "request": break_glass_view(request),
        "session": session.to_dict() if session is not None else None,
        "rotation": rotation,
    }


def break_glass_stats() -> Dict[str, Any]:
    """Real aggregates over requests, signatures and the module's ledger
    actions (the Break-Glass screen header cards)."""
    requests: Dict[str, Any] = {"total": 0}
    for status in BREAK_GLASS_STATUSES:
        requests[status] = 0
    for status, count in (
        db.session.query(
            BreakGlassRequest.status, db.func.count(BreakGlassRequest.id)
        )
        .group_by(BreakGlassRequest.status)
        .all()
    ):
        requests[status] = int(count)
        requests["total"] += int(count)

    # signatures still owed on pending requests (two distinct approvers each)
    pending_ids = [
        row[0]
        for row in db.session.query(BreakGlassRequest.id)
        .filter_by(status="pending")
        .all()
    ]
    signed: Dict[int, int] = {}
    if pending_ids:
        signed = {
            int(request_id): int(count)
            for request_id, count in (
                db.session.query(
                    BreakGlassApproval.request_id,
                    db.func.count(BreakGlassApproval.id),
                )
                .filter(BreakGlassApproval.request_id.in_(pending_ids))
                .group_by(BreakGlassApproval.request_id)
                .all()
            )
        }
    outstanding = sum(max(0, 2 - signed.get(pid, 0)) for pid in pending_ids)
    recorded = BreakGlassApproval.query.count()

    actions = {name: 0 for name in BREAK_GLASS_ACTIONS}
    last_request = last_open = last_close = None
    for action, count, latest in db.session.query(
        BreakGlassEvent.action,
        db.func.count(BreakGlassEvent.id),
        db.func.max(BreakGlassEvent.created_at),
    ).group_by(BreakGlassEvent.action).all():
        actions[action] = int(count)
        if action == "requested":
            last_request = latest
        elif action == "opened":
            last_open = latest
        elif action == "closed":
            last_close = latest

    return {
        "requests": requests,
        "approvals": {"recorded": recorded, "outstanding": outstanding},
        "open_emergencies": requests["used"],
        "actions": actions,
        "last_request_at": last_request.isoformat() if last_request else None,
        "last_opened_at": last_open.isoformat() if last_open else None,
        "last_closed_at": last_close.isoformat() if last_close else None,
    }
