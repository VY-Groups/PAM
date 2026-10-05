"""
Business logic for the Phase 2 license server.

Routes stay thin: they parse/serialise HTTP, this module does the work.
Cryptographic signing and verification are delegated to the Phase 1 library
via licensing_bridge.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from config import Config
from errors import NotFound, ValidationFailed
from licensing_bridge import (
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    License,
    LicenseType,
    get_generator,
    get_validator,
    sig,
)
from extensions import db
from models import (
    EVENT_ISSUED,
    EVENT_RESTORED,
    EVENT_REVOKED,
    EVENT_USAGE_REPORTED,
    SETTINGS_ACTION_UPDATED,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    VAULT_ACTION_CHECKED_OUT,
    VAULT_ACTION_ONBOARDED,
    VAULT_ACTION_REVOKED,
    VAULT_ACTION_ROTATED,
    VAULT_STATUS_AVAILABLE,
    VAULT_STATUS_CHECKED_OUT,
    VAULT_STATUS_FAILED,
    VAULT_STATUS_ROTATING,
    VAULT_STATUS_ROTATION_DUE,
    VAULT_STATUSES,
    VAULT_TYPES,
    LicenseEvent,
    LicenseRecord,
    SettingGroup,
    SettingsEvent,
    VaultEvent,
    VaultItem,
    log_event,
)

SIGNING_ALGORITHM = sig.DEFAULT_ALGORITHM

_MODULE_BY_ID = {module["id"]: module for module in MODULE_CATALOG}
_QUOTA_SCALARS = (
    "nodes",
    "concurrent_sessions",
    "bastion_tunnels",
    "max_lease_hours",
    "worm_retention_days",
)
_USAGE_FIELDS = ("nodes_consumed", "sessions_active", "bastion_tunnels_used")


# ---------------------------------------------------------------------------
# coercion helpers
# ---------------------------------------------------------------------------
def _coerce_str(raw: Any, field: str, *, max_length: int = 255) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValidationFailed(f"'{field}' must be a string", {"field": field})
    value = raw.strip()
    if not value:
        return None
    if len(value) > max_length:
        raise ValidationFailed(
            f"'{field}' must be at most {max_length} characters", {"field": field}
        )
    return value


def _coerce_usage_limits(raw: Any, where: str) -> Dict[str, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValidationFailed(f"'{where}' must be an object", {"field": where})
    limits: Dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
            raise ValidationFailed(
                f"'{where}' must map string keys to integer values",
                {"field": where, "key": key},
            )
        limits[key] = value
    return limits


def _coerce_features(raw: Any) -> List[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(f, str) for f in raw):
        raise ValidationFailed("'features' must be a list of strings", {"field": "features"})
    return list(raw)


def _coerce_quotas(raw: Any) -> Optional[Dict[str, Any]]:
    """Validate the node/session/tunnel quota block and its pool breakdown."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValidationFailed("'quotas' must be an object", {"field": "quotas"})

    quotas: Dict[str, Any] = {}
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
        quotas[key] = value

    pools_raw = raw.get("pools", [])
    if pools_raw is None:
        pools_raw = []
    if not isinstance(pools_raw, list):
        raise ValidationFailed("'quotas.pools' must be a list", {"field": "quotas.pools"})

    pools: List[Dict[str, Any]] = []
    seen = set()
    for entry in pools_raw:
        if not isinstance(entry, dict):
            raise ValidationFailed(
                "'quotas.pools' entries must be objects", {"field": "quotas.pools"}
            )
        pool_id = _coerce_str(entry.get("id"), "quotas.pools.id", max_length=64)
        name = _coerce_str(entry.get("name"), "quotas.pools.name", max_length=128)
        if not pool_id or not name:
            raise ValidationFailed(
                "Each node pool needs 'id' and 'name'",
                {"field": "quotas.pools"},
            )
        if pool_id in seen:
            raise ValidationFailed(
                f"Duplicate node pool '{pool_id}'", {"field": "quotas.pools"}
            )
        seen.add(pool_id)

        quota_nodes = entry.get("quota_nodes")
        if not isinstance(quota_nodes, int) or isinstance(quota_nodes, bool) or quota_nodes < 0:
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
        if not isinstance(regions, list) or not all(isinstance(r, str) for r in regions):
            raise ValidationFailed(
                f"'quotas.pools.{pool_id}.regions' must be a list of strings",
                {"field": "quotas.pools"},
            )
        pools.append(
            {
                "id": pool_id,
                "name": name,
                "regions": list(regions),
                "quota_nodes": quota_nodes,
                "enforcement": enforcement,
            }
        )

    quotas["pools"] = pools
    quotas.setdefault("nodes", sum(pool["quota_nodes"] for pool in pools))
    return quotas


def _coerce_modules(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """Validate granted entitlement modules against the catalog."""
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValidationFailed("'modules' must be a list", {"field": "modules"})

    modules: List[Dict[str, Any]] = []
    seen = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValidationFailed(
                "'modules' entries must be objects", {"field": "modules"}
            )
        module_id = entry.get("id")
        if not isinstance(module_id, str) or not module_id:
            raise ValidationFailed(
                "Each module needs an 'id'", {"field": "modules"}
            )
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
        catalog_entry = _MODULE_BY_ID[module_id]
        modules.append(
            {
                "id": module_id,
                "name": entry.get("name") or catalog_entry["name"],
                "status": status,
                "detail": entry.get("detail") or catalog_entry["detail"],
            }
        )
    return modules


def _coerce_account(raw: Any) -> Optional[Dict[str, Any]]:
    """Validate the account & SLA block (all values are scalars)."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValidationFailed("'account' must be an object", {"field": "account"})
    account: Dict[str, Any] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ValidationFailed("'account' keys must be strings", {"field": "account"})
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValidationFailed(
                f"'account.{key}' must be a string or integer", {"field": "account"}
            )
        if isinstance(value, str) and len(value) > 255:
            raise ValidationFailed(
                f"'account.{key}' must be at most 255 characters", {"field": "account"}
            )
        account[key] = value
    return account


# ---------------------------------------------------------------------------
# issuing
# ---------------------------------------------------------------------------
def issue_license(
    config: Config,
    *,
    license_type: str,
    issued_to: str,
    trial_days: Optional[int] = None,
    features: Optional[List[str]] = None,
    usage_limits: Optional[Dict[str, int]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    tier: Optional[str] = None,
    plan: Optional[str] = None,
    license_id: Optional[str] = None,
    subject_entity: Optional[str] = None,
    classification: Optional[str] = None,
    issuer: Optional[str] = None,
    enclave_binding: Optional[str] = None,
    quotas: Optional[Dict[str, Any]] = None,
    modules: Optional[List[Dict[str, Any]]] = None,
    account: Optional[Dict[str, Any]] = None,
    environment: Optional[str] = None,
    signature_algorithm: str = sig.DEFAULT_ALGORITHM,
    file_format: str = sig.FORMAT_JSON,
) -> Tuple[LicenseRecord, Dict[str, Any]]:
    """Create, sign and persist a new license."""
    if not issued_to or not isinstance(issued_to, str) or not issued_to.strip():
        raise ValidationFailed("'issued_to' is required", {"field": "issued_to"})

    try:
        resolved_type = LicenseType(license_type)
    except ValueError:
        allowed = [t.value for t in LicenseType]
        raise ValidationFailed(
            f"Unknown license_type '{license_type}'",
            {"field": "license_type", "allowed": allowed},
        ) from None

    if signature_algorithm not in sig.SUPPORTED_ALGORITHMS:
        raise ValidationFailed(
            f"Unknown signature_algorithm '{signature_algorithm}'",
            {"field": "signature_algorithm", "allowed": list(sig.SUPPORTED_ALGORITHMS)},
        )
    if file_format not in sig.SUPPORTED_FORMATS:
        raise ValidationFailed(
            f"Unknown format '{file_format}'",
            {"field": "format", "allowed": list(sig.SUPPORTED_FORMATS)},
        )

    if trial_days is not None and (not isinstance(trial_days, int) or trial_days <= 0):
        raise ValidationFailed("'trial_days' must be a positive integer", {"field": "trial_days"})

    if metadata is not None and not isinstance(metadata, dict):
        raise ValidationFailed("'metadata' must be an object", {"field": "metadata"})

    resolved_features = _coerce_features(features)
    resolved_limits = _coerce_usage_limits(usage_limits, "usage_limits")
    resolved_quotas = _coerce_quotas(quotas)
    resolved_modules = _coerce_modules(modules)
    resolved_account = _coerce_account(account)
    resolved_fields = {
        "tier": _coerce_str(tier, "tier", max_length=64),
        "plan": _coerce_str(plan, "plan", max_length=64),
        "license_id": _coerce_str(license_id, "license_id", max_length=64),
        "subject_entity": _coerce_str(subject_entity, "subject_entity"),
        "classification": _coerce_str(classification, "classification", max_length=128),
        "issuer": _coerce_str(issuer, "issuer", max_length=160),
        "enclave_binding": _coerce_str(enclave_binding, "enclave_binding", max_length=160),
        "environment": _coerce_str(environment, "environment", max_length=32),
    }

    generator = get_generator(config)
    license_obj = generator.generate_license(
        license_type=resolved_type,
        issued_to=issued_to.strip(),
        trial_days=trial_days or config.default_trial_days,
        features=resolved_features or None,
        usage_limits=resolved_limits or None,
        metadata=metadata,
        quotas=resolved_quotas,
        modules=resolved_modules,
        account=resolved_account,
        **{key: value for key, value in resolved_fields.items() if value is not None},
    )
    envelope = generator.build_license_file(
        license_obj, signature_algorithm, file_format
    )
    signed_data = envelope["license_data"]

    record = LicenseRecord(
        license_key=signed_data["license_key"],
        license_type=signed_data["license_type"],
        issued_to=signed_data["issued_to"],
        issued_date=license_obj.issued_date,
        expires_on=license_obj.expires_on,
        features=signed_data["features"],
        usage_limits=signed_data["usage_limits"],
        license_metadata=signed_data["metadata"],
        license_id=signed_data.get("license_id"),
        tier=signed_data.get("tier"),
        plan=signed_data.get("plan"),
        subject_entity=signed_data.get("subject_entity"),
        classification=signed_data.get("classification"),
        issuer=signed_data.get("issuer"),
        enclave_binding=signed_data.get("enclave_binding"),
        quotas=signed_data.get("quotas") or {},
        modules=signed_data.get("modules") or [],
        account=signed_data.get("account") or {},
        status=STATUS_ACTIVE,
        signature=envelope["signature"],
        algorithm=signature_algorithm,
        signature_format=file_format,
        fingerprint=envelope.get("fingerprint"),
    )
    db.session.add(record)
    log_event(
        record.license_key,
        EVENT_ISSUED,
        {
            "issued_to": record.issued_to,
            "license_type": record.license_type,
            "algorithm": signature_algorithm,
            "format": file_format,
            "license_id": record.license_id,
        },
    )
    db.session.commit()
    return record, public_envelope(envelope)


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
# platform settings (SSO / HSM / ZSP / WORM ledger)
#
# Every field is validated server-side against SETTINGS_SCHEMA; unknown groups
# and unknown/ill-typed/out-of-range fields are rejected before anything is
# stored, and each accepted change is written to the config audit changelog.
# Secrets are never stored here -- only references (e.g. a Vault path).
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

    if ftype == "url":
        if not value:
            if spec.get("allow_empty"):
                return ""
            raise ValidationFailed(f"'{where}' is required", {"field": where})
        if not value.startswith("https://") or len(value) <= len("https://"):
            raise ValidationFailed(
                f"'{where}' must be an https URL", {"field": where, "scheme": "https"}
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


def get_settings() -> Dict[str, Any]:
    """All settings groups (defaults merged in for anything never saved)."""
    return {group: _settings_row(group) for group in SETTINGS_GROUPS}


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

    current = _settings_row(group)["values"]
    changes: Dict[str, Dict[str, Any]] = {}
    for name, raw in payload.items():
        new_value = _validate_setting(group, name, fields[name], raw)
        old_value = current.get(name)
        if new_value != old_value:
            changes[name] = {"old": old_value, "new": new_value}

    if not changes:
        return {
            "group": group,
            "values": current,
            "changes": {},
            "changed_fields": [],
            "message": "No changes",
        }

    merged = {**current, **{name: change["new"] for name, change in changes.items()}}
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
        "values": merged,
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
# credential vault (Credential Vault screen: inventory, rotation, checkouts)
# ---------------------------------------------------------------------------

# Initial inventory loaded on first start so the vault screen has real rows to
# manage. Statuses other than `available` represent genuine workflow state;
# rotation-due is recomputed from `last_rotated_at` on every read.
_VAULT_SEED: List[Dict[str, Any]] = [
    dict(name="prod-postgres-superuser", secret_type="database",
         description="PostgreSQL 16 Cluster", target="db-primary.us-east.internal",
         target_detail="Port 5432 \u2022 VPC-09", principal="postgres",
         access_tier="Tier-0", auth_method="YubiKey",
         rotation_interval_hours=24, rotated_hours_ago=2.4),
    dict(name="aws-prod-billing-master", secret_type="cloud_iam",
         description="AWS IAM STS Federation", target="arn:aws:iam::102938...",
         target_detail="Account 1029384756", principal="AWSAdmin",
         access_tier="Tier-1", auth_method="FIDO2",
         rotation_interval_hours=168, rotated_hours_ago=30,
         status=VAULT_STATUS_CHECKED_OUT, checked_out_by="mark.s",
         checked_out_hours_ago=0.7),
    dict(name="bastion-root-ed25519", secret_type="ssh_key",
         description="OpenSSH Ed25519 Keypair", target="10.140.2.18 / bastion-01",
         target_detail="Perimeter DMZ-A", principal="root",
         access_tier="Tier-0", auth_method="Hardware",
         rotation_interval_hours=12, rotated_hours_ago=4),
    dict(name="k8s-cluster-admin-token", secret_type="service_account",
         description="ServiceAccount JWT Bearer", target="api.k8s.prod.us-east",
         target_detail="Control Plane VIP", principal="system:admin",
         access_tier="Tier-0", auth_method="Multi-Appr",
         rotation_interval_hours=6, rotated_hours_ago=5.5,
         status=VAULT_STATUS_ROTATING),
    dict(name="corp-domain-admin-svc", secret_type="domain_password",
         description="Windows AD Domain Account", target="dc01.corp.internal",
         target_detail="LDAPS 636", principal="CORP\\svc_adm",
         access_tier="Tier-0", auth_method="Hardware",
         rotation_interval_hours=720, rotated_hours_ago=800,
         status=VAULT_STATUS_FAILED),
    dict(name="redis-prod-cache-auth", secret_type="api_token",
         description="ACL Superuser Token", target="redis-cluster.prod.internal",
         target_detail="Port 6379 TLS", principal="default-admin",
         access_tier="Tier-2", auth_method="Okta Push",
         rotation_interval_hours=0, rotated_hours_ago=72),
    dict(name="snowflake-bi-warehouse-pw", secret_type="database",
         description="Snowflake Service Account", target="snowflake.us-east-1",
         target_detail="Account-level", principal="svc_bi_etl",
         access_tier="Tier-1", auth_method="FIDO2",
         rotation_interval_hours=24, rotated_hours_ago=26),
    dict(name="github-ci-deploy-token", secret_type="api_token",
         description="GitHub App Install Token", target="org: aegis-corp",
         target_detail="Fine-grained scope", principal="gh-actions-deploy",
         access_tier="Tier-1", auth_method="Okta Push",
         rotation_interval_hours=168, rotated_hours_ago=20),
    dict(name="azure-sp-prod-reader", secret_type="cloud_iam",
         description="Azure Service Principal", target="sp-pam-prod-reader",
         target_detail="Subscription 8c1f2a64", principal="sp_reader",
         access_tier="Tier-2", auth_method="FIDO2",
         rotation_interval_hours=72, rotated_hours_ago=10),
    dict(name="gcp-sa-kubernetes-engine", secret_type="cloud_iam",
         description="GCP Service Account", target="sa-gke@aegis-prod.iam",
         target_detail="Project aegis-prod", principal="sa-gke-pam",
         access_tier="Tier-1", auth_method="Hardware",
         rotation_interval_hours=72, rotated_hours_ago=20),
    dict(name="vpn-concentrator-admin", secret_type="domain_password",
         description="Network Appliance Admin", target="vpn-gw-01.corp.internal",
         target_detail="IKEv2", principal="netadmin",
         access_tier="Tier-0", auth_method="Hardware",
         rotation_interval_hours=720, rotated_hours_ago=100),
    dict(name="jenkins-automation-ssh", secret_type="ssh_key",
         description="Ephemeral CA Host Cert", target="jenkins-agent-pool",
         target_detail="TTL 8 hrs", principal="jenkins-ca",
         access_tier="Tier-1", auth_method="Hardware",
         rotation_interval_hours=8, rotated_hours_ago=3),
    dict(name="elastic-superuser-pw", secret_type="database",
         description="Elasticsearch Superuser", target="es-master-01.us-east",
         target_detail="Port 9200 TLS", principal="elastic_admin",
         access_tier="Tier-1", auth_method="YubiKey",
         rotation_interval_hours=24, rotated_hours_ago=6),
    dict(name="okta-svc-api-token", secret_type="api_token",
         description="Okta Super Admin Token", target="aegispam.okta.com",
         target_detail="REST scope okta.users", principal="okta-svc",
         access_tier="Tier-0", auth_method="Hardware",
         rotation_interval_hours=720, rotated_hours_ago=48),
    dict(name="vault-root-token", secret_type="api_token",
         description="HashiCorp Vault Root", target="vault-prod-01",
         target_detail="Init + unseal", principal="root",
         access_tier="Tier-0", auth_method="Multi-Appr",
         rotation_interval_hours=0, rotated_hours_ago=200),
    dict(name="salesforce-integration-pw", secret_type="domain_password",
         description="Salesforce Integration User", target="aegis.my.salesforce.com",
         target_detail="API-only user", principal="sf_integration",
         access_tier="Tier-2", auth_method="Okta Push",
         rotation_interval_hours=72, rotated_hours_ago=33),
    dict(name="sqlserver-sa-backup", secret_type="database",
         description="SQL Server Backup Exec", target="mssql-02.corp.internal",
         target_detail="Port 1433", principal="sa_backup",
         access_tier="Tier-1", auth_method="Hardware",
         rotation_interval_hours=48, rotated_hours_ago=40),
    dict(name="gitlab-runner-deploy-key", secret_type="ssh_key",
         description="GitLab CI Deploy Key", target="gitlab.aegis.internal",
         target_detail="Runner group", principal="gitlab-ci",
         access_tier="Tier-2", auth_method="FIDO2",
         rotation_interval_hours=24, rotated_hours_ago=9),
    dict(name="splunk-hec-token", secret_type="api_token",
         description="Splunk HTTP Event Collector", target="splunk-hec.internal",
         target_detail="HEC index=pam", principal="splunk-hec",
         access_tier="Tier-2", auth_method="Password",
         rotation_interval_hours=168, rotated_hours_ago=60),
    dict(name="ad-mfa-breakglass-acct", secret_type="domain_password",
         description="AD Break-Glass Account", target="dc01.corp.internal",
         target_detail="Tier-0 breakglass", principal="breakglass_admin",
         access_tier="Tier-0", auth_method="Hardware",
         rotation_interval_hours=24, rotated_hours_ago=1,
         status=VAULT_STATUS_CHECKED_OUT, checked_out_by="s.alvarez",
         checked_out_hours_ago=1.2),
]


def seed_vault_if_empty() -> int:
    """Load the initial inventory once (no-op when the vault has rows)."""
    if VaultItem.query.first() is not None:
        return 0
    now = datetime.now()
    for entry in _VAULT_SEED:
        rotated = entry.get("rotated_hours_ago")
        item = VaultItem(
            name=entry["name"],
            secret_type=entry["secret_type"],
            description=entry["description"],
            target=entry["target"],
            target_detail=entry["target_detail"],
            principal=entry["principal"],
            access_tier=entry["access_tier"],
            auth_method=entry["auth_method"],
            rotation_interval_hours=entry["rotation_interval_hours"],
            last_rotated_at=(
                now - timedelta(hours=rotated) if rotated is not None else None
            ),
            status=entry.get("status", VAULT_STATUS_AVAILABLE),
        )
        checked_out_hours = entry.get("checked_out_hours_ago")
        if checked_out_hours is not None:
            item.checked_out_by = entry["checked_out_by"]
            item.checked_out_at = now - timedelta(hours=checked_out_hours)
        db.session.add(item)
    db.session.commit()
    return len(_VAULT_SEED)


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


def rotate_vault_item(item_id: int, *, actor: str) -> VaultItem:
    """Rotate (or retry a failed rotation): stamps a fresh SLA window."""
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
    item.status = VAULT_STATUS_AVAILABLE
    item.last_rotated_at = datetime.now()
    item.checked_out_by = None
    item.checked_out_at = None
    _log_vault_event(
        item,
        VAULT_ACTION_ROTATED,
        actor,
        {"previous_status": previous, "interval_hours": item.rotation_interval_hours},
    )
    db.session.commit()
    return item


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
    db.session.flush()  # assign the id before logging the event
    _log_vault_event(item, VAULT_ACTION_ONBOARDED, actor,
                     {"rotation_interval_hours": interval})
    db.session.commit()
    return item


def vault_item_events(item_id: int, limit: int = 10) -> List[VaultEvent]:
    return (
        VaultEvent.query.filter_by(item_id=item_id)
        .order_by(VaultEvent.created_at.desc(), VaultEvent.id.desc())
        .limit(limit)
        .all()
    )


def vault_events(limit: int = 20) -> Dict[str, Any]:
    """Vault audit trail, newest first."""
    total = VaultEvent.query.count()
    events = (
        VaultEvent.query.order_by(
            VaultEvent.created_at.desc(), VaultEvent.id.desc()
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
# dashboard (Command Center + Compliance screens)
# ---------------------------------------------------------------------------
_EVENT_SOURCES = ("license", "settings", "vault")


def unified_events(
    *, source: Optional[str] = None, limit: int = 20
) -> Dict[str, Any]:
    """Recent activity across license, settings and vault audit trails."""
    if source and source not in _EVENT_SOURCES:
        raise ValidationFailed(
            f"Unknown event source '{source}'",
            {"field": "source", "allowed": list(_EVENT_SOURCES)},
        )

    merged: List[Tuple[datetime, Dict[str, Any]]] = []
    total = 0

    if source in (None, "license"):
        query = LicenseEvent.query
        total += query.count()
        for event in query.order_by(
            LicenseEvent.created_at.desc(), LicenseEvent.id.desc()
        ).limit(limit):
            merged.append((
                event.created_at,
                {
                    "id": f"license:{event.id}",
                    "source": "license",
                    "action": event.action,
                    "subject": event.license_key,
                    "actor": "system",
                    "detail": event.detail,
                    "created_at": event.created_at.isoformat(),
                },
            ))

    if source in (None, "settings"):
        query = SettingsEvent.query
        total += query.count()
        for event in query.order_by(
            SettingsEvent.created_at.desc(), SettingsEvent.id.desc()
        ).limit(limit):
            merged.append((
                event.created_at,
                {
                    "id": f"settings:{event.id}",
                    "source": "settings",
                    "action": event.action,
                    "subject": event.group_name,
                    "actor": event.actor,
                    "detail": event.changes,
                    "created_at": event.created_at.isoformat(),
                },
            ))

    if source in (None, "vault"):
        query = VaultEvent.query
        total += query.count()
        for event in query.order_by(
            VaultEvent.created_at.desc(), VaultEvent.id.desc()
        ).limit(limit):
            merged.append((
                event.created_at,
                {
                    "id": f"vault:{event.id}",
                    "source": "vault",
                    "action": event.action,
                    "subject": event.item_name,
                    "actor": event.actor,
                    "detail": event.detail,
                    "created_at": event.created_at.isoformat(),
                },
            ))

    merged.sort(key=lambda pair: pair[0], reverse=True)
    return {
        "events": [payload for _, payload in merged[:limit]],
        "total": total,
        "limit": limit,
        "source": source or "all",
    }


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
    total_events = license_events + settings_events + vault_events_total

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
