"""
Business logic for the Phase 2 license server.

Routes stay thin: they parse/serialise HTTP, this module does the work.
Cryptographic signing and verification are delegated to the Phase 1 library
via licensing_bridge.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from config import Config
from errors import NotFound, ValidationFailed
from licensing_bridge import (
    License,
    LicenseType,
    get_generator,
    get_validator,
)
from extensions import db
from models import (
    EVENT_ISSUED,
    EVENT_RESTORED,
    EVENT_REVOKED,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    LicenseRecord,
    log_event,
)

SIGNING_ALGORITHM = "RSA-PSS-SHA256"


# ---------------------------------------------------------------------------
# issuing
# ---------------------------------------------------------------------------
def _build_license_file(config: Config, license_obj: License) -> Dict[str, Any]:
    """Sign a license and wrap it in the Phase 1 wire format."""
    generator = get_generator(config)
    license_data = license_obj.to_dict()
    return {
        "license_data": license_data,
        "signature": generator.sign_license(license_data),
        "algorithm": SIGNING_ALGORITHM,
        "version": "1.0",
    }


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


def issue_license(
    config: Config,
    *,
    license_type: str,
    issued_to: str,
    trial_days: Optional[int] = None,
    features: Optional[List[str]] = None,
    usage_limits: Optional[Dict[str, int]] = None,
    metadata: Optional[Dict[str, Any]] = None,
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

    if trial_days is not None and (not isinstance(trial_days, int) or trial_days <= 0):
        raise ValidationFailed("'trial_days' must be a positive integer", {"field": "trial_days"})

    if metadata is not None and not isinstance(metadata, dict):
        raise ValidationFailed("'metadata' must be an object", {"field": "metadata"})

    resolved_features = _coerce_features(features)
    resolved_limits = _coerce_usage_limits(usage_limits, "usage_limits")

    generator = get_generator(config)
    license_obj = generator.generate_license(
        license_type=resolved_type,
        issued_to=issued_to.strip(),
        trial_days=trial_days or config.default_trial_days,
        features=resolved_features or None,
        usage_limits=resolved_limits or None,
        metadata=metadata,
    )
    license_file = _build_license_file(config, license_obj)
    signed_data = license_file["license_data"]

    record = LicenseRecord(
        license_key=signed_data["license_key"],
        license_type=signed_data["license_type"],
        issued_to=signed_data["issued_to"],
        issued_date=license_obj.issued_date,
        expires_on=license_obj.expires_on,
        features=signed_data["features"],
        usage_limits=signed_data["usage_limits"],
        license_metadata=signed_data["metadata"],
        status=STATUS_ACTIVE,
        signature=license_file["signature"],
        algorithm=license_file["algorithm"],
    )
    db.session.add(record)
    log_event(
        record.license_key,
        EVENT_ISSUED,
        {"issued_to": record.issued_to, "license_type": record.license_type},
    )
    db.session.commit()
    return record, license_file


# ---------------------------------------------------------------------------
# querying
# ---------------------------------------------------------------------------
def get_record(license_key: str) -> LicenseRecord:
    """Fetch a license by key or raise 404."""
    record = LicenseRecord.query.filter_by(license_key=license_key.upper()).first()
    if record is None:
        raise NotFound(f"No license with key {license_key}")
    return record


def list_licenses(
    *,
    status: Optional[str] = None,
    license_type: Optional[str] = None,
    issued_to: Optional[str] = None,
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
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                LicenseRecord.license_key.ilike(pattern),
                LicenseRecord.issued_to.ilike(pattern),
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
# validation
# ---------------------------------------------------------------------------
def validate_license_payload(config: Config, payload: Any) -> Dict[str, Any]:
    """
    Fully validate a signed license file.

    Checks: structure -> cryptographic signature -> revocation list -> expiry.
    """
    if not isinstance(payload, dict):
        return _result(
            valid=False,
            status="malformed",
            signature_valid=False,
            registered=False,
            reason="License payload must be a JSON object",
        )

    license_data = payload.get("license_data")
    signature = payload.get("signature")

    if not isinstance(license_data, dict) or not isinstance(signature, str) or not signature:
        return _result(
            valid=False,
            status="malformed",
            signature_valid=False,
            registered=False,
            reason="License must contain 'license_data' object and 'signature' string",
        )

    validator = get_validator(config)
    if not validator.verify_signature(license_data, signature):
        return _result(
            valid=False,
            status="signature_invalid",
            signature_valid=False,
            registered=license_key_of(license_data) is not None,
            reason="Signature does not match the signed license data",
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
        )

    record = LicenseRecord.query.filter_by(license_key=license_obj.license_key).first()
    registered = record is not None
    revoked = registered and record.status == STATUS_REVOKED
    expired = license_obj.is_expired()
    matches_record = record.signature == signature if registered else None

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
    }


# ---------------------------------------------------------------------------
# feature / usage checks
# ---------------------------------------------------------------------------
def check_access(
    license_key: str,
    *,
    feature: Optional[str] = None,
    limit_type: Optional[str] = None,
    current_usage: Optional[int] = None,
) -> Dict[str, Any]:
    """Check a registered license for feature access and/or usage limits."""
    if feature is None and limit_type is None:
        raise ValidationFailed(
            "Provide 'feature' and/or 'limit_type' to check",
            {"fields": ["feature", "limit_type"]},
        )

    record = get_record(license_key)
    response: Dict[str, Any] = {
        "license_key": record.license_key,
        "status": record.effective_status(),
        "active": record.status == STATUS_ACTIVE and not record.is_expired,
    }

    if feature is not None:
        response["feature"] = feature
        response["feature_allowed"] = response["active"] and feature in (record.features or [])

    if limit_type is not None:
        if current_usage is None or not isinstance(current_usage, int) or isinstance(current_usage, bool):
            raise ValidationFailed(
                "'current_usage' must be an integer when checking a limit",
                {"field": "current_usage"},
            )
        limit = (record.usage_limits or {}).get(limit_type)
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
