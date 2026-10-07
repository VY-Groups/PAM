"""License issuance for VY-PAM MASTER (Phase 2c).

Flow per deal: validate the form -> shared engine builds the claims
(tiers/modules/quotas/validity defaults come from the engine's catalog,
never restated here) -> sign -> **encrypted archive** + master audit trail +
registry issuance history. Renewal produces a fresh signed license for the
same customer and supersedes the previous row atomically.

The signed envelope itself contains the licensee's name (issued_to) — as any
real license file does — so the *archive* is encrypted with the registry PII
key (AAD = license_id) and the database file never holds it in plaintext.
The delivery bundle ships the license to the customer, who already knows
their own name.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from pam_master import crypto, db, registry
from pam_master.config import Config
from pam_master.errors import (
    CustomerNotFound,
    DataIntegrityError,
    LicenseConflict,
    LicenseNotFound,
    SigningUnavailable,
    ValidationError,
)
from pam_master.keys import KeyCustodyError
from pam_master.licensing import (
    DEFAULT_CLASSIFICATIONS,
    DEFAULT_MODULE_IDS,
    DEFAULT_PLANS,
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    LicenseType,
    get_generator,
    sig,
)

LICENSE_TYPES: Tuple[str, ...] = tuple(t.value for t in LicenseType)
MODULE_BY_ID = {m["id"]: m for m in MODULE_CATALOG}
MIN_VALIDITY_DAYS = 1
MAX_VALIDITY_DAYS = 3650
ENVIRONMENT_RE = re.compile(r"[A-Za-z0-9-]{1,16}")
ENVIRONMENT_DEFAULT = "PROD"
STATUS_ACTIVE = "active"
STATUS_SUPERSEDED = "superseded"
AUDIT_ACTIONS = (
    "license_issued",
    "license_renewed",
    "license_bundle_exported",
)
# Engine truth: generate_license() expires trials after trial_days (30 by
# default), subscriptions after 365 days, and never expires perpetual or
# enterprise licenses (license_tool.generate_license).
DEFAULT_VALIDITY_DAYS: Dict[str, Optional[int]] = {
    "trial": 30,
    "subscription": 365,
    "perpetual": None,
    "enterprise": None,
}
_ISSUE_FIELDS = (
    "license_type",
    "validity_days",
    "modules",
    "quotas",
    "algorithm",
    "environment",
)
_LICENSE_INSERT = (
    "INSERT INTO licenses "
    "(license_id, license_key, customer_public_id, license_type, tier, plan,"
    " algorithm, status, issued_date, expires_on, fingerprint, superseded_by,"
    " archive_ct, created_at, updated_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------ validation --
def _is_scalar_tree(value: Any, depth: int = 0) -> bool:
    if isinstance(value, dict):
        if depth >= 3:
            return False
        return all(
            isinstance(key, str) and _is_scalar_tree(item, depth + 1)
            for key, item in value.items()
        )
    return isinstance(value, (str, int, float, bool))


def validate_issue_body(body: Any) -> Dict[str, Any]:
    """Validate the issuance form; returns the normalized spec."""
    if not isinstance(body, dict):
        raise ValidationError("JSON object body required")
    unknown = [key for key in body if key not in _ISSUE_FIELDS]
    if unknown:
        raise ValidationError(
            "unknown field(s): "
            + ", ".join(sorted(unknown))
            + "; allowed: "
            + ", ".join(_ISSUE_FIELDS)
        )
    license_type = body.get("license_type")
    if not license_type or not isinstance(license_type, str):
        raise ValidationError(
            "missing required field: license_type "
            f"(one of: {', '.join(LICENSE_TYPES)})"
        )
    if license_type not in LICENSE_TYPES:
        raise ValidationError(
            f"license_type must be one of: {', '.join(LICENSE_TYPES)}"
        )
    spec: Dict[str, Any] = {"license_type": license_type}

    validity = body.get("validity_days")
    if validity is not None:
        if isinstance(validity, bool) or not isinstance(validity, int):
            raise ValidationError("validity_days must be an integer")
        if not MIN_VALIDITY_DAYS <= validity <= MAX_VALIDITY_DAYS:
            raise ValidationError(
                "validity_days must be between "
                f"{MIN_VALIDITY_DAYS} and {MAX_VALIDITY_DAYS}"
            )
        spec["validity_days"] = validity

    modules = body.get("modules")
    if modules is not None:
        if not isinstance(modules, list) or not modules:
            raise ValidationError(
                "modules must be a non-empty array of module ids"
            )
        if any(not isinstance(item, str) for item in modules):
            raise ValidationError("modules entries must be strings (ids)")
        unknown_ids = sorted(set(modules) - set(MODULE_IDS))
        if unknown_ids:
            raise ValidationError(
                "unknown module id(s): "
                + ", ".join(unknown_ids)
                + " — see GET /api/v1/license-options"
            )
        spec["modules"] = sorted(set(modules), key=MODULE_IDS.index)

    quotas = body.get("quotas")
    if quotas is not None:
        if not isinstance(quotas, dict) or not _is_scalar_tree(quotas):
            raise ValidationError(
                "quotas must be a JSON object of scalar values "
                "(max depth 3)"
            )
        spec["quotas"] = quotas

    algorithm = body.get("algorithm")
    if algorithm is not None:
        if algorithm not in sig.SUPPORTED_ALGORITHMS:
            raise ValidationError(
                "algorithm must be one of: "
                + ", ".join(sig.SUPPORTED_ALGORITHMS)
            )
        spec["algorithm"] = algorithm

    environment = body.get("environment")
    if environment is not None:
        if not isinstance(environment, str) or not ENVIRONMENT_RE.fullmatch(
            environment
        ):
            raise ValidationError(
                "environment must be 1-16 letters, digits or hyphens"
            )
        spec["environment"] = environment
    return spec


# -------------------------------------------------------------- helpers --
def _generator(config: Config):
    try:
        return get_generator(config)
    except KeyCustodyError as exc:
        raise SigningUnavailable(str(exc)) from exc


def _fetch_license(
    connection: sqlite3.Connection, license_id: str
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM licenses WHERE license_id = ?", (license_id,)
    ).fetchone()
    if row is None:
        raise LicenseNotFound(f"license {license_id} not found")
    return row


def _record(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "license_id": row["license_id"],
        "license_key": row["license_key"],
        "customer_public_id": row["customer_public_id"],
        "license_type": row["license_type"],
        "tier": row["tier"],
        "plan": row["plan"],
        "algorithm": row["algorithm"],
        "format": "json",
        "status": row["status"],
        "issued_date": row["issued_date"],
        "expires_on": row["expires_on"],
        "fingerprint": row["fingerprint"],
        "superseded_by": row["superseded_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _audit(
    connection: sqlite3.Connection,
    action: str,
    subject: str,
    detail: Dict[str, Any],
) -> None:
    connection.execute(
        "INSERT INTO master_audit (action, subject, detail, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            action,
            subject,
            json.dumps(detail, sort_keys=True, separators=(",", ":")),
            _now(),
        ),
    )


def _module_records(module_ids: List[str]) -> List[Dict[str, Any]]:
    """Shape module entries exactly like the engine's default_modules."""
    return [
        {
            "id": module["id"],
            "name": module["name"],
            "status": "entitled",
            "detail": module["detail"],
        }
        for module_id in module_ids
        for module in [MODULE_BY_ID[module_id]]
    ]


# ------------------------------------------------------------- issuing --
def _issue(
    config: Config,
    customer_public_id: str,
    spec: Dict[str, Any],
    *,
    history_action: str,
    audit_action: str,
    metadata_extra: Optional[Dict[str, Any]] = None,
    audit_extra: Optional[Dict[str, Any]] = None,
    supersede: Optional[str] = None,
) -> Dict[str, Any]:
    # Decrypt the customer only as far as the name (licensee identity) —
    # this also enforces registry-key availability before anything is signed.
    customer = registry.get_customer(config, customer_public_id)
    generator = _generator(config)

    license_type = LicenseType(spec["license_type"])
    metadata: Dict[str, Any] = {"customer_ref": customer_public_id}
    if metadata_extra:
        metadata.update(metadata_extra)
    kwargs: Dict[str, Any] = {
        "license_type": license_type,
        "issued_to": customer["name"],
        "metadata": metadata,
        "environment": spec.get("environment", ENVIRONMENT_DEFAULT),
    }
    validity = spec.get("validity_days")
    if validity is not None and license_type is LicenseType.TRIAL:
        kwargs["trial_days"] = validity
    if "modules" in spec:
        kwargs["modules"] = _module_records(spec["modules"])
    if "quotas" in spec:
        kwargs["quotas"] = spec["quotas"]

    license_obj = generator.generate_license(**kwargs)
    if validity is not None and license_type is not LicenseType.TRIAL:
        # Custom validity for non-trial types (engine defaults: subscription
        # +365d, perpetual/enterprise never expire).
        license_obj.expires_on = license_obj.issued_date + timedelta(
            days=validity
        )

    algorithm = spec.get("algorithm", sig.DEFAULT_ALGORITHM)
    envelope = generator.build_license_file(
        license_obj, algorithm, sig.FORMAT_JSON
    )
    claims = envelope["license_data"]
    license_id = str(claims["license_id"])
    license_key = str(claims.get("license_key") or license_obj.license_key)

    key = registry.require_registry_key(config)
    archive = crypto.encrypt_payload(key, license_id, envelope)
    now = _now()
    history_detail: Dict[str, Any] = {
        "license_type": spec["license_type"],
        "tier": claims.get("tier"),
        "expires_on": claims.get("expires_on"),
        "algorithm": algorithm,
    }
    if supersede:
        history_detail["renews"] = supersede

    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        if supersede is not None:
            old_row = _fetch_license(connection, supersede)
            if old_row["status"] != STATUS_ACTIVE:
                raise LicenseConflict(
                    f"license {supersede} is {old_row['status']}; "
                    "only active licenses can be renewed"
                )
        connection.execute(
            _LICENSE_INSERT,
            (
                license_id,
                license_key,
                customer_public_id,
                spec["license_type"],
                str(claims.get("tier") or ""),
                claims.get("plan"),
                algorithm,
                STATUS_ACTIVE,
                str(claims["issued_date"]),
                claims.get("expires_on"),
                str(envelope.get("fingerprint") or ""),
                None,
                archive,
                now,
                now,
            ),
        )
        if supersede is not None:
            connection.execute(
                "UPDATE licenses SET status = ?, superseded_by = ?, "
                "updated_at = ? WHERE license_id = ?",
                (STATUS_SUPERSEDED, license_id, now, supersede),
            )
        registry.record_issuance(
            config,
            customer_public_id,
            license_id,
            history_action,
            history_detail,
            connection=connection,
        )
        _audit(
            connection,
            audit_action,
            license_id,
            {
                "customer_public_id": customer_public_id,
                "license_type": spec["license_type"],
                "algorithm": algorithm,
                **(audit_extra or {}),
            },
        )
        connection.commit()
        row = _fetch_license(connection, license_id)
    return _record(row)


def issue_license(
    config: Config, customer_public_id: str, body: Any
) -> Dict[str, Any]:
    """Sign + archive a new license for an existing customer (201 flow)."""
    spec = validate_issue_body(body)
    return _issue(
        config,
        customer_public_id,
        spec,
        history_action="issued",
        audit_action="license_issued",
    )


def renew_license(
    config: Config, license_id: str, body: Any
) -> Dict[str, Any]:
    """Issue a replacement license and supersede the previous one."""
    spec = validate_issue_body(body)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        old_row = _fetch_license(connection, license_id)
    if old_row["status"] != STATUS_ACTIVE:
        raise LicenseConflict(
            f"license {license_id} is {old_row['status']}; "
            "only active licenses can be renewed"
        )
    return _issue(
        config,
        old_row["customer_public_id"],
        spec,
        history_action="renewed",
        audit_action="license_renewed",
        metadata_extra={"renews": license_id},
        audit_extra={"replaces": license_id},
        supersede=license_id,
    )


# ------------------------------------------------------------- reading --
def get_license(config: Config, license_id: str) -> Dict[str, Any]:
    """License metadata (no decryption needed — claims PII lives in the
    encrypted archive; the customer name is one lookup away)."""
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        row = _fetch_license(connection, license_id)
    return _record(row)


def list_licenses(
    config: Config,
    *,
    customer: Optional[str] = None,
    status: Optional[str] = None,
    limit: Any = registry.DEFAULT_LIMIT,
    offset: Any = 0,
) -> Dict[str, Any]:
    limit_int, offset_int = registry.page_args(limit, offset)
    clauses: List[str] = []
    params: List[Any] = []
    if customer is not None:
        if not registry.customer_exists(config, customer):
            raise CustomerNotFound(f"customer {customer} not found")
        clauses.append("customer_public_id = ?")
        params.append(customer)
    if status is not None:
        if status not in (STATUS_ACTIVE, STATUS_SUPERSEDED):
            raise ValidationError(
                "status must be one of: "
                f"{STATUS_ACTIVE}, {STATUS_SUPERSEDED}"
            )
        clauses.append("status = ?")
        params.append(status)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        total = connection.execute(
            f"SELECT count(*) FROM licenses{where}", params
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM licenses{where} ORDER BY id DESC "
            "LIMIT ? OFFSET ?",
            [*params, limit_int, offset_int],
        ).fetchall()
    return {
        "licenses": [_record(row) for row in rows],
        "total": int(total),
        "limit": limit_int,
        "offset": offset_int,
    }


def list_audit(
    config: Config,
    limit: Any = registry.DEFAULT_LIMIT,
    offset: Any = 0,
) -> Dict[str, Any]:
    limit_int, offset_int = registry.page_args(limit, offset)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        total = connection.execute(
            "SELECT count(*) FROM master_audit"
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT * FROM master_audit ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit_int, offset_int),
        ).fetchall()
    events = [
        {
            "action": row["action"],
            "subject": row["subject"],
            "detail": json.loads(row["detail"]) if row["detail"] else None,
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return {
        "events": events,
        "total": int(total),
        "limit": limit_int,
        "offset": offset_int,
    }


# ------------------------------------------------------- delivery bundle --
def _bundle_readme(row: sqlite3.Row) -> str:
    expires = row["expires_on"] or "none (non-expiring license type)"
    license_file = f"{row['license_id']}.lic"
    return (
        "VY-PAM license delivery bundle\n"
        "==============================\n"
        "\n"
        f"License id:     {row['license_id']}\n"
        f"License key:    {row['license_key']}\n"
        f"Customer ref:   {row['customer_public_id']}\n"
        f"Type / tier:    {row['license_type']} / {row['tier']}\n"
        f"Issued:         {row['issued_date']}\n"
        f"Expires:        {expires}\n"
        f"Algorithm:      {row['algorithm']}\n"
        f"Fingerprint:    {row['fingerprint']}\n"
        "\n"
        "Contents\n"
        "--------\n"
        f"{license_file}\n"
        "    Signed license file (JSON envelope; the signature covers\n"
        "    license_data).\n"
        "license_public_key.pem\n"
        "    Public key that verifies the signature.\n"
        "README.txt\n"
        "    This file.\n"
        "SHA256SUMS.txt\n"
        "    SHA-256 of the three files above (verify with:\n"
        "    sha256sum -c SHA256SUMS.txt).\n"
        "\n"
        "Apply: open the VY-PAM license activation screen and upload the\n"
        f"{license_file} file. Verification is offline - no connection to\n"
        "the vendor is required.\n"
    )


def export_bundle(
    config: Config, license_id: str
) -> Tuple[bytes, str]:
    """Build the delivery zip: license file + public key + checksums.

    Returns ``(zip_bytes, download_filename)``. Requires both custody
    (signing key for the public half) and the registry key (archive
    decryption) — honest 503s otherwise.
    """
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        row = _fetch_license(connection, license_id)
    key = registry.require_registry_key(config)
    try:
        envelope = crypto.decrypt_payload(key, license_id, row["archive_ct"])
    except crypto.PayloadIntegrityError as exc:
        raise DataIntegrityError(
            f"license {license_id} archive failed authentication: {exc}"
        ) from exc
    generator = _generator(config)
    public_pem = generator.get_public_key_pem(row["algorithm"])
    if isinstance(public_pem, bytes):
        public_pem = public_pem.decode("ascii")

    license_name = f"{license_id}.lic"
    files: Dict[str, bytes] = {
        license_name: (json.dumps(envelope, indent=2) + "\n").encode("utf-8"),
        "license_public_key.pem": public_pem.encode("ascii"),
        "README.txt": _bundle_readme(row).encode("utf-8"),
    }
    checksums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in files.items()
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("SHA256SUMS.txt", checksums.encode("ascii"))

    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        _audit(
            connection,
            "license_bundle_exported",
            license_id,
            {
                "algorithm": row["algorithm"],
                "fingerprint": row["fingerprint"],
            },
        )
        connection.commit()
    return buffer.getvalue(), f"vy-pam-{license_id}-bundle.zip"


# ------------------------------------------------------------ catalog --
def license_options() -> Dict[str, Any]:
    """Everything the issuance form needs — all values straight from the
    shared engine's catalog (no restated copy)."""
    return {
        "license_types": [
            {
                "value": license_type.value,
                "default_tier": DEFAULT_TIERS[license_type],
                "default_plan": DEFAULT_PLANS[license_type],
                "default_classification": DEFAULT_CLASSIFICATIONS[
                    license_type
                ],
                "default_modules": list(DEFAULT_MODULE_IDS[license_type]),
                "default_validity_days": DEFAULT_VALIDITY_DAYS[
                    license_type.value
                ],
            }
            for license_type in LicenseType
        ],
        "modules": MODULE_CATALOG,
        "algorithms": list(sig.SUPPORTED_ALGORITHMS),
        "formats": [sig.FORMAT_JSON],
        "enforcement_levels": list(ENFORCEMENT_LEVELS),
        "validity_days": {
            "min": MIN_VALIDITY_DAYS,
            "max": MAX_VALIDITY_DAYS,
        },
        "environment": {
            "pattern": "[A-Za-z0-9-]{1,16}",
            "default": ENVIRONMENT_DEFAULT,
        },
    }
