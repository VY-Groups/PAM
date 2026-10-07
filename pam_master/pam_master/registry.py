"""Customer registry domain: validation, encryption, persistence.

Rules enforced here:

* **PII encrypted at rest** — every customer payload is an AES-256-GCM blob
  bound to the row's ``public_id``; the database file never contains
  plaintext names/contacts.
* **No hard deletes** — customers with issuance history must stay resolvable
  (list/create/edit only, per the plan; deletion is out of scope on purpose).
* **Honest failures** — missing registry key -> :class:`RegistryUnavailable`
  (503), unknown customer -> :class:`CustomerNotFound` (404), corrupt/
  undecryptable row -> :class:`DataIntegrityError` (500). Never guesses.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pam_master import crypto, db
from pam_master.config import Config
from pam_master.keys import KeyCustodyError, load_registry_key

# ------------------------------------------------------------ exceptions --
class RegistryApiError(Exception):
    """Base for registry failures the HTTP layer maps to a status code."""

    status = 500
    error_type = "internal_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ValidationError(RegistryApiError):
    status = 400
    error_type = "validation_error"


class CustomerNotFound(RegistryApiError):
    status = 404
    error_type = "customer_not_found"


class RegistryUnavailable(RegistryApiError):
    status = 503
    error_type = "registry_unavailable"


class DataIntegrityError(RegistryApiError):
    status = 500
    error_type = "registry_data_corrupt"


# ------------------------------------------------------------- constants --
FIELDS = (
    "name",
    "region",
    "contact_name",
    "contact_email",
    "contact_phone",
    "notes",
)
REQUIRED_FIELDS = ("name", "region")
LIMITS = {
    "name": 200,
    "region": 100,
    "contact_name": 200,
    "contact_email": 320,
    "contact_phone": 40,
    "notes": 4000,
}
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+$")
PUBLIC_ID_RE = re.compile(r"[0-9a-f]{32}")
ISSUANCE_ACTIONS = (
    "issued",
    "renewed",
    "upgraded",
    "revoked",
    "restored",
)
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------- validation --
def _validate_body(body: Any, *, require_required: bool) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise ValidationError("JSON object body required")
    unknown = [key for key in body if key not in FIELDS]
    if unknown:
        raise ValidationError(
            "unknown field(s): "
            + ", ".join(sorted(unknown))
            + "; allowed: "
            + ", ".join(FIELDS)
        )
    if require_required:
        missing = [
            key
            for key in REQUIRED_FIELDS
            if not str(body.get(key) or "").strip()
        ]
        if missing:
            raise ValidationError(
                "missing required field(s): " + ", ".join(missing)
            )
    cleaned: Dict[str, Any] = {}
    for key, value in body.items():
        if value is None:
            if key in REQUIRED_FIELDS:
                raise ValidationError(f"field {key!r} must not be empty")
            cleaned[key] = None
            continue
        if not isinstance(value, str):
            raise ValidationError(f"field {key!r} must be a string")
        value = value.strip()
        if len(value) > LIMITS[key]:
            raise ValidationError(
                f"field {key!r} exceeds {LIMITS[key]} characters"
            )
        if key in REQUIRED_FIELDS and not value:
            raise ValidationError(f"field {key!r} must not be empty")
        if key == "contact_email" and value and not EMAIL_RE.match(value):
            raise ValidationError(
                "field 'contact_email' must be a valid email address"
            )
        cleaned[key] = value
    return cleaned


def _validate_public_id(public_id: str) -> str:
    if not PUBLIC_ID_RE.fullmatch(public_id or ""):
        raise ValidationError(
            "customer id must be 32 lowercase hex characters"
        )
    return public_id


def _page(limit: Any, offset: Any) -> Tuple[int, int]:
    try:
        limit_int = int(limit)
        offset_int = int(offset)
    except (TypeError, ValueError):
        raise ValidationError("limit and offset must be integers") from None
    if not 1 <= limit_int <= MAX_LIMIT:
        raise ValidationError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset_int < 0:
        raise ValidationError("offset must be at least 0")
    return limit_int, offset_int


# -------------------------------------------------------------- helpers --
def _key(config: Config) -> bytes:
    try:
        return load_registry_key(config)
    except KeyCustodyError as exc:
        raise RegistryUnavailable(str(exc)) from exc


def _encrypt(key: bytes, public_id: str, payload: Dict[str, Any]) -> str:
    return crypto.encrypt_payload(key, public_id, payload)


def _decrypt(
    key: bytes, public_id: str, blob: str
) -> Dict[str, Any]:
    try:
        return crypto.decrypt_payload(key, public_id, blob)
    except crypto.PayloadIntegrityError as exc:
        raise DataIntegrityError(
            f"customer {public_id} payload failed authentication: {exc}"
        ) from exc


def _record(
    key: bytes,
    row: sqlite3.Row,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if payload is None:
        payload = _decrypt(key, row["public_id"], row["data_ct"])
    record: Dict[str, Any] = {
        "public_id": row["public_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    for field in FIELDS:
        record[field] = payload.get(field)
    return record


def _fetch_row(
    connection: sqlite3.Connection, public_id: str
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM customers WHERE public_id = ?", (public_id,)
    ).fetchone()
    if row is None:
        raise CustomerNotFound(f"customer {public_id} not found")
    return row


# ------------------------------------------------------------ public API --
def create_customer(config: Config, body: Any) -> Dict[str, Any]:
    payload = _validate_body(body, require_required=True)
    key = _key(config)
    public_id = uuid.uuid4().hex
    now = _now()
    blob = _encrypt(key, public_id, payload)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        connection.execute(
            "INSERT INTO customers "
            "(public_id, data_ct, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (public_id, blob, now, now),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM customers WHERE public_id = ?", (public_id,)
        ).fetchone()
    return _record(key, row, payload=payload)


def list_customers(
    config: Config, limit: Any = DEFAULT_LIMIT, offset: Any = 0
) -> Dict[str, Any]:
    limit_int, offset_int = _page(limit, offset)
    key = _key(config)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        total = connection.execute(
            "SELECT count(*) FROM customers"
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT * FROM customers ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit_int, offset_int),
        ).fetchall()
        records = [_record(key, row) for row in rows]
    return {
        "customers": records,
        "total": int(total),
        "limit": limit_int,
        "offset": offset_int,
    }


def get_customer(config: Config, public_id: str) -> Dict[str, Any]:
    _validate_public_id(public_id)
    key = _key(config)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        row = _fetch_row(connection, public_id)
    return _record(key, row)


def update_customer(
    config: Config, public_id: str, body: Any
) -> Dict[str, Any]:
    _validate_public_id(public_id)
    changes = _validate_body(body, require_required=False)
    if not changes:
        raise ValidationError(
            "at least one of: " + ", ".join(FIELDS)
        )
    key = _key(config)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        row = _fetch_row(connection, public_id)
        merged = dict(_decrypt(key, public_id, row["data_ct"]))
        merged.update(changes)
        blob = _encrypt(key, public_id, merged)
        now = _now()
        connection.execute(
            "UPDATE customers SET data_ct = ?, updated_at = ? "
            "WHERE public_id = ?",
            (blob, now, public_id),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM customers WHERE public_id = ?", (public_id,)
        ).fetchone()
    return _record(key, row)


def record_issuance(
    config: Config,
    customer_public_id: str,
    license_id: str,
    action: str,
    detail: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append an issuance-history entry (internal: called by the issuance
    flow, no public write endpoint). Entitlement facts only — no PII."""
    _validate_public_id(customer_public_id)
    if action not in ISSUANCE_ACTIONS:
        raise ValidationError(
            f"action must be one of: {', '.join(ISSUANCE_ACTIONS)}"
        )
    if not license_id or not str(license_id).strip():
        raise ValidationError("license_id must not be empty")
    detail_json = None
    if detail is not None:
        if not isinstance(detail, dict):
            raise ValidationError("detail must be a JSON object")
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"))
    now = _now()
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        _fetch_row(connection, customer_public_id)
        connection.execute(
            "INSERT INTO issuance_history "
            "(customer_public_id, license_id, action, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                customer_public_id,
                str(license_id).strip(),
                action,
                detail_json,
                now,
            ),
        )
        connection.commit()
    return {
        "customer_public_id": customer_public_id,
        "license_id": str(license_id).strip(),
        "action": action,
        "detail": detail,
        "created_at": now,
    }


def issuance_history(
    config: Config, public_id: str
) -> Dict[str, Any]:
    _validate_public_id(public_id)
    with closing(db.connect(config)) as connection:
        db.init_schema(connection)
        _fetch_row(connection, public_id)
        rows = connection.execute(
            "SELECT license_id, action, detail, created_at "
            "FROM issuance_history WHERE customer_public_id = ? "
            "ORDER BY id DESC",
            (public_id,),
        ).fetchall()
    actions = [
        {
            "license_id": row["license_id"],
            "action": row["action"],
            "detail": json.loads(row["detail"]) if row["detail"] else None,
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return {
        "customer_public_id": public_id,
        "actions": actions,
        "total": len(actions),
    }
