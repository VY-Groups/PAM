"""Database models for the license server."""
from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Dict, List, Optional

from extensions import db
from licensing_bridge import optional_fields, sig

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

EVENT_ISSUED = "issued"
EVENT_REVOKED = "revoked"
EVENT_RESTORED = "restored"
EVENT_USAGE_REPORTED = "usage_reported"

# Columns added after the first release. SQLite cannot ALTER TABLE its way to
# new columns, so they are appended at startup (see ensure_schema) instead of
# forcing users to delete their database.
SCHEMA_COLUMNS: Dict[str, Dict[str, str]] = {
    "licenses": {
        "license_id": "VARCHAR(64)",
        "tier": "VARCHAR(64)",
        "plan": "VARCHAR(64)",
        "subject_entity": "VARCHAR(255)",
        "classification": "VARCHAR(128)",
        "issuer": "VARCHAR(160)",
        "enclave_binding": "VARCHAR(160)",
        "fingerprint": "VARCHAR(80)",
        "signature_format": "VARCHAR(16) NOT NULL DEFAULT 'json'",
        "quotas": "JSON NOT NULL DEFAULT '{}'",
        "modules": "JSON NOT NULL DEFAULT '[]'",
        "account": "JSON NOT NULL DEFAULT '{}'",
        "reported_usage": "JSON NOT NULL DEFAULT '{}'",
        "last_reported_at": "DATETIME",
    },
}


def ensure_schema(engine) -> List[str]:
    """Add any missing spec columns to an existing database.

    Returns the columns that were added (empty when the schema was current).
    """
    added: List[str] = []
    with engine.begin() as connection:
        for table, columns in SCHEMA_COLUMNS.items():
            existing = {
                row[1]
                for row in connection.exec_driver_sql(f"PRAGMA table_info({table})")
            }
            for name, ddl in columns.items():
                if name in existing:
                    continue
                connection.exec_driver_sql(
                    f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"
                )
                added.append(f"{table}.{name}")
    return added


class LicenseRecord(db.Model):
    """A license issued by this server, including its signature."""

    __tablename__ = "licenses"

    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(36), nullable=False, unique=True, index=True)
    license_type = db.Column(db.String(32), nullable=False, index=True)
    issued_to = db.Column(db.String(255), nullable=False, index=True)
    issued_date = db.Column(db.DateTime, nullable=False)
    expires_on = db.Column(db.DateTime, nullable=True)

    # Commercial spec fields (mirrors the signed claims)
    license_id = db.Column(db.String(64), nullable=True, index=True)
    tier = db.Column(db.String(64), nullable=True, index=True)
    plan = db.Column(db.String(64), nullable=True)
    subject_entity = db.Column(db.String(255), nullable=True)
    classification = db.Column(db.String(128), nullable=True)
    issuer = db.Column(db.String(160), nullable=True)
    enclave_binding = db.Column(db.String(160), nullable=True)

    # JSON columns: note "metadata" is reserved on the declarative base, so the
    # attribute is renamed while keeping the wire-format column name.
    features = db.Column(db.JSON, nullable=False, default=list)
    usage_limits = db.Column(db.JSON, nullable=False, default=dict)
    license_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)
    quotas = db.Column(db.JSON, nullable=False, default=dict)
    modules = db.Column(db.JSON, nullable=False, default=list)
    account = db.Column(db.JSON, nullable=False, default=dict)

    # Runtime consumption reported by the deployed instance
    reported_usage = db.Column(db.JSON, nullable=False, default=dict)
    last_reported_at = db.Column(db.DateTime, nullable=True)

    status = db.Column(db.String(16), nullable=False, default=STATUS_ACTIVE, index=True)
    signature = db.Column(db.Text, nullable=False)
    algorithm = db.Column(db.String(32), nullable=False, default="RSA-PSS-SHA256")
    signature_format = db.Column(db.String(16), nullable=False, default="json")
    fingerprint = db.Column(db.String(80), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    @property
    def is_expired(self) -> bool:
        return self.expires_on is not None and datetime.now() > self.expires_on

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calendar days until expiry; None when perpetual or already expired.

        Matches the Phase 1 `License.days_until_expiry` semantics exactly.
        """
        if self.expires_on is None:
            return None
        now = datetime.now()
        if now > self.expires_on:
            return None
        return (self.expires_on.date() - now.date()).days

    def effective_status(self) -> str:
        if self.status == STATUS_REVOKED:
            return STATUS_REVOKED
        if self.is_expired:
            return "expired"
        return "valid"

    # ------------------------------------------------------------------
    # signed material (must reproduce the issued bytes exactly)
    # ------------------------------------------------------------------
    def license_data(self) -> Dict[str, Any]:
        """The claims that were signed, rebuilt from the stored record."""
        data: Dict[str, Any] = {
            "license_key": self.license_key,
            "license_type": self.license_type,
            "issued_to": self.issued_to,
            "issued_date": self.issued_date.isoformat(),
            "expires_on": self.expires_on.isoformat() if self.expires_on else None,
            "features": self.features,
            "usage_limits": self.usage_limits,
            "metadata": self.license_metadata,
        }
        data.update(
            optional_fields(
                tier=self.tier,
                plan=self.plan,
                license_id=self.license_id,
                subject_entity=self.subject_entity,
                classification=self.classification,
                issuer=self.issuer,
                enclave_binding=self.enclave_binding,
                quotas=self.quotas,
                modules=self.modules,
                account=self.account,
            )
        )
        return data

    def license_file(self) -> Dict[str, Any]:
        """Rebuild the signed JSON envelope exactly as it was issued."""
        envelope = sig.rebuild_json_envelope(
            self.license_data(), self.signature, self.algorithm
        )
        fingerprint = self.fingerprint_or_derived()
        if fingerprint:
            envelope["fingerprint"] = fingerprint
        return envelope

    def license_token(self) -> str:
        """Rebuild the compact .lic / .jwt token for this license."""
        return sig.rebuild_token(self.license_data(), self.signature, self.algorithm)

    # ------------------------------------------------------------------
    # runtime usage
    # ------------------------------------------------------------------
    def usage_summary(self) -> Dict[str, Any]:
        """Assigned ceilings (signed) vs consumption (reported at runtime)."""
        quotas = self.quotas or {}
        reported = self.reported_usage or {}

        def block(quota: Any, consumed: Any) -> Dict[str, Any]:
            quota_int = int(quota or 0)
            consumed_int = max(int(consumed or 0), 0)
            return {
                "quota": quota_int,
                "consumed": consumed_int,
                "headroom": max(quota_int - consumed_int, 0),
                "utilization": round(consumed_int / quota_int, 4)
                if quota_int
                else None,
                "over_quota": bool(quota_int and consumed_int > quota_int),
            }

        reported_pools = {
            pool.get("id"): pool
            for pool in reported.get("pools", []) or []
            if isinstance(pool, dict) and pool.get("id")
        }
        pools: List[Dict[str, Any]] = []
        for pool in quotas.get("pools", []) or []:
            if not isinstance(pool, dict):
                continue
            reported_pool = reported_pools.get(pool.get("id"), {})
            summary = block(
                pool.get("quota_nodes"), reported_pool.get("nodes_consumed", 0)
            )
            pools.append(
                {
                    "id": pool.get("id"),
                    "name": pool.get("name"),
                    "regions": pool.get("regions", []),
                    "quota_nodes": summary["quota"],
                    "enforcement": pool.get("enforcement"),
                    "consumed": summary["consumed"],
                    "headroom": summary["headroom"],
                    "utilization": summary["utilization"],
                    "over_quota": summary["over_quota"],
                }
            )

        nodes_consumed = reported.get("nodes_consumed")
        if nodes_consumed is None:
            nodes_consumed = sum(pool["consumed"] for pool in pools)

        return {
            "reported": bool(reported),
            "reported_at": (
                self.last_reported_at.isoformat() if self.last_reported_at else None
            ),
            "nodes": block(quotas.get("nodes"), nodes_consumed),
            "concurrent_sessions": block(
                quotas.get("concurrent_sessions"), reported.get("sessions_active", 0)
            ),
            "bastion_tunnels": block(
                quotas.get("bastion_tunnels"),
                reported.get("bastion_tunnels_used", 0),
            ),
            "pools": pools,
        }

    # ------------------------------------------------------------------
    # serialisation
    # ------------------------------------------------------------------
    def fingerprint_or_derived(self) -> str:
        if self.fingerprint:
            return self.fingerprint
        try:
            return sig.fingerprint(base64.b64decode(self.signature))
        except Exception:
            return None

    def to_dict(self, include_events: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "license_key": self.license_key,
            "license_type": self.license_type,
            "issued_to": self.issued_to,
            "issued_date": self.issued_date.isoformat(),
            "expires_on": self.expires_on.isoformat() if self.expires_on else None,
            "features": self.features,
            "usage_limits": self.usage_limits,
            "metadata": self.license_metadata,
            # commercial spec
            "license_id": self.license_id,
            "tier": self.tier,
            "plan": self.plan,
            "subject_entity": self.subject_entity,
            "classification": self.classification,
            "issuer": self.issuer,
            "enclave_binding": self.enclave_binding,
            "quotas": self.quotas or {},
            "modules": self.modules or [],
            "account": self.account or {},
            # signature
            "status": self.status,
            "effective_status": self.effective_status(),
            "algorithm": self.algorithm,
            "signature_format": self.signature_format,
            "fingerprint": self.fingerprint_or_derived(),
            "days_until_expiry": self.days_until_expiry,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
            "created_at": self.created_at.isoformat(),
            # runtime
            "usage": self.usage_summary(),
            "last_reported_at": (
                self.last_reported_at.isoformat() if self.last_reported_at else None
            ),
        }
        if include_events:
            data["events"] = [event.to_dict() for event in self.audit_events()]
        return data

    def audit_events(self) -> List["LicenseEvent"]:
        """Audit entries for this license, oldest first (chronological)."""
        return (
            LicenseEvent.query.filter_by(license_key=self.license_key)
            .order_by(LicenseEvent.created_at.asc(), LicenseEvent.id.asc())
            .all()
        )


class LicenseEvent(db.Model):
    """Audit trail entry for license lifecycle changes."""

    __tablename__ = "license_events"

    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(36), nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)
    detail = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "license_key": self.license_key,
            "action": self.action,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }


def log_event(license_key: str, action: str, detail: Optional[Dict[str, Any]] = None) -> None:
    """Record an audit event (does not commit)."""
    db.session.add(
        LicenseEvent(
            license_key=license_key,
            action=action,
            detail=detail or {},
        )
    )


# ---------------------------------------------------------------------------
# platform settings (Platform Settings screen: SSO / HSM / ZSP / WORM)
# ---------------------------------------------------------------------------
SETTINGS_ACTION_UPDATED = "updated"


class SettingGroup(db.Model):
    """One saved block of platform settings (sso / hsm / zsp / worm)."""

    __tablename__ = "platform_settings"

    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(32), nullable=False, unique=True, index=True)
    value = db.Column(db.JSON, nullable=False, default=dict)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_by = db.Column(db.String(64), nullable=False, default="admin")

    def to_dict(self, values: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "group": self.group_name,
            "values": self.value if values is None else values,
            "stored": True,
            "updated_at": self.updated_at.isoformat(),
            "updated_by": self.updated_by,
        }


class SettingsEvent(db.Model):
    """Config audit changelog entry: which fields changed, who, when."""

    __tablename__ = "settings_events"

    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(32), nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)
    changes = db.Column(db.JSON, nullable=False, default=dict)
    actor = db.Column(db.String(64), nullable=False, default="admin")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "group": self.group_name,
            "action": self.action,
            "changes": self.changes,
            "actor": self.actor,
            "created_at": self.created_at.isoformat(),
        }
