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
EVENT_IMPORTED = "imported"
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
    # credential vault: encrypted secret storage (phase 4a rotation engine)
    "vault_items": {
        "secret_version": "INTEGER",
        "secret_updated_at": "DATETIME",
    },
    # command control (phase 4d): the policy decision on each recorded command,
    # the rule that produced it, and the approval row that resolves a hold
    "session_events": {
        "decision": "VARCHAR(16)",
        "rule_id": "INTEGER",
        "ref_seq": "INTEGER",
    },
    # contextual watermarking (phase 4k, section 12): the SOURCE line of the
    # overlay is the address the access really came from.
    "privileged_sessions": {
        "source_ip": "VARCHAR(64)",
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


# ---------------------------------------------------------------------------
# credential vault (Credential Vault screen: inventory, rotation, checkouts)
# ---------------------------------------------------------------------------
VAULT_STATUS_AVAILABLE = "available"
VAULT_STATUS_CHECKED_OUT = "checked_out"
VAULT_STATUS_ROTATING = "rotating"
VAULT_STATUS_ROTATION_DUE = "rotation_due"
VAULT_STATUS_FAILED = "failed"
VAULT_STATUSES = (
    VAULT_STATUS_AVAILABLE,
    VAULT_STATUS_CHECKED_OUT,
    VAULT_STATUS_ROTATING,
    VAULT_STATUS_ROTATION_DUE,
    VAULT_STATUS_FAILED,
)

# Inventory categories; matches the Credential Vault screen's type filter.
VAULT_TYPE_DATABASE = "database"
VAULT_TYPE_CLOUD_IAM = "cloud_iam"
VAULT_TYPE_SSH_KEY = "ssh_key"
VAULT_TYPE_SERVICE_ACCOUNT = "service_account"
VAULT_TYPE_DOMAIN_PASSWORD = "domain_password"
VAULT_TYPE_API_TOKEN = "api_token"
VAULT_TYPES = (
    VAULT_TYPE_DATABASE,
    VAULT_TYPE_CLOUD_IAM,
    VAULT_TYPE_SSH_KEY,
    VAULT_TYPE_SERVICE_ACCOUNT,
    VAULT_TYPE_DOMAIN_PASSWORD,
    VAULT_TYPE_API_TOKEN,
)

VAULT_ACTION_ONBOARDED = "onboarded"
VAULT_ACTION_CHECKED_OUT = "checked_out"
VAULT_ACTION_REVOKED = "revoked"
VAULT_ACTION_ROTATED = "rotated"
VAULT_ACTION_ROTATION_FAILED = "rotation_failed"
# an admin reveal is exactly the kind of access an audit must show
VAULT_ACTION_REVEALED = "revealed"


class VaultItem(db.Model):
    """One managed credential in the vault inventory."""

    __tablename__ = "vault_items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True, index=True)
    secret_type = db.Column(db.String(32), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")
    target = db.Column(db.String(255), nullable=False)
    target_detail = db.Column(db.String(255), nullable=False, default="")
    principal = db.Column(db.String(128), nullable=False)
    access_tier = db.Column(db.String(16), nullable=False, default="Tier-2")
    auth_method = db.Column(db.String(32), nullable=False, default="Password")

    # 0 means on-demand rotation (no scheduled SLA).
    rotation_interval_hours = db.Column(db.Integer, nullable=False, default=24)
    last_rotated_at = db.Column(db.DateTime, nullable=True)

    # Encrypted secret storage (AES-256-GCM); NULL version = metadata-only
    # record with no stored value. The value itself lives in
    # vault_secret_versions (versioned history), never in this row.
    secret_version = db.Column(db.Integer, nullable=True)
    secret_updated_at = db.Column(db.DateTime, nullable=True)

    status = db.Column(
        db.String(16), nullable=False, default=VAULT_STATUS_AVAILABLE, index=True
    )
    checked_out_by = db.Column(db.String(64), nullable=True)
    checked_out_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    @property
    def rotation_interval_label(self) -> str:
        """Human label for the SLA: 'On-demand', 'Every 24h', 'Every 7d'..."""
        hours = self.rotation_interval_hours or 0
        if hours <= 0:
            return "On-demand"
        if hours % 24 == 0:
            return f"Every {hours // 24}d"
        return f"Every {hours}h"

    @property
    def rotation_hours_remaining(self) -> Optional[int]:
        """Hours until the next rotation is due; None when on-demand."""
        hours = self.rotation_interval_hours or 0
        if hours <= 0 or self.last_rotated_at is None:
            return None
        elapsed = (datetime.now() - self.last_rotated_at).total_seconds() / 3600.0
        return int(hours - elapsed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "secret_type": self.secret_type,
            "description": self.description,
            "target": self.target,
            "target_detail": self.target_detail,
            "principal": self.principal,
            "access_tier": self.access_tier,
            "auth_method": self.auth_method,
            "rotation_interval_hours": self.rotation_interval_hours,
            "rotation_interval_label": self.rotation_interval_label,
            "rotation_hours_remaining": self.rotation_hours_remaining,
            "last_rotated_at": (
                self.last_rotated_at.isoformat() if self.last_rotated_at else None
            ),
            "secret_version": self.secret_version,
            "secret_updated_at": (
                self.secret_updated_at.isoformat() if self.secret_updated_at else None
            ),
            "status": self.status,
            "checked_out_by": self.checked_out_by,
            "checked_out_at": (
                self.checked_out_at.isoformat() if self.checked_out_at else None
            ),
            "created_at": self.created_at.isoformat(),
        }


class VaultEvent(db.Model):
    """Vault audit trail entry: onboarding, checkouts, rotations."""

    __tablename__ = "vault_events"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, nullable=False, index=True)
    item_name = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    detail = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "item_id": self.item_id,
            "item_name": self.item_name,
            "action": self.action,
            "actor": self.actor,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }


class VaultSecretVersion(db.Model):
    """One immutable stored secret value for a vault item.

    The plaintext never touches this table: `blob` is the AES-256-GCM wire
    form `{"v", "alg", "nonce", "ct"}` with the AAD bound to the owning item
    id, so a ciphertext copied between rows fails its integrity check. The
    highest `version` for an item is the current secret (secret versioning);
    older rows are retained history and are never rewritten.
    """

    __tablename__ = "vault_secret_versions"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False)
    blob = db.Column(db.JSON, nullable=False)
    # "generated" = minted by the rotation engine, "operator" = supplied at
    # onboarding by the admin.
    source = db.Column(db.String(16), nullable=False, default="generated")
    trigger = db.Column(db.String(32), nullable=False, default="onboarded")
    created_by = db.Column(db.String(64), nullable=False, default="system")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "item_id": self.item_id,
            "version": self.version,
            "alg": (self.blob or {}).get("alg"),
            "source": self.source,
            "trigger": self.trigger,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# discovery engine (module 3)
# ---------------------------------------------------------------------------
ASSET_TYPES = (
    "windows",
    "linux",
    "unix",
    "aix",
    "solaris",
    "vmware",
    "hyperv",
    "kubernetes",
    "docker",
    "network",
    "firewall",
    "loadbalancer",
    "database",
    "cloud",
    "unknown",
)
ASSET_RISKS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ASSET_PAM_STATUSES = ("unmanaged", "managed", "ignored")
ACCOUNT_KINDS = ("builtin_admin", "database_admin", "service_account", "other")

# Classify -> risk-score (rules v1): base severity per asset family. Matches the
# reference architecture's scoring: Linux/Windows/DB/Firewall/Cloud land at
# HIGH-or-CRITICAL; edge devices stay MEDIUM until an operator reclassifies.
BASE_RISK = {
    "database": "CRITICAL",
    "windows": "CRITICAL",
    "cloud": "CRITICAL",
    "firewall": "HIGH",
    "loadbalancer": "HIGH",
    "network": "HIGH",
    "kubernetes": "HIGH",
    "linux": "HIGH",
    "unix": "MEDIUM",
    "aix": "MEDIUM",
    "solaris": "MEDIUM",
    "vmware": "MEDIUM",
    "hyperv": "MEDIUM",
    "docker": "MEDIUM",
    "unknown": "LOW",
}

# Recommend policy (advisory, rules v1): the policy an operator should apply
# when ingesting this asset type. Shown during onboarding, never auto-enforced.
RECOMMENDED_POLICY = {
    "database": "JIT checkout + 24h credential rotation + session recording",
    "windows": "JIT AD account + MFA + 8h credential rotation",
    "cloud": "Federated role assumption + 4h credential rotation",
    "firewall": "JIT admin + change-window approval + 7d rotation",
    "loadbalancer": "JIT admin + change-window approval + 7d rotation",
    "network": "JIT admin + 7d credential rotation",
    "kubernetes": "Short-lived kubeconfig + 1h token TTL",
    "linux": "SSH certificate JIT + 24h credential rotation",
    "unix": "SSH certificate JIT + 24h credential rotation",
    "aix": "SSH certificate JIT + 24h credential rotation",
    "solaris": "SSH certificate JIT + 24h credential rotation",
    "vmware": "Named admin account + MFA + 24h rotation",
    "hyperv": "Named admin account + MFA + 24h rotation",
    "docker": "Short-lived registry credential + 24h rotation",
    "unknown": "Classify the asset, then apply a tier policy",
}

# Onboard -> the vault secret type that best describes the admin account.
ASSET_SECRET_TYPES = {
    "database": "database",
    "cloud": "cloud_iam",
    "windows": "domain_password",
    "kubernetes": "ssh_key",
    "docker": "ssh_key",
    "linux": "ssh_key",
    "unix": "ssh_key",
    "aix": "ssh_key",
    "solaris": "ssh_key",
    "vmware": "service_account",
    "hyperv": "service_account",
    "firewall": "service_account",
    "network": "service_account",
    "loadbalancer": "service_account",
    "unknown": "service_account",
}

DISCOVERY_ACTION_SCAN_STARTED = "scan_started"
DISCOVERY_ACTION_SCAN_COMPLETED = "scan_completed"
DISCOVERY_ACTION_SCAN_FAILED = "scan_failed"
DISCOVERY_ACTION_ASSET_DISCOVERED = "asset_discovered"
DISCOVERY_ACTION_ASSET_ONBOARDED = "asset_onboarded"
DISCOVERY_ACTION_ASSET_UPDATED = "asset_updated"

DISCOVERY_SOURCE_SCAN = "scan"
DISCOVERY_SOURCE_MANUAL = "manual"
DISCOVERY_METHOD_PROBE = "tcp_probe"
DISCOVERY_METHOD_MANUAL = "manual"

DISCOVERY_SCAN_RUNNING = "running"
DISCOVERY_SCAN_COMPLETED = "completed"
DISCOVERY_SCAN_FAILED = "failed"

# Username pattern -> account kind (reference taxonomy: root, administrator,
# postgres/oracle/sa/mysql, svc_*, backup_*). Group-derived kinds (domain
# admins, local admins) require directory enumeration, which no module
# performs yet, so they are never guessed.
def classify_account_kind(username: str) -> str:
    lower = (username or "").strip().lower()
    if lower in ("root", "administrator", "admin", "adm"):
        return "builtin_admin"
    if lower in ("postgres", "oracle", "mysql", "mssql", "mongo", "mongodb", "sa"):
        return "database_admin"
    if lower.startswith(("svc_", "svc-", "backup_", "backup-")):
        return "service_account"
    return "other"


class DiscoveredAsset(db.Model):
    """One target host: discovered by a real probe or registered by an operator."""

    __tablename__ = "discovered_assets"

    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), nullable=False, unique=True, index=True)
    hostname = db.Column(db.String(255), nullable=False, default="")
    asset_type = db.Column(db.String(32), nullable=False, default="unknown", index=True)
    risk = db.Column(db.String(16), nullable=False, default="LOW", index=True)
    pam_status = db.Column(
        db.String(16), nullable=False, default="unmanaged", index=True
    )
    detail = db.Column(db.String(255), nullable=False, default="")
    ports = db.Column(db.JSON, nullable=False, default=list)
    source = db.Column(db.String(16), nullable=False, default=DISCOVERY_SOURCE_SCAN)
    method = db.Column(db.String(32), nullable=False, default=DISCOVERY_METHOD_PROBE)
    notes = db.Column(db.String(255), nullable=False, default="")
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.now)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.now)

    @property
    def recommended_policy(self) -> str:
        return RECOMMENDED_POLICY.get(self.asset_type, RECOMMENDED_POLICY["unknown"])

    @property
    def open_ports(self) -> List[int]:
        return [entry.get("port") for entry in (self.ports or []) if entry.get("port")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "address": self.address,
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "risk": self.risk,
            "pam_status": self.pam_status,
            "detail": self.detail,
            "ports": self.ports or [],
            "source": self.source,
            "method": self.method,
            "notes": self.notes,
            "recommended_policy": self.recommended_policy,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class DiscoveredAccount(db.Model):
    """A privileged account recorded against a discovered/onboarded asset."""

    __tablename__ = "discovered_accounts"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, nullable=False, index=True)
    asset_address = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(128), nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False, default="other", index=True)
    source = db.Column(db.String(16), nullable=False, default=DISCOVERY_SOURCE_MANUAL)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "asset_address": self.asset_address,
            "username": self.username,
            "kind": self.kind,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
        }


class DiscoveryScan(db.Model):
    """One discovery scan run (scope, ports, honest counters)."""

    __tablename__ = "discovery_scans"

    id = db.Column(db.Integer, primary_key=True)
    scope = db.Column(db.String(64), nullable=False)
    method = db.Column(db.String(32), nullable=False, default=DISCOVERY_METHOD_PROBE)
    ports = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(
        db.String(16), nullable=False, default=DISCOVERY_SCAN_RUNNING, index=True
    )
    hosts_probed = db.Column(db.Integer, nullable=False, default=0)
    hosts_open = db.Column(db.Integer, nullable=False, default=0)
    services_found = db.Column(db.Integer, nullable=False, default=0)
    findings = db.Column(db.Integer, nullable=False, default=0)
    error = db.Column(db.String(255), nullable=False, default="")
    triggered_by = db.Column(db.String(64), nullable=False, default="system")
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    finished_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scope": self.scope,
            "method": self.method,
            "ports": self.ports or [],
            "status": self.status,
            "hosts_probed": self.hosts_probed,
            "hosts_open": self.hosts_open,
            "services_found": self.services_found,
            "findings": self.findings,
            "error": self.error,
            "triggered_by": self.triggered_by,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


class DiscoveryEvent(db.Model):
    """Discovery audit trail entry: scans, discoveries, onboarding, updates."""

    __tablename__ = "discovery_events"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(32), nullable=False)
    subject = db.Column(db.String(128), nullable=False, default="")
    actor = db.Column(db.String(64), nullable=False, default="system")
    detail = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "subject": self.subject,
            "actor": self.actor,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# JIT / JEA access (module 6)
# ---------------------------------------------------------------------------
JIT_STATUSES = (
    "pending",    # awaiting the approvals its risk level requires
    "approved",   # approvals complete (or auto-approved by low risk)
    "active",     # granted: the vault credential is checked out until expires_at
    "closed",     # access ended early -> credential rotated
    "expired",    # the time box elapsed -> credential rotated
    "denied",     # an approver rejected it
    "blocked",    # risk >= 76: policy blocks it outright
)
JIT_ROLES = ("manager", "security")
RISK_LEVELS = ("low", "medium", "high", "critical")


class JitRequest(db.Model):
    """One time-boxed privileged access request (architecture module 6):
    reason + ticket -> risk evaluation -> approvals -> grant -> expiry ->
    credential rotation. Every state carries who did it and when."""

    __tablename__ = "jit_requests"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, nullable=False, index=True)
    requester = db.Column(db.String(64), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    ticket = db.Column(db.String(64), nullable=False)
    minutes = db.Column(db.Integer, nullable=False, default=15)
    # Real evaluation over request context (target tier, duration, off-hours,
    # repeat behaviour, ticket shape, credential health) - factors carry the
    # points that produced the score, nothing is assigned arbitrarily.
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.String(16), nullable=False, default="low")
    risk_factors = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    # {actor, at, role?} snapshots; auto-approval records the policy itself.
    manager_approval = db.Column(db.JSON, nullable=True)
    security_approval = db.Column(db.JSON, nullable=True)
    granted_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    session_ref = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        minutes_left = None
        if self.status == "active" and self.expires_at is not None:
            seconds = (self.expires_at - datetime.now()).total_seconds()
            minutes_left = max(0, int(seconds // 60))
        return {
            "id": self.id,
            "item_id": self.item_id,
            "requester": self.requester,
            "reason": self.reason,
            "ticket": self.ticket,
            "minutes": self.minutes,
            "minutes_left": minutes_left,
            "risk": {
                "score": self.risk_score,
                "level": self.risk_level,
                "factors": self.risk_factors or [],
            },
            "status": self.status,
            "approvals": {
                "manager": self.manager_approval,
                "security": self.security_approval,
            },
            "granted_at": self.granted_at.isoformat() if self.granted_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "session_ref": self.session_ref,
            "created_at": self.created_at.isoformat(),
        }


class JitEvent(db.Model):
    """JIT audit trail: requested / approved / denied / granted / expired /
    closed, each with the real actor and detail (append-only)."""

    __tablename__ = "jit_events"

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    detail = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "action": self.action,
            "actor": self.actor,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# privileged session management (module 8)
# ---------------------------------------------------------------------------
SESSION_PROTOCOLS = (
    "ssh", "rdp", "telnet", "vnc", "http", "https", "sql", "oracle",
    "postgresql", "mssql", "mysql", "sap", "kubernetes",
)
SESSION_STATUSES = (
    "active",     # running: events are accepted and recorded
    "paused",     # supervisor paused it: events refused
    "locked",     # locked pending review: events refused
    "terminated", # stopped early (kill switch / control action)
    "completed",  # ran to its natural end
)
SESSION_TERMINAL_STATUSES = ("terminated", "completed")
SESSION_EVENT_TYPES = (
    "keystroke",   # typed input (content withheld when keystroke_log is off)
    "command",     # executed command (always kept: the safety channel)
    "file_upload", # gated by upload_allowed
    "file_download",  # gated by download_allowed
    "clipboard",   # gated by clipboard_allowed
    "screenshot",  # gated by screenshot_allowed
    "note",        # operator annotation (recorded like other content)
    "status",      # server-written lifecycle marker (pause/lock/terminate...)
    "approval",    # resolution of a held command (ref_seq -> the command row)
)


class PrivilegedSession(db.Model):
    """One privileged session (architecture module 8): protocol + target, the
    control flags that govern recording / transfer / clipboard / watermark,
    the real start-stop clock, and the vault checkout or JIT grant it runs
    under. Ending a session drives the release-and-rotate cascade."""

    __tablename__ = "privileged_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_ref = db.Column(db.String(64), nullable=False, unique=True, index=True)
    protocol = db.Column(db.String(16), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    # linkage: a session runs against a vault credential, optionally the one
    # an active JIT grant already checked out (both nullable).
    item_id = db.Column(db.Integer, nullable=True, index=True)
    jit_request_id = db.Column(db.Integer, nullable=True, index=True)
    # section 12 watermark: where the access came from, kept on the row so the
    # overlay's SOURCE line is real evidence (nullable - sessions recorded
    # before this column existed render an em dash, never a guess).
    source_ip = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), nullable=False, default="active", index=True)
    # session controls (module 8 control list); all default on.
    record = db.Column(db.Boolean, nullable=False, default=True)
    keystroke_log = db.Column(db.Boolean, nullable=False, default=True)
    watermark = db.Column(db.Boolean, nullable=False, default=True)
    clipboard_allowed = db.Column(db.Boolean, nullable=False, default=True)
    upload_allowed = db.Column(db.Boolean, nullable=False, default=True)
    download_allowed = db.Column(db.Boolean, nullable=False, default=True)
    screenshot_allowed = db.Column(db.Boolean, nullable=False, default=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    ended_at = db.Column(db.DateTime, nullable=True)
    end_reason = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        end = self.ended_at or datetime.now()
        duration = max(0, int((end - self.started_at).total_seconds()))
        return {
            "id": self.id,
            "session_ref": self.session_ref,
            "protocol": self.protocol,
            "target": self.target,
            "actor": self.actor,
            "item_id": self.item_id,
            "jit_request_id": self.jit_request_id,
            "status": self.status,
            "controls": {
                "record": self.record,
                "keystroke_log": self.keystroke_log,
                "watermark": self.watermark,
                "clipboard_allowed": self.clipboard_allowed,
                "upload_allowed": self.upload_allowed,
                "download_allowed": self.download_allowed,
                "screenshot_allowed": self.screenshot_allowed,
            },
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "end_reason": self.end_reason,
            "duration_seconds": duration,
            "created_at": self.created_at.isoformat(),
        }


class SessionEvent(db.Model):
    """Append-only session recording rows: what flowed through the channel,
    whether the controls allowed it, and the watermark that proves custody."""

    __tablename__ = "session_events"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, nullable=False, index=True)
    seq = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(16), nullable=False)
    content = db.Column(db.Text, nullable=True)
    allowed = db.Column(db.Boolean, nullable=False, default=True)
    blocked_reason = db.Column(db.String(64), nullable=True)
    withheld = db.Column(db.Boolean, nullable=False, default=False)
    # command control (module 9): the policy decision for `command` rows
    # (allow / approval / block), the rule id that produced it (null when no
    # rule matched -> default allow), and ref_seq pointing at the held command
    # an `approval` row resolves.
    decision = db.Column(db.String(16), nullable=True)
    rule_id = db.Column(db.Integer, nullable=True)
    ref_seq = db.Column(db.Integer, nullable=True)
    watermark = db.Column(db.String(160), nullable=True)
    actor = db.Column(db.String(64), nullable=False, default="system")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "seq": self.seq,
            "type": self.type,
            "content": self.content,
            "allowed": self.allowed,
            "blocked_reason": self.blocked_reason,
            "withheld": self.withheld,
            "decision": self.decision,
            "rule_id": self.rule_id,
            "ref_seq": self.ref_seq,
            "watermark": self.watermark,
            "actor": self.actor,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# command control (module 9)
# ---------------------------------------------------------------------------
COMMAND_ACTIONS = ("allow", "approval", "block")


class CommandRule(db.Model):
    """One shipped policy rule (architecture 9): match a command pattern
    (optionally scoped to a target glob) and allow, hold for approval or
    block it - optionally terminating the session as context-aware response."""

    __tablename__ = "command_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    pattern = db.Column(db.String(160), nullable=False, index=True)
    action = db.Column(db.String(16), nullable=False, default="allow")
    # fnmatch glob on the session target (case-insensitive); "" = any target
    target_pattern = db.Column(db.String(120), nullable=False, default="")
    # context-aware escalation: on a block, end the session and raise an incident
    terminate_on_match = db.Column(db.Boolean, nullable=False, default=False)
    description = db.Column(db.String(255), nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_by = db.Column(db.String(64), nullable=False, default="admin")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern,
            "action": self.action,
            "target_pattern": self.target_pattern,
            "terminate_on_match": self.terminate_on_match,
            "description": self.description,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "updated_by": self.updated_by,
        }


class CommandIncident(db.Model):
    """Evidence preserved when an escalated block kills a session: the command,
    the rule, the session it happened in, and the lifecycle of the incident."""

    __tablename__ = "command_incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_ref = db.Column(db.String(32), nullable=False, unique=True, index=True)
    session_id = db.Column(db.Integer, nullable=False, index=True)
    event_seq = db.Column(db.Integer, nullable=False)
    rule_id = db.Column(db.Integer, nullable=True)
    # snapshot so the evidence survives the rule being edited or deleted
    rule_name = db.Column(db.String(120), nullable=False, default="")
    rule_pattern = db.Column(db.String(160), nullable=False, default="")
    command = db.Column(db.Text, nullable=False)
    target = db.Column(db.String(255), nullable=False, default="")
    actor = db.Column(db.String(64), nullable=False, default="system")
    status = db.Column(db.String(16), nullable=False, default="open", index=True)
    closed_by = db.Column(db.String(64), nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    close_note = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_ref": self.incident_ref,
            "session_id": self.session_id,
            "event_seq": self.event_seq,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_pattern": self.rule_pattern,
            "command": self.command,
            "target": self.target,
            "actor": self.actor,
            "status": self.status,
            "closed_by": self.closed_by,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "close_note": self.close_note,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# risk-based access engine (architecture section 7)
# ---------------------------------------------------------------------------
RISK_CONTEXT_MANUAL = "manual"          # scored from the console (advisory)
RISK_CONTEXT_SESSION_START = "session_start"  # scored when a session begins
RISK_CONTEXTS = (RISK_CONTEXT_MANUAL, RISK_CONTEXT_SESSION_START)
# band -> the policy the architecture prescribes for it
RISK_DECISIONS = ("allow", "mfa", "approval", "block")
RISK_DECISION_BY_BAND = {
    "low": "allow",
    "medium": "mfa",
    "high": "approval",
    "critical": "block",
}
# what happened to this request: a console evaluation only advises, a session
# start is actually allowed through or refused by the gate
RISK_RESULTS = ("advisory", "allowed", "refused")


class RiskEvent(db.Model):
    """One request scored by the risk engine (architecture section 7).

    Eight components - user, device, asset, time, location, behavior, ticket
    and command - each read from a measured input, sum to the score; the
    band (0-25 low, 26-50 medium, 51-75 high, 76-100 critical) drives the
    decision (allow / MFA / approval / block). Session starts are gated on
    it: CRITICAL is refused outright, HIGH needs an active JIT grant (the
    approval the band demands), everything else runs.
    """

    __tablename__ = "risk_events"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    # who asked for the evaluation
    actor = db.Column(db.String(64), nullable=False, default="system")
    # who the score is about
    subject = db.Column(db.String(160), nullable=False, default="", index=True)
    context = db.Column(db.String(32), nullable=False, default=RISK_CONTEXT_MANUAL, index=True)
    # the request's own inputs (scored, never guessed)
    target = db.Column(db.String(255), nullable=False, default="")
    device = db.Column(db.String(128), nullable=False, default="")
    source_ip = db.Column(db.String(64), nullable=False, default="")
    ticket = db.Column(db.String(64), nullable=False, default="")
    command = db.Column(db.String(1000), nullable=False, default="")
    # the evaluation
    score = db.Column(db.Integer, nullable=False, default=0)
    band = db.Column(db.String(16), nullable=False, default="low", index=True)
    decision = db.Column(db.String(16), nullable=False, default="allow")
    result = db.Column(db.String(16), nullable=False, default="advisory")
    # every component with its points and the detail that produced them
    components = db.Column(db.JSON, nullable=False, default=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "actor": self.actor,
            "subject": self.subject,
            "context": self.context,
            "target": self.target,
            "device": self.device,
            "source_ip": self.source_ip,
            "ticket": self.ticket,
            "command": self.command,
            "score": self.score,
            "band": self.band,
            "decision": self.decision,
            "result": self.result,
            "components": self.components or [],
        }


class BehaviorBaseline(db.Model):
    """One principal's learned behavior baseline (architecture section 11).

    Trained explicitly from the product's own history - `risk_events`,
    `privileged_sessions`, `session_events` (commands) and
    `command_incidents` rows over a rolling window - never from synthetic
    users: which hours, devices, source IPs, targets, command verbs and
    privilege verbs the principal actually used, and the session cadence
    that came with them. Evaluations then diff the request against this
    profile; each deviation is a named reason ("unusual time", ...) on the
    `behavior` component and drives the section 11 response chain when the
    band turns critical.
    """

    __tablename__ = "behavior_baselines"

    id = db.Column(db.Integer, primary_key=True)
    # the principal the profile describes (evaluation subject / session actor)
    subject = db.Column(db.String(160), nullable=False, unique=True, index=True)
    window_days = db.Column(db.Integer, nullable=False, default=30)
    # how many real history rows the profile learned from (0 = nothing seen)
    samples = db.Column(db.Integer, nullable=False, default=0)
    profile = db.Column(db.JSON, nullable=False, default=dict)
    trained_by = db.Column(db.String(64), nullable=False, default="system")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        profile = self.profile or {}
        return {
            "id": self.id,
            "subject": self.subject,
            "window_days": self.window_days,
            "samples": self.samples,
            "sessions": int(profile.get("sessions", 0)),
            "evaluations": int(profile.get("evaluations", 0)),
            "incidents": int(profile.get("incidents", 0)),
            "hours": list(profile.get("hours", [])),
            "devices": list(profile.get("devices", [])),
            "source_ips": list(profile.get("source_ips", [])),
            "targets": list(profile.get("targets", [])),
            "protocols": list(profile.get("protocols", [])),
            "command_verbs": list(profile.get("command_verbs", [])),
            "privilege_verbs": list(profile.get("privilege_verbs", [])),
            "sessions_per_day": float(profile.get("sessions_per_day", 0.0)),
            "first_at": profile.get("first_at"),
            "last_at": profile.get("last_at"),
            "trained_by": self.trained_by,
            "updated_at": self.updated_at.isoformat(),
        }


class AnomalyEvent(db.Model):
    """One UEBA incident: a critical evaluation whose `behavior` component
    named baseline deviations (architecture section 11), plus the response
    the engine executed for it - sessions ended (release-and-rotate
    cascade), credentials rotated, evidence pointers.

    Named `*Event` deliberately: the ledger drift guard requires every
    `*Event` table to join the audit ledger, and this one fans into the
    `risk` trail (`action: "anomaly-incident"`) next to the evaluation it
    came from. One incident per refused evaluation (`evaluation_id` is
    unique); rows are preserved evidence and are never rewritten.
    """

    __tablename__ = "anomaly_incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_ref = db.Column(db.String(64), nullable=False, unique=True, index=True)
    # the refused evaluation this incident preserves
    evaluation_id = db.Column(db.Integer, nullable=False, unique=True, index=True)
    actor = db.Column(db.String(64), nullable=False, default="system")
    subject = db.Column(db.String(160), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, default="")
    score = db.Column(db.Integer, nullable=False, default=0)
    band = db.Column(db.String(16), nullable=False, default="critical")
    # the named deviations, verbatim from the component ("unusual time", ...)
    reasons = db.Column(db.JSON, nullable=False, default=list)
    # what the response chain did: sessions ended, rotations, evidence refs
    actions = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_ref": self.incident_ref,
            "evaluation_id": self.evaluation_id,
            "actor": self.actor,
            "subject": self.subject,
            "target": self.target,
            "score": self.score,
            "band": self.band,
            "reasons": list(self.reasons or []),
            "actions": self.actions or {},
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# immutable audit ledger (architecture 19)
# ---------------------------------------------------------------------------
# sha256 of the zero hash: the chain every record links back to.
AUDIT_GENESIS_HASH = "0" * 64


class AuditEvent(db.Model):
    """One record of the append-only, hash-chained audit ledger (§19).

    Every module event row (license, settings, vault, discovery, JIT,
    session lifecycle, command control and risk evaluation) is copied here
    at flush time: `seq` is the chain position, `event_hash` =
    sha256(prev_hash + canonical payload), and SQLite BEFORE UPDATE/DELETE
    triggers make the rows immutable at the storage layer - there is no API
    path that writes or removes them either.
    """

    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    # chain position: 1..N with no gaps (verify reports any break)
    seq = db.Column(db.Integer, nullable=False, unique=True, index=True)
    # stable key of the source row, e.g. "vault:12" / "incident:3"
    event_ref = db.Column(db.String(64), nullable=False, unique=True, index=True)
    source = db.Column(db.String(16), nullable=False, index=True)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    subject = db.Column(db.String(160), nullable=False, default="")
    detail = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, index=True)
    prev_hash = db.Column(db.String(64), nullable=False)
    event_hash = db.Column(db.String(64), nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.event_ref,
            "seq": self.seq,
            "event_ref": self.event_ref,
            "source": self.source,
            "action": self.action,
            "actor": self.actor,
            "subject": self.subject,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
        }


# ---------------------------------------------------------------------------
# PAM bypass detection (architecture section 10)
# ---------------------------------------------------------------------------
# Correlation outcome for one parsed connection observation.
BYPASS_SIGNAL_OBSERVED = "observed"        # ingested, not yet correlated
BYPASS_SIGNAL_CANDIDATE = "candidate"      # managed target, no recorded session
BYPASS_SIGNAL_COVERED = "covered"          # a recorded (through-PAM) session covers it
BYPASS_SIGNAL_OUT_OF_SCOPE = "out_of_scope"  # target is not a managed PAM asset
BYPASS_SIGNAL_STATUSES = (
    BYPASS_SIGNAL_OBSERVED,
    BYPASS_SIGNAL_CANDIDATE,
    BYPASS_SIGNAL_COVERED,
    BYPASS_SIGNAL_OUT_OF_SCOPE,
)
BYPASS_INCIDENT_STATUSES = ("open", "closed")


class BypassSignal(db.Model):
    """One connection observation parsed from real platform logs (§10).

    Ingest feeds it (OpenSSH `Accepted …` lines or structured JSON records
    from Windows/EDR/network exports); a correlation scan then decides
    whether the target is a managed PAM asset and whether a recorded
    privileged session covers the connection. The original line is kept as
    evidence - it is never rewritten.
    """

    __tablename__ = "bypass_signals"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    # when the connection happened: the line's own timestamp when it carried
    # one, otherwise the ingest time (recorded in `detail.at_source`)
    observed_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    user = db.Column(db.String(128), nullable=False, index=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, default="")
    protocol = db.Column(db.String(16), nullable=False, default="unknown")
    # which log bundle this came from (file name or api label)
    origin = db.Column(db.String(128), nullable=False, default="api")
    raw = db.Column(db.Text, nullable=False, default="")
    status = db.Column(
        db.String(16), nullable=False, default=BYPASS_SIGNAL_OBSERVED, index=True
    )
    # correlation notes: matched asset, covering session, reason
    detail = db.Column(db.JSON, nullable=False, default=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "observed_at": self.observed_at.isoformat(),
            "user": self.user,
            "source_ip": self.source_ip,
            "target": self.target,
            "protocol": self.protocol,
            "origin": self.origin,
            "raw": self.raw,
            "status": self.status,
            "detail": self.detail or {},
        }


class BypassIncident(db.Model):
    """A managed target reached outside any recorded session (§10).

    Creating one carries the architecture's response: alert SOC (the ledger
    record itself), force credential rotation (the real §5 pipeline), and
    block source - recorded honestly as `not_connected` until an
    enforcement connector exists.
    """

    __tablename__ = "bypass_incidents"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    incident_ref = db.Column(db.String(32), nullable=False, unique=True, index=True)
    signal_id = db.Column(db.Integer, nullable=False, index=True)
    user = db.Column(db.String(128), nullable=False, default="")
    source_ip = db.Column(db.String(64), nullable=False, default="")
    target = db.Column(db.String(255), nullable=False, default="")
    protocol = db.Column(db.String(16), nullable=False, default="unknown")
    observed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(
        db.String(16), nullable=False, default=BYPASS_INCIDENT_STATUSES[0], index=True
    )
    # the ACTION block: alert / rotation / block_source outcomes
    actions = db.Column(db.JSON, nullable=False, default=dict)
    closed_by = db.Column(db.String(64), nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    close_note = db.Column(db.String(255), nullable=False, default="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_ref": self.incident_ref,
            "signal_id": self.signal_id,
            "user": self.user,
            "source_ip": self.source_ip,
            "target": self.target,
            "protocol": self.protocol,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "status": self.status,
            "actions": self.actions or {},
            "closed_by": self.closed_by,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "close_note": self.close_note,
            "created_at": self.created_at.isoformat(),
        }


class BypassEvent(db.Model):
    """Module action log for §10: log ingestions, correlation scans,
    detections and incident closes - folded into the §19 ledger as the
    ninth source (`bypass`). Individual signal rows stay evidence, not
    actions, so the ledger records what the product *did*."""

    __tablename__ = "bypass_events"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    subject = db.Column(db.String(160), nullable=False, default="")
    detail = db.Column(db.JSON, nullable=False, default=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "actor": self.actor,
            "subject": self.subject,
            "detail": self.detail or {},
            "created_at": self.created_at.isoformat(),
        }


# --- break glass (architecture section 17) --------------------------------
BREAK_GLASS_SEVERITIES = ("sev1", "sev2", "sev3")
BREAK_GLASS_STATUSES = (
    "pending",   # filed: two distinct approvals outstanding
    "approved",  # dual approval reached - the credential may be released
    "denied",    # turned down before anything was released
    "used",      # emergency credential released, recorded session running
    "closed",    # session ended, credential rotated, review note filed
)
BREAK_GLASS_ACTIONS = ("requested", "approved", "denied", "opened", "closed")


class BreakGlassRequest(db.Model):
    """One emergency break-glass request (architecture section 17): reason,
    severity and target up front; two distinct approvals before anything is
    released; the opened session is recorded regardless of operator
    preferences; close forces credential rotation plus a post-incident
    review note.

    Every transition is queued on ``BreakGlassEvent`` and folded into the
    section-19 ledger under the tenth source (`break-glass`) in the same
    commit - the break-glass process itself is auditable.
    """

    __tablename__ = "break_glass_requests"

    id = db.Column(db.Integer, primary_key=True)
    request_ref = db.Column(db.String(24), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    reason = db.Column(db.String(1000), nullable=False)
    severity = db.Column(db.String(8), nullable=False, default="sev1")
    target = db.Column(db.String(255), nullable=False)
    protocol = db.Column(db.String(16), nullable=False, default="ssh")
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)

    requested_by = db.Column(db.String(64), nullable=False, default="system")
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    # MFA runs only when a factor exists (section 20); until then the request
    # records this honestly - never a fake challenge.
    mfa = db.Column(db.String(32), nullable=False, default="not configured")

    denied_by = db.Column(db.String(64), nullable=True)
    denied_at = db.Column(db.DateTime, nullable=True)
    deny_note = db.Column(db.String(500), nullable=False, default="")

    session_id = db.Column(db.Integer, nullable=True)
    opened_by = db.Column(db.String(64), nullable=True)
    opened_at = db.Column(db.DateTime, nullable=True)
    # the credential released for the emergency and the secret version it
    # carried at release, so close can tell an already-rotated credential
    # from one still owed its rotation
    opened_item_id = db.Column(db.Integer, nullable=True)
    opened_secret_version = db.Column(db.Integer, nullable=True)

    closed_by = db.Column(db.String(64), nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    review = db.Column(db.String(1000), nullable=False, default="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "request_ref": self.request_ref,
            "created_at": self.created_at.isoformat(),
            "reason": self.reason,
            "severity": self.severity,
            "target": self.target,
            "protocol": self.protocol,
            "status": self.status,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at.isoformat(),
            "mfa": self.mfa,
            "denied_by": self.denied_by,
            "denied_at": self.denied_at.isoformat() if self.denied_at else None,
            "deny_note": self.deny_note,
            "session_id": self.session_id,
            "opened_by": self.opened_by,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "opened_item_id": self.opened_item_id,
            "closed_by": self.closed_by,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "review": self.review,
        }


class BreakGlassApproval(db.Model):
    """Append-only dual-approval snapshots for one request (architecture
    section 17): two distinct approvers sign before the emergency credential
    exists - no edits, no deletes (the other decision tables' posture)."""

    __tablename__ = "break_glass_approvals"

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, nullable=False, index=True)
    approver = db.Column(db.String(64), nullable=False)
    decided_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    note = db.Column(db.String(500), nullable=False, default="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "approver": self.approver,
            "decided_at": self.decided_at.isoformat(),
            "note": self.note,
        }


class BreakGlassEvent(db.Model):
    """Module action log for section 17: requests, approval signatures,
    denials, unseals and closes - folded into the section-19 ledger as the
    tenth source (`break-glass`). Request rows stay evidence, not actions:
    the ledger records what the product *did*."""

    __tablename__ = "break_glass_events"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    subject = db.Column(db.String(160), nullable=False, default="")
    detail = db.Column(db.JSON, nullable=False, default=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "actor": self.actor,
            "subject": self.subject,
            "detail": self.detail or {},
            "created_at": self.created_at.isoformat(),
        }


class IntegrationEvent(db.Model):
    """Module action log for section 20: MFA enrolments and verifications,
    the medium-band MFA gate, ITSM ticket verifications, LDAP logins and
    SIEM push failures - folded into the section-19 ledger as the eleventh
    source (`integration`). Connector configuration itself stays on the
    settings changelog; this trail records what the product *did* against
    an external system. Secrets (TOTP seeds, API tokens, passwords) never
    appear in `detail` - only what was attempted and how it answered."""

    __tablename__ = "integration_events"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now, index=True)
    action = db.Column(db.String(32), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="system")
    subject = db.Column(db.String(160), nullable=False, default="")
    detail = db.Column(db.JSON, nullable=False, default=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "actor": self.actor,
            "subject": self.subject,
            "detail": self.detail or {},
            "created_at": self.created_at.isoformat(),
        }
