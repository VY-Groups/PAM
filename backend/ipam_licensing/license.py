"""
License data structures and constants for IPAM Tool licensing system.
"""
from enum import Enum
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import json


class LicenseType(Enum):
    """Types of licenses supported."""
    TRIAL = "trial"
    SUBSCRIPTION = "subscription"
    PERPETUAL = "perpetual"
    ENTERPRISE = "enterprise"


class LicenseStatus(Enum):
    """Status of a license."""
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MALFORMED = "malformed"
    SIGNATURE_INVALID = "signature_invalid"


# ---------------------------------------------------------------------------
# enterprise licensing spec (tiers, plans, classifications)
# ---------------------------------------------------------------------------
DEFAULT_TIERS: Dict[LicenseType, str] = {
    LicenseType.TRIAL: "TRIAL EVALUATION",
    LicenseType.SUBSCRIPTION: "PROFESSIONAL CLOUD",
    LicenseType.PERPETUAL: "PERPETUAL ON-PREM",
    LicenseType.ENTERPRISE: "ENTERPRISE ZSP ULTIMATE",
}

DEFAULT_PLANS: Dict[LicenseType, str] = {
    LicenseType.TRIAL: "30-Day Evaluation",
    LicenseType.SUBSCRIPTION: "Annual Multi-Cloud",
    LicenseType.PERPETUAL: "Perpetual On-Prem",
    LicenseType.ENTERPRISE: "Annual Multi-Cloud",
}

DEFAULT_CLASSIFICATIONS: Dict[LicenseType, str] = {
    LicenseType.TRIAL: "Evaluation Trial (Sandbox)",
    LicenseType.SUBSCRIPTION: "Cloud Subscription (Regional)",
    LicenseType.PERPETUAL: "Perpetual On-Premises (Single-Region)",
    LicenseType.ENTERPRISE: "Air-Gapped Production Enterprise (Multi-Region)",
}

DEFAULT_ISSUER = "licensing.aegispam.internal (Air-Gap Root)"

# ---------------------------------------------------------------------------
# entitlement modules (the licensed zero-trust building blocks)
# ---------------------------------------------------------------------------
# `detail` is the static entitlement line printed on the module card; live
# consumption numbers (tunnels in use, leases granted) are reported at runtime
# and overlaid by the console, never baked into the signature.
MODULE_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "zsp_dynamic_leases",
        "name": "Zero-Standing Privilege Dynamic Leases",
        "icon": "timer",
        "detail": "Zero Residual Footprint",
        "description": "Ephemeral just-in-time privileges with no standing admin rights.",
    },
    {
        "id": "hsm_integration",
        "name": "HSM Integration",
        "icon": "key",
        "detail": "PKCS#11 Active / Unlimited Keys",
        "description": "FIPS 140-2 Level 4 keystores via PKCS#11, AWS KMS, CloudHSM, YubiHSM.",
    },
    {
        "id": "dual_control_quorum",
        "name": "Dual-Control Quorum & 4-Eyes Interception",
        "icon": "groups",
        "detail": "Strict Mode / Real-time Terminal Block",
        "description": "Two-person approval with live blocking of destructive commands.",
    },
    {
        "id": "worm_audit_ledger",
        "name": "Immutable WORM Storage & Merkle Audit Ledger",
        "icon": "receipt_long",
        "detail": "SHA-256 Chained Retention",
        "description": "Write-once audit evidence chained into Merkle trees.",
    },
    {
        "id": "ai_anomaly_radar",
        "name": "AI Keystroke Anomaly Radar & eBPF Drops",
        "icon": "radar",
        "detail": "Kernel Filter v6 / Sub-3ms Drop Latency",
        "description": "Kernel-level session inspection that drops malicious input in flight.",
    },
    {
        "id": "airgap_bastion_tunnels",
        "name": "Air-Gapped Bastion Connectors & mTLS Tunnels",
        "icon": "vpn_key",
        "detail": "Reverse mTLS / Quota Enforced",
        "description": "Reverse-tunnel bastion connectors for air-gapped estates.",
    },
    {
        "id": "idp_federation_bridge",
        "name": "Multi-Cloud Identity Federation & PAM Bridge",
        "icon": "domain",
        "detail": "Uncapped IdPs / SCIM 2.0 Sync",
        "description": "SAML2, OIDC, SCIM 2.0 with Entra, Okta, PingFederate, CyberArk.",
    },
    {
        "id": "shamir_breakglass",
        "name": "Shamir Secret Break-Glass Vault Unseal",
        "icon": "emergency_home",
        "detail": "3-of-5 Custodians / Cryptographic Air-Gap",
        "description": "Split-key recovery with no cloud vendor dependency.",
    },
]

MODULE_IDS: List[str] = [module["id"] for module in MODULE_CATALOG]

DEFAULT_MODULE_IDS: Dict[LicenseType, List[str]] = {
    LicenseType.TRIAL: ["zsp_dynamic_leases", "idp_federation_bridge", "ai_anomaly_radar"],
    LicenseType.PERPETUAL: [
        "zsp_dynamic_leases",
        "idp_federation_bridge",
        "ai_anomaly_radar",
        "worm_audit_ledger",
    ],
    LicenseType.SUBSCRIPTION: [
        "zsp_dynamic_leases",
        "idp_federation_bridge",
        "ai_anomaly_radar",
        "worm_audit_ledger",
        "dual_control_quorum",
        "airgap_bastion_tunnels",
    ],
    LicenseType.ENTERPRISE: list(MODULE_IDS),
}

# Quota enforcement actions applied per node pool.
ENFORCEMENT_LEVELS = ("soft-warning", "auto-scale", "audit-log", "hard-block")


def default_modules(license_type: LicenseType) -> List[Dict[str, Any]]:
    """Entitlement module records granted by default for a license type."""
    granted = set(DEFAULT_MODULE_IDS.get(license_type, []))
    return [
        {
            "id": module["id"],
            "name": module["name"],
            "status": "entitled",
            "detail": module["detail"],
        }
        for module in MODULE_CATALOG
        if module["id"] in granted
    ]


# ---------------------------------------------------------------------------
# node quota pools (assigned ceilings; consumption is reported at runtime)
# ---------------------------------------------------------------------------
def _pool(pool_id: str, name: str, regions: List[str], quota_nodes: int, enforcement: str) -> Dict[str, Any]:
    return {
        "id": pool_id,
        "name": name,
        "regions": regions,
        "quota_nodes": quota_nodes,
        "enforcement": enforcement,
    }


def default_quotas(license_type: LicenseType) -> Dict[str, Any]:
    """
    Default quota block: scalar ceilings plus the environment pool breakdown.

    The pools mirror the enterprise spec (AWS / Kubernetes / bare-metal /
    staging) with the matching escalation of enforcement, scaled to the tier.
    """
    pools_by_type: Dict[LicenseType, List[Dict[str, Any]]] = {
        LicenseType.TRIAL: [
            _pool("aws-prod", "AWS Production", ["us-east-1"], 50, "soft-warning"),
            _pool("k8s-core", "Kubernetes Clusters", ["EKS Core Mesh"], 25, "audit-log"),
            _pool("baremetal", "Bare-Metal & Bastions", ["DirectConnect On-Prem"], 15, "audit-log"),
            _pool("staging", "Multi-Tenant Staging", ["Sandbox VPCs"], 10, "hard-block"),
        ],
        LicenseType.SUBSCRIPTION: [
            _pool("aws-prod", "AWS Production", ["us-east-1", "us-west-2"], 600, "soft-warning"),
            _pool("k8s-core", "Kubernetes Clusters", ["EKS & GKE Core Mesh"], 450, "auto-scale"),
            _pool("baremetal", "Bare-Metal & Bastions", ["DirectConnect On-Prem"], 300, "audit-log"),
            _pool("staging", "Multi-Tenant Staging", ["Sandbox & QA VPCs"], 150, "hard-block"),
        ],
        LicenseType.PERPETUAL: [
            _pool("aws-prod", "AWS Production", ["us-east-1", "us-west-2"], 300, "soft-warning"),
            _pool("k8s-core", "Kubernetes Clusters", ["EKS & GKE Core Mesh"], 200, "auto-scale"),
            _pool("baremetal", "Bare-Metal & Bastions", ["DirectConnect On-Prem"], 150, "audit-log"),
            _pool("staging", "Multi-Tenant Staging", ["Sandbox & QA VPCs"], 50, "hard-block"),
        ],
        LicenseType.ENTERPRISE: [
            _pool("aws-prod", "AWS Production", ["us-east-1", "us-west-2"], 2000, "soft-warning"),
            _pool("k8s-core", "Kubernetes Clusters", ["EKS & GKE Core Mesh"], 1500, "auto-scale"),
            _pool("baremetal", "Bare-Metal & Bastions", ["DirectConnect On-Prem"], 800, "audit-log"),
            _pool("staging", "Multi-Tenant Staging", ["Sandbox & QA VPCs"], 700, "hard-block"),
        ],
    }
    ceilings: Dict[LicenseType, Dict[str, int]] = {
        LicenseType.TRIAL: {
            "nodes": 100, "concurrent_sessions": 5, "bastion_tunnels": 10,
            "max_lease_hours": 24, "worm_retention_days": 30,
        },
        LicenseType.SUBSCRIPTION: {
            "nodes": 1500, "concurrent_sessions": 20, "bastion_tunnels": 250,
            "max_lease_hours": 8, "worm_retention_days": 730,
        },
        LicenseType.PERPETUAL: {
            "nodes": 700, "concurrent_sessions": 15, "bastion_tunnels": 100,
            "max_lease_hours": 12, "worm_retention_days": 1825,
        },
        LicenseType.ENTERPRISE: {
            "nodes": 5000, "concurrent_sessions": 40, "bastion_tunnels": 1000,
            "max_lease_hours": 4, "worm_retention_days": 2555,
        },
    }
    pools = pools_by_type[license_type]
    quota = dict(ceilings[license_type])
    quota["pools"] = pools
    # Keep the scalar ceiling honest: it is the sum of the assigned pools.
    quota["nodes"] = sum(pool["quota_nodes"] for pool in pools)
    return quota


def optional_fields(
    *,
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
) -> Dict[str, Any]:
    """
    Spec fields that are only present when actually set.

    Used both when signing (License.to_dict) and when rebuilding a stored
    record, so a round trip through the database reproduces byte-identical
    signed claims.
    """
    fields: Dict[str, Any] = {}
    for name, value in (
        ("tier", tier),
        ("plan", plan),
        ("license_id", license_id),
        ("subject_entity", subject_entity),
        ("classification", classification),
        ("issuer", issuer),
        ("enclave_binding", enclave_binding),
    ):
        if isinstance(value, str) and value:
            fields[name] = value
    if isinstance(quotas, dict) and quotas:
        fields["quotas"] = quotas
    if isinstance(modules, list) and modules:
        fields["modules"] = modules
    if isinstance(account, dict) and account:
        fields["account"] = account
    return fields


class License:
    """
    Represents a software license for the IPAM tool.

    Attributes:
        license_key: Unique identifier for the license
        license_type: Type of license (trial, subscription, etc.)
        issued_to: Customer/entity the license is issued to
        issued_date: When the license was issued
        expires_on: When the license expires (None for perpetual)
        features: List of enabled features
        usage_limits: Dictionary of usage constraints (users, sessions, etc.)
        metadata: Additional information
        tier: Commercial tier display name (e.g. ENTERPRISE ZSP ULTIMATE)
        plan: Commercial plan display name (e.g. Annual Multi-Cloud)
        license_id: Human-readable license identifier (LIC-9942-AEGIS-SEC-PROD)
        subject_entity: Legal entity the entitlement is bound to
        classification: License classification string
        issuer: Issuing authority
        enclave_binding: Optional hardware enclave (TPM/PCR) binding
        quotas: Node/session/tunnel ceilings plus the node pool breakdown
        modules: Granted entitlement modules (subset of MODULE_CATALOG)
        account: Account & SLA block (customer id, TAM, PO, response target)
    """

    def __init__(
        self,
        license_key: str,
        license_type: LicenseType,
        issued_to: str,
        issued_date: datetime,
        expires_on: Optional[datetime] = None,
        features: Optional[list] = None,
        usage_limits: Optional[Dict[str, Any]] = None,
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
    ):
        self.license_key = license_key
        self.license_type = license_type
        self.issued_to = issued_to
        self.issued_date = issued_date
        self.expires_on = expires_on
        self.features = features or []
        self.usage_limits = usage_limits or {}
        self.metadata = metadata or {}
        self.tier = tier
        self.plan = plan
        self.license_id = license_id
        self.subject_entity = subject_entity
        self.classification = classification
        self.issuer = issuer
        self.enclave_binding = enclave_binding
        self.quotas = quotas or {}
        self.modules = modules or []
        self.account = account or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert license to dictionary for serialization."""
        data: Dict[str, Any] = {
            "license_key": self.license_key,
            "license_type": self.license_type.value,
            "issued_to": self.issued_to,
            "issued_date": self.issued_date.isoformat(),
            "expires_on": self.expires_on.isoformat() if self.expires_on else None,
            "features": self.features,
            "usage_limits": self.usage_limits,
            "metadata": self.metadata,
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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'License':
        """Create license from dictionary."""
        return cls(
            license_key=data["license_key"],
            license_type=LicenseType(data["license_type"]),
            issued_to=data["issued_to"],
            issued_date=datetime.fromisoformat(data["issued_date"]),
            expires_on=datetime.fromisoformat(data["expires_on"]) if data["expires_on"] else None,
            features=data.get("features", []),
            usage_limits=data.get("usage_limits", {}),
            metadata=data.get("metadata", {}),
            tier=data.get("tier"),
            plan=data.get("plan"),
            license_id=data.get("license_id"),
            subject_entity=data.get("subject_entity"),
            classification=data.get("classification"),
            issuer=data.get("issuer"),
            enclave_binding=data.get("enclave_binding"),
            quotas=data.get("quotas") or {},
            modules=data.get("modules") or [],
            account=data.get("account") or {},
        )

    @property
    def entitled_module_ids(self) -> List[str]:
        """Ids of the entitlement modules granted by this license."""
        return [module.get("id") for module in self.modules if module.get("id")]

    def is_expired(self) -> bool:
        """Check if license has expired."""
        if self.expires_on is None:
            return False  # Perpetual license
        return datetime.now() > self.expires_on

    def days_until_expiry(self) -> Optional[int]:
        """
        Get days until expiry.

        Returns None if the license is perpetual (no expiry) or already
        expired; otherwise the calendar-day difference, so a fresh 30-day
        trial reports 30 (not 29) and a license expiring later today reports 0.
        """
        if self.expires_on is None:
            return None
        now = datetime.now()
        if now > self.expires_on:
            return None  # expired
        return (self.expires_on.date() - now.date()).days

    def __str__(self) -> str:
        return f"License({self.license_key}, {self.license_type.value}, issued to {self.issued_to})"
