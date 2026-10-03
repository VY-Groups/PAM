"""
License data structures and constants for IPAM Tool licensing system.
"""
from enum import Enum
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
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
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.license_key = license_key
        self.license_type = license_type
        self.issued_to = issued_to
        self.issued_date = issued_date
        self.expires_on = expires_on
        self.features = features or []
        self.usage_limits = usage_limits or {}
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert license to dictionary for serialization."""
        return {
            "license_key": self.license_key,
            "license_type": self.license_type.value,
            "issued_to": self.issued_to,
            "issued_date": self.issued_date.isoformat(),
            "expires_on": self.expires_on.isoformat() if self.expires_on else None,
            "features": self.features,
            "usage_limits": self.usage_limits,
            "metadata": self.metadata
        }
    
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
            metadata=data.get("metadata", {})
        )
    
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