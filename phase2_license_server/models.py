"""Database models for the license server."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from extensions import db

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

EVENT_ISSUED = "issued"
EVENT_REVOKED = "revoked"
EVENT_RESTORED = "restored"


class LicenseRecord(db.Model):
    """A license issued by this server, including its signature."""

    __tablename__ = "licenses"

    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(36), nullable=False, unique=True, index=True)
    license_type = db.Column(db.String(32), nullable=False, index=True)
    issued_to = db.Column(db.String(255), nullable=False, index=True)
    issued_date = db.Column(db.DateTime, nullable=False)
    expires_on = db.Column(db.DateTime, nullable=True)

    # JSON columns: note "metadata" is reserved on the declarative base, so the
    # attribute is renamed while keeping the wire-format column name.
    features = db.Column(db.JSON, nullable=False, default=list)
    usage_limits = db.Column(db.JSON, nullable=False, default=dict)
    license_metadata = db.Column("metadata", db.JSON, nullable=False, default=dict)

    status = db.Column(db.String(16), nullable=False, default=STATUS_ACTIVE, index=True)
    signature = db.Column(db.Text, nullable=False)
    algorithm = db.Column(db.String(32), nullable=False, default="RSA-PSS-SHA256")

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

    def license_file(self) -> Dict[str, Any]:
        """Rebuild the signed license file exactly as it was issued."""
        return {
            "license_data": {
                "license_key": self.license_key,
                "license_type": self.license_type,
                "issued_to": self.issued_to,
                "issued_date": self.issued_date.isoformat(),
                "expires_on": self.expires_on.isoformat() if self.expires_on else None,
                "features": self.features,
                "usage_limits": self.usage_limits,
                "metadata": self.license_metadata,
            },
            "signature": self.signature,
            "algorithm": self.algorithm,
            "version": "1.0",
        }

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
            "status": self.status,
            "effective_status": self.effective_status(),
            "algorithm": self.algorithm,
            "days_until_expiry": self.days_until_expiry,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
            "created_at": self.created_at.isoformat(),
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
