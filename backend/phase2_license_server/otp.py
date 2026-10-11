"""E-mail OTP over the sealed `smtp` settings group (Addendum C - phase 7).

- The code is a CSPRNG 8-digit value, stored HMAC-hashed (key derived from
  the vault master key), expires in ~5 minutes, is single use and bound to
  its challenge id; attempts are capped and a resend cooldown applies.
- **No user enumeration**: `/auth/otp/start` answers with the identical
  generic shape whether or not the account exists, whether or not SMTP is
  configured, and whether or not a cooldown suppressed the send - the
  ledger records the honest internals (`otp-sent`, `otp-suppressed`,
  `otp-verified`, `otp-failed`, `otp-locked`) and never the code.
- Delivery rows show admins the measured send status (`sent` / `failed`
  with the provider error / `queued` for retry); the monitor tick retries
  failed sends up to three attempts, rotating the code each attempt (the
  plaintext exists only inside the message being sent - never at rest).
- `POST /settings/smtp/test` sends a real message so operators can verify
  host/port/TLS/credentials before enabling anything."""
from __future__ import annotations

import hashlib
import hmac
import smtplib
import secrets as pysecrets
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any, Dict, Optional

from errors import ServiceUnavailable, ValidationFailed
from extensions import db
from identity import auth_event, auth_settings
from models import AuthOtp, SettingGroup, SmtpDelivery, User

OTP_TTL_SECONDS = 300
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_MAX_DELIVERY_ATTEMPTS = 3
SMTP_TIMEOUT_SECONDS = 10
OTP_LENGTH = 8


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------
def smtp_values() -> Dict[str, Any]:
    row = SettingGroup.query.filter(SettingGroup.group_name == "smtp").first()
    values = dict(row.value) if row is not None and row.value else {}
    return {
        "enabled": bool(values.get("enabled", False)),
        "host": str(values.get("host", "") or "").strip(),
        "port": int(values.get("port", 587) or 587),
        "use_tls": bool(values.get("use_tls", True)),
        "username": str(values.get("username", "") or "").strip(),
        "from_address": str(values.get("from_address", "") or "").strip(),
    }


def smtp_password() -> str:
    """Unseal the SMTP password (empty when never set)."""
    from service import unseal_setting_secret

    return unseal_setting_secret("smtp", "password")


def smtp_configured() -> bool:
    values = smtp_values()
    return bool(values["enabled"] and values["host"] and values["from_address"])


def mask_email(address: str) -> str:
    """`alice@example.com` -> `a***@example.com` (admins see status, not
    the mailbox)."""
    address = str(address or "").strip()
    if "@" not in address or len(address) < 3:
        return "***"
    local, _, domain = address.partition("@")
    return f"{local[0]}***@{domain}"


# ---------------------------------------------------------------------------
# HMAC key + code handling
# ---------------------------------------------------------------------------
def _otp_key() -> bytes:
    """The OTP HMAC key derives from the vault master key (one secret
    machine, no second key to distribute)."""
    import secrets_store
    from flask import current_app

    master = secrets_store.load_key(current_app.config["LICENSE_CONFIG"])
    return hashlib.sha256(master + b"auth-otp-hmac").digest()


def _code_hmac(challenge_id: str, code: str) -> str:
    return hmac.new(
        _otp_key(), f"{challenge_id}:{code}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _new_code() -> str:
    return f"{pysecrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


# ---------------------------------------------------------------------------
# SMTP delivery (measured, never claims success it did not observe)
# ---------------------------------------------------------------------------
def _send_via_smtp(to_address: str, subject: str, body: str) -> None:
    """One real SMTP conversation; raises ServiceUnavailable with the
    provider's own error text on failure."""
    values = smtp_values()
    password = smtp_password()
    message = EmailMessage()
    message["From"] = values["from_address"]
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(values["host"], values["port"], timeout=SMTP_TIMEOUT_SECONDS) as client:
            client.ehlo()
            if values["use_tls"]:
                client.starttls()
                client.ehlo()
            if values["username"] and password:
                client.login(values["username"], password)
            client.send_message(message)
    except smtplib.SMTPException as exc:
        raise ServiceUnavailable(
            f"SMTP delivery failed: {exc}", {"provider_error": str(exc)[:200]}
        ) from exc
    except (OSError, TimeoutError) as exc:
        raise ServiceUnavailable(
            f"SMTP server unreachable: {exc}", {"provider_error": str(exc)[:200]}
        ) from exc


def send_test_email(to_address: str, *, actor: str) -> Dict[str, Any]:
    """Admin test-send: a real message through the configured server, with
    the measured outcome (and an honest 503 when SMTP is not configured)."""
    if not smtp_configured():
        raise ServiceUnavailable(
            "SMTP is not configured - set host, port and from_address in the "
            "`smtp` settings group and enable it first",
            {"configured": False},
        )
    if not to_address or "@" not in str(to_address):
        raise ValidationFailed("'to' must be an e-mail address", {"field": "to"})
    delivery = SmtpDelivery(
        purpose="test", recipient_masked=mask_email(to_address), status="queued"
    )
    db.session.add(delivery)
    db.session.flush()
    try:
        _send_via_smtp(
            to_address,
            "VY-PAM SMTP test message",
            "This is a real test message from your VY-PAM console.\n"
            "If you received it, the `smtp` settings group works.\n",
        )
    except ServiceUnavailable as exc:
        delivery.status = "failed"
        delivery.attempts = 1
        delivery.last_error = str(exc.message)[:255]
        auth_event(
            "settings.smtp.test-failed",
            actor=actor,
            subject=delivery.recipient_masked,
            detail={"error": delivery.last_error},
        )
        db.session.commit()
        raise
    delivery.status = "sent"
    delivery.attempts = 1
    delivery.sent_at = datetime.now()
    auth_event(
        "settings.smtp.test-sent",
        actor=actor,
        subject=delivery.recipient_masked,
        detail={"delivery_id": delivery.id},
    )
    db.session.commit()
    return delivery.to_dict()


# ---------------------------------------------------------------------------
# challenge lifecycle
# ---------------------------------------------------------------------------
def _active_challenge(username: str, purpose: str) -> Optional[AuthOtp]:
    return (
        AuthOtp.query.filter(
            AuthOtp.username == username,
            AuthOtp.purpose == purpose,
            AuthOtp.consumed_at.is_(None),
            AuthOtp.expires_at > datetime.now(),
        )
        .order_by(AuthOtp.created_at.desc())
        .first()
    )


def _deliver(otp: AuthOtp, user: Optional[User], code: str) -> None:
    """Attempt (or retry) the send for this challenge; the code rotates on
    every attempt so the plaintext exists only in the message being sent."""
    values = smtp_values()
    if not user or not user.email or not smtp_configured():
        delivery = SmtpDelivery(
            purpose="otp",
            recipient_masked=mask_email(user.email) if user and user.email else "***",
            status="failed",
            attempts=(otp.attempts or 0) + 1,
            last_error="smtp not configured or user has no e-mail address",
        )
        db.session.add(delivery)
        db.session.flush()
        otp.delivery_id = delivery.id
        otp.code_hmac = _code_hmac(otp.challenge_id, code)
        auth_event(
            "otp-suppressed",
            actor="system",
            subject=otp.username,
            detail={"reason": delivery.last_error},
        )
        return
    delivery = db.session.get(SmtpDelivery, otp.delivery_id) if otp.delivery_id else None
    if delivery is None:
        delivery = SmtpDelivery(
            purpose="otp", recipient_masked=mask_email(user.email), status="queued"
        )
        db.session.add(delivery)
        db.session.flush()
        otp.delivery_id = delivery.id
    otp.code_hmac = _code_hmac(otp.challenge_id, code)
    try:
        _send_via_smtp(
            user.email,
            "Your VY-PAM one-time code",
            f"Your one-time sign-in code is: {code}\n"
            f"\nIt expires in {OTP_TTL_SECONDS // 60} minutes and can be used "
            "once. If you did not request this, alert your administrators "
            "immediately - someone may be trying to sign in as you.\n",
        )
    except ServiceUnavailable as exc:
        delivery.status = "failed" if delivery.attempts + 1 >= OTP_MAX_DELIVERY_ATTEMPTS else "queued"
        delivery.attempts += 1
        delivery.last_error = str(exc.message)[:255]
        auth_event(
            "otp-failed",
            actor="system",
            subject=otp.username,
            detail={"delivery_id": delivery.id, "attempts": delivery.attempts},
        )
        return
    delivery.status = "sent"
    delivery.attempts += 1
    delivery.sent_at = datetime.now()
    delivery.last_error = ""
    auth_event(
        "otp-sent",
        actor="system",
        subject=otp.username,
        detail={"challenge_id": otp.challenge_id, "purpose": otp.purpose},
    )


def start_otp(username: str, *, purpose: str = "login") -> Dict[str, Any]:
    """Start (or silently re-send under the cooldown) an e-mail OTP
    challenge. The response is identical for every syntactically valid
    username - existing or not, configured or not (no enumeration)."""
    if purpose not in ("login", "stepup", "recovery"):
        raise ValidationFailed("Unknown OTP purpose", {"allowed": ["login", "stepup", "recovery"]})
    name = str(username or "").strip().lower()
    generic = {"status": "sent"}
    if not name:
        raise ValidationFailed("'username' is required", {"field": "username"})
    user = User.query.filter(User.username == name).first()

    def _send_or_suppress(challenge: AuthOtp, target: Optional[User]) -> None:
        """Deliver the code - except to a sealed or inactive account, where
        the code is minted and HMAC-stored but never sent. Either way the
        challenge shape and its stability are identical, so the answer never
        reveals whether the username exists (no enumeration)."""
        code = _new_code()
        if target is not None and (target.is_emergency or not target.is_active):
            challenge.code_hmac = _code_hmac(challenge.challenge_id, code)
            auth_event(
                "otp-suppressed",
                actor="system",
                subject=name,
                detail={"reason": "inactive-or-emergency"},
            )
            return
        _deliver(challenge, target, code)

    active = _active_challenge(name, purpose)
    if active is not None:
        age = (datetime.now() - active.created_at).total_seconds()
        if age < OTP_RESEND_COOLDOWN_SECONDS:
            # cooldown: identical answer, the send is silently suppressed
            auth_event("otp-suppressed", actor="system", subject=name,
                       detail={"reason": "resend-cooldown", "challenge_id": active.challenge_id})
            db.session.commit()
            return dict(generic, challenge_id=active.challenge_id)
        if active.delivery_id:
            delivery = db.session.get(SmtpDelivery, active.delivery_id)
            if delivery is not None and delivery.attempts >= OTP_MAX_DELIVERY_ATTEMPTS:
                auth_event("otp-locked", actor="system", subject=name,
                           detail={"challenge_id": active.challenge_id,
                                   "attempts": delivery.attempts})
                db.session.commit()
                return dict(generic, challenge_id=active.challenge_id)
        challenge_id = active.challenge_id
        _send_or_suppress(active, user)
        db.session.commit()
        return dict(generic, challenge_id=challenge_id)

    challenge_id = pysecrets.token_hex(16)
    otp = AuthOtp(
        challenge_id=challenge_id,
        user_id=user.id if user is not None else None,
        username=name,
        purpose=purpose,
        code_hmac="",
        max_attempts=OTP_MAX_ATTEMPTS,
        expires_at=datetime.now() + timedelta(seconds=OTP_TTL_SECONDS),
    )
    db.session.add(otp)
    db.session.flush()
    _send_or_suppress(otp, user)
    db.session.commit()
    return dict(generic, challenge_id=challenge_id)


def verify_code(
    challenge_id: str, code: str, *, purpose: str, username: str = ""
) -> AuthOtp:
    """Check a code against its challenge (single use, attempt-capped,
    expired -> the same honest refusal); consumes on success."""
    otp = AuthOtp.query.filter(AuthOtp.challenge_id == str(challenge_id or "")).first()
    if (
        otp is None
        or otp.purpose != purpose
        or (username and otp.username != str(username).strip().lower())
    ):
        raise UnauthorizedOtp()
    now = datetime.now()
    if otp.consumed_at is not None or otp.expires_at <= now:
        auth_event("otp-failed", actor="system", subject=otp.username,
                   detail={"challenge_id": otp.challenge_id,
                           "reason": "expired-or-used"})
        db.session.commit()
        raise UnauthorizedOtp()
    if otp.attempts >= otp.max_attempts:
        auth_event("otp-locked", actor="system", subject=otp.username,
                   detail={"challenge_id": otp.challenge_id, "attempts": otp.attempts})
        db.session.commit()
        raise UnauthorizedOtp(locked=True)
    otp.attempts += 1
    digest = _code_hmac(otp.challenge_id, str(code or "").strip())
    if not hmac.compare_digest(digest, otp.code_hmac or ""):
        auth_event("otp-failed", actor="system", subject=otp.username,
                   detail={"challenge_id": otp.challenge_id, "attempts": otp.attempts})
        if otp.attempts >= otp.max_attempts:
            auth_event("otp-locked", actor="system", subject=otp.username,
                       detail={"challenge_id": otp.challenge_id, "attempts": otp.attempts})
        db.session.commit()
        raise UnauthorizedOtp()
    otp.consumed_at = now
    auth_event("otp-verified", actor=otp.username, subject=otp.username,
               detail={"challenge_id": otp.challenge_id, "purpose": otp.purpose})
    db.session.commit()
    return otp


class UnauthorizedOtp(Exception):
    """Internal marker rendered by routes as a generic 401."""

    def __init__(self, locked: bool = False):
        super().__init__("One-time code invalid or expired")
        self.locked = locked


def verify_for_login(user: User, code: str) -> bool:
    """The MFA-assertion path: check a code against the user's newest
    active login/stepup challenge (the login challenge already binds the
    account, so no enumeration surface exists here)."""
    for purpose in ("login", "stepup"):
        otp = _active_challenge(user.username, purpose)
        if otp is None:
            continue
        try:
            verify_code(otp.challenge_id, code, purpose=purpose, username=user.username)
            return True
        except UnauthorizedOtp:
            return False
    return False


# ---------------------------------------------------------------------------
# retry queue (called from the monitor tick)
# ---------------------------------------------------------------------------
def retry_failed_deliveries(*, limit: int = 10) -> Dict[str, Any]:
    """Retry queued OTP deliveries: the challenge keeps its id, the code
    rotates, the attempt counter grows to `OTP_MAX_DELIVERY_ATTEMPTS`
    (then the row is honestly `failed`). Delivery status is a measured
    fact throughout."""
    retried = 0
    rows = (
        SmtpDelivery.query.filter(
            SmtpDelivery.purpose == "otp",
            SmtpDelivery.status == "queued",
            SmtpDelivery.attempts < OTP_MAX_DELIVERY_ATTEMPTS,
        )
        .order_by(SmtpDelivery.created_at)
        .limit(limit)
        .all()
    )
    for delivery in rows:
        otp = AuthOtp.query.filter(AuthOtp.delivery_id == delivery.id).first()
        if otp is None or otp.consumed_at is not None or otp.expires_at <= datetime.now():
            delivery.status = "failed"
            delivery.last_error = "challenge expired before delivery succeeded"
            continue
        user = db.session.get(User, otp.user_id) if otp.user_id else None
        _deliver(otp, user, _new_code())
        retried += 1
    db.session.commit()
    return {"retried": retried}


def delivery_status(*, limit: int = 50) -> list:
    """Admin view: recent deliveries with the measured outcome (never a
    code)."""
    rows = SmtpDelivery.query.order_by(SmtpDelivery.created_at.desc()).limit(limit).all()
    return [row.to_dict() for row in rows]
