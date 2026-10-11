"""Per-user MFA factors (Addendum C - phase 7).

- TOTP (RFC 6238): the seed is sealed per user (AES-256-GCM, never
  returned) and the factor carries `last_step`, so a **reused time step is
  refused** - the replay protection the shipped global factor lacked.
- Backup codes: ten single-use codes, sha256 at rest, shown once;
  regeneration invalidates every earlier code.
- Email OTP and RADIUS factors assert through `otp.py` / `radius_client`;
  WebAuthn assertions through `webauthn.py` (all funalled through
  `verify_assertion`, so a login challenge accepts every enrolled method
  and records exactly what was asserted).

Nothing here ever logs or returns a seed, a code or a token; every
attempt (pass or fail) lands on the twentieth ledger trail `auth`."""
from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from errors import Conflict, Forbidden, NotFound, ValidationFailed
from extensions import db
from identity import auth_event, auth_settings, consume_challenge
import integrations
from models import (
    MfaBackupCode,
    MfaFactor,
    User,
    WebauthnCredential,
)

BACKUP_CODE_COUNT = 10
BACKUP_CODE_BYTES = 8  # 64 bits of CSPRNG output per code


# ---------------------------------------------------------------------------
# TOTP (RFC 6238, replay-protected)
# ---------------------------------------------------------------------------
def _seal_seed(seed: str, user_id: int) -> Dict[str, Any]:
    import secrets_store
    from flask import current_app

    return secrets_store.seal_with_aad(
        seed, f"mfa:totp:{user_id}".encode("utf-8"),
        current_app.config["LICENSE_CONFIG"],
    )


def _unseal_seed(blob: Any, user_id: int) -> str:
    import secrets_store
    from flask import current_app

    if not isinstance(blob, dict):
        return ""
    try:
        return secrets_store.unseal_with_aad(
            blob, f"mfa:totp:{user_id}".encode("utf-8"),
            current_app.config["LICENSE_CONFIG"],
        )
    except Exception:
        return ""


def enroll_totp(user: User, *, actor: str) -> Dict[str, Any]:
    """Create - or rotate - the user's TOTP factor. The seed comes back
    exactly once (with the otpauth URI); re-enrolling resets the replay
    counter with the new seed."""
    seed = integrations.generate_totp_secret()
    sealed = _seal_seed(seed, user.id)
    factor = MfaFactor.query.filter(
        MfaFactor.user_id == user.id, MfaFactor.kind == "totp"
    ).first()
    rotated = factor is not None
    if factor is None:
        factor = MfaFactor(user_id=user.id, kind="totp", name="Authenticator app")
        db.session.add(factor)
    factor.secret_sealed = sealed
    factor.last_step = 0
    factor.active = True
    factor.last_used_at = None
    db.session.flush()
    auth_event(
        "auth.mfa.enrolled" if not rotated else "auth.mfa.re-enrolled",
        actor=actor or user.username,
        subject=user.username,
        detail={"kind": "totp", "factor_id": factor.id},
    )
    db.session.commit()
    return {
        "factor": factor.to_dict(),
        "secret": seed,
        "otpauth_uri": integrations.otpauth_uri(seed, account=user.username),
        "shown_once": True,
    }


def _matched_totp_step(seed: str, code: str, *, window: int = 1) -> int:
    """Which time step this code matches (0 when none), for the replay
    check - `verify_totp` says yes/no, replay needs the step."""
    import time as _time

    candidate = code.strip().replace(" ", "")
    step = int(_time.time() // integrations.TOTP_PERIOD)
    for offset in range(-window, window + 1):
        if integrations.hotp(seed, step + offset) == candidate:
            return step + offset
    return 0


def verify_totp_code(user: User, code: str, *, actor: str = "") -> bool:
    """Check a TOTP code against the user's factor with replay protection:
    the matched time step must be strictly newer than the last accepted
    one, so a captured code cannot be played twice."""
    factor = MfaFactor.query.filter(
        MfaFactor.user_id == user.id,
        MfaFactor.kind == "totp",
        MfaFactor.active.is_(True),
    ).first()
    if factor is None or not isinstance(code, str):
        return False
    seed = _unseal_seed(factor.secret_sealed, user.id)
    if not seed or not integrations.verify_totp(seed, code):
        return False
    matched = _matched_totp_step(seed, code)
    if matched <= factor.last_step:
        # the exact time step was already consumed - replay refused
        auth_event(
            "auth.mfa.replay-refused",
            actor=actor or user.username,
            subject=user.username,
            detail={"kind": "totp", "step": matched},
        )
        db.session.commit()
        return False
    factor.last_step = matched
    factor.last_used_at = datetime.now()
    db.session.commit()
    return True


# ---------------------------------------------------------------------------
# backup codes (hashed, single use, shown once)
# ---------------------------------------------------------------------------
def generate_backup_codes(user: User, *, actor: str = "") -> List[str]:
    """Ten fresh single-use codes (shown exactly once); every earlier code
    is invalidated."""
    for old in MfaBackupCode.query.filter(MfaBackupCode.user_id == user.id).all():
        db.session.delete(old)
    codes: List[str] = []
    for _ in range(BACKUP_CODE_COUNT):
        raw = pysecrets.token_hex(BACKUP_CODE_BYTES)
        display = f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
        codes.append(display)
        db.session.add(
            MfaBackupCode(
                user_id=user.id,
                code_hash=hashlib.sha256(
                    raw.encode("utf-8")
                ).hexdigest(),
            )
        )
    auth_event(
        "auth.mfa.backup-codes.generated",
        actor=actor or user.username,
        subject=user.username,
        detail={"count": BACKUP_CODE_COUNT},
    )
    db.session.commit()
    return codes


def consume_backup_code(user: User, code: str) -> bool:
    """Check and burn one unused backup code (constant-time compare)."""
    if not isinstance(code, str):
        return False
    normalized = code.strip().replace("-", "").replace(" ", "").lower()
    if not normalized or len(normalized) != BACKUP_CODE_BYTES * 2:
        return False
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    for row in MfaBackupCode.query.filter(
        MfaBackupCode.user_id == user.id, MfaBackupCode.used_at.is_(None)
    ).all():
        if hmac.compare_digest(digest, row.code_hash):
            row.used_at = datetime.now()
            auth_event(
                "auth.mfa.backup-code-used",
                actor=user.username,
                subject=user.username,
                detail={"code_id": row.id},
            )
            db.session.commit()
            return True
    return False


def unused_backup_code_count(user: User) -> int:
    return MfaBackupCode.query.filter(
        MfaBackupCode.user_id == user.id, MfaBackupCode.used_at.is_(None)
    ).count()


# ---------------------------------------------------------------------------
# factor bookkeeping
# ---------------------------------------------------------------------------
def list_factors(user_id: int) -> List[Dict[str, Any]]:
    rows = MfaFactor.query.filter(MfaFactor.user_id == user_id).order_by(MfaFactor.id).all()
    out = [row.to_dict() for row in rows]
    webauthn_count = WebauthnCredential.query.filter(
        WebauthnCredential.user_id == user_id
    ).count()
    for row in out:
        if row["kind"] == "webauthn":
            row["credentials"] = webauthn_count
    return out


def delete_factor(user_id: int, factor_id: int, *, actor: str) -> Dict[str, Any]:
    """Remove one factor. The last factor of a `mfa_required` user needs a
    two-admin recovery approval instead (fail-closed - never a silent
    downgrade to single-factor)."""
    factor = db.session.get(MfaFactor, factor_id)
    if factor is None or factor.user_id != user_id:
        raise NotFound(f"Unknown MFA factor {factor_id}")
    policy = auth_settings()
    remaining = MfaFactor.query.filter(
        MfaFactor.user_id == user_id,
        MfaFactor.id != factor.id,
        MfaFactor.active.is_(True),
    ).count()
    if remaining == 0 and policy["mfa_required"]:
        raise Forbidden(
            "This is the user's last factor and mfa_required is on - "
            "request a two-admin recovery instead "
            "(POST /api/v1/auth/factor-recovery/request)",
            {"mfa_required": True},
        )
    user = db.session.get(User, user_id)
    db.session.delete(factor)
    auth_event(
        "auth.mfa.factor-deleted",
        actor=actor or (user.username if user else ""),
        subject=user.username if user else "",
        detail={"factor_id": factor_id, "kind": factor.kind},
    )
    db.session.commit()
    return {"deleted": True, "factor_id": factor_id}


def active_factors(user: User) -> List[MfaFactor]:
    return MfaFactor.query.filter(
        MfaFactor.user_id == user.id, MfaFactor.active.is_(True)
    ).all()


# ---------------------------------------------------------------------------
# one assertion entry point for every method
# ---------------------------------------------------------------------------
def verify_assertion(
    user: User,
    body: Dict[str, Any],
    *,
    actor: str = "",
) -> Optional[str]:
    """Try the presented factor assertion (TOTP code, e-mail OTP code,
    RADIUS code, backup code) and return the method that passed, else None.
    WebAuthn is handled by `webauthn.verify_assertion` (its payload shape
    differs) before this is called."""
    methods = [factor.kind for factor in active_factors(user)]

    code = body.get("totp_code") or body.get("code")
    if code and "totp" in methods:
        if verify_totp_code(user, str(code), actor=actor or user.username):
            return "totp"

    otp_code = body.get("otp_code")
    if otp_code and "email" in methods:
        import otp as otp_module

        if otp_module.verify_for_login(user, str(otp_code)):
            return "email"

    radius_code = body.get("radius_code")
    radius_reported = False
    if radius_code and "radius" in methods:
        import radius_client

        if radius_client.verify_factor(user, str(radius_code)):
            return "radius"
        # the provider records its own detailed event (kind/reason) - one
        # failed assertion must land on the ledger exactly once
        radius_reported = True

    backup = body.get("backup_code")
    if backup:
        if consume_backup_code(user, str(backup)):
            return "backup-code"

    if (code or otp_code or radius_code or backup) and not radius_reported:
        auth_event(
            "auth.mfa.failed",
            actor=actor or user.username,
            subject=user.username,
            detail={"methods_available": sorted(set(methods))},
        )
        db.session.commit()
    return None
