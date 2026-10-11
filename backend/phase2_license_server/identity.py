"""Real identity & login security (Addendum C - phase 7).

The console finally has humans behind it:

- `users` + local login: the password hash is stdlib scrypt (memory-hard,
  argon2id-class; argon2id itself needs a third-party binding the program
  forbids), constant-time verified. Password policy follows NIST: length
  over complexity (14+ default), an embedded breached-password denylist,
  no forced periodic rotation.
- Server-side console sessions: `vypam-ui1.<id>.<secret>` (sha256 at rest,
  shown once) with idle + absolute timeouts, revocation with a reason,
  a per-user concurrent cap and "log out everywhere". The same value is
  set as an HttpOnly/SameSite cookie for browsers; cookie-authenticated
  mutations must carry the double-submit CSRF token (checked in routes).
- Login defence: per-account lockout with progressive windows, per-account
  and per-IP sliding-window rate limits, progressive delay on failures,
  and spray detection (many distinct usernames from one IP -> alert + block).
- `mfa_required` is fail-closed: a login with no enrolled factor yields a
  single-use enrolment ticket (`vypam-enr1`) instead of a session - never
  a silent pass. With a factor enrolled the password check yields a
  single-use MFA challenge (`vypam-mfa1`), consumed by exactly one factor
  assertion.
- "Remember this device" only for low-privilege principals (no approver or
  admin binding - enforced here, not by policy prose), short lifetime.
- The sealed emergency admin (offline SSO-outage path): its password is
  sealed at rest and unusable until two distinct admins open a short
  window; every use is alerted on the `auth` ledger and rotates the seal.
- Recovery: password reset through an e-mail OTP challenge; factor recovery
  needs two-admin approval - never self-service alone.

Every record lands on the twentieth ledger trail `auth` (an AuthEvent row,
folded in the same transaction); passwords, codes, tokens and seeds never
enter a detail payload."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets as pysecrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from errors import (
    Conflict,
    Forbidden,
    NotFound,
    Unauthorized,
    ValidationFailed,
)
from extensions import db
from models import (
    CONSOLE_TOKEN_PREFIX,
    DEVICE_TOKEN_PREFIX,
    ENROL_TICKET_PREFIX,
    MFA_CHALLENGE_PREFIX,
    USER_SOURCES,
    AuthDevice,
    AuthEvent,
    ConsoleSession,
    EmergencyApproval,
    EmergencyGrant,
    FactorRecoveryApproval,
    FactorRecoveryRequest,
    LoginChallenge,
    MfaBackupCode,
    MfaFactor,
    RoleBinding,
    User,
)

# password hashing: stdlib scrypt, argon2id-class parameters
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16
PASSWORD_MIN_DEFAULT = 14
PASSWORD_MAX_LENGTH = 200

# console session lifetimes and caps (overridable in the `auth` group)
SESSION_IDLE_MINUTES_DEFAULT = 30
SESSION_ABSOLUTE_HOURS_DEFAULT = 12
MAX_SESSIONS_PER_USER_DEFAULT = 5
STEPUP_TTL_MINUTES_DEFAULT = 5
REMEMBER_DEVICE_DAYS_DEFAULT = 30

# lockout + rate limiting
LOCKOUT_THRESHOLD_DEFAULT = 5
LOCKOUT_WINDOW_MINUTES = 15
LOCKOUT_BASE_MINUTES = 15
LOCKOUT_MAX_STREAK = 6  # 15m doubling to a 12h cap
LOCKOUT_STREAK_RESET_HOURS = 24
PROGRESSIVE_DELAY_MAX_SECONDS = 8.0
RATE_LIMIT_WINDOW_MINUTES = 5
RATE_LIMIT_PER_IP_DEFAULT = 30
RATE_LIMIT_PER_ACCOUNT_DEFAULT = 15
SPRAY_THRESHOLD_DEFAULT = 10
SPRAY_BLOCK_MINUTES = 15

# login-step challenges
MFA_CHALLENGE_TTL_SECONDS = 300
ENROL_TICKET_TTL_SECONDS = 600

# emergency admin
EMERGENCY_USERNAME = "emergency-admin"
EMERGENCY_WINDOW_MINUTES_DEFAULT = 15
EMERGENCY_APPROVALS_REQUIRED = 2

# the "remember this device" feature is refused for these roles
PRIVILEGED_ROLES = ("admin", "approver")

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")

# NIST SP 800-63B: length over complexity. This list is the honest core of
# the breached-password check - the most common passwords (offline product
# rule: no external k-anonymity service is called). Operators extend it in
# `auth.breached_password_extra` (comma-separated).
BREACHED_PASSWORDS = frozenset(
    """
    password password1 password12 password123 password1234 password12345
    password123456 passw0rd p@ssw0rd p@ssword letmein letmein1 letmein123
    welcome welcome1 welcome12 welcome123 admin admin12 admin123 admin1234
    administrator root toor changeme default secret secret12 qwerty qwerty123
    qwertyuiop abc123 abc1234 abc12345 iloveyou princess dragon master login
    sunshine shadow michael jennifer 123456 1234567 12345678 123456789
    1234567890 12345678910 111111 000000 654321 123123 666666 888888
    asdfgh asdfghjkl zxcvbn zxcvbnm 1q2w3e4r 1qaz2wsx qazwsx trustno1
    freedom whateverStar football baseball harley jordan michelle charlie
    andrew joshua matthew daniel connor batman superman starwars whatever
    nicole chelsea biteme trustno1 fuckyou asshole dontknow nothing
    passwort motdepasse contrasena senha parola haslo parola123 senha123
    vypam vypam123 vypam1234 aegispam aegispam1 pamadmin pam password1!
    admin12345 letmein1234 welcome1234 changeme123 newpassword oldpassword
    qwe123 qwe12345 q1w2e3r4 test123 test1234 demo123 sample temp123
    """.split()
)


# ---------------------------------------------------------------------------
# settings + small helpers
# ---------------------------------------------------------------------------
def _vault_config():
    """Runtime config for at-rest crypto (works in request and app context)."""
    from flask import current_app

    return current_app.config["LICENSE_CONFIG"]


def auth_settings() -> Dict[str, Any]:
    """The `auth` policy group with schema defaults merged in (the settings
    group is validated by service; this reader is the single source the
    identity machinery consumes)."""
    from models import SettingGroup

    row = SettingGroup.query.filter(SettingGroup.group_name == "auth").first()
    values = dict(row.value) if row is not None and row.value else {}
    return {
        "mfa_required": bool(values.get("mfa_required", True)),
        "password_min_length": int(values.get("password_min_length", PASSWORD_MIN_DEFAULT)),
        "breached_password_extra": str(values.get("breached_password_extra", "") or ""),
        "lockout_threshold": int(values.get("lockout_threshold", LOCKOUT_THRESHOLD_DEFAULT)),
        "lockout_minutes": int(values.get("lockout_minutes", LOCKOUT_BASE_MINUTES)),
        "rate_limit_per_ip": int(values.get("rate_limit_per_ip", RATE_LIMIT_PER_IP_DEFAULT)),
        "rate_limit_per_account": int(
            values.get("rate_limit_per_account", RATE_LIMIT_PER_ACCOUNT_DEFAULT)
        ),
        "spray_threshold": int(values.get("spray_threshold", SPRAY_THRESHOLD_DEFAULT)),
        "progressive_delay": bool(values.get("progressive_delay", True)),
        "session_idle_minutes": int(
            values.get("session_idle_minutes", SESSION_IDLE_MINUTES_DEFAULT)
        ),
        "session_absolute_hours": int(
            values.get("session_absolute_hours", SESSION_ABSOLUTE_HOURS_DEFAULT)
        ),
        "max_sessions_per_user": int(
            values.get("max_sessions_per_user", MAX_SESSIONS_PER_USER_DEFAULT)
        ),
        "stepup_ttl_minutes": int(values.get("stepup_ttl_minutes", STEPUP_TTL_MINUTES_DEFAULT)),
        "remember_device_days": int(
            values.get("remember_device_days", REMEMBER_DEVICE_DAYS_DEFAULT)
        ),
        "emergency_window_minutes": int(
            values.get("emergency_window_minutes", EMERGENCY_WINDOW_MINUTES_DEFAULT)
        ),
        "require_device_posture": bool(values.get("require_device_posture", False)),
    }


def auth_event(action: str, *, actor: str = "system", subject: str = "",
               detail: Optional[Dict[str, Any]] = None) -> AuthEvent:
    """Queue one login-security record; the audit flush listener folds it
    into the immutable ledger under source `auth` in the same transaction."""
    event = AuthEvent(
        action=action,
        actor=actor[:64] or "system",
        subject=subject[:128],
        detail=detail or {},
    )
    db.session.add(event)
    return event


# ---------------------------------------------------------------------------
# password hashing + policy (NIST: length over complexity)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """scrypt(password, salt) -> `scrypt$n$r$p$salt$hash` (stdlib, memory-
    hard, argon2id-class)."""
    salt = pysecrets.token_bytes(SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), digest.hex()
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored scrypt hash."""
    if not stored or not stored.startswith("scrypt$"):
        # keep the timing shape honest for sealed/emergency/unknown users
        hashlib.scrypt(
            password.encode("utf-8"),
            salt=b"\x00" * SCRYPT_SALT_BYTES,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
        )
        return False
    try:
        _tag, n, r, p, salt_hex, digest_hex = stored.split("$")
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def check_password_policy(password: str, *, username: str = "",
                          email: str = "", policy: Optional[Dict[str, Any]] = None) -> None:
    """Raise ValidationFailed unless the password satisfies the shipped NIST
    policy: minimum length (default 14), sane maximum, not a breached
    common password, does not contain the username."""
    policy = policy or auth_settings()
    minimum = max(8, int(policy.get("password_min_length", PASSWORD_MIN_DEFAULT)))
    if not isinstance(password, str) or not password:
        raise ValidationFailed("'password' is required", {"field": "password"})
    if len(password) < minimum:
        raise ValidationFailed(
            f"Password must be at least {minimum} characters "
            "(NIST: length over complexity)",
            {"field": "password", "min_length": minimum},
        )
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValidationFailed(
            f"Password must be at most {PASSWORD_MAX_LENGTH} characters",
            {"field": "password", "max_length": PASSWORD_MAX_LENGTH},
        )
    lowered = password.lower()
    denylist = BREACHED_PASSWORDS
    extra = str(policy.get("breached_password_extra") or "")
    if extra:
        denylist = denylist | {p.strip().lower() for p in extra.split(",") if p.strip()}
    if lowered in denylist:
        raise ValidationFailed(
            "Password is on the breached-password denylist "
            "(most common passwords are refused)",
            {"field": "password"},
        )
    for needle in (username, email.split("@")[0] if email else ""):
        needle = (needle or "").lower()
        if len(needle) >= 4 and needle and needle in lowered:
            raise ValidationFailed(
                "Password must not contain the username or e-mail name",
                {"field": "password"},
            )


# ---------------------------------------------------------------------------
# in-process rate limiting + spray detection
#
# Sliding windows live in this process (single-binary scope; in cluster
# mode each node enforces its own window and the lockout counters - which
# live on the user row - still hold globally).
# ---------------------------------------------------------------------------
class _SlidingWindows:
    def __init__(self) -> None:
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._spray: Dict[str, Tuple[set, datetime]] = {}
        self._blocked_until: Dict[str, datetime] = {}

    def hit(self, key: str, window_seconds: int, limit: int) -> bool:
        """Record one hit; False when the limit is exhausted for this key."""
        now = datetime.now()
        window = self._hits[key]
        while window and (now - window[0]).total_seconds() > window_seconds:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True

    def spray(self, ip: str, username: str, *, threshold: int,
              window_seconds: int) -> bool:
        """Record one login username from this IP; True when the IP just
        crossed the spray threshold (distinct usernames in the window)."""
        if not ip:
            return False
        now = datetime.now()
        seen, since = self._spray.get(ip, (set(), now))
        if (now - since).total_seconds() > window_seconds:
            seen, since = set(), now
        seen.add(username.lower())
        self._spray[ip] = (seen, since)
        return len(seen) >= threshold

    def block(self, ip: str, minutes: int) -> None:
        self._blocked_until[ip] = datetime.now() + timedelta(minutes=minutes)

    def blocked(self, ip: str) -> Optional[datetime]:
        until = self._blocked_until.get(ip)
        if until is None:
            return None
        if until <= datetime.now():
            self._blocked_until.pop(ip, None)
            return None
        return until


WINDOWS = _SlidingWindows()


def reset_windows_for_tests() -> None:
    """Fresh limiter state (tests and the E2E rig call this between runs)."""
    global WINDOWS
    WINDOWS = _SlidingWindows()


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
def get_user(username: str) -> Optional[User]:
    return User.query.filter(User.username == str(username).strip().lower()).first()


def _normalize_username(username: str) -> str:
    name = str(username or "").strip().lower()
    if not _USERNAME_RE.match(name):
        raise ValidationFailed(
            "Username must be 3-64 chars: lowercase letters, digits, '.', '_', '-' "
            "(starting alphanumeric)",
            {"field": "username"},
        )
    return name


def list_users(*, limit: int = 100, source: str = "") -> List[Dict[str, Any]]:
    query = User.query.order_by(User.username)
    if source:
        query = query.filter(User.source == source)
    return [user.to_dict() for user in query.limit(limit).all()]


def create_user(
    *,
    username: str,
    actor: str,
    email: str = "",
    display_name: str = "",
    password: str = "",
    source: str = "local",
    must_change_password: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """Create a local console user. When no password is given a strong one
    is generated and returned exactly once (the caller shows it once)."""
    name = _normalize_username(username)
    if source not in USER_SOURCES:
        raise ValidationFailed(
            f"Unknown user source '{source}'", {"allowed": list(USER_SOURCES)}
        )
    if get_user(name) is not None:
        raise Conflict(f"User '{name}' already exists")
    policy = auth_settings()
    generated = ""
    if not password:
        if source != "local":
            raise ValidationFailed(
                "A provider-managed user needs no password", {"field": "password"}
            )
        generated = pysecrets.token_urlsafe(18)
        password = generated
    check_password_policy(password, username=name, email=email, policy=policy)
    user = User(
        username=name,
        email=str(email).strip()[:255],
        display_name=str(display_name).strip()[:128] or name,
        password_hash=hash_password(password),
        source=source,
        must_change_password=must_change_password or bool(generated),
        password_changed_at=None if generated else datetime.now(),
        created_by=actor[:64],
    )
    db.session.add(user)
    db.session.flush()
    auth_event(
        "auth.user.created",
        actor=actor,
        subject=name,
        detail={"source": source, "must_change_password": user.must_change_password},
    )
    db.session.commit()
    data = user.to_dict()
    return data, generated


def update_user(
    user_id: int, *, actor: str, active: Optional[bool] = None,
    email: Optional[str] = None, display_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin edit: activate/deactivate (deactivation revokes every live
    session immediately) and contact fields."""
    user = db.session.get(User, user_id)
    if user is None:
        raise NotFound(f"Unknown user {user_id}")
    changed: Dict[str, Any] = {}
    if active is not None and bool(active) != user.is_active:
        user.is_active = bool(active)
        changed["is_active"] = user.is_active
        if not user.is_active:
            revoked = _revoke_all_sessions(user, reason="user-deactivated")
            changed["sessions_revoked"] = revoked
    if email is not None:
        user.email = str(email).strip()[:255]
        changed["email"] = True
    if display_name is not None:
        user.display_name = str(display_name).strip()[:128] or user.username
        changed["display_name"] = True
    auth_event("auth.user.updated", actor=actor, subject=user.username, detail=changed)
    db.session.commit()
    return user.to_dict()


def unlock_user(user_id: int, *, actor: str) -> Dict[str, Any]:
    """Admin unlock: clears the lockout and the failure counters."""
    user = db.session.get(User, user_id)
    if user is None:
        raise NotFound(f"Unknown user {user_id}")
    user.locked_until = None
    user.failed_logins = 0
    auth_event("auth.user.unlocked", actor=actor, subject=user.username, detail={})
    db.session.commit()
    return user.to_dict()


def admin_reset_password(user_id: int, *, actor: str, password: str = "") -> Dict[str, Any]:
    """Admin-assisted reset: a fresh password (generated when not supplied,
    returned exactly once) and `must_change_password` on the next login."""
    user = db.session.get(User, user_id)
    if user is None:
        raise NotFound(f"Unknown user {user_id}")
    if user.is_emergency:
        raise Forbidden("The emergency admin's password is sealed - rotate it, never set it")
    if user.source == "scim":
        raise Forbidden(
            "This user is managed by the identity provider (SCIM) - "
            "reset the password there"
        )
    generated = password or pysecrets.token_urlsafe(18)
    check_password_policy(generated, username=user.username, email=user.email)
    user.password_hash = hash_password(generated)
    user.must_change_password = True
    user.password_changed_at = datetime.now()
    revoked = _revoke_all_sessions(user, reason="password-reset")
    auth_event(
        "auth.password.reset",
        actor=actor,
        subject=user.username,
        detail={"by": "admin", "sessions_revoked": revoked},
    )
    db.session.commit()
    data = user.to_dict()
    data["generated_password"] = generated if not password else None
    return data


# ---------------------------------------------------------------------------
# console sessions
# ---------------------------------------------------------------------------
def _principals_roles(username: str) -> set:
    """The roles bound to this username (kind `user` bindings - 6b decides)."""
    rows = RoleBinding.query.filter(
        RoleBinding.principal == username,
        RoleBinding.revoked_at.is_(None),
    ).all()
    return {row.role for row in rows if row.kind in ("user", "local")}


def _may_remember_device(username: str) -> bool:
    """`remember this device` is refused for approvers/admins (Addendum C)."""
    return not (_principals_roles(username) & set(PRIVILEGED_ROLES))


def mint_session(
    user: User,
    *,
    methods: List[str],
    source_ip: str = "",
    user_agent: str = "",
    is_emergency: bool = False,
    config=None,
) -> Dict[str, Any]:
    """Mint a server-side console session (idle + absolute timeouts, CSRF
    secret, concurrent cap). The token is returned exactly once."""
    policy = auth_settings()
    now = datetime.now()
    # concurrent-session cap: the oldest live session is revoked
    live = (
        ConsoleSession.query.filter(
            ConsoleSession.user_id == user.id,
            ConsoleSession.revoked_at.is_(None),
        )
        .order_by(ConsoleSession.created_at)
        .all()
    )
    cap = max(1, policy["max_sessions_per_user"])
    while len(live) >= cap:
        oldest = live.pop(0)
        oldest.revoked_at = now
        oldest.revoked_reason = "session-limit"
        auth_event(
            "auth.session.revoked",
            actor="system",
            subject=user.username,
            detail={"session_id": oldest.id, "reason": "session-limit"},
        )
    secret = pysecrets.token_urlsafe(32)
    csrf_secret = pysecrets.token_urlsafe(32)
    absolute = now + timedelta(hours=policy["session_absolute_hours"])
    session = ConsoleSession(
        user_id=user.id,
        token_sha256=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        token_prefix="",
        csrf_sha256=hashlib.sha256(csrf_secret.encode("utf-8")).hexdigest(),
        mfa_at=now,
        mfa_methods=list(methods),
        is_emergency=is_emergency,
        source_ip=source_ip[:64],
        user_agent=user_agent[:255],
        last_seen_at=now,
        idle_expires_at=now + timedelta(minutes=policy["session_idle_minutes"]),
        absolute_expires_at=absolute,
    )
    session.token_prefix = f"{CONSOLE_TOKEN_PREFIX}.{session.id}."
    db.session.add(session)
    db.session.flush()
    session.token_prefix = f"{CONSOLE_TOKEN_PREFIX}.{session.id}."
    user.last_login_at = now
    user.failed_logins = 0
    token = f"{session.token_prefix}{secret}"
    auth_event(
        "auth.login.succeeded",
        actor=user.username,
        subject=user.username,
        detail={
            "session_id": session.id,
            "methods": list(methods),
            "emergency": is_emergency,
            "source_ip": source_ip[:64] if source_ip else "",
        },
    )
    db.session.commit()
    return {
        "session_id": session.id,
        "session_token": token,
        "csrf_token": csrf_secret,
        "expires_at": session.absolute_expires_at.isoformat(),
        "idle_expires_at": session.idle_expires_at.isoformat(),
        "user": user.to_dict(),
        "mfa_methods": list(methods),
        "is_emergency": is_emergency,
    }


def verify_console_session(token: Any) -> Tuple[User, ConsoleSession]:
    """The live console session a presented `vypam-ui1.<id>.<secret>`
    authenticates: idle + absolute timeouts enforced (the first refusal
    marks the row expired and lands on the ledger exactly once)."""
    if not isinstance(token, str) or not token.startswith(CONSOLE_TOKEN_PREFIX + "."):
        raise Unauthorized("Console session required")
    body = token[len(CONSOLE_TOKEN_PREFIX) + 1 :]
    parts = body.split(".")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1]:
        raise Unauthorized("Console session required")
    session = db.session.get(ConsoleSession, int(parts[0]))
    digest = hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
    if (
        session is None
        or not hmac.compare_digest(digest, session.token_sha256)
    ):
        raise Unauthorized("Console session required")
    user = db.session.get(User, session.user_id)
    now = datetime.now()
    if session.revoked_at is not None:
        raise Unauthorized(f"Console session revoked ({session.revoked_reason or 'revoked'})")
    if user is None or not user.is_active:
        _end_session(session, "user-inactive")
        raise Unauthorized("Console session revoked (user inactive)")
    if session.absolute_expires_at <= now:
        _end_session(session, "absolute-timeout")
        raise Unauthorized("Console session expired (absolute timeout)")
    if session.idle_expires_at <= now:
        _end_session(session, "idle-timeout")
        raise Unauthorized("Console session expired (idle timeout)")
    # slide the idle window, bounded by the absolute one
    policy = auth_settings()
    session.last_seen_at = now
    slid = now + timedelta(minutes=policy["session_idle_minutes"])
    session.idle_expires_at = min(slid, session.absolute_expires_at)
    db.session.commit()
    return user, session


def _end_session(session: ConsoleSession, reason: str) -> None:
    if session.revoked_at is None:
        session.revoked_at = datetime.now()
        session.revoked_reason = reason
        auth_event(
            "auth.session.revoked",
            actor="system",
            subject="",
            detail={"session_id": session.id, "reason": reason},
        )
        db.session.commit()


def csrf_ok(session: ConsoleSession, presented: str) -> bool:
    """Double-submit check for cookie-authenticated mutations."""
    if not presented:
        return False
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, session.csrf_sha256)


def list_user_sessions(
    user_id: int, *, include_revoked: bool = False, limit: int = 100
) -> List[Dict[str, Any]]:
    query = ConsoleSession.query.filter(ConsoleSession.user_id == user_id)
    if not include_revoked:
        query = query.filter(ConsoleSession.revoked_at.is_(None))
    rows = query.order_by(ConsoleSession.created_at.desc()).limit(limit).all()
    out: List[Dict[str, Any]] = []
    for row in rows:
        data = row.to_dict()
        user = db.session.get(User, row.user_id)
        data["username"] = user.username if user else ""
        out.append(data)
    return out


def revoke_session(session_id: int, *, actor: str, reason: str = "revoked") -> Dict[str, Any]:
    """Revoke one console session (own or admin-initiated)."""
    session = db.session.get(ConsoleSession, session_id)
    if session is None:
        raise NotFound(f"Unknown console session {session_id}")
    if session.revoked_at is not None:
        raise Conflict(f"Session {session_id} is already revoked")
    session.revoked_at = datetime.now()
    session.revoked_reason = reason[:64] or "revoked"
    user = db.session.get(User, session.user_id)
    auth_event(
        "auth.session.revoked",
        actor=actor,
        subject=user.username if user else "",
        detail={"session_id": session_id, "reason": session.revoked_reason},
    )
    db.session.commit()
    return session.to_dict()


def logout_all(user_id: int, *, actor: str, keep_session_id: Optional[int] = None) -> int:
    """Log out everywhere: revoke every live session of this user."""
    revoked = _revoke_all_sessions(
        db.session.get(User, user_id),
        reason="logout-all",
        keep_session_id=keep_session_id,
        actor=actor,
    )
    db.session.commit()
    return revoked


def _revoke_all_sessions(
    user: User, *, reason: str, keep_session_id: Optional[int] = None,
    actor: str = "system",
) -> int:
    now = datetime.now()
    count = 0
    rows = ConsoleSession.query.filter(
        ConsoleSession.user_id == user.id,
        ConsoleSession.revoked_at.is_(None),
    ).all()
    for row in rows:
        if keep_session_id is not None and row.id == keep_session_id:
            continue
        row.revoked_at = now
        row.revoked_reason = reason[:64]
        count += 1
        auth_event(
            "auth.session.revoked",
            actor=actor,
            subject=user.username,
            detail={"session_id": row.id, "reason": reason},
        )
    return count


def touch_stepup(session: ConsoleSession) -> None:
    """Refresh the step-up timestamp after a successful assertion."""
    session.mfa_at = datetime.now()
    db.session.commit()


def stepup_stale(session: ConsoleSession) -> bool:
    """True when the session's last MFA assertion is older than the
    configured step-up TTL."""
    if session.mfa_at is None:
        return True
    policy = auth_settings()
    age = datetime.now() - session.mfa_at
    return age > timedelta(minutes=policy["stepup_ttl_minutes"])


# ---------------------------------------------------------------------------
# lockout + failures
# ---------------------------------------------------------------------------
def _register_failure(user: User, *, ip: str, username: str) -> None:
    """One failed password check: counters, progressive delay, lockout."""
    policy = auth_settings()
    now = datetime.now()
    if user is not None:
        if user.locked_until is not None and user.locked_until <= now:
            user.locked_until = None
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= max(3, policy["lockout_threshold"]):
            streak = user.lockout_streak or 0
            minutes = min(
                policy["lockout_minutes"] * (2 ** min(streak, LOCKOUT_MAX_STREAK)),
                60 * 24,
            )
            user.locked_until = now + timedelta(minutes=minutes)
            user.lockout_streak = streak + 1
            user.failed_logins = 0
            auth_event(
                "auth.lockout",
                actor="system",
                subject=user.username,
                detail={
                    "minutes": minutes,
                    "streak": user.lockout_streak,
                    "source_ip": ip[:64] if ip else "",
                },
            )
    if policy["progressive_delay"]:
        fails = user.failed_logins if user is not None else 1
        time.sleep(min(PROGRESSIVE_DELAY_MAX_SECONDS, 2.0 ** max(0, fails - 1) * 0.25))


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------
def login(
    *,
    username: str,
    password: str,
    source_ip: str = "",
    user_agent: str = "",
    device_token: str = "",
    remember_device: bool = False,
) -> Dict[str, Any]:
    """Password login. The outcome is one of: a session (no factor and
    `mfa_required` off), an MFA challenge (`vypam-mfa1`), an enrolment
    ticket (`vypam-enr1`, fail-closed), or an honest refusal. Rate limits
    and spray detection run before anything else."""
    policy = auth_settings()
    name = str(username or "").strip().lower()
    ip = source_ip[:64]

    # per-IP block (spray) then sliding windows
    blocked_until = WINDOWS.blocked(ip)
    if blocked_until is not None:
        raise Forbidden(
            "Too many failed attempts from this address - try again later",
            {"retry_after_seconds": int((blocked_until - datetime.now()).total_seconds())},
        )
    if not WINDOWS.hit(f"ip:{ip}", RATE_LIMIT_WINDOW_MINUTES * 60, policy["rate_limit_per_ip"]):
        auth_event(
            "auth.rate-limited",
            actor="system",
            subject=name,
            detail={"scope": "ip", "source_ip": ip},
        )
        db.session.commit()
        raise Forbidden(
            "Too many login attempts from this address",
            {"retry_after_seconds": RATE_LIMIT_WINDOW_MINUTES * 60},
        )
    if name and not WINDOWS.hit(
        f"acct:{name}", RATE_LIMIT_WINDOW_MINUTES * 60, policy["rate_limit_per_account"]
    ):
        auth_event("auth.rate-limited", actor="system", subject=name,
                   detail={"scope": "account"})
        db.session.commit()
        raise Forbidden(
            "Too many login attempts for this account",
            {"retry_after_seconds": RATE_LIMIT_WINDOW_MINUTES * 60},
        )
    if name and WINDOWS.spray(
        ip, name,
        threshold=max(3, policy["spray_threshold"]),
        window_seconds=RATE_LIMIT_WINDOW_MINUTES * 60,
    ):
        WINDOWS.block(ip, SPRAY_BLOCK_MINUTES)
        auth_event(
            "auth.spray-alert",
            actor="system",
            subject=name,
            detail={
                "source_ip": ip,
                "blocked_minutes": SPRAY_BLOCK_MINUTES,
                "threshold": policy["spray_threshold"],
            },
        )
        db.session.commit()
        raise Forbidden(
            "Credential-spray pattern detected from this address - blocked",
            {"blocked_minutes": SPRAY_BLOCK_MINUTES},
        )

    user = get_user(name) if name else None

    if user is not None and user.is_emergency:
        # the sealed admin never logs in through the ordinary password path
        auth_event("auth.login.refused", actor=name, subject=name,
                   detail={"reason": "emergency-sealed"})
        db.session.commit()
        raise Forbidden(
            "The emergency admin is sealed - open a dual-approved grant first "
            "(POST /api/v1/auth/emergency/open)",
            {"reason": "emergency-sealed"},
        )

    generic_fail = Unauthorized("Invalid username or password")
    if user is None:
        # equalise the work for unknown users, then fail identically
        verify_password(password or "", hash_password("timing-equaliser"))
        _register_failure(None, ip=ip, username=name)
        auth_event("auth.login.failed", actor=name or "unknown", subject=name,
                   detail={"reason": "unknown-user", "source_ip": ip})
        db.session.commit()
        raise generic_fail

    if not verify_password(password or "", user.password_hash):
        _register_failure(user, ip=ip, username=name)
        # a provider-managed row has no local credential to verify: the
        # answer stays the uniform 401 (never an existence oracle), while
        # the ledger records the true reason - exactly the inactive pattern
        auth_event("auth.login.failed", actor=name, subject=name,
                   detail={"reason": "scim-managed" if user.source == "scim" else "bad-password",
                           "source_ip": ip})
        db.session.commit()
        raise generic_fail

    if user.locked_until is not None and user.locked_until > datetime.now():
        auth_event("auth.login.refused", actor=name, subject=name,
                   detail={"reason": "locked", "source_ip": ip})
        db.session.commit()
        raise Forbidden(
            "Account locked after repeated failures",
            {"reason": "locked", "locked_until": user.locked_until.isoformat()},
        )
    if not user.is_active:
        auth_event("auth.login.refused", actor=name, subject=name,
                   detail={"reason": "inactive", "source_ip": ip})
        db.session.commit()
        raise generic_fail
    if user.source == "scim":
        # fail-closed defense in depth: no local password can verify for a
        # provider-managed row (the branch above answers first with the
        # uniform 401), so this only fires if an scim row ever carried a
        # valid local hash - the credential still never signs in here
        auth_event("auth.login.refused", actor=name, subject=name,
                   detail={"reason": "scim-managed", "source_ip": ip})
        db.session.commit()
        raise Forbidden(
            "This account is managed by the identity provider (SCIM) - "
            "sign in through SSO",
            {"reason": "scim-managed"},
        )
    if user.must_change_password:
        auth_event("auth.login.refused", actor=name, subject=name,
                   detail={"reason": "password-change-required"})
        db.session.commit()
        raise Forbidden(
            "Password must be changed before signing in "
            "(POST /api/v1/auth/password with the current password)",
            {"reason": "password-change-required"},
        )

    # lockout cleared by a genuinely successful password check
    if user.failed_logins or user.locked_until:
        user.failed_logins = 0
        user.locked_until = None

    factors = MfaFactor.query.filter(
        MfaFactor.user_id == user.id, MfaFactor.active.is_(True)
    ).all()
    methods = [factor.kind for factor in factors]

    if not factors:
        if policy["mfa_required"]:
            # fail-closed: an enrolment ticket, never a silent pass
            challenge, secret = _mint_challenge(user, kind="enrol")
            auth_event("auth.enrolment.required", actor=name, subject=name,
                       detail={"source_ip": ip})
            db.session.commit()
            return {
                "status": "enrolment_required",
                "enrol_ticket": f"{ENROL_TICKET_PREFIX}.{challenge.id}.{secret}",
                "methods_allowed": ["totp", "webauthn", "email"],
            }
        db.session.commit()
        minted = mint_session(
            user, methods=[], source_ip=ip, user_agent=user_agent
        )
        return maybe_remember_device(
            user, minted, requested=remember_device, source_ip=ip
        )

    # remembered device (low-privilege only) may skip the second factor
    if device_token and _device_matches(user, device_token):
        auth_event("auth.login.mfa-skipped", actor=name, subject=name,
                   detail={"via": "remembered-device"})
        db.session.commit()
        return mint_session(
            user, methods=["remembered-device"], source_ip=ip, user_agent=user_agent
        )

    challenge, secret = _mint_challenge(user, kind="mfa")
    db.session.commit()
    has_codes = MfaBackupCode.query.filter(
        MfaBackupCode.user_id == user.id, MfaBackupCode.used_at.is_(None)
    ).count() > 0
    return {
        "status": "mfa_required",
        "challenge": f"{MFA_CHALLENGE_PREFIX}.{challenge.id}.{secret}",
        "methods": sorted(set(methods) | ({"backup-code"} if has_codes else set())),
        "expires_in_seconds": MFA_CHALLENGE_TTL_SECONDS,
    }


def _mint_challenge(user: User, *, kind: str) -> Tuple[LoginChallenge, str]:
    """One single-use login step; the secret rides the token once and its
    sha256 stays on the row (the codebase rule for every credential)."""
    challenge_id = pysecrets.token_hex(16)
    secret = pysecrets.token_urlsafe(32)
    challenge = LoginChallenge(
        id=challenge_id,
        user_id=user.id,
        kind=kind,
        secret_sha256=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        expires_at=datetime.now()
        + timedelta(seconds=ENROL_TICKET_TTL_SECONDS if kind == "enrol" else MFA_CHALLENGE_TTL_SECONDS),
    )
    db.session.add(challenge)
    db.session.flush()
    return challenge, secret


def consume_challenge(challenge_id: str, presented: str, *, kind: str) -> Tuple[User, LoginChallenge]:
    """Validate and consume a single-use login challenge (`mfa` or
    `enrol`). Unknown, wrong-secret, expired or already-used -> the same
    honest 401."""
    challenge = db.session.get(LoginChallenge, str(challenge_id or ""))
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest() if presented else ""
    if (
        challenge is None
        or challenge.kind != kind
        or challenge.consumed_at is not None
        or challenge.expires_at <= datetime.now()
        or not presented
        or not hmac.compare_digest(digest, challenge.secret_sha256 or "")
    ):
        raise Unauthorized("Login challenge invalid or expired")
    challenge.consumed_at = datetime.now()
    user = db.session.get(User, challenge.user_id)
    if user is None or not user.is_active:
        raise Unauthorized("Login challenge invalid or expired")
    return user, challenge


# ---------------------------------------------------------------------------
# remembered devices
# ---------------------------------------------------------------------------
def remember_device(user: User, *, source_ip: str = "") -> Optional[Dict[str, Any]]:
    """Issue a device token when policy allows (never for approver/admin
    bindings). Shown once; only its sha256 is stored."""
    if not _may_remember_device(user.username):
        return None
    policy = auth_settings()
    secret = pysecrets.token_urlsafe(24)
    device = AuthDevice(
        user_id=user.id,
        device_sha256=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        device_prefix="",
        expires_at=datetime.now() + timedelta(days=max(1, policy["remember_device_days"])),
    )
    db.session.add(device)
    db.session.flush()
    device.device_prefix = f"{DEVICE_TOKEN_PREFIX}.{device.id}."
    auth_event(
        "auth.device.remembered",
        actor=user.username,
        subject=user.username,
        detail={"device_id": device.id, "source_ip": source_ip[:64] if source_ip else ""},
    )
    db.session.commit()
    return {
        "device_id": device.id,
        "device_token": f"{device.device_prefix}{secret}",
        "expires_at": device.expires_at.isoformat(),
    }


def maybe_remember_device(
    user: User, result: Dict[str, Any], *, requested: bool, source_ip: str = ""
) -> Dict[str, Any]:
    """Attach a remembered-device token to a fresh session mint when the
    login asked for one and policy allows (never approver/admin bindings -
    Addendum C). The skip path (a `device_token` already presented) needs
    no new token, and a refusal to issue never fails the login - the
    session itself is the primary credential."""
    if not requested or not isinstance(result, dict) or not result.get("session_token"):
        return result
    issued = remember_device(user, source_ip=source_ip)
    if issued is None:
        return result
    result["device_token"] = issued["device_token"]
    result["device_expires_at"] = issued["expires_at"]
    return result


def _device_matches(user: User, token: str) -> bool:
    if not isinstance(token, str) or not token.startswith(DEVICE_TOKEN_PREFIX + "."):
        return False
    body = token[len(DEVICE_TOKEN_PREFIX) + 1 :]
    parts = body.split(".")
    if len(parts) != 2 or not parts[0].isdigit():
        return False
    device = db.session.get(AuthDevice, int(parts[0]))
    if device is None or device.user_id != user.id:
        return False
    if device.revoked_at is not None or device.expires_at <= datetime.now():
        return False
    digest = hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, device.device_sha256):
        return False
    device.last_used_at = datetime.now()
    return True


# ---------------------------------------------------------------------------
# password change + recovery (e-mail OTP path lives in otp.py)
# ---------------------------------------------------------------------------
def change_password(
    *,
    username: str,
    old_password: str,
    new_password: str,
    session: Optional[ConsoleSession] = None,
) -> Dict[str, Any]:
    """Self-service change (authenticated by the old password, or by a live
    session presenting it) and a first-login forced change."""
    name = str(username or "").strip().lower()
    user = get_user(name)
    if user is None or user.is_emergency or not verify_password(old_password or "", user.password_hash):
        auth_event("auth.password.change-refused", actor=name or "unknown",
                   subject=name, detail={"reason": "bad-current-password"})
        db.session.commit()
        raise Unauthorized("Current password is incorrect")
    check_password_policy(new_password, username=user.username, email=user.email)
    if verify_password(new_password, user.password_hash):
        raise ValidationFailed(
            "The new password must differ from the current one", {"field": "new_password"}
        )
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now()
    revoked = _revoke_all_sessions(
        user, reason="password-changed",
        keep_session_id=session.id if session is not None else None,
    )
    auth_event(
        "auth.password.changed",
        actor=user.username,
        subject=user.username,
        detail={"by": "self", "sessions_revoked": revoked},
    )
    db.session.commit()
    return {"user": user.to_dict(), "sessions_revoked": revoked}


def set_password_with_recovery(
    *, username: str, new_password: str, actor: str = "recovery"
) -> Dict[str, Any]:
    """Password reset after a verified e-mail OTP (called by otp.py once the
    challenge is consumed). The factor stays - only the password rotates."""
    user = get_user(username)
    if user is None or user.is_emergency:
        raise NotFound("No such user")
    check_password_policy(new_password, username=user.username, email=user.email)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now()
    revoked = _revoke_all_sessions(user, reason="password-recovered")
    auth_event(
        "auth.password.recovered",
        actor=actor,
        subject=user.username,
        detail={"sessions_revoked": revoked},
    )
    db.session.commit()
    return {"user": user.to_dict(), "sessions_revoked": revoked}


# ---------------------------------------------------------------------------
# factor recovery (two-admin approval; never self-service alone)
# ---------------------------------------------------------------------------
def request_factor_recovery(user_id: int, *, reason: str = "") -> Dict[str, Any]:
    """A signed-in user who lost every factor asks for recovery; two
    distinct admins must approve before the factors are deleted."""
    user = db.session.get(User, user_id)
    if user is None:
        raise NotFound(f"Unknown user {user_id}")
    pending = FactorRecoveryRequest.query.filter(
        FactorRecoveryRequest.user_id == user.id,
        FactorRecoveryRequest.status == "pending",
    ).first()
    if pending is not None:
        raise Conflict(f"Recovery request {pending.id} is already pending")
    request = FactorRecoveryRequest(
        user_id=user.id, reason=str(reason).strip()[:255],
    )
    db.session.add(request)
    db.session.flush()
    auth_event(
        "auth.factor-recovery.requested",
        actor=user.username,
        subject=user.username,
        detail={"request_id": request.id},
    )
    db.session.commit()
    return request.to_dict()


def approve_factor_recovery(
    request_id: int, *, approver: str, decision: str, note: str = ""
) -> Dict[str, Any]:
    """Two distinct approvals delete the user's factors (the next login
    forces a fresh enrolment); one denial closes the request."""
    request = db.session.get(FactorRecoveryRequest, request_id)
    if request is None:
        raise NotFound(f"Unknown recovery request {request_id}")
    if request.status != "pending":
        raise Conflict(f"Recovery request {request_id} is already {request.status}")
    if decision not in ("approve", "deny"):
        raise ValidationFailed("decision must be 'approve' or 'deny'")
    user = db.session.get(User, request.user_id)
    if user is not None and approver == user.username:
        raise Forbidden("The affected user may not approve their own recovery")
    approval = FactorRecoveryApproval(
        request_id=request.id, approver=approver[:64], decision=decision,
        note=str(note).strip()[:255],
    )
    db.session.add(approval)
    db.session.flush()
    auth_event(
        f"auth.factor-recovery.{decision}d",
        actor=approver,
        subject=user.username if user else "",
        detail={"request_id": request.id},
    )
    if decision == "deny":
        request.status = "denied"
        request.resolved_at = datetime.now()
        db.session.commit()
        return request.to_dict()
    approvals = FactorRecoveryApproval.query.filter(
        FactorRecoveryApproval.request_id == request.id,
        FactorRecoveryApproval.decision == "approve",
    ).all()
    distinct = {row.approver for row in approvals}
    if len(distinct) < EMERGENCY_APPROVALS_REQUIRED:
        db.session.commit()
        return request.to_dict()
    deleted = 0
    for factor in MfaFactor.query.filter(MfaFactor.user_id == user.id).all():
        db.session.delete(factor)
        deleted += 1
    request.status = "approved"
    request.resolved_at = datetime.now()
    auth_event(
        "auth.factor-recovery.completed",
        actor=approver,
        subject=user.username if user else "",
        detail={"request_id": request.id, "factors_deleted": deleted},
    )
    db.session.commit()
    return request.to_dict()


def list_factor_recovery_requests(*, status: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    query = FactorRecoveryRequest.query.order_by(FactorRecoveryRequest.created_at.desc())
    if status:
        query = query.filter(FactorRecoveryRequest.status == status)
    out: List[Dict[str, Any]] = []
    for request in query.limit(limit).all():
        data = request.to_dict()
        user = db.session.get(User, request.user_id)
        data["username"] = user.username if user else ""
        approvals = FactorRecoveryApproval.query.filter(
            FactorRecoveryApproval.request_id == request.id
        ).all()
        data["approvals"] = [row.to_dict() for row in approvals]
        out.append(data)
    return out


# ---------------------------------------------------------------------------
# the sealed emergency admin (offline path for SSO outages)
# ---------------------------------------------------------------------------
def _seal_emergency_password(password: str) -> Dict[str, Any]:
    import secrets_store

    return secrets_store.seal_with_aad(password, b"auth:emergency-admin", _vault_config())


def _unseal_emergency_password(blob: Any) -> str:
    import secrets_store

    if not isinstance(blob, dict):
        return ""
    try:
        return secrets_store.unseal_with_aad(blob, b"auth:emergency-admin", _vault_config())
    except Exception:
        return ""


def ensure_emergency_admin() -> Optional[User]:
    """Seed the sealed emergency admin exactly once (startup, like the role
    seeds). Its password is random, sealed, and unusable until a grant
    opens - the row alone grants nothing. Returns the fresh row on first
    creation, None when it already exists."""
    existing = User.query.filter(User.username == EMERGENCY_USERNAME).first()
    if existing is not None:
        return None
    password = f"emg-{pysecrets.token_urlsafe(24)}"
    user = User(
        username=EMERGENCY_USERNAME,
        display_name="Emergency administrator (offline)",
        email="",
        password_hash="",  # the seal lives below, never as a usable hash
        source="emergency",
        is_emergency=True,
        created_by="system",
    )
    db.session.add(user)
    db.session.flush()
    # no scrypt hash exists for this account: the sealed blob is the only
    # credential form, and it is unusable until a dual-approved grant opens
    seal = _seal_emergency_password(password)
    user.password_hash = "sealed$" + json.dumps(seal)
    auth_event(
        "auth.emergency.seeded",
        actor="system",
        subject=EMERGENCY_USERNAME,
        detail={"note": "sealed offline admin created at first boot"},
    )
    db.session.commit()
    return user


def request_emergency_open(*, actor: str, reason: str, ticket: str = "") -> Dict[str, Any]:
    """Ask to open the emergency admin: a `pending` grant awaiting two
    distinct approvals."""
    if len(str(reason).strip()) < 8:
        raise ValidationFailed("A reason of at least 8 characters is required")
    pending = EmergencyGrant.query.filter(EmergencyGrant.status == "pending").first()
    if pending is not None:
        raise Conflict(f"Grant {pending.id} is already pending approval")
    open_grant = EmergencyGrant.query.filter(EmergencyGrant.status == "open").first()
    if open_grant is not None and open_grant.expires_at and open_grant.expires_at > datetime.now():
        raise Conflict(f"Grant {open_grant.id} is already open")
    grant = EmergencyGrant(
        requested_by=actor[:64],
        reason=str(reason).strip()[:255],
        ticket=str(ticket).strip()[:64],
    )
    db.session.add(grant)
    db.session.flush()
    auth_event(
        "auth.emergency.requested",
        actor=actor,
        subject=EMERGENCY_USERNAME,
        detail={"grant_id": grant.id, "ticket": grant.ticket},
    )
    db.session.commit()
    return grant.to_dict()


def approve_emergency_open(
    grant_id: int, *, approver: str, decision: str, note: str = ""
) -> Dict[str, Any]:
    """Two distinct approvals (never the requester) open a short window;
    one denial closes the grant."""
    grant = db.session.get(EmergencyGrant, grant_id)
    if grant is None:
        raise NotFound(f"Unknown emergency grant {grant_id}")
    if grant.status not in ("pending",):
        raise Conflict(f"Emergency grant {grant_id} is already {grant.status}")
    if decision not in ("approve", "deny"):
        raise ValidationFailed("decision must be 'approve' or 'deny'")
    if approver == grant.requested_by:
        raise Forbidden("The requester may not approve their own grant")
    approval = EmergencyApproval(
        grant_id=grant.id, approver=approver[:64], decision=decision,
        note=str(note).strip()[:255],
    )
    db.session.add(approval)
    db.session.flush()
    auth_event(
        f"auth.emergency.{decision}d",
        actor=approver,
        subject=EMERGENCY_USERNAME,
        detail={"grant_id": grant.id},
    )
    if decision == "deny":
        grant.status = "denied"
        db.session.commit()
        return grant.to_dict()
    approvals = EmergencyApproval.query.filter(
        EmergencyApproval.grant_id == grant.id,
        EmergencyApproval.decision == "approve",
    ).all()
    distinct = {row.approver for row in approvals}
    if len(distinct) < EMERGENCY_APPROVALS_REQUIRED:
        db.session.commit()
        return grant.to_dict()
    policy = auth_settings()
    grant.status = "open"
    grant.opened_at = datetime.now()
    grant.expires_at = datetime.now() + timedelta(minutes=policy["emergency_window_minutes"])
    auth_event(
        "auth.emergency.opened",
        actor=approver,
        subject=EMERGENCY_USERNAME,
        detail={
            "grant_id": grant.id,
            "window_minutes": policy["emergency_window_minutes"],
        },
    )
    db.session.commit()
    return grant.to_dict()


def emergency_login(*, password: str, source_ip: str = "",
                    user_agent: str = "") -> Dict[str, Any]:
    """One login through the sealed credential while a grant is open and
    unexpired. Success seals a fresh random password (the used credential
    never works twice) and is alerted on the `auth` ledger."""
    user = User.query.filter(User.username == EMERGENCY_USERNAME).first()
    if user is None:
        raise Unauthorized("Emergency admin not initialised")
    grant = (
        EmergencyGrant.query.filter(EmergencyGrant.status == "open")
        .order_by(EmergencyGrant.created_at.desc())
        .first()
    )
    now = datetime.now()
    if grant is None or grant.expires_at is None or grant.expires_at <= now:
        if grant is not None and grant.status == "open":
            grant.status = "expired"
            db.session.commit()
        auth_event("auth.emergency.refused", actor=EMERGENCY_USERNAME,
                   subject=EMERGENCY_USERNAME, detail={"reason": "no-open-grant"})
        db.session.commit()
        raise Forbidden(
            "No open emergency grant - request and dual-approve one first",
            {"reason": "no-open-grant"},
        )
    sealed = user.password_hash
    plaintext = ""
    if sealed.startswith("sealed$"):
        try:
            plaintext = _unseal_emergency_password(json.loads(sealed[len("sealed$"):]))
        except Exception:
            plaintext = ""
    if not plaintext or not hmac.compare_digest(password or "", plaintext):
        auth_event("auth.emergency.refused", actor=EMERGENCY_USERNAME,
                   subject=EMERGENCY_USERNAME,
                   detail={"reason": "bad-password", "grant_id": grant.id})
        db.session.commit()
        raise Unauthorized("Emergency password incorrect")
    grant.status = "used"
    grant.used_at = now
    # rotate the seal: the used credential never works twice
    fresh = f"emg-{pysecrets.token_urlsafe(24)}"
    user.password_hash = "sealed$" + json.dumps(_seal_emergency_password(fresh))
    grant.rotated_at = datetime.now()
    auth_event(
        "auth.emergency.used",
        actor=EMERGENCY_USERNAME,
        subject=EMERGENCY_USERNAME,
        detail={"grant_id": grant.id, "rotated": True, "source_ip": source_ip[:64] if source_ip else ""},
    )
    db.session.commit()
    return mint_session(
        user, methods=["emergency"], source_ip=source_ip[:64],
        user_agent=user_agent, is_emergency=True,
    )


def ip(value: str) -> str:
    return (value or "")[:64]


def list_emergency_grants(*, limit: int = 50) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for grant in EmergencyGrant.query.order_by(EmergencyGrant.created_at.desc()).limit(limit).all():
        data = grant.to_dict()
        approvals = EmergencyApproval.query.filter(
            EmergencyApproval.grant_id == grant.id
        ).all()
        data["approvals"] = [row.to_dict() for row in approvals]
        out.append(data)
    return out


# ---------------------------------------------------------------------------
# auditor report (the `auth` trail summarised)
# ---------------------------------------------------------------------------
def auth_report(*, window_hours: int = 24, limit: int = 200) -> Dict[str, Any]:
    """Login-security report for auditors: counts per action plus the newest
    raw events from the `auth` ledger source (never any secret)."""
    since = datetime.now() - timedelta(hours=max(1, min(window_hours, 24 * 30)))
    rows = AuthEvent.query.filter(AuthEvent.created_at >= since).all()
    counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        counts[row.action] += 1
    newest = (
        AuthEvent.query.filter(AuthEvent.created_at >= since)
        .order_by(AuthEvent.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return {
        "window_hours": max(1, min(window_hours, 24 * 30)),
        "total_events": len(rows),
        "by_action": dict(sorted(counts.items())),
        "events": [row.to_dict() for row in newest],
    }
