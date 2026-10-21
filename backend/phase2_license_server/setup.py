"""First-run setup (ADR-0018): the two bootstrap officers, the instance
profile and the one-way completion.

The install ships with exactly two identities - `vypam-maker` and
`vypam-checker` (maker-checker: two humans, two passwords, neither one
alone finishes setup). They are created on the first boot of an instance
that has never completed setup and has no other console identity (the
sealed emergency admin grants nothing, so it does not count); each is
bound to the admin role through the ordinary kind:user binding, each
carries the forced-change-at-sign-in flag, and their generated passwords
are printed to the server log exactly once.

While setup runs, the instance belongs to those two officers alone: they
set the company profile here and configure SMTP and the company's admins
through the existing admin surface, then `POST /api/v1/setup/complete`
verifies BOTH passwords in one request before `setup_completed_at` is
stamped - after which the completion answers 409 forever and the two
officers keep working as ordinary admins.
"""
from __future__ import annotations

import base64
import binascii
import logging
from datetime import datetime
from typing import Any, Dict, Optional

import service
from errors import Conflict, Unauthorized, ValidationFailed
from extensions import db
from identity import (
    EMERGENCY_USERNAME,
    auth_event,
    create_user,
    get_user,
    verify_password,
)
from models import InstanceProfile, User

logger = logging.getLogger(__name__)

BOOTSTRAP_MAKER = "vypam-maker"
BOOTSTRAP_CHECKER = "vypam-checker"
BOOTSTRAP_OFFICERS = (BOOTSTRAP_MAKER, BOOTSTRAP_CHECKER)

# The logo is display data that reaches every signed-out page: bounded to
# a PNG/JPEG data URI of at most 64 KB decoded (ADR-0018 Decision 2).
MAX_LOGO_BYTES = 64 * 1024
_LOGO_PREFIXES = ("data:image/png;base64,", "data:image/jpeg;base64,")


def instance_configured() -> bool:
    """True once the two officers attested and the one-way stamp is set;
    no profile row yet means a virgin install - never configured."""
    row = db.session.get(InstanceProfile, 1)
    return row is not None and row.setup_completed_at is not None


def ensure_bootstrap_officers() -> Optional[Dict[str, str]]:
    """First boot only (ADR-0018 Decision 1): create the two bootstrap
    officers - admin-role bound, forced-change at first sign-in - when
    setup has never completed and no console identity exists yet besides
    the sealed emergency admin. Returns {username: generated_password}
    for the boot log, or None when there is nothing to create: an
    existing officer pair, any other user, or a completed instance all
    mean the same thing - leave the state alone."""
    if instance_configured():
        return None
    if User.query.filter(User.username != EMERGENCY_USERNAME).first() is not None:
        return None
    plaintexts: Dict[str, str] = {}
    for username, display_name in (
        (BOOTSTRAP_MAKER, "VY-PAM maker officer"),
        (BOOTSTRAP_CHECKER, "VY-PAM checker officer"),
    ):
        _, generated = create_user(
            username=username,
            actor="system:bootstrap",
            display_name=display_name,
            must_change_password=True,
        )
        plaintexts[username] = generated
        service.create_role_binding(
            {"principal": username, "role": "admin", "kind": "user"},
            actor="system:bootstrap",
        )
    auth_event(
        "auth.bootstrap.created",
        actor="system:bootstrap",
        subject="setup",
        detail={"officers": list(BOOTSTRAP_OFFICERS), "role": "admin"},
    )
    db.session.commit()
    logger.warning(
        "First boot: VY-PAM bootstrap officers created - "
        "Shown once - store it now.\n"
        "  maker   %s: %s\n"
        "  checker %s: %s\n"
        "Sign in as either officer, change both passwords, then finish setup "
        "with POST /api/v1/setup/complete - it needs both passwords.",
        BOOTSTRAP_MAKER,
        plaintexts[BOOTSTRAP_MAKER],
        BOOTSTRAP_CHECKER,
        plaintexts[BOOTSTRAP_CHECKER],
    )
    return plaintexts


def setup_state() -> Dict[str, Any]:
    """The public first-run state for the login card and the /setup
    wizard: the branding this instance presents, whether the wizard is
    still open, whether SMTP has a host, and who the two officers are.
    No password field ever appears here, whoever asks."""
    row = db.session.get(InstanceProfile, 1)
    smtp = service.get_settings()["smtp"]["values"]
    return {
        "configured": row is not None and row.setup_completed_at is not None,
        "company_name": row.company_name if row is not None else "",
        "logo_data_uri": row.logo_data_uri if row is not None else "",
        "contact_email": row.contact_email if row is not None else "",
        "smtp_configured": bool(smtp.get("enabled")) and bool(smtp.get("host")),
        "bootstrap": {"maker": BOOTSTRAP_MAKER, "checker": BOOTSTRAP_CHECKER},
    }


def update_profile(payload: Any, *, actor: str) -> Dict[str, Any]:
    """Write the instance profile (partial update; `company_name` may
    never end up blank, `logo_data_uri` is a bounded PNG/JPEG data URI or
    "" to clear). A write that changes nothing records nothing - the
    settings-group no-op rule, kept here. Returns the fresh state."""
    if not isinstance(payload, dict):
        raise ValidationFailed(
            "Body must be an object with company_name / logo_data_uri / "
            "contact_email"
        )
    allowed = {"company_name", "logo_data_uri", "contact_email"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValidationFailed(
            "Unknown field(s) in instance profile",
            {"fields": unknown, "allowed": sorted(allowed)},
        )
    if not payload:
        raise ValidationFailed(
            "Provide at least one profile field", {"allowed": sorted(allowed)}
        )
    row = db.session.get(InstanceProfile, 1)
    if row is None:
        row = InstanceProfile(id=1)
        db.session.add(row)
    changed: Dict[str, Any] = {}
    if "company_name" in payload:
        name = str(payload.get("company_name") or "").strip()
        if not 1 <= len(name) <= 128:
            raise ValidationFailed(
                "company_name must be 1-128 characters",
                {"field": "company_name"},
            )
        if name != row.company_name:
            row.company_name = name
            changed["company_name"] = name
    if "contact_email" in payload:
        email = str(payload.get("contact_email") or "").strip()[:255]
        if email != row.contact_email:
            row.contact_email = email
            changed["contact_email"] = email
    if "logo_data_uri" in payload:
        logo = str(payload.get("logo_data_uri") or "")
        if logo:
            if not logo.startswith(_LOGO_PREFIXES):
                raise ValidationFailed(
                    "Logo must be a data:image/png or data:image/jpeg "
                    "base64 URI",
                    {"field": "logo_data_uri"},
                )
            body = logo[len(next(p for p in _LOGO_PREFIXES if logo.startswith(p))):]
            try:
                raw = base64.b64decode(body, validate=True)
            except (binascii.Error, ValueError):
                raise ValidationFailed(
                    "Logo base64 payload is not decodable",
                    {"field": "logo_data_uri"},
                ) from None
            if len(raw) > MAX_LOGO_BYTES:
                raise ValidationFailed(
                    "Logo must be at most 64 KB decoded",
                    {"field": "logo_data_uri", "max_bytes": MAX_LOGO_BYTES},
                )
        if logo != row.logo_data_uri:
            row.logo_data_uri = logo
            changed["logo_data_uri"] = len(logo)
    if not row.company_name.strip():
        # never let a profile write leave the instance nameless - the
        # wizard's first step exists exactly to fill it
        raise ValidationFailed(
            "company_name is required", {"field": "company_name"}
        )
    if not changed:
        return setup_state()
    row.updated_at = datetime.now()
    row.updated_by = actor[:64]
    auth_event(
        "setup.profile.updated",
        actor=actor,
        subject="instance",
        detail={"fields": sorted(changed), "company_name": row.company_name},
    )
    db.session.commit()
    return setup_state()


def complete(*, maker_password: str, checker_password: str) -> Dict[str, Any]:
    """The two-officer attestation (ADR-0018 Decision 2): BOTH bootstrap
    passwords verified against their rows in one request. Either wrong
    answers the uniform login 401 - no oracle for which one failed - and
    a completed instance answers 409 forever (the stamp is one-way)."""
    if instance_configured():
        raise Conflict("Setup already completed")
    maker = get_user(BOOTSTRAP_MAKER)
    checker = get_user(BOOTSTRAP_CHECKER)
    ok = (
        maker is not None
        and checker is not None
        and verify_password(str(maker_password or ""), maker.password_hash)
        and verify_password(str(checker_password or ""), checker.password_hash)
    )
    if not ok:
        # the same bytes the login path answers with: wrong password and
        # missing officer are never distinguishable from outside
        raise Unauthorized("Invalid username or password")
    row = db.session.get(InstanceProfile, 1)
    if row is None:
        row = InstanceProfile(id=1)
        db.session.add(row)
    row.setup_completed_at = datetime.now()
    row.updated_by = f"{BOOTSTRAP_MAKER}+{BOOTSTRAP_CHECKER}"
    auth_event(
        "setup.completed",
        actor=f"{BOOTSTRAP_MAKER}+{BOOTSTRAP_CHECKER}",
        subject="setup",
        detail={
            "maker": BOOTSTRAP_MAKER,
            "checker": BOOTSTRAP_CHECKER,
            "company_name": row.company_name,
        },
    )
    db.session.commit()
    return {"message": "Setup completed - sign in with your company admins"}
