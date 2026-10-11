"""SCIM 2.0 lifecycle sync (Addendum C - phase 7).

The identity provider drives joiner-mover-leaver through a real SCIM 2.0
surface: `Users` (create / read / replace / PATCH / deactivate) and
`Groups` (membership the provider owns). Deactivation is immediate and
real - every live console session of that user is revoked in the same
transaction and the `auth` trail records it.

SCIM users are `source=scim` rows: password login is refused for them
(the IdP owns the credential), and privilege still only ever comes from a
role binding. Requests authenticate with a bearer token minted once by
`POST /api/v1/settings/scim/rotate` (sha256 at rest); the SCIM error body
follows RFC 7644 §3.12."""
from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from errors import APIError, ValidationFailed
from extensions import db
from identity import auth_event, _revoke_all_sessions
from models import ScimGroup, SettingGroup, User


class ScimError(APIError):
    """RFC 7644 error body (schemas/status/detail)."""

    def __init__(self, status: int, detail: str):
        super().__init__(status, detail)
        self.details = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(status),
            "detail": detail,
        }


# ---------------------------------------------------------------------------
# settings + token
# ---------------------------------------------------------------------------
def scim_values() -> Dict[str, Any]:
    row = SettingGroup.query.filter(SettingGroup.group_name == "scim").first()
    values = dict(row.value) if row is not None and row.value else {}
    return {
        "enabled": bool(values.get("enabled", False)),
        "token_sha256": str(values.get("token_sha256", "") or ""),
    }


def rotate_token() -> str:
    """Mint a fresh SCIM bearer token (shown exactly once; only its
    sha256 is stored, in the settings row, through the same internal
    writer the MFA factor endpoint uses)."""
    from service import _persist_settings, _settings_row

    token = f"vypam-scim1.{pysecrets.token_urlsafe(24)}"
    had = bool(_settings_row("scim")["values"].get("token_sha256"))
    _persist_settings(
        "scim",
        {
            "token_sha256": {"old": "<set>" if had else "", "new": "<set>"},
        },
        {
            "enabled": True,
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        },
        "scim-rotate",
    )
    auth_event(
        "auth.scim.token-rotated",
        actor="system",
        subject="scim",
        detail={},
    )
    db.session.commit()
    return token


def verify_token(presented: Optional[str]) -> bool:
    """Constant-time check of the presented SCIM bearer token."""
    values = scim_values()
    if not values["enabled"] or not values["token_sha256"] or not presented:
        return False
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, values["token_sha256"])


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def _scim_user(user: User, *, base_url: str = "/scim/v2") -> Dict[str, Any]:
    name_parts = (user.display_name or user.username).split(" ", 1)
    payload: Dict[str, Any] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "externalId": "",
        "userName": user.username,
        "name": {
            "formatted": user.display_name,
            "givenName": name_parts[0] if name_parts else "",
            "familyName": name_parts[1] if len(name_parts) > 1 else "",
        },
        "displayName": user.display_name,
        "active": bool(user.is_active),
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat(),
            "lastModified": (user.password_changed_at or user.created_at).isoformat(),
            "location": f"{base_url}/Users/{user.id}",
        },
    }
    if user.email:
        payload["emails"] = [{"value": user.email, "primary": True, "type": "work"}]
    return payload


def list_users(*, start_index: int = 1, count: int = 100,
               user_name: str = "") -> Dict[str, Any]:
    query = User.query.filter(User.source == "scim")
    if user_name:
        query = query.filter(User.username == str(user_name).strip().lower())
    total = query.count()
    start = max(1, start_index)
    rows = query.order_by(User.username).offset(start - 1).limit(max(1, min(count, 200))).all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(rows),
        "Resources": [_scim_user(row) for row in rows],
    }


def get_user(scim_id: str) -> Dict[str, Any]:
    user = _find(scim_id)
    return _scim_user(user)


def _find(scim_id: str) -> User:
    if not str(scim_id).isdigit():
        raise ScimError(404, f"Unknown user id {scim_id}")
    user = db.session.get(User, int(scim_id))
    if user is None or user.source != "scim":
        raise ScimError(404, f"Unknown user id {scim_id}")
    return user


def _extract(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict) or not str(payload.get("userName") or "").strip():
        raise ScimError(400, "userName is required")
    name = payload.get("name") or {}
    emails = payload.get("emails") or []
    email = ""
    for entry in emails:
        if isinstance(entry, dict) and entry.get("primary") and entry.get("value"):
            email = str(entry["value"])
            break
    if not email and emails and isinstance(emails[0], dict):
        email = str(emails[0].get("value") or "")
    display = str(payload.get("displayName") or "").strip()
    if not display and isinstance(name, dict):
        given = str(name.get("givenName") or "")
        family = str(name.get("familyName") or "")
        display = f"{given} {family}".strip()
    return {
        "userName": str(payload["userName"]).strip().lower(),
        "email": email.strip()[:255],
        "display_name": display[:128],
        "active": bool(payload.get("active", True)),
    }


def create_user(payload: Dict[str, Any], *, actor: str = "scim") -> Dict[str, Any]:
    fields = _extract(payload)
    from identity import _normalize_username

    try:
        username = _normalize_username(fields["userName"])
    except ValidationFailed as exc:
        raise ScimError(400, exc.message) from exc
    if User.query.filter(User.username == username).first() is not None:
        raise ScimError(409, f"User {username} already exists")
    user = User(
        username=username,
        email=fields["email"],
        display_name=fields["display_name"] or username,
        password_hash="",  # provider-managed: no local password exists
        source="scim",
        is_active=fields["active"],
        created_by=actor[:64],
    )
    db.session.add(user)
    db.session.flush()
    auth_event(
        "auth.scim.user-created",
        actor=actor,
        subject=username,
        detail={"scim_id": user.id},
    )
    db.session.commit()
    return _scim_user(user)


def replace_user(scim_id: str, payload: Dict[str, Any], *, actor: str = "scim") -> Dict[str, Any]:
    user = _find(scim_id)
    fields = _extract(payload)
    changed: Dict[str, Any] = {}
    if fields["email"] and fields["email"] != user.email:
        user.email = fields["email"]
        changed["email"] = True
    if fields["display_name"] and fields["display_name"] != user.display_name:
        user.display_name = fields["display_name"]
        changed["display_name"] = True
    if fields["active"] != user.is_active:
        changed["active"] = _set_active(user, fields["active"])
    auth_event("auth.scim.user-updated", actor=actor, subject=user.username,
               detail=changed)
    db.session.commit()
    return _scim_user(user)


def patch_user(scim_id: str, payload: Dict[str, Any], *, actor: str = "scim") -> Dict[str, Any]:
    """RFC 7644 PATCH: `replace` operations for active / displayName /
    emails (the offboarding path is `active: false`)."""
    user = _find(scim_id)
    operations = payload.get("Operations") or payload.get("operations") or []
    if not isinstance(operations, list) or not operations:
        raise ScimError(400, "PATCH requires at least one operation")
    changed: Dict[str, Any] = {}
    for operation in operations:
        if not isinstance(operation, dict) or str(operation.get("op", "")).lower() != "replace":
            raise ScimError(400, "Only 'replace' operations are supported")
        value = operation.get("value")
        if not isinstance(value, dict):
            raise ScimError(400, "Operation value must be an object")
        if "active" in value:
            changed["active"] = _set_active(user, bool(value["active"]))
        if "displayName" in value:
            user.display_name = str(value["displayName"]).strip()[:128] or user.username
            changed["display_name"] = True
        if "emails" in value:
            emails = value["emails"]
            if isinstance(emails, list) and emails and isinstance(emails[0], dict):
                user.email = str(emails[0].get("value") or "")[:255]
                changed["email"] = True
    auth_event("auth.scim.user-patched", actor=actor, subject=user.username,
               detail=changed)
    db.session.commit()
    return _scim_user(user)


def _set_active(user: User, active: bool) -> Dict[str, Any]:
    user.is_active = bool(active)
    if not user.is_active:
        revoked = _revoke_all_sessions(user, reason="scim-deactivated")
        return {"is_active": False, "sessions_revoked": revoked}
    return {"is_active": True}


def delete_user(scim_id: str, *, actor: str = "scim") -> None:
    """SCIM DELETE = deactivate (the row stays as evidence)."""
    user = _find(scim_id)
    result = _set_active(user, False)
    auth_event(
        "auth.scim.user-deactivated",
        actor=actor,
        subject=user.username,
        detail={"scim_id": user.id, "sessions_revoked": result.get("sessions_revoked", 0)},
    )
    db.session.commit()


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------
def list_groups(*, start_index: int = 1, count: int = 100) -> Dict[str, Any]:
    total = ScimGroup.query.count()
    start = max(1, start_index)
    rows = ScimGroup.query.order_by(ScimGroup.display_name).offset(start - 1).limit(
        max(1, min(count, 200))
    ).all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(rows),
        "Resources": [_scim_group(row) for row in rows],
    }


def _scim_group(group: ScimGroup) -> Dict[str, Any]:
    members = []
    for username in group.members or []:
        user = User.query.filter(User.username == username).first()
        members.append({"value": str(user.id) if user else "", "display": username})
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": group.scim_id,
        "displayName": group.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": group.created_at.isoformat(),
            "lastModified": (group.updated_at or group.created_at).isoformat(),
        },
    }


def create_group(payload: Dict[str, Any], *, actor: str = "scim") -> Dict[str, Any]:
    display = str((payload or {}).get("displayName") or "").strip()
    if not display:
        raise ScimError(400, "displayName is required")
    members = _member_names(payload.get("members"))
    group = ScimGroup(
        scim_id=f"grp-{pysecrets.token_hex(8)}",
        display_name=display[:128],
        members=members,
        updated_at=datetime.now(),
    )
    db.session.add(group)
    db.session.flush()
    auth_event("auth.scim.group-created", actor=actor, subject=display[:128],
               detail={"scim_id": group.scim_id, "members": len(members)})
    db.session.commit()
    return _scim_group(group)


def _member_names(raw: Any) -> List[str]:
    names: List[str] = []
    if isinstance(raw, list):
        for entry in raw:
            display = str(entry.get("display") or "") if isinstance(entry, dict) else str(entry)
            value = str(entry.get("value") or "") if isinstance(entry, dict) else ""
            if display:
                names.append(display.strip().lower())
            elif value.isdigit():
                user = db.session.get(User, int(value))
                if user is not None:
                    names.append(user.username)
    return sorted(set(names))


def get_group(scim_id: str) -> Dict[str, Any]:
    group = ScimGroup.query.filter(ScimGroup.scim_id == str(scim_id)).first()
    if group is None:
        raise ScimError(404, f"Unknown group {scim_id}")
    return _scim_group(group)


def replace_group(scim_id: str, payload: Dict[str, Any], *, actor: str = "scim") -> Dict[str, Any]:
    group = ScimGroup.query.filter(ScimGroup.scim_id == str(scim_id)).first()
    if group is None:
        raise ScimError(404, f"Unknown group {scim_id}")
    display = str((payload or {}).get("displayName") or "").strip()
    if display:
        group.display_name = display[:128]
    if "members" in (payload or {}):
        group.members = _member_names(payload.get("members"))
    group.updated_at = datetime.now()
    auth_event("auth.scim.group-updated", actor=actor, subject=group.display_name,
               detail={"scim_id": group.scim_id, "members": len(group.members or [])})
    db.session.commit()
    return _scim_group(group)
