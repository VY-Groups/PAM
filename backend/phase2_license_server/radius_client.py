"""RADIUS factor client (Addendum C - phase 7).

A real RFC 2865 Access-Request over UDP: the packet is built byte by byte
(Code/ID/Length, a CSPRNG Request Authenticator, User-Name and the
XOR-masked User-Password attribute) and the response is authenticated with
the Response Authenticator rule (MD5 over Code+ID+Length+RequestAuth+
Attributes+shared secret). Access-Accept passes the factor, Access-Reject
fails it, a timeout or a bad response authenticator is reported as an
honest 503 - never as a pass.

This is the wire a NPS / FreeRADIUS / Duo RADIUS endpoint speaks; the
settings group points at the real server. The shared secret is sealed at
rest like every other credential."""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from errors import ServiceUnavailable
from identity import auth_event
from models import MfaFactor, SettingGroup, User
from extensions import db

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
RADIUS_PORT_DEFAULT = 1812
RETRIES = 2


def radius_values() -> Dict[str, Any]:
    row = SettingGroup.query.filter(SettingGroup.group_name == "radius").first()
    values = dict(row.value) if row is not None and row.value else {}
    return {
        "enabled": bool(values.get("enabled", False)),
        "host": str(values.get("host", "") or "").strip(),
        "port": int(values.get("port", RADIUS_PORT_DEFAULT) or RADIUS_PORT_DEFAULT),
        "timeout_seconds": max(1, min(int(values.get("timeout_seconds", 5) or 5), 30)),
    }


def radius_secret() -> str:
    from service import unseal_setting_secret

    return unseal_setting_secret("radius", "secret")


def configured() -> bool:
    values = radius_values()
    return bool(values["enabled"] and values["host"] and radius_secret())


# ---------------------------------------------------------------------------
# packet build / parse (RFC 2865)
# ---------------------------------------------------------------------------
def _mask_password(password: str, secret: bytes, request_auth: bytes) -> bytes:
    plain = password.encode("utf-8")
    padded = plain + b"\x00" * (16 - len(plain) % 16 if len(plain) % 16 else 0)
    masked = b""
    prev = request_auth
    for offset in range(0, len(padded), 16):
        block = padded[offset : offset + 16]
        mask = hashlib.md5(secret + prev).digest()
        cipher = bytes(a ^ b for a, b in zip(block, mask))
        masked += cipher
        prev = cipher
    return masked


def build_access_request(
    username: str, password: str, secret: str, *, request_id: Optional[int] = None
) -> Tuple[bytes, bytes]:
    """One Access-Request packet + its Request Authenticator."""
    secret_bytes = secret.encode("utf-8")
    request_auth = os.urandom(16)
    rid = (request_id if request_id is not None else int.from_bytes(os.urandom(1), "big")) & 0xFF
    attributes = bytes([ATTR_USER_NAME, 2 + len(username.encode("utf-8"))]) + username.encode("utf-8")
    masked = _mask_password(password, secret_bytes, request_auth)
    attributes += bytes([ATTR_USER_PASSWORD, 2 + len(masked)]) + masked
    length = 20 + len(attributes)
    header = struct.pack(">BBH", ACCESS_REQUEST, rid, length) + request_auth
    return header + attributes, request_auth


def parse_response(
    data: bytes, request_auth: bytes, secret: str
) -> Tuple[Optional[int], str]:
    """(code, failure-reason). The response authenticator is verified
    first - a packet that does not authenticate is not even read."""
    if len(data) < 20:
        return None, "response shorter than the RADIUS header"
    code, _rid, length = struct.unpack(">BBH", data[:4])
    if length != len(data):
        return None, f"length field {length} does not match datagram {len(data)}"
    response_auth = data[4:20]
    attributes = data[20:]
    expected = hashlib.md5(
        bytes([code, _rid]) + struct.pack(">H", length) + request_auth + attributes
        + secret.encode("utf-8")
    ).digest()
    if response_auth != expected:
        return None, "response authenticator does not verify"
    return code, ""


def _exchange(username: str, password: str) -> Tuple[Optional[int], str]:
    """One request/response conversation against the configured server."""
    values = radius_values()
    secret = radius_secret()
    packet, request_auth = build_access_request(username, password, secret)
    last_error = "no response"
    for attempt in range(RETRIES):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(values["timeout_seconds"])
            sock.sendto(packet, (values["host"], values["port"]))
            data, _addr = sock.recvfrom(4096)
            code, reason = parse_response(data, request_auth, secret)
            if code is None:
                last_error = reason
                time.sleep(0.2)
                continue
            return code, ""
        except (socket.timeout, TimeoutError):
            last_error = f"no response within {values['timeout_seconds']}s"
        except OSError as exc:
            last_error = str(exc)
        finally:
            sock.close()
    return None, last_error


# ---------------------------------------------------------------------------
# factor verification
# ---------------------------------------------------------------------------
def verify_factor(user: User, code: str) -> bool:
    """Assert the `radius` factor: the user's code travels as the RADIUS
    User-Password (the standard push/OTP-over-RADIUS pattern). Unconfigured
    -> honest 503; Accept -> True; Reject/bad response -> False."""
    if not configured():
        raise ServiceUnavailable(
            "RADIUS is not configured - set host, port and the shared secret "
            "in the `radius` settings group and enable it first",
            {"configured": False},
        )
    factor = MfaFactor.query.filter(
        MfaFactor.user_id == user.id,
        MfaFactor.kind == "radius",
        MfaFactor.active.is_(True),
    ).first()
    if factor is None or not isinstance(code, str) or not code.strip():
        return False
    remote_code, reason = _exchange(user.username, code.strip())
    if remote_code == ACCESS_ACCEPT:
        factor.last_used_at = datetime.now()
        db.session.commit()
        return True
    if remote_code is None:
        auth_event(
            "auth.mfa.radius-unreachable",
            actor=user.username,
            subject=user.username,
            detail={"error": reason[:200]},
        )
        db.session.commit()
        raise ServiceUnavailable(
            f"RADIUS server unreachable: {reason}", {"provider_error": reason[:200]}
        )
    auth_event(
        "auth.mfa.failed",
        actor=user.username,
        subject=user.username,
        detail={"kind": "radius", "reason": "reject"},
    )
    db.session.commit()
    return False


def enroll_radius(user: User, *, actor: str) -> Dict[str, Any]:
    """Enrol the RADIUS factor (the push/OTP code arrives out of band on
    the authenticator app the RADIUS server owns)."""
    if not configured():
        raise ServiceUnavailable(
            "RADIUS is not configured - set host, port and the shared secret "
            "in the `radius` settings group and enable it first",
            {"configured": False},
        )
    from models import MfaFactor as _MfaFactor

    factor = _MfaFactor.query.filter(
        _MfaFactor.user_id == user.id, _MfaFactor.kind == "radius"
    ).first()
    if factor is None:
        factor = _MfaFactor(user_id=user.id, kind="radius", name="RADIUS push/OTP")
        db.session.add(factor)
    factor.active = True
    auth_event(
        "auth.mfa.enrolled",
        actor=actor or user.username,
        subject=user.username,
        detail={"kind": "radius", "factor_id": factor.id},
    )
    db.session.commit()
    return factor.to_dict()
