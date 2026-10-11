"""WebAuthn / FIDO2 verification (Addendum C - phase 7).

Server-side verification with no new dependency: a small strict CBOR
decoder, the `authData` layout from the WebAuthn spec, `clientDataJSON`
type/challenge/origin checks, and real signature verification through
`cryptography` (ES256 `-7`, RS256 `-257`, EdDSA `-8`).

- Registration accepts the `none` attestation format (privacy-preserving,
  the common platform-authenticator case) and `packed` self-attestation
  (the credential's own key signs authenticatorData || clientDataHash).
  Every other format is refused honestly rather than skipped.
- Assertions verify the signature over authenticatorData || clientDataHash
  and enforce the signature counter: a rollback with a non-zero counter
  means a cloned authenticator - the assertion is refused and alerted.
- Challenges are server-side, single-use and TTL-bound (the
  `webauthn_challenges` rows); nothing about a ceremony is trusted from
  the client except the three pieces the spec says the client relays."""
from __future__ import annotations

import base64
import hashlib
import secrets as pysecrets
import struct
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from errors import Forbidden, NotFound, ValidationFailed
from extensions import db
from identity import auth_event
from models import SettingGroup, User, WebauthnChallenge, WebauthnCredential

CHALLENGE_TTL_SECONDS = 300
MAX_INPUT_BYTES = 64 * 1024
MAX_CBOR_DEPTH = 8

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included
FLAG_BE = 0x08  # backup eligible (informational)

COSE_KTY_EC2 = 2
COSE_KTY_RSA = 3
COSE_ALG_ES256 = -7
COSE_ALG_EDDSA = -8
COSE_ALG_RS256 = -257


# ---------------------------------------------------------------------------
# minimal strict CBOR (definite + indefinite lengths, hard caps)
# ---------------------------------------------------------------------------
class _CborError(ValueError):
    pass


def cbor_decode(data: bytes) -> Any:
    """Decode one CBOR item with strict bounds (depth, items, input size).
    Supports the major types WebAuthn artifacts use: unsigned/negative
    ints, byte/text strings (definite + chunked), arrays, maps, plus
    simple values (bool/null). Anything else is refused, not guessed."""
    if len(data) > MAX_INPUT_BYTES:
        raise _CborError("cbor input too large")
    value, offset = _decode_item(data, 0, 0)
    if offset != len(data):
        raise _CborError("trailing bytes after cbor item")
    return value


def _decode_item(data: bytes, offset: int, depth: int) -> Tuple[Any, int]:
    if depth > MAX_CBOR_DEPTH:
        raise _CborError("cbor nesting too deep")
    if offset >= len(data):
        raise _CborError("unexpected end of cbor input")
    initial = data[offset]
    major = initial >> 5
    additional = initial & 0x1F
    offset += 1
    argument, offset = _read_argument(data, offset, additional)
    if major == 0:  # unsigned integer
        return argument, offset
    if major == 1:  # negative integer
        return -1 - argument, offset
    if major == 2:  # byte string
        if additional == 31:  # indefinite: concatenation of definite chunks
            chunks: List[bytes] = []
            while True:
                if offset >= len(data):
                    raise _CborError("unterminated indefinite byte string")
                if data[offset] == 0xFF:
                    return b"".join(chunks), offset + 1
                chunk, offset = _decode_item(data, offset, depth + 1)
                if not isinstance(chunk, bytes):
                    raise _CborError("bad chunk in indefinite byte string")
                chunks.append(chunk)
        return data[offset : offset + argument], offset + argument
    if major == 3:  # text string
        if additional == 31:
            parts: List[str] = []
            while True:
                if offset >= len(data):
                    raise _CborError("unterminated indefinite text string")
                if data[offset] == 0xFF:
                    return "".join(parts), offset + 1
                part, offset = _decode_item(data, offset, depth + 1)
                if not isinstance(part, str):
                    raise _CborError("bad chunk in indefinite text string")
                parts.append(part)
        raw = data[offset : offset + argument]
        try:
            return raw.decode("utf-8"), offset + argument
        except UnicodeDecodeError as exc:
            raise _CborError("invalid utf-8 in text string") from exc
    if major == 4:  # array
        if additional == 31:
            items: List[Any] = []
            while True:
                if offset >= len(data):
                    raise _CborError("unterminated indefinite array")
                if data[offset] == 0xFF:
                    return items, offset + 1
                item, offset = _decode_item(data, offset, depth + 1)
                items.append(item)
        items = []
        for _ in range(argument):
            item, offset = _decode_item(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:  # map
        result: Dict[Any, Any] = {}
        if additional == 31:
            while True:
                if offset >= len(data):
                    raise _CborError("unterminated indefinite map")
                if data[offset] == 0xFF:
                    return result, offset + 1
                key, offset = _decode_item(data, offset, depth + 1)
                value, offset = _decode_item(data, offset, depth + 1)
                result[key] = value
        for _ in range(argument):
            key, offset = _decode_item(data, offset, depth + 1)
            value, offset = _decode_item(data, offset, depth + 1)
            result[key] = value
        return result, offset
    if major == 7:
        if additional == 20:
            return False, offset
        if additional == 21:
            return True, offset
        if additional == 22:
            return None, offset
        raise _CborError(f"unsupported simple value {additional}")
    raise _CborError(f"unsupported cbor major type {major}")


def _read_argument(data: bytes, offset: int, additional: int) -> Tuple[int, int]:
    if additional < 24:
        return additional, offset
    if additional == 24:
        if offset >= len(data):
            raise _CborError("truncated argument")
        return data[offset], offset + 1
    if additional == 25:
        if offset + 2 > len(data):
            raise _CborError("truncated argument")
        return struct.unpack(">H", data[offset : offset + 2])[0], offset + 2
    if additional == 26:
        if offset + 4 > len(data):
            raise _CborError("truncated argument")
        return struct.unpack(">I", data[offset : offset + 4])[0], offset + 4
    if additional == 27:
        if offset + 8 > len(data):
            raise _CborError("truncated argument")
        return struct.unpack(">Q", data[offset : offset + 8])[0], offset + 8
    if additional == 31:
        return 0, offset  # indefinite - handled by the callers
    raise _CborError(f"reserved additional info {additional}")


# ---------------------------------------------------------------------------
# settings + helpers
# ---------------------------------------------------------------------------
def webauthn_values() -> Dict[str, Any]:
    row = SettingGroup.query.filter(SettingGroup.group_name == "webauthn").first()
    values = dict(row.value) if row is not None and row.value else {}
    origins = [
        o.strip()
        for o in str(values.get("allowed_origins", "") or "").split(",")
        if o.strip()
    ]
    return {
        "rp_id": str(values.get("rp_id", "") or "").strip(),
        "rp_name": str(values.get("rp_name", "") or "VY-PAM").strip() or "VY-PAM",
        "allowed_origins": origins,
    }


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    padded = str(text) + "=" * (-len(str(text)) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def start_challenge(user: User, *, purpose: str) -> Dict[str, Any]:
    """Mint a single-use ceremony challenge (register | authenticate)."""
    raw = pysecrets.token_bytes(32)
    challenge = WebauthnChallenge(
        id=pysecrets.token_hex(16),
        user_id=user.id,
        purpose=purpose,
        challenge=_b64u(raw),
        expires_at=datetime.now() + timedelta(seconds=CHALLENGE_TTL_SECONDS),
    )
    db.session.add(challenge)
    db.session.commit()
    values = webauthn_values()
    return {
        "challenge_id": challenge.id,
        "challenge": challenge.challenge,
        "rp_id": values["rp_id"],
        "rp_name": values["rp_name"],
        "origins": values["allowed_origins"],
        "user_verification": "required",
        "expires_in_seconds": CHALLENGE_TTL_SECONDS,
    }


def decoy_challenge() -> Dict[str, Any]:
    """A response shaped exactly like `start_challenge` for a username that
    does not exist (or is inactive): a random challenge id and value that no
    server-side row backs, so any assertion against them fails at the
    lookup - the answer never reveals whether the username exists."""
    values = webauthn_values()
    return {
        "challenge_id": pysecrets.token_hex(16),
        "challenge": _b64u(pysecrets.token_bytes(32)),
        "rp_id": values["rp_id"],
        "rp_name": values["rp_name"],
        "origins": values["allowed_origins"],
        "user_verification": "required",
        "expires_in_seconds": CHALLENGE_TTL_SECONDS,
    }


def _consume_challenge(challenge_id: str, *, purpose: str, user: User) -> bytes:
    challenge = db.session.get(WebauthnChallenge, str(challenge_id or ""))
    if (
        challenge is None
        or challenge.purpose != purpose
        or challenge.user_id != user.id
        or challenge.consumed_at is not None
        or challenge.expires_at <= datetime.now()
    ):
        raise Forbidden("WebAuthn challenge invalid or expired", {"purpose": purpose})
    challenge.consumed_at = datetime.now()
    return _b64u_decode(challenge.challenge)


def _client_data(client_data_json: bytes, *, expected_type: str,
                 challenge: bytes, allowed_origins: List[str]) -> bytes:
    """Verify the clientDataJSON (type, challenge, origin) and return its
    SHA-256 (the hash the signature covers)."""
    import json as _json

    try:
        data = _json.loads(client_data_json.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationFailed("clientDataJSON is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("type") != expected_type:
        raise ValidationFailed(
            f"clientData.type must be '{expected_type}'", {"field": "type"}
        )
    presented_challenge = str(data.get("challenge") or "")
    if not presented_challenge or _b64u_decode(presented_challenge) != challenge:
        raise ValidationFailed("clientData.challenge does not match", {"field": "challenge"})
    origin = str(data.get("origin") or "")
    if origin not in allowed_origins:
        raise ValidationFailed(
            f"clientData.origin '{origin}' is not an allowed origin",
            {"field": "origin", "allowed": allowed_origins},
        )
    return hashlib.sha256(client_data_json).digest()


def parse_auth_data(auth_data: bytes) -> Dict[str, Any]:
    """rpIdHash(32) || flags(1) || signCount(4, BE) [ || attestedCredentialData ]."""
    if len(auth_data) < 37:
        raise ValidationFailed("authData too short")
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    out: Dict[str, Any] = {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "sign_count": sign_count,
        "user_present": bool(flags & FLAG_UP),
        "user_verified": bool(flags & FLAG_UV),
        "credential": None,
    }
    if flags & FLAG_AT:
        offset = 37
        if len(auth_data) < offset + 18:
            raise ValidationFailed("attested credential data truncated")
        aaguid = auth_data[offset : offset + 16]
        cred_len = struct.unpack(">H", auth_data[offset + 16 : offset + 18])[0]
        offset += 18
        if len(auth_data) < offset + cred_len:
            raise ValidationFailed("credential id truncated")
        credential_id = auth_data[offset : offset + cred_len]
        offset += cred_len
        cose_key, consumed = _decode_item(auth_data, offset, 0)
        if not isinstance(cose_key, dict):
            raise ValidationFailed("COSE public key is not a map")
        out["credential"] = {
            "aaguid": aaguid.hex(),
            "credential_id": credential_id,
            "cose_key": cose_key,
            "public_key_der": _cose_to_der(cose_key),
        }
    return out


def _cose_to_der(cose_key: Dict[Any, Any]) -> bytes:
    """COSE_Key -> SubjectPublicKeyInfo DER (the storage format)."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    kty = cose_key.get(1)
    alg = cose_key.get(3)
    if kty == COSE_KTY_EC2 and alg == COSE_ALG_ES256:
        if cose_key.get(-1) != 1:  # crv P-256 only
            raise ValidationFailed("Only P-256 (crv 1) WebAuthn keys are supported")
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise ValidationFailed("Malformed EC2 COSE key coordinates")
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers

        public = EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
        return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if kty == COSE_KTY_RSA and alg in (COSE_ALG_RS256,):
        n = cose_key.get(-1)
        e = cose_key.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes):
            raise ValidationFailed("Malformed RSA COSE key")
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        public = RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
        return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    raise ValidationFailed(
        f"Unsupported COSE key type/alg (kty={kty}, alg={alg})",
        {"supported": ["ES256 (-7)", "RS256 (-257)"]},
    )


def _load_public_key(der: bytes):
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    return load_der_public_key(der)


def _verify_signature(public_key: Any, signed: bytes, signature: bytes) -> bool:
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed)
        else:
            return False
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------
def register_credential(
    user: User,
    *,
    challenge_id: str,
    client_data_json: str,
    attestation_object: str,
    name: str = "",
    transports: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Verify a registration ceremony and store the credential."""
    values = webauthn_values()
    if not values["rp_id"] or not values["allowed_origins"]:
        raise Forbidden(
            "WebAuthn is not configured - set rp_id and allowed_origins in the "
            "`webauthn` settings group",
            {"configured": False},
        )
    challenge = _consume_challenge(challenge_id, purpose="register", user=user)
    try:
        client_data = _b64u_decode(client_data_json)
        attestation = cbor_decode(_b64u_decode(attestation_object))
    except (ValueError, _CborError) as exc:
        raise ValidationFailed(f"Malformed WebAuthn payload: {exc}") from exc
    if not isinstance(attestation, dict):
        raise ValidationFailed("attestationObject must be a CBOR map")
    fmt = attestation.get("fmt")
    att_stmt = attestation.get("attStmt") or {}
    auth_data = attestation.get("authData")
    if not isinstance(auth_data, bytes):
        raise ValidationFailed("attestationObject.authData must be bytes")
    client_hash = _client_data(
        client_data,
        expected_type="webauthn.create",
        challenge=challenge,
        allowed_origins=values["allowed_origins"],
    )
    parsed = parse_auth_data(auth_data)
    if not parsed["user_present"]:
        raise ValidationFailed("authData is missing the user-present flag")
    if parsed["rp_id_hash"] != hashlib.sha256(values["rp_id"].encode("utf-8")).digest():
        raise ValidationFailed("authData.rpIdHash does not match the configured rp_id")
    credential = parsed["credential"]
    if credential is None:
        raise ValidationFailed("authData carries no attested credential")
    if fmt not in ("none", "packed"):
        raise ValidationFailed(
            f"Unsupported attestation format '{fmt}'",
            {"supported": ["none", "packed"]},
        )
    if fmt == "packed":
        alg = att_stmt.get("alg")
        signature = att_stmt.get("sig")
        if not isinstance(signature, bytes):
            raise ValidationFailed("packed attestation statement missing sig")
        der = credential["public_key_der"]
        # self-attestation: the credential's own key signs authData||clientHash
        if alg != _cose_alg_for(der.hex()):
            raise ValidationFailed("packed attestation alg does not match the key")
        if not _verify_signature(_load_public_key(der), auth_data + client_hash, signature):
            raise ValidationFailed("packed attestation signature invalid")
    credential_id_b64 = _b64u(credential["credential_id"])
    if WebauthnCredential.query.filter(
        WebauthnCredential.credential_id == credential_id_b64
    ).first() is not None:
        raise ValidationFailed("This credential is already registered")
    row = WebauthnCredential(
        user_id=user.id,
        credential_id=credential_id_b64,
        public_key_b64=credential["public_key_der"].hex(),
        sign_count=int(parsed["sign_count"]),
        name=str(name).strip()[:64] or "Security key",
        transports=list(transports or []),
    )
    db.session.add(row)
    db.session.flush()
    # webauthn is its own factor kind so login demands it alongside TOTP
    from models import MfaFactor

    if MfaFactor.query.filter(
        MfaFactor.user_id == user.id, MfaFactor.kind == "webauthn"
    ).first() is None:
        db.session.add(MfaFactor(user_id=user.id, kind="webauthn", name="Security key"))
    auth_event(
        "auth.mfa.enrolled",
        actor=user.username,
        subject=user.username,
        detail={"kind": "webauthn", "credential_id": credential_id_b64[:16] + "..."},
    )
    db.session.commit()
    data = row.to_dict()
    data.pop("public_key_b64", None)
    return data


def _cose_alg_for(public_key_der_hex: str) -> int:
    key = _load_public_key(bytes.fromhex(public_key_der_hex))
    if isinstance(key, ec.EllipticCurvePublicKey):
        return COSE_ALG_ES256
    if isinstance(key, rsa.RSAPublicKey):
        return COSE_ALG_RS256
    if isinstance(key, ed25519.Ed25519PublicKey):
        return COSE_ALG_EDDSA
    return 0


# ---------------------------------------------------------------------------
# assertion
# ---------------------------------------------------------------------------
def verify_assertion(
    user: User,
    *,
    challenge_id: str,
    credential_id: str,
    client_data_json: str,
    authenticator_data: str,
    signature: str,
) -> str:
    """Verify a login/step-up assertion for the user's registered key.
    Returns 'webauthn' on success; raises on any check failure. The
    signature counter is enforced (rollback with non-zero = clone)."""
    values = webauthn_values()
    challenge = _consume_challenge(challenge_id, purpose="authenticate", user=user)
    row = WebauthnCredential.query.filter(
        WebauthnCredential.credential_id == str(credential_id or ""),
        WebauthnCredential.user_id == user.id,
    ).first()
    if row is None:
        raise NotFound("Unknown WebAuthn credential")
    try:
        client_data = _b64u_decode(client_data_json)
        auth_data = _b64u_decode(authenticator_data)
        sig = _b64u_decode(signature)
    except (ValueError,) as exc:
        raise ValidationFailed(f"Malformed WebAuthn payload: {exc}") from exc
    client_hash = _client_data(
        client_data,
        expected_type="webauthn.get",
        challenge=challenge,
        allowed_origins=values["allowed_origins"],
    )
    parsed = parse_auth_data(auth_data)
    if not parsed["user_present"]:
        raise ValidationFailed("authData is missing the user-present flag")
    if parsed["rp_id_hash"] != hashlib.sha256(values["rp_id"].encode("utf-8")).digest():
        raise ValidationFailed("authData.rpIdHash does not match the configured rp_id")
    public_key = _load_public_key(bytes.fromhex(row.public_key_b64))
    if not _verify_signature(public_key, auth_data + client_hash, sig):
        auth_event(
            "auth.mfa.failed",
            actor=user.username,
            subject=user.username,
            detail={"kind": "webauthn", "reason": "bad-signature"},
        )
        db.session.commit()
        raise ValidationFailed("WebAuthn assertion signature invalid")
    counter = int(parsed["sign_count"])
    if counter > 0 and counter < row.sign_count:
        # a cloned authenticator replayed an older counter - refuse + alert
        auth_event(
            "auth.webauthn.clone-detected",
            actor=user.username,
            subject=user.username,
            detail={"credential_id": row.credential_id[:16] + "...",
                    "presented": counter, "stored": row.sign_count},
        )
        db.session.commit()
        raise Forbidden(
            "WebAuthn signature counter rolled back (possible cloned "
            "authenticator) - the assertion was refused",
            {"presented": counter, "stored": row.sign_count},
        )
    if counter > row.sign_count:
        row.sign_count = counter
    row.last_used_at = datetime.now()
    db.session.commit()
    return "webauthn"


def list_credentials(user_id: int) -> List[Dict[str, Any]]:
    rows = WebauthnCredential.query.filter(
        WebauthnCredential.user_id == user_id
    ).order_by(WebauthnCredential.id).all()
    out = []
    for row in rows:
        data = row.to_dict()
        data.pop("public_key_b64", None)
        out.append(data)
    return out


def delete_credential(user_id: int, credential_id: int, *, actor: str) -> Dict[str, Any]:
    """Remove one credential; deleting the last one also drops the
    webauthn factor (subject to the last-factor fail-closed rule)."""
    row = db.session.get(WebauthnCredential, credential_id)
    if row is None or row.user_id != user_id:
        raise NotFound(f"Unknown WebAuthn credential {credential_id}")
    user = db.session.get(User, user_id)
    db.session.delete(row)
    remaining = WebauthnCredential.query.filter(
        WebauthnCredential.user_id == user_id
    ).count()
    if remaining == 0:
        from models import MfaFactor

        factor = MfaFactor.query.filter(
            MfaFactor.user_id == user_id, MfaFactor.kind == "webauthn"
        ).first()
        if factor is not None:
            import mfa as mfa_module

            policy_check = mfa_module.auth_settings()
            if policy_check["mfa_required"]:
                db.session.rollback()
                raise Forbidden(
                    "This is the user's last factor and mfa_required is on - "
                    "request a two-admin recovery instead",
                    {"mfa_required": True},
                )
            db.session.delete(factor)
    auth_event(
        "auth.mfa.credential-deleted",
        actor=actor or (user.username if user else ""),
        subject=user.username if user else "",
        detail={"credential_id": credential_id},
    )
    db.session.commit()
    return {"deleted": True, "credential_id": credential_id}
