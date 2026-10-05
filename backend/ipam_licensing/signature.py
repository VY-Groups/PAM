"""
Signature algorithms and license envelopes for the IPAM licensing system.

This module is the single place where "what is signed and how" is defined, so
the generator (license_tool) and the validator (license_validator) can never
drift apart.

Algorithms
----------
- ``RSA-PSS-SHA256`` (JWS ``PS256``) - the original Phase 1 algorithm, default.
- ``Ed25519`` (JWS ``EdDSA``) - compact signatures for air-gapped ingestion.

Wire formats
------------
- ``json``: the original Phase 1 envelope
  ``{"license_data": {...}, "signature": "<std b64>", "algorithm": "..."}``.
  The signature covers ``json.dumps(license_data, sort_keys=True)``.
- ``jwt``: a compact JWS token ``<b64 header>.<b64 claims>.<b64 signature>``
  (what the ``.lic`` / ``.jwt`` upload path accepts). The signature covers the
  standard JWS signing input, so any JWT library can verify it with PS256 or
  EdDSA.

Both formats carry the same claims; only the envelope and the signed message
differ.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

ALGORITHM_RSA = "RSA-PSS-SHA256"
ALGORITHM_ED25519 = "Ed25519"
DEFAULT_ALGORITHM = ALGORITHM_RSA
SUPPORTED_ALGORITHMS = (ALGORITHM_RSA, ALGORITHM_ED25519)

FORMAT_JSON = "json"
FORMAT_JWT = "jwt"
SUPPORTED_FORMATS = (FORMAT_JSON, FORMAT_JWT)

JWS_ALG_BY_ALGORITHM = {ALGORITHM_RSA: "PS256", ALGORITHM_ED25519: "EdDSA"}
ALGORITHM_BY_JWS_ALG = {v: k for k, v in JWS_ALG_BY_ALGORITHM.items()}

ENVIRONMENT_VERSION = "1.0"


class UnsupportedAlgorithm(ValueError):
    """Raised when an algorithm is unknown or the key type cannot be used."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def b64url_encode(raw: bytes) -> str:
    """URL-safe base64 without padding (JWT segment encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    padding_needed = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_needed)


def canonical_json(data: Dict[str, Any]) -> bytes:
    """Deterministic JSON bytes: this is what gets signed/verified."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def jws_alg(algorithm: str) -> str:
    if algorithm not in JWS_ALG_BY_ALGORITHM:
        raise UnsupportedAlgorithm(f"Unsupported algorithm '{algorithm}'")
    return JWS_ALG_BY_ALGORITHM[algorithm]


def algorithm_for_jws_alg(alg: str) -> str:
    if alg not in ALGORITHM_BY_JWS_ALG:
        raise UnsupportedAlgorithm(f"Unsupported JWS 'alg' header '{alg}'")
    return ALGORITHM_BY_JWS_ALG[alg]


def fingerprint(signature: bytes) -> str:
    """Human-readable signature fingerprint (``sha256:<hex>``)."""
    return "sha256:" + hashlib.sha256(signature).hexdigest()


# ---------------------------------------------------------------------------
# signing / verification
# ---------------------------------------------------------------------------
def sign_bytes(private_key: Any, message: bytes, algorithm: str) -> bytes:
    """Sign raw message bytes with the configured algorithm."""
    if algorithm == ALGORITHM_RSA:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise UnsupportedAlgorithm(
                f"{ALGORITHM_RSA} requires an RSA private key, got "
                f"{type(private_key).__name__}"
            )
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    if algorithm == ALGORITHM_ED25519:
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise UnsupportedAlgorithm(
                f"{ALGORITHM_ED25519} requires an Ed25519 private key, got "
                f"{type(private_key).__name__}"
            )
        return private_key.sign(message)
    raise UnsupportedAlgorithm(f"Unsupported algorithm '{algorithm}'")


def verify_bytes(
    public_key: Any, message: bytes, signature: bytes, algorithm: str
) -> bool:
    """Verify raw message bytes; never raises for a bad signature."""
    try:
        if algorithm == ALGORITHM_RSA:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        if algorithm == ALGORITHM_ED25519:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(signature, message)
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False


def sign_claims(
    private_key: Any, license_data: Dict[str, Any], algorithm: str = DEFAULT_ALGORITHM
) -> str:
    """Sign claims for the ``json`` envelope (canonical JSON message)."""
    return base64.b64encode(
        sign_bytes(private_key, canonical_json(license_data), algorithm)
    ).decode("utf-8")


def verify_claims(
    public_key: Any,
    license_data: Dict[str, Any],
    signature_b64: str,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    return verify_bytes(public_key, canonical_json(license_data), signature, algorithm)


# ---------------------------------------------------------------------------
# compact JWS / JWT tokens
# ---------------------------------------------------------------------------
def encode_token(
    private_key: Any,
    license_data: Dict[str, Any],
    algorithm: str = DEFAULT_ALGORITHM,
    extra_header: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """
    Encode a compact JWS token.

    Returns ``(token, signing_input)``; the signing input is kept so the exact
    bytes that were signed can be re-verified even after a round trip through
    storage.
    """
    header: Dict[str, Any] = {"alg": jws_alg(algorithm), "typ": "JWT"}
    if extra_header:
        header.update(extra_header)

    header_segment = b64url_encode(canonical_json(header))
    payload_segment = b64url_encode(canonical_json(license_data))
    signing_input = f"{header_segment}.{payload_segment}"
    signature = sign_bytes(private_key, signing_input.encode("ascii"), algorithm)
    token = f"{signing_input}.{b64url_encode(signature)}"
    return token, signing_input


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode a compact token into a license envelope.

    Raises ``ValueError`` when the token is not three well-formed segments or
    its headers/claims are not JSON objects.
    """
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("Token must have three dot-separated segments")
    header_segment, payload_segment, signature_segment = parts

    header = json.loads(b64url_decode(header_segment))
    claims = json.loads(b64url_decode(payload_segment))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("Token header and claims must be JSON objects")

    algorithm = algorithm_for_jws_alg(str(header.get("alg", "")))
    signature = b64url_decode(signature_segment)

    return {
        "license_data": claims,
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": algorithm,
        "format": FORMAT_JWT,
        "header": header,
        "signing_input": f"{header_segment}.{payload_segment}",
        "version": ENVIRONMENT_VERSION,
    }


def build_json_envelope(
    private_key: Any,
    license_data: Dict[str, Any],
    algorithm: str = DEFAULT_ALGORITHM,
) -> Dict[str, Any]:
    """Build the original Phase 1 JSON envelope (signing now, or rebuild)."""
    return {
        "license_data": license_data,
        "signature": sign_claims(private_key, license_data, algorithm),
        "algorithm": algorithm,
        "format": FORMAT_JSON,
        "version": ENVIRONMENT_VERSION,
    }


def rebuild_json_envelope(
    license_data: Dict[str, Any],
    signature_b64: str,
    algorithm: str = DEFAULT_ALGORITHM,
) -> Dict[str, Any]:
    """Re-serialise a stored JSON envelope without re-signing."""
    return {
        "license_data": license_data,
        "signature": signature_b64,
        "algorithm": algorithm,
        "format": FORMAT_JSON,
        "version": ENVIRONMENT_VERSION,
    }


def rebuild_token(
    license_data: Dict[str, Any],
    signature_b64: str,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Re-serialise a stored signature back into a compact token."""
    header: Dict[str, Any] = {"alg": jws_alg(algorithm), "typ": "JWT"}
    header_segment = b64url_encode(canonical_json(header))
    payload_segment = b64url_encode(canonical_json(license_data))
    signature = base64.b64decode(signature_b64)
    return f"{header_segment}.{payload_segment}.{b64url_encode(signature)}"


def signing_input_candidates(
    license_data: Dict[str, Any],
    algorithm: str,
    envelope: Optional[Dict[str, Any]] = None,
) -> List[bytes]:
    """
    Messages a stored signature may legitimately have been produced over.

    A registered license keeps exactly one signature and one fingerprint, but
    the authority may re-serve the same claims as a JSON envelope or as a
    compact token without re-signing. Verification therefore accepts both
    signing inputs: the canonical claim bytes used by the Phase 1 JSON
    envelope, and the RFC 7515 ``header.payload`` used by compact JWS.

    Both messages are derived from the same claims under the issuing key, so
    accepting either grants an attacker nothing they could not already forge.
    """
    envelope = envelope or {}
    header = envelope.get("header") or {"alg": jws_alg(algorithm), "typ": "JWT"}
    signing_input = envelope.get("signing_input")

    candidates = [canonical_json(license_data)]
    if isinstance(signing_input, str):
        candidates.append(signing_input.encode("ascii"))
    else:
        candidates.append(
            f"{b64url_encode(canonical_json(header))}."
            f"{b64url_encode(canonical_json(license_data))}".encode("ascii")
        )
    return candidates


def verify_envelope(public_key: Any, envelope: Dict[str, Any]) -> bool:
    """Verify either wire format held in an envelope produced here."""
    algorithm = str(envelope.get("algorithm") or DEFAULT_ALGORITHM)
    license_data = envelope.get("license_data")
    signature_b64 = envelope.get("signature")
    if not isinstance(license_data, dict) or not isinstance(signature_b64, str):
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    return any(
        verify_bytes(public_key, message, signature, algorithm)
        for message in signing_input_candidates(license_data, algorithm, envelope)
    )


def parse_envelope(payload: Any) -> Optional[Dict[str, Any]]:
    """
    Normalise anything a caller may hand us into a license envelope.

    Accepts a compact token string, a JSON envelope object, ``{"token": "..."}``
    or ``{"license": <either>}`` wrappers. Returns ``None`` when the payload
    cannot be understood.
    """
    if isinstance(payload, str):
        stripped = payload.strip()
        if not stripped:
            return None
        if stripped.startswith("{"):
            try:
                return parse_envelope(json.loads(stripped))
            except json.JSONDecodeError:
                return None
        try:
            return decode_token(stripped)
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    if not isinstance(payload, dict):
        return None

    if "token" in payload and isinstance(payload["token"], str):
        return parse_envelope(payload["token"])
    if "license" in payload:
        return parse_envelope(payload["license"])
    if "license_data" in payload and "signature" in payload:
        # Structural check: anything else cannot be verified as a license.
        if not isinstance(payload["license_data"], dict):
            return None
        signature = payload["signature"]
        if not isinstance(signature, str) or not signature:
            return None
        envelope = dict(payload)
        envelope.setdefault("format", FORMAT_JSON)
        envelope.setdefault("algorithm", DEFAULT_ALGORITHM)
        return envelope
    return None
