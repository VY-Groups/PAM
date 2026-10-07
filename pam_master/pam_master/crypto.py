"""PII encryption at rest for the VY-PAM MASTER customer registry.

Customer payloads (names, contacts, notes) are encrypted with AES-256-GCM
under a dedicated 32-byte key (see ``keys.load_registry_key``) — the license
signing keys never touch data confidentiality. Each row's ciphertext is bound
to its ``public_id`` via the GCM additional-authenticated-data, so a database
attacker cannot swap one customer's blob onto another row without failing
authentication.

Wire form (stored as TEXT in ``customers.data_ct``)::

    {"v": 1, "alg": "AES-256-GCM", "nonce": "<b64 12B>", "ct": "<b64>"}
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
ALGORITHM = "AES-256-GCM"
NONCE_BYTES = 12


class PayloadIntegrityError(ValueError):
    """Ciphertext failed authentication or carries an unknown envelope."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def encrypt_payload(key: bytes, aad: str, payload: Dict[str, Any]) -> str:
    """Serialise + encrypt ``payload``; AAD binds it to ``aad`` (row id)."""
    plaintext = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce, plaintext, aad.encode("utf-8")
    )
    return json.dumps(
        {
            "v": VERSION,
            "alg": ALGORITHM,
            "nonce": _b64(nonce),
            "ct": _b64(ciphertext),
        },
        separators=(",", ":"),
    )


def decrypt_payload(key: bytes, aad: str, blob: str) -> Dict[str, Any]:
    """Authenticate + decrypt a blob written by :func:`encrypt_payload`."""
    try:
        envelope = json.loads(blob)
        if (
            not isinstance(envelope, dict)
            or envelope.get("v") != VERSION
            or envelope.get("alg") != ALGORITHM
        ):
            raise PayloadIntegrityError("unknown envelope version/algorithm")
        plaintext = AESGCM(key).decrypt(
            _unb64(envelope["nonce"]),
            _unb64(envelope["ct"]),
            aad.encode("utf-8"),
        )
        payload = json.loads(plaintext.decode("utf-8"))
    except PayloadIntegrityError:
        raise
    except Exception as exc:  # decryption/auth/parse failures are all integrity
        raise PayloadIntegrityError(str(exc)) from exc
    if not isinstance(payload, dict):
        raise PayloadIntegrityError("payload is not a JSON object")
    return payload
