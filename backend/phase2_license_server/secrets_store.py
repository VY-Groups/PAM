"""Encrypted at-rest storage for credential-vault secrets (module 4/5).

Values are sealed with AES-256-GCM under a machine-local master key
(`VAULT_KEY_PATH`, default `vault_master.key` next to the database; the dev
default generates one on first use when `VAULT_AUTOGENERATE_KEY` is enabled).
The AAD binds every ciphertext to the vault item that owns it, so a blob
copied between rows fails its integrity check on read.

Wire/storage form matches the PAM-MASTER convention:
    {"v": 1, "alg": "AES-256-GCM", "nonce": <b64>, "ct": <b64>}

Plaintext is only ever produced by an explicit reveal or an in-process
rotation; it is never logged, never returned in list responses and never
written to the database.
"""
from __future__ import annotations

import base64
import json
import math
import os
import secrets as pysecrets
import string
import threading
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import Config
from errors import APIError, ServiceUnavailable, ValidationFailed
from models import (
    VAULT_TYPE_API_TOKEN,
    VAULT_TYPE_CLOUD_IAM,
    VAULT_TYPE_DATABASE,
    VAULT_TYPE_DOMAIN_PASSWORD,
    VAULT_TYPE_SERVICE_ACCOUNT,
    VAULT_TYPE_SSH_KEY,
)

WIRE_VERSION = 1
ALGORITHM = "AES-256-GCM"
_KEY_BYTES = 32
_NONCE_BYTES = 12

# Password types share one generation policy; the others mint type-appropriate
# material (below).
PASSWORD_TYPES = (
    VAULT_TYPE_DATABASE,
    VAULT_TYPE_DOMAIN_PASSWORD,
    VAULT_TYPE_SERVICE_ACCOUNT,
)
_PASSWORD_LENGTH = 24
_PASSWORD_POOL = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"

# (path, mtime, size) -> key; revalidated on every use so a rotated key file
# takes effect without a restart.
_KEY_CACHE: Dict[str, Tuple[float, int, bytes]] = {}
_KEY_LOCK = threading.Lock()


def _parse_key(raw: bytes, path: Path) -> bytes:
    """Accept a 64-hex-char file or a base64-encoded 32-byte file."""
    text = raw.decode("ascii", errors="strict").strip()
    if len(text) == _KEY_BYTES * 2 and all(c in string.hexdigits for c in text):
        return bytes.fromhex(text)
    decoded = base64.b64decode(text, validate=True)
    if len(decoded) == _KEY_BYTES:
        return decoded
    raise ServiceUnavailable(
        "Vault key file is not a 32-byte key (expected 64 hex chars or base64)",
        {"path": str(path)},
    )


def load_key(config: Config) -> bytes:
    """Load the vault master key, generating it once when allowed."""
    path = Path(config.vault_key_path)
    with _KEY_LOCK:
        if path.is_file():
            stat = path.stat()
            cached = _KEY_CACHE.get(str(path))
            if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
                return cached[2]
            key = _parse_key(path.read_bytes(), path)
            _KEY_CACHE[str(path)] = (stat.st_mtime, stat.st_size, key)
            return key
        if not config.vault_autogenerate_key:
            raise ServiceUnavailable(
                "Vault encryption key unavailable",
                {
                    "path": str(path),
                    "hint": "provision the key or set VAULT_AUTOGENERATE_KEY=1 for development",
                },
            )
        # Dev convenience: mint a real key once, never overwrite an existing
        # file (same custody rule as pam_master.keygen).
        key = os.urandom(_KEY_BYTES)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(key.hex() + "\n", encoding="ascii")
        stat = path.stat()
        _KEY_CACHE[str(path)] = (stat.st_mtime, stat.st_size, key)
        return key


def aad_for(item_id: int) -> bytes:
    """Additional authenticated data: a ciphertext belongs to exactly one row."""
    return f"vault_item:{item_id}".encode("utf-8")


def seal(plaintext: str, item_id: int, config: Config) -> Dict[str, Any]:
    """Encrypt one secret value for storage."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValidationFailed("Secret value must be a non-empty string")
    key = load_key(config)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce, plaintext.encode("utf-8"), aad_for(item_id)
    )
    return {
        "v": WIRE_VERSION,
        "alg": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }


def unseal(blob: Dict[str, Any], item_id: int, config: Config) -> str:
    """Decrypt one stored secret; a tampered/moved blob fails honestly."""
    if not isinstance(blob, dict) or blob.get("v") != WIRE_VERSION:
        raise APIError(500, "Stored secret has an unsupported format")
    if blob.get("alg") != ALGORITHM:
        raise APIError(500, f"Stored secret uses an unsupported algorithm: {blob.get('alg')!r}")
    try:
        nonce = base64.b64decode(blob["nonce"], validate=True)
        ciphertext = base64.b64decode(blob["ct"], validate=True)
    except (KeyError, ValueError) as exc:
        raise APIError(500, "Stored secret is malformed") from exc
    try:
        plaintext = AESGCM(load_key(config)).decrypt(
            nonce, ciphertext, aad_for(item_id)
        )
    except InvalidTag as exc:
        # Wrong key, tampered ciphertext or a blob moved from another item.
        raise APIError(
            500, "Stored secret failed its integrity check (wrong key, tampered data or foreign row)"
        ) from exc
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# generation: real material per credential type (never a placeholder)
# ---------------------------------------------------------------------------
def _generate_password() -> str:
    """24 printable chars, guaranteed mixed classes, `secrets`-uniform."""
    chars = [
        pysecrets.choice(string.ascii_uppercase),
        pysecrets.choice(string.ascii_lowercase),
        pysecrets.choice(string.digits),
        pysecrets.choice("!@#$%^&*()-_=+[]{}"),
    ]
    chars += [pysecrets.choice(_PASSWORD_POOL) for _ in range(_PASSWORD_LENGTH - len(chars))]
    # SystemRandom.shuffle is Fisher-Yates under the OS CSPRNG.
    pysecrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _generate_token() -> str:
    return pysecrets.token_urlsafe(32)


def _generate_cloud_iam() -> str:
    """A neutral cloud credential pair (no vendor claim): id + secret."""
    alphabet = string.ascii_uppercase + string.digits
    access_key_id = "".join(pysecrets.choice(alphabet) for _ in range(20))
    return json.dumps(
        {"access_key_id": access_key_id, "secret_access_key": pysecrets.token_urlsafe(40)},
        separators=(",", ":"),
    )


def _generate_ssh_key() -> str:
    private = Ed25519PrivateKey.generate()
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def generate_secret(secret_type: str) -> str:
    """Mint a real credential value appropriate for the inventory type."""
    if secret_type in PASSWORD_TYPES:
        return _generate_password()
    if secret_type == VAULT_TYPE_API_TOKEN:
        return _generate_token()
    if secret_type == VAULT_TYPE_CLOUD_IAM:
        return _generate_cloud_iam()
    if secret_type == VAULT_TYPE_SSH_KEY:
        return _generate_ssh_key()
    raise ValidationFailed(
        f"Cannot generate a secret for unknown vault type '{secret_type}'",
        {"field": "secret_type"},
    )


def generated_secret_is_valid(secret_type: str, value: str) -> bool:
    """Format check for values this module minted (not for operator input)."""
    if not isinstance(value, str) or not value:
        return False
    if secret_type in PASSWORD_TYPES:
        if len(value) != _PASSWORD_LENGTH:
            return False
        classes = (
            any(c in string.ascii_lowercase for c in value),
            any(c in string.ascii_uppercase for c in value),
            any(c in string.digits for c in value),
            any(c not in string.ascii_letters + string.digits for c in value),
        )
        return all(classes)
    if secret_type == VAULT_TYPE_API_TOKEN:
        return len(value) >= 32
    if secret_type == VAULT_TYPE_CLOUD_IAM:
        try:
            parsed = json.loads(value)
        except ValueError:
            return False
        return isinstance(parsed, dict) and bool(parsed.get("access_key_id")) and bool(
            parsed.get("secret_access_key")
        )
    if secret_type == VAULT_TYPE_SSH_KEY:
        try:
            serialization.load_pem_private_key(value.encode("utf-8"), password=None)
            return True
        except (ValueError, TypeError):
            return False
    return True


def approximate_entropy_bits(value: str) -> int:
    """Length x log2(observed character classes) — an honest estimate, not a
    measured entropy figure; callers label it with `~`."""
    if not value:
        return 0
    pool = 0
    if any(c.islower() for c in value):
        pool += 26
    if any(c.isupper() for c in value):
        pool += 26
    if any(c.isdigit() for c in value):
        pool += 10
    if any(not c.isalnum() for c in value):
        pool += 33
    if pool <= 1:
        return 0
    return int(len(value) * math.log2(pool))
