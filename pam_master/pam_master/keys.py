"""Private-key custody for VY-PAM MASTER.

The MASTER holds the only copy of the license signing keys. Two rules:

1. **No implicit key creation.** The shared engine's ``LicenseGenerator``
   happily mints a key when the path is empty (useful on the customer side,
   dangerous here): a silently-created trust root would sign licenses that
   nothing else trusts, and nobody would know custody changed. Keys exist only
   after an explicit ``python -m pam_master.keygen``.
2. **Key material never leaves this process.** Endpoints report presence
   (``present`` / ``missing``) only — never bytes, never paths' contents.

The matching *public* key is written beside each private key using the shared
engine's naming convention (``..._private.pem`` -> ``..._public.pem``) so
``LicenseValidator`` on the shipped side finds it.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


class KeyCustodyError(RuntimeError):
    """A required private key is missing or unusable."""


def key_presence(path: Path) -> str:
    """Honest presence marker for health output (no key bytes, ever)."""
    return "present" if path.is_file() else "missing"


def require_keys(config) -> None:
    """Raise unless both configured private keys exist on disk.

    Called before any generator is constructed, which is what keeps the
    engine's load-or-create path from ever running in the MASTER.
    """
    missing = [
        str(p)
        for p in (
            config.rsa_private_key_path,
            config.ed25519_private_key_path,
        )
        if not p.is_file()
    ]
    if missing:
        raise KeyCustodyError(
            "refusing to operate without configured private keys (the MASTER "
            "never creates signing keys implicitly): "
            + ", ".join(missing)
            + " — run: python -m pam_master.keygen"
        )


def _write_key(path: Path, key) -> Path:
    """Write a private key PEM (never overwriting) + its public counterpart."""
    if path.exists():
        raise KeyCustodyError(
            f"refusing to overwrite an existing private key: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path = path.with_name(
        path.stem.replace("private", "public") + path.suffix
    )
    if public_path != path and not public_path.exists():
        public_path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return path


def generate_rsa_key(path: Path) -> Path:
    """Create a new 2048-bit RSA private key at ``path`` (+ public)."""
    return _write_key(
        path,
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def generate_ed25519_key(path: Path) -> Path:
    """Create a new Ed25519 private key at ``path`` (+ public)."""
    return _write_key(path, ed25519.Ed25519PrivateKey.generate())


def load_public_key(path: Path):
    """Load a public key PEM (used by tests for sign/verify round trips)."""
    if not path.is_file():
        raise KeyCustodyError(f"public key not found: {path}")
    return serialization.load_pem_public_key(path.read_bytes())


# ------------------------------------------------------- registry PII key --
# Customer-registry data-encryption key (AES-256-GCM), completely separate
# from the license signing keys: data confidentiality is not signing trust.

REGISTRY_KEY_BYTES = 32


class RegistryKeyError(KeyCustodyError):
    """The customer-registry PII key is missing or unusable."""


def _decode_registry_key(raw: str, origin: str) -> bytes:
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RegistryKeyError(
            f"registry PII key from {origin} is not valid base64: {exc}"
        ) from exc
    if len(key) != REGISTRY_KEY_BYTES:
        raise RegistryKeyError(
            f"registry PII key from {origin} must decode to "
            f"{REGISTRY_KEY_BYTES} bytes, got {len(key)}"
        )
    return key


def generate_registry_key(path: Path) -> Path:
    """Create the registry PII key (base64 of 32 random bytes, never
    overwriting)."""
    if path.exists():
        raise KeyCustodyError(
            f"refusing to overwrite an existing registry key: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    token = base64.b64encode(os.urandom(REGISTRY_KEY_BYTES)).decode("ascii")
    path.write_text(token + "\n", encoding="ascii")
    return path


def load_registry_key(config) -> bytes:
    """Load the registry PII key — file by default, ``MASTER_CUSTOMER_KEY_B64``
    wins when set (docker/orchestration secrets). Never creates one."""
    if config.customer_key_b64:
        return _decode_registry_key(
            config.customer_key_b64, "MASTER_CUSTOMER_KEY_B64"
        )
    path = config.customer_key_path
    if not path.is_file():
        raise RegistryKeyError(
            f"registry PII key not found: {path} — run: "
            "python -m pam_master.keygen"
        )
    return _decode_registry_key(
        path.read_text(encoding="ascii"), str(path)
    )


def registry_key_status(config) -> str:
    """Honest presence marker for health output: present | missing | invalid."""
    try:
        if config.customer_key_b64:
            _decode_registry_key(
                config.customer_key_b64, "MASTER_CUSTOMER_KEY_B64"
            )
            return "present"
        if config.customer_key_path.is_file():
            load_registry_key(config)
            return "present"
    except RegistryKeyError:
        return "invalid"
    return "missing"
