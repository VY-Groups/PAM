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
