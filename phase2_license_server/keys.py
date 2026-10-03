"""
Key material checks performed at server startup.

Fail fast rather than signing licences with a half-configured key set:
- a missing private key is only acceptable when LICENSE_AUTOGENERATE_KEYS=1
- the stored public key must match the private key (otherwise every licence
  the server issues would be unverifiable by clients)
"""
from __future__ import annotations

from config import Config
from licensing_bridge import LicenseGenerator


class KeyConfigError(RuntimeError):
    """Raised when the configured signing keys are unusable."""


def ensure_keys(config: Config) -> LicenseGenerator:
    """
    Validate (and, if explicitly allowed, create) the signing key pair.

    Returns the generator so callers can keep using the loaded private key.
    """
    if not config.private_key_path.exists():
        if not config.autogenerate_keys:
            raise KeyConfigError(
                f"Private key not found at {config.private_key_path}. "
                "Generate one with the Phase 1 tool or set "
                "LICENSE_AUTOGENERATE_KEYS=1 to create it automatically."
            )

    try:
        generator = LicenseGenerator(private_key_path=str(config.private_key_path))
    except Exception as exc:  # unreadable/corrupt PEM
        raise KeyConfigError(
            f"Cannot load private key at {config.private_key_path}: {exc}"
        ) from exc

    derived_public = generator.get_public_key_pem()

    if config.public_key_path.exists():
        stored_public = config.public_key_path.read_bytes().strip()
        if stored_public != derived_public.strip():
            raise KeyConfigError(
                f"Public key {config.public_key_path} does not match private key "
                f"{config.private_key_path}. Licences signed by this server would "
                "fail verification; fix the key pair before starting."
            )
    else:
        config.public_key_path.parent.mkdir(parents=True, exist_ok=True)
        config.public_key_path.write_bytes(derived_public)

    return generator
