"""
Key material checks performed at server startup.

Fail fast rather than signing licences with a half-configured key set:
- a missing RSA private key is only acceptable when LICENSE_AUTOGENERATE_KEYS=1
- the stored RSA public key must match the private key (otherwise every licence
  the server issues would be unverifiable by clients)
- the optional Ed25519 pair follows the same consistency rule when present;
  it is created on first Ed25519 issuance (or at startup when autogeneration is
  enabled), since RSA-only deployments never need it
"""
from __future__ import annotations

from config import Config
from licensing_bridge import LicenseGenerator, sig


class KeyConfigError(RuntimeError):
    """Raised when the configured signing keys are unusable."""


def ensure_keys(config: Config) -> LicenseGenerator:
    """
    Validate (and, if explicitly allowed, create) the signing key pairs.

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
        generator = LicenseGenerator(
            private_key_path=str(config.private_key_path),
            ed25519_private_key_path=str(config.ed25519_private_key_path),
        )
    except Exception as exc:  # unreadable/corrupt PEM
        raise KeyConfigError(
            f"Cannot load private key at {config.private_key_path}: {exc}"
        ) from exc

    _check_public_key(
        config,
        generator,
        derived_public=generator.get_public_key_pem(sig.ALGORITHM_RSA),
        stored_path=config.public_key_path,
        label="RSA",
    )

    # Ed25519 is optional; only enforce consistency for a pair that exists (or
    # is about to be created because autogeneration is on).
    if config.ed25519_private_key_path.exists() or config.autogenerate_keys:
        try:
            derived_ed25519 = generator.get_public_key_pem(sig.ALGORITHM_ED25519)
        except Exception as exc:
            raise KeyConfigError(
                f"Cannot load Ed25519 private key at "
                f"{config.ed25519_private_key_path}: {exc}"
            ) from exc
        _check_public_key(
            config,
            generator,
            derived_public=derived_ed25519,
            stored_path=config.ed25519_public_key_path,
            label="Ed25519",
        )

    return generator


def _check_public_key(
    config: Config,
    generator: LicenseGenerator,
    *,
    derived_public: bytes,
    stored_path,
    label: str,
) -> None:
    if stored_path.exists():
        stored_public = stored_path.read_bytes().strip()
        if stored_public != derived_public.strip():
            raise KeyConfigError(
                f"Public key {stored_path} does not match {label} private key. "
                "Licences signed by this server would fail verification; fix "
                "the key pair before starting."
            )
        return

    stored_path.parent.mkdir(parents=True, exist_ok=True)
    stored_path.write_bytes(derived_public)
