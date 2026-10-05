"""
Bridge to the Phase 1 licensing library (backend/ipam_licensing/).

The Phase 2 server never re-implements cryptography: it imports
LicenseGenerator / LicenseValidator straight from Phase 1 so that signing
and verification stay in sync. This module also caches key-loading
constructors, since loading a key from disk on every request is wasteful.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Tuple

SERVER_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SERVER_DIR.parent
REPO_ROOT = BACKEND_DIR.parent
IPAM_LICENSING_DIR = BACKEND_DIR / "ipam_licensing"

if not IPAM_LICENSING_DIR.is_dir():
    raise ImportError(
        f"Phase 1 licensing library not found at {IPAM_LICENSING_DIR}. "
        "The license server cannot start without it."
    )

if str(IPAM_LICENSING_DIR) not in sys.path:
    sys.path.insert(0, str(IPAM_LICENSING_DIR))

from license import (  # noqa: E402
    DEFAULT_CLASSIFICATIONS,
    DEFAULT_ISSUER,
    DEFAULT_PLANS,
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    License,
    LicenseStatus,
    LicenseType,
    default_modules,
    default_quotas,
    optional_fields,
)
from license_tool import LicenseGenerator  # noqa: E402
from license_validator import LicenseValidator  # noqa: E402
import signature as sig  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from config import Config

__all__ = [
    "License",
    "LicenseStatus",
    "LicenseType",
    "LicenseGenerator",
    "LicenseValidator",
    "MODULE_CATALOG",
    "MODULE_IDS",
    "ENFORCEMENT_LEVELS",
    "DEFAULT_TIERS",
    "DEFAULT_PLANS",
    "DEFAULT_CLASSIFICATIONS",
    "DEFAULT_ISSUER",
    "default_modules",
    "default_quotas",
    "optional_fields",
    "sig",
    "get_generator",
    "get_validator",
]

_lock = threading.Lock()
_generators: Dict[Tuple[str, str], LicenseGenerator] = {}
_validators: Dict[Tuple[str, str], LicenseValidator] = {}


def get_generator(config: "Config") -> LicenseGenerator:
    """Return a cached LicenseGenerator for the configured key pair."""
    cache_key = (str(config.private_key_path), str(config.ed25519_private_key_path))
    if cache_key not in _generators:
        with _lock:
            if cache_key not in _generators:
                _generators[cache_key] = LicenseGenerator(
                    private_key_path=str(config.private_key_path),
                    ed25519_private_key_path=str(config.ed25519_private_key_path),
                )
    return _generators[cache_key]


def get_validator(config: "Config") -> LicenseValidator:
    """Return a cached LicenseValidator for the configured public keys."""
    cache_key = (str(config.public_key_path), str(config.ed25519_public_key_path))
    if cache_key not in _validators:
        with _lock:
            if cache_key not in _validators:
                _validators[cache_key] = LicenseValidator(
                    public_key_path=str(config.public_key_path),
                    ed25519_public_key_path=str(config.ed25519_public_key_path),
                )
    return _validators[cache_key]
