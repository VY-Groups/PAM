"""
Bridge to the Phase 1 licensing library (ipam_licensing/).

The Phase 2 server never re-implements cryptography: it imports
LicenseGenerator / LicenseValidator straight from Phase 1 so that signing
and verification stay in sync. This module also caches key-loading
constructors, since loading an RSA key from disk on every request is wasteful.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Dict

SERVER_DIR = Path(__file__).resolve().parent
REPO_ROOT = SERVER_DIR.parent
IPAM_LICENSING_DIR = REPO_ROOT / "ipam_licensing"

if not IPAM_LICENSING_DIR.is_dir():
    raise ImportError(
        f"Phase 1 licensing library not found at {IPAM_LICENSING_DIR}. "
        "The license server cannot start without it."
    )

if str(IPAM_LICENSING_DIR) not in sys.path:
    sys.path.insert(0, str(IPAM_LICENSING_DIR))

from license import License, LicenseStatus, LicenseType  # noqa: E402
from license_tool import LicenseGenerator  # noqa: E402
from license_validator import LicenseValidator  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from config import Config

__all__ = [
    "License",
    "LicenseStatus",
    "LicenseType",
    "LicenseGenerator",
    "LicenseValidator",
    "get_generator",
    "get_validator",
]

_lock = threading.Lock()
_generators: Dict[str, LicenseGenerator] = {}
_validators: Dict[str, LicenseValidator] = {}


def get_generator(config: "Config") -> LicenseGenerator:
    """Return a cached LicenseGenerator for the configured private key."""
    key = str(config.private_key_path)
    if key not in _generators:
        with _lock:
            if key not in _generators:
                _generators[key] = LicenseGenerator(private_key_path=key)
    return _generators[key]


def get_validator(config: "Config") -> LicenseValidator:
    """Return a cached LicenseValidator for the configured public key."""
    key = str(config.public_key_path)
    if key not in _validators:
        with _lock:
            if key not in _validators:
                _validators[key] = LicenseValidator(public_key_path=key)
    return _validators[key]
