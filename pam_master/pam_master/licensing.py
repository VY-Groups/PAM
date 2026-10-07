"""Bridge to the shared crypto engine (``backend/ipam_licensing``).

VY-PAM MASTER **signs** licenses; the shipped VY-PAM **verifies** them. Both
sides import the same engine so signing and verification can never drift
apart — but the MASTER keeps its *own* bridge file: it must never import the
PAM runtime (anti-mixing), and the whole ``pam_master/`` folder has to stay
extractable into its own repository.

Custody: ``get_generator`` checks key presence *before* constructing the
engine's ``LicenseGenerator``, because that class auto-creates a key when the
configured path is empty — fine for a customer install, unacceptable in the
tool that owns the trust root.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Dict, Tuple

# pam_master/pam_master/licensing.py -> <repo>/pam_master -> <repo>
PAM_MASTER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PAM_MASTER_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend"
IPAM_LICENSING_DIR = BACKEND_DIR / "ipam_licensing"

if not IPAM_LICENSING_DIR.is_dir():
    raise ImportError(
        f"Shared crypto engine not found at {IPAM_LICENSING_DIR}. "
        "VY-PAM MASTER cannot sign without backend/ipam_licensing."
    )

if str(IPAM_LICENSING_DIR) not in sys.path:
    sys.path.insert(0, str(IPAM_LICENSING_DIR))

from license_tool import LicenseGenerator  # noqa: E402
import signature as sig  # noqa: E402
# Entitlement catalog + commercial defaults come from the engine so the
# issuance API can never drift from what signing/verification actually use.
from license import (  # noqa: E402
    DEFAULT_CLASSIFICATIONS,
    DEFAULT_MODULE_IDS,
    DEFAULT_PLANS,
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    LicenseType,
)

from pam_master.config import Config  # noqa: E402
from pam_master.keys import require_keys  # noqa: E402

__all__ = [
    "LicenseGenerator",
    "LicenseType",
    "MODULE_CATALOG",
    "MODULE_IDS",
    "DEFAULT_MODULE_IDS",
    "DEFAULT_TIERS",
    "DEFAULT_PLANS",
    "DEFAULT_CLASSIFICATIONS",
    "ENFORCEMENT_LEVELS",
    "sig",
    "get_generator",
]

_lock = threading.Lock()
_generators: Dict[Tuple[str, str], LicenseGenerator] = {}


def get_generator(config: Config) -> LicenseGenerator:
    """Return a cached generator for the configured key pair.

    Raises ``KeyCustodyError`` when either configured private key is missing:
    the MASTER refuses to start the signing path rather than let the engine
    mint a key implicitly.
    """
    require_keys(config)
    cache_key = (
        str(config.rsa_private_key_path),
        str(config.ed25519_private_key_path),
    )
    generator = _generators.get(cache_key)
    if generator is not None:
        return generator
    with _lock:
        generator = _generators.get(cache_key)
        if generator is None:
            generator = LicenseGenerator(
                private_key_path=str(config.rsa_private_key_path),
                ed25519_private_key_path=str(
                    config.ed25519_private_key_path
                ),
            )
            _generators[cache_key] = generator
    return generator
