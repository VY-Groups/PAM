"""Fixtures for the VY-PAM MASTER test suite.

Path bootstrap mirrors the PAM server's conftest: the project folder (and the
repo root) go on ``sys.path`` so ``import pam_master`` resolves to the inner
package no matter where pytest was invoked from.

Keys are generated fresh per run under pytest's ``tmp_path`` — the suite
never reads, writes, or even needs the real repo-root custody keys.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PAM_MASTER_DIR = TESTS_DIR.parent  # <repo>/pam_master (project folder)
REPO_ROOT = PAM_MASTER_DIR.parent  # <repo>
for _entry in (str(REPO_ROOT), str(PAM_MASTER_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

from pam_master.app import create_app  # noqa: E402
from pam_master.config import Config  # noqa: E402
from pam_master.keys import (  # noqa: E402
    generate_ed25519_key,
    generate_rsa_key,
)


@pytest.fixture()
def custody(tmp_path):
    """Fresh RSA + Ed25519 key pair (engine naming) in a temp directory."""
    keys_dir = tmp_path / "keys"
    rsa_path = generate_rsa_key(keys_dir / "license_private_key.pem")
    ed_path = generate_ed25519_key(keys_dir / "license_ed25519_private.pem")
    return {"rsa": rsa_path, "ed25519": ed_path}


@pytest.fixture()
def config(tmp_path, custody):
    """Isolated master config: temp database + temp keys."""
    return Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(custody["rsa"]),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(custody["ed25519"]),
            "MASTER_SERVER_PORT": "5401",
        }
    )


@pytest.fixture()
def app(config):
    return create_app(config)


@pytest.fixture()
def client(app):
    return app.test_client()
