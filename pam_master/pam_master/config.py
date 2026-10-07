"""Configuration for VY-PAM MASTER (the vendor license authority).

Everything is environment-driven with a ``MASTER_*`` prefix so the tool runs
identically on a workstation, in dev Docker, or installed on the vendor's own
hosts — and so its settings never collide with the shipped VY-PAM server
(``LICENSE_*``). Key paths default to the repo-root custody files for dev
continuity with the shared crypto engine; production replaces the paths via
environment, never the code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

# pam_master/pam_master/config.py -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_PORT = 5400
DEFAULT_BIND = "127.0.0.1"
SQLITE_PREFIX = "sqlite:///"
DEFAULT_DATABASE_URI = f"sqlite:///{REPO_ROOT / 'pam_master' / 'master.db'}"
DEFAULT_RSA_KEY = REPO_ROOT / "license_private_key.pem"
DEFAULT_ED25519_KEY = REPO_ROOT / "license_ed25519_private.pem"


class ConfigError(ValueError):
    """Invalid or unusable configuration."""


def _database_path_from_uri(uri: str) -> Path:
    """Resolve a ``sqlite:///`` URI to a filesystem path.

    ``sqlite:///relative/or/windows/path`` (three slashes; the rest is taken
    literally, which also covers ``C:\\...`` drive letters) and
    ``sqlite:////absolute/unix/path`` (four slashes) both work. Only sqlite is
    supported — this tool installs directly, no external database required.
    """
    if not uri.startswith(SQLITE_PREFIX):
        raise ConfigError(
            "MASTER_DATABASE_URI must start with "
            f"{SQLITE_PREFIX!r} (only sqlite is supported); got {uri!r}"
        )
    raw = uri[len(SQLITE_PREFIX):]
    if not raw:
        raise ConfigError(
            "MASTER_DATABASE_URI must include a database file path; got empty"
        )
    return Path(raw)


@dataclass(frozen=True)
class Config:
    """Resolved runtime configuration (see ``from_env``)."""

    database_uri: str
    database_path: Path
    rsa_private_key_path: Path
    ed25519_private_key_path: Path
    host: str
    port: int

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        """Build config from ``MASTER_*`` environment variables.

        Pass ``env`` explicitly (e.g. a dict) in tests; ``None`` reads the
        real process environment.
        """
        source = os.environ if env is None else env

        database_uri = source.get("MASTER_DATABASE_URI", DEFAULT_DATABASE_URI)
        database_path = _database_path_from_uri(database_uri)

        port_raw = source.get("MASTER_SERVER_PORT", str(DEFAULT_PORT))
        try:
            port = int(port_raw)
        except ValueError:
            raise ConfigError(
                f"MASTER_SERVER_PORT must be an integer; got {port_raw!r}"
            ) from None
        if not 1 <= port <= 65535:
            raise ConfigError(
                f"MASTER_SERVER_PORT must be between 1 and 65535; got {port}"
            )

        return cls(
            database_uri=database_uri,
            database_path=database_path,
            rsa_private_key_path=Path(
                source.get("MASTER_RSA_PRIVATE_KEY_PATH", str(DEFAULT_RSA_KEY))
            ),
            ed25519_private_key_path=Path(
                source.get(
                    "MASTER_ED25519_PRIVATE_KEY_PATH", str(DEFAULT_ED25519_KEY)
                )
            ),
            host=source.get("MASTER_BIND", DEFAULT_BIND),
            port=port,
        )
