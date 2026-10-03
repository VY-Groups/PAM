"""
Configuration for the Phase 2 license server.

All values come from environment variables (optionally loaded from
phase2_license_server/.env). Relative key paths are resolved against this
directory, so the server behaves the same no matter where it is started from.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

SERVER_DIR = Path(__file__).resolve().parent
REPO_ROOT = SERVER_DIR.parent

# Load .env overrides next to this file (no-op when the file is absent).
load_dotenv(SERVER_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_path(value: Optional[str], default: Path) -> Path:
    if not value:
        return default
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (SERVER_DIR / path).resolve()
    return path


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration for one server instance."""

    database_uri: str
    private_key_path: Path
    public_key_path: Path
    ed25519_private_key_path: Path
    ed25519_public_key_path: Path
    secret_key: str
    admin_token: Optional[str] = None
    autogenerate_keys: bool = False
    default_trial_days: int = 30

    @classmethod
    def from_env(cls) -> "Config":
        default_db = SERVER_DIR / "licenses.db"
        database_uri = (
            os.getenv("LICENSE_DATABASE_URI")
            or f"sqlite:///{default_db.as_posix()}"
        )

        return cls(
            database_uri=database_uri,
            private_key_path=_resolve_path(
                os.getenv("LICENSE_PRIVATE_KEY_PATH"),
                REPO_ROOT / "license_private_key.pem",
            ),
            public_key_path=_resolve_path(
                os.getenv("LICENSE_PUBLIC_KEY_PATH"),
                REPO_ROOT / "license_public_key.pem",
            ),
            # Optional second algorithm (created on first Ed25519 issuance).
            ed25519_private_key_path=_resolve_path(
                os.getenv("LICENSE_ED25519_PRIVATE_KEY_PATH"),
                REPO_ROOT / "license_ed25519_private.pem",
            ),
            ed25519_public_key_path=_resolve_path(
                os.getenv("LICENSE_ED25519_PUBLIC_KEY_PATH"),
                REPO_ROOT / "license_ed25519_public.pem",
            ),
            secret_key=os.getenv("LICENSE_SECRET_KEY") or secrets.token_hex(32),
            admin_token=os.getenv("LICENSE_ADMIN_TOKEN") or None,
            autogenerate_keys=_env_bool("LICENSE_AUTOGENERATE_KEYS", False),
            default_trial_days=int(os.getenv("LICENSE_DEFAULT_TRIAL_DAYS", "30")),
        )
