"""Vendor-tool endpoints.

Phase 2a (skeleton): an honest index and a health probe that reports the
*real* state of the database and key custody — presence only for keys, never
material. The customer registry (2b) and issuance API (2c) register here
next.
"""
from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, jsonify

from pam_master.config import Config
from pam_master.keys import key_presence

master_bp = Blueprint("master", __name__)

ROLE = "VY-Groups internal license authority (vendor tool, never shipped)"


def _database_probe(config: Config) -> dict:
    """Touch the configured sqlite file and report what is actually there."""
    try:
        config.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(config.database_path))
        try:
            tables = connection.execute(
                "SELECT count(*) FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
        finally:
            connection.close()
        return {
            "scheme": "sqlite",
            "reachable": True,
            "tables": int(tables),
        }
    except sqlite3.Error as exc:
        return {
            "scheme": "sqlite",
            "reachable": False,
            "error": str(exc)[:200],
        }


@master_bp.get("/")
def index():
    """Service index — descriptive only, no state claims."""
    return jsonify(
        {
            "service": "vy-pam-master",
            "role": ROLE,
            "endpoints": {"health": "/health"},
        }
    )


@master_bp.get("/health")
def health():
    """Honest process health: real DB state + key presence (no material)."""
    config = current_app.config["MASTER_CONFIG"]
    rsa = key_presence(config.rsa_private_key_path)
    ed25519_state = key_presence(config.ed25519_private_key_path)
    return jsonify(
        {
            "status": "ok",
            "service": "vy-pam-master",
            "role": ROLE,
            "database": _database_probe(config),
            "signing": {
                "algorithms": ["RSA-PSS-SHA256", "Ed25519"],
                "rsa_key": rsa,
                "ed25519_key": ed25519_state,
                "ready": rsa == "present" and ed25519_state == "present",
            },
        }
    )
