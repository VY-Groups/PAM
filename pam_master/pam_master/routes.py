"""Vendor-tool endpoints: honest index/health + the customer registry API.

The registry surface is deliberately small (list/create/get/edit + issuance
history view) and fails honestly: validation problems -> 400, unknown
customer -> 404, missing registry key -> 503 with the real reason.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing

from flask import Blueprint, current_app, jsonify, request

from pam_master import db, registry
from pam_master.config import Config
from pam_master.keys import key_presence, registry_key_status

master_bp = Blueprint("master", __name__)

ROLE = "VY-Groups internal license authority (vendor tool, never shipped)"


def _config() -> Config:
    return current_app.config["MASTER_CONFIG"]


@master_bp.errorhandler(registry.RegistryApiError)
def _handle_registry_error(error: registry.RegistryApiError):
    return (
        jsonify(
            {"error": {"type": error.error_type, "message": error.message}}
        ),
        error.status,
    )


def _database_probe(config: Config) -> dict:
    """Touch the configured sqlite file and report what is actually there."""
    try:
        config.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(db.connect(config)) as connection:
            return {
                "scheme": "sqlite",
                "reachable": True,
                "tables": db.table_count(connection),
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
            "endpoints": {
                "health": "/health",
                "customers": "/api/v1/customers",
            },
        }
    )


@master_bp.get("/health")
def health():
    """Honest process health: real DB state + key presence (no material)."""
    config = _config()
    rsa = key_presence(config.rsa_private_key_path)
    ed25519_state = key_presence(config.ed25519_private_key_path)
    pii_state = registry_key_status(config)
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
            "registry": {
                "pii_key": pii_state,
                "ready": pii_state == "present",
            },
        }
    )


# ------------------------------------------------------- customer registry --
@master_bp.get("/api/v1/customers")
def customers_list():
    page = registry.list_customers(
        _config(),
        request.args.get("limit", registry.DEFAULT_LIMIT),
        request.args.get("offset", 0),
    )
    return jsonify(page)


@master_bp.post("/api/v1/customers")
def customers_create():
    record = registry.create_customer(
        _config(), request.get_json(silent=True)
    )
    response = jsonify(record)
    response.status_code = 201
    response.headers["Location"] = (
        f"/api/v1/customers/{record['public_id']}"
    )
    return response


@master_bp.get("/api/v1/customers/<public_id>")
def customers_get(public_id: str):
    return jsonify(registry.get_customer(_config(), public_id))


@master_bp.patch("/api/v1/customers/<public_id>")
def customers_edit(public_id: str):
    return jsonify(
        registry.update_customer(
            _config(), public_id, request.get_json(silent=True)
        )
    )


@master_bp.get("/api/v1/customers/<public_id>/issuance-history")
def customers_history(public_id: str):
    return jsonify(registry.issuance_history(_config(), public_id))
