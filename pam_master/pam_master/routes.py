"""Vendor-tool endpoints: honest index/health + registry + issuance APIs.

Failure discipline stays uniform (see ``errors.py``): validation -> 400,
unknown record -> 404, wrong-state conflict -> 409, missing registry key or
signing custody -> 503 with the real reason, corrupt ciphertext -> 500.
Nothing is guessed and nothing is silently created.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing

from flask import Blueprint, current_app, jsonify, request

from pam_master import db, errors, issuance, registry
from pam_master.config import Config
from pam_master.keys import key_presence, registry_key_status

master_bp = Blueprint("master", __name__)

ROLE = "VY-Groups internal license authority (vendor tool, never shipped)"


def _config() -> Config:
    return current_app.config["MASTER_CONFIG"]


@master_bp.errorhandler(errors.RegistryApiError)
def _handle_api_error(error: errors.RegistryApiError):
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
                "licenses": "/api/v1/licenses",
                "license-options": "/api/v1/license-options",
                "audit": "/api/v1/audit",
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


# ------------------------------------------------------- license issuance --
@master_bp.get("/api/v1/license-options")
def license_options():
    return jsonify(issuance.license_options())


@master_bp.get("/api/v1/licenses")
def licenses_list():
    page = issuance.list_licenses(
        _config(),
        customer=request.args.get("customer"),
        status=request.args.get("status"),
        limit=request.args.get("limit", registry.DEFAULT_LIMIT),
        offset=request.args.get("offset", 0),
    )
    return jsonify(page)


@master_bp.post("/api/v1/customers/<public_id>/licenses")
def licenses_issue(public_id: str):
    record = issuance.issue_license(
        _config(), public_id, request.get_json(silent=True)
    )
    response = jsonify(record)
    response.status_code = 201
    response.headers["Location"] = f"/api/v1/licenses/{record['license_id']}"
    return response


@master_bp.get("/api/v1/licenses/<license_id>")
def licenses_get(license_id: str):
    return jsonify(issuance.get_license(_config(), license_id))


@master_bp.post("/api/v1/licenses/<license_id>/renew")
def licenses_renew(license_id: str):
    record = issuance.renew_license(
        _config(), license_id, request.get_json(silent=True)
    )
    response = jsonify(record)
    response.status_code = 201
    response.headers["Location"] = f"/api/v1/licenses/{record['license_id']}"
    return response


@master_bp.get("/api/v1/licenses/<license_id>/bundle")
def licenses_bundle(license_id: str):
    data, filename = issuance.export_bundle(_config(), license_id)
    response = current_app.response_class(data, mimetype="application/zip")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{filename}"'
    )
    return response


# ------------------------------------------------------------- audit trail --
@master_bp.get("/api/v1/audit")
def audit_list():
    events = issuance.list_audit(
        _config(),
        request.args.get("limit", registry.DEFAULT_LIMIT),
        request.args.get("offset", 0),
    )
    return jsonify(events)
