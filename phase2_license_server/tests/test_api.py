"""End-to-end tests for the Phase 2 license server API (run with pytest)."""
from __future__ import annotations

import base64
import json
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from licensing_bridge import (  # noqa: E402
    License,
    LicenseType,
    get_generator,
    get_validator,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        secret_key="test-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
    )


@pytest.fixture
def client(config: Config):
    app = create_app(config)
    app.config["TESTING"] = True
    return app.test_client()


def issue(client, **overrides):
    payload = {"license_type": "subscription", "issued_to": "Acme Ltd"}
    payload.update(overrides)
    return client.post("/api/v1/licenses", json=payload, headers=ADMIN)


# ---------------------------------------------------------------------------
# health / auth
# ---------------------------------------------------------------------------
def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert data["auth"] == "token"


def test_license_screen_served_at_root_and_license(client):
    """The UI screen is served same-origin so its API calls resolve."""
    for path in ("/", "/license"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.content_type.startswith("text/html")
        html = response.get_data(as_text=True)
        assert "License &amp; Entitlement Center" in html
        assert "workspace_premium" in html            # sidebar item present
        assert "'api/v1/'" in html                    # wired to this server's API
        assert "cdn.tailwindcss.com" in html          # suite design system
        assert "X-Admin-Token" in html                # admin auth plumbing


def test_admin_endpoints_require_token(client):
    payload = {"license_type": "trial", "issued_to": "Acme"}

    assert client.post("/api/v1/licenses", json=payload).status_code == 401
    bad = client.post(
        "/api/v1/licenses",
        json=payload,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert bad.status_code == 401
    assert "error" in bad.get_json()

    ok = client.post(
        "/api/v1/licenses",
        json={"license_type": "trial", "issued_to": "Acme"},
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert ok.status_code == 201


def test_validation_endpoint_is_public(client, config):
    license_obj = License(
        license_key=str(uuid.uuid4()).upper(),
        license_type=LicenseType.TRIAL,
        issued_to="Public Customer",
        issued_date=datetime.now(),
        expires_on=datetime.now() + timedelta(days=10),
    )
    data = license_obj.to_dict()
    payload = {
        "license_data": data,
        "signature": get_generator(config).sign_license(data),
    }
    assert client.post("/api/v1/licenses/validate", json=payload).status_code == 200


# ---------------------------------------------------------------------------
# issuing
# ---------------------------------------------------------------------------
def test_issue_license_round_trip(client):
    response = issue(client, features=["ip_discovery"], usage_limits={"max_users": 10})
    assert response.status_code == 201
    body = response.get_json()

    record = body["license"]
    license_file = body["license_file"]
    assert record["status"] == "active"
    assert record["effective_status"] == "valid"
    assert record["license_type"] == "subscription"
    assert record["features"] == ["ip_discovery"]
    assert record["usage_limits"] == {"max_users": 10}
    assert record["days_until_expiry"] == 365
    assert license_file["license_data"]["license_key"] == record["license_key"]
    assert license_file["algorithm"] == "RSA-PSS-SHA256"
    assert len(license_file["signature"]) > 100

    # the issued file validates immediately
    validated = client.post("/api/v1/licenses/validate", json=license_file).get_json()
    assert validated["valid"] is True
    assert validated["status"] == "valid"
    assert validated["registered"] is True
    assert validated["matches_registered_record"] is True
    assert validated["license"]["issued_to"] == "Acme Ltd"


def test_issue_applies_defaults_per_type(client):
    trial = issue(client, license_type="trial", issued_to="Trial Co").get_json()["license"]
    assert trial["days_until_expiry"] == 30
    assert trial["usage_limits"] == {"max_users": 5, "max_subnets": 100, "max_devices": 1000}

    perpetual = issue(client, license_type="perpetual", issued_to="Perp Co").get_json()["license"]
    assert perpetual["expires_on"] is None
    assert perpetual["days_until_expiry"] is None
    assert perpetual["effective_status"] == "valid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"license_type": None},
        {"license_type": "lifetime"},
        {"issued_to": ""},
        {"trial_days": 0},
        {"features": "ip_discovery"},
        {"usage_limits": {"max_users": "ten"}},
        {"metadata": []},
    ],
)
def test_issue_rejects_bad_input(client, overrides):
    response = issue(client, **overrides)
    assert response.status_code == 400, response.get_json()
    assert "error" in response.get_json()


# ---------------------------------------------------------------------------
# listing / reading
# ---------------------------------------------------------------------------
def test_list_filter_and_paginate(client):
    issue(client, license_type="trial", issued_to="Trial Co")
    issue(client, license_type="subscription", issued_to="Sub Co")

    everything = client.get("/api/v1/licenses").get_json()
    assert everything["total"] == 2

    trials = client.get("/api/v1/licenses?license_type=trial").get_json()
    assert trials["total"] == 1
    assert trials["licenses"][0]["issued_to"] == "Trial Co"

    by_name = client.get("/api/v1/licenses?issued_to=Sub").get_json()
    assert by_name["total"] == 1

    page = client.get("/api/v1/licenses?limit=1&offset=1").get_json()
    assert len(page["licenses"]) == 1
    assert page["total"] == 2

    assert client.get("/api/v1/licenses?status=banana").status_code == 400
    assert client.get("/api/v1/licenses?limit=notanumber").status_code == 400
    assert client.get("/api/v1/licenses?status=valid").get_json()["total"] == 2


def test_get_license_detail_includes_events(client):
    created = issue(client).get_json()["license"]
    response = client.get(f"/api/v1/licenses/{created['license_key']}")
    assert response.status_code == 200
    detail = response.get_json()["license"]
    assert detail["license_key"] == created["license_key"]
    assert [event["action"] for event in detail["events"]] == ["issued"]

    missing = client.get("/api/v1/licenses/NOT-A-REAL-KEY")
    assert missing.status_code == 404


def test_download_license_file_round_trip(client, config):
    created = issue(client).get_json()["license"]
    key = created["license_key"]

    response = client.get(f"/api/v1/licenses/{key}/file", headers=ADMIN)
    assert response.status_code == 200
    assert f'license_{key}.json' in response.headers["Content-Disposition"]

    license_file = json.loads(response.data)
    validator = get_validator(config)
    assert (
        validator.verify_signature(license_file["license_data"], license_file["signature"])
        is True
    )

    validated = client.post("/api/v1/licenses/validate", json=license_file).get_json()
    assert validated["valid"] is True


# ---------------------------------------------------------------------------
# revoke / restore
# ---------------------------------------------------------------------------
def test_revoke_then_restore(client):
    created = issue(client).get_json()["license"]
    key = created["license_key"]

    revoked = client.post(
        f"/api/v1/licenses/{key}/revoke", json={"reason": "non-payment"}, headers=ADMIN
    )
    assert revoked.status_code == 200
    assert revoked.get_json()["license"]["status"] == "revoked"
    assert revoked.get_json()["license"]["revoked_reason"] == "non-payment"

    validated = client.post(
        "/api/v1/licenses/validate", json=client.get(f"/api/v1/licenses/{key}/file", headers=ADMIN).get_json()
    ).get_json()
    assert validated["valid"] is False
    assert validated["status"] == "revoked"
    assert validated["revoked"] is True
    assert validated["revoked_reason"] == "non-payment"
    assert validated["signature_valid"] is True

    assert client.post(f"/api/v1/licenses/{key}/revoke", json={}, headers=ADMIN).status_code == 400
    assert client.get("/api/v1/licenses?status=revoked").get_json()["total"] == 1

    restored = client.post(f"/api/v1/licenses/{key}/restore", headers=ADMIN)
    assert restored.status_code == 200
    assert restored.get_json()["license"]["status"] == "active"

    assert client.post(f"/api/v1/licenses/{key}/restore", headers=ADMIN).status_code == 400
    assert client.get("/api/v1/licenses?status=revoked").get_json()["total"] == 0

    detail = client.get(f"/api/v1/licenses/{key}").get_json()["license"]
    assert [event["action"] for event in detail["events"]] == ["issued", "revoked", "restored"]


def test_revoke_requires_token(client):
    created = issue(client).get_json()["license"]
    response = client.post(f"/api/v1/licenses/{created['license_key']}/revoke", json={})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def test_validate_tampered_payload_fails(client):
    license_file = issue(client).get_json()["license_file"]
    license_file["license_data"]["issued_to"] = "Someone Else"

    result = client.post("/api/v1/licenses/validate", json=license_file).get_json()
    assert result["valid"] is False
    assert result["status"] == "signature_invalid"
    assert result["signature_valid"] is False


def test_validate_signature_from_foreign_key_fails(client):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    license_obj = License(
        license_key=str(uuid.uuid4()).upper(),
        license_type=LicenseType.TRIAL,
        issued_to="Impostor",
        issued_date=datetime.now(),
        expires_on=datetime.now() + timedelta(days=5),
    )
    data = license_obj.to_dict()
    signature = foreign_key.sign(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    result = client.post(
        "/api/v1/licenses/validate",
        json={"license_data": data, "signature": base64.b64encode(signature).decode()},
    ).get_json()
    assert result["valid"] is False
    assert result["status"] == "signature_invalid"


def test_validate_expired_signature_is_valid_but_expired(client, config):
    license_obj = License(
        license_key=str(uuid.uuid4()).upper(),
        license_type=LicenseType.TRIAL,
        issued_to="Old Customer",
        issued_date=datetime.now() - timedelta(days=60),
        expires_on=datetime.now() - timedelta(days=10),
    )
    data = license_obj.to_dict()
    payload = {"license_data": data, "signature": get_generator(config).sign_license(data)}

    result = client.post("/api/v1/licenses/validate", json=payload).get_json()
    assert result["valid"] is False
    assert result["status"] == "expired"
    assert result["signature_valid"] is True
    assert result["registered"] is False


@pytest.mark.parametrize("payload", [{}, {"license_data": "nope", "signature": "x"}, {"license": []}])
def test_validate_malformed_payloads(client, payload):
    result = client.post("/api/v1/licenses/validate", json=payload).get_json()
    assert result["valid"] is False
    assert result["status"] == "malformed"


def test_validate_rejects_non_json_body(client):
    assert client.post("/api/v1/licenses/validate", data="not json").status_code == 400


# ---------------------------------------------------------------------------
# feature / usage checks
# ---------------------------------------------------------------------------
def test_feature_and_usage_checks(client):
    created = issue(
        client,
        license_type="subscription",
        issued_to="Acme Ltd",
        features=["ip_discovery"],
        usage_limits={"max_users": 10},
    ).get_json()["license"]
    key = created["license_key"]

    allowed = client.post(
        f"/api/v1/licenses/{key}/check",
        json={"feature": "ip_discovery", "limit_type": "max_users", "current_usage": 5},
    ).get_json()
    assert allowed["feature_allowed"] is True
    assert allowed["limit_allowed"] is True
    assert allowed["limit"] == 10
    assert allowed["active"] is True

    denied = client.post(
        f"/api/v1/licenses/{key}/check",
        json={"feature": "ldap_integration", "limit_type": "max_users", "current_usage": 99},
    ).get_json()
    assert denied["feature_allowed"] is False
    assert denied["limit_allowed"] is False

    no_limit = client.post(
        f"/api/v1/licenses/{key}/check",
        json={"limit_type": "max_something_new", "current_usage": 1},
    ).get_json()
    assert no_limit["limit"] is None
    assert no_limit["limit_allowed"] is True

    assert client.post(f"/api/v1/licenses/{key}/check", json={}).status_code == 400
    assert (
        client.post(f"/api/v1/licenses/{key}/check", json={"limit_type": "max_users"}).status_code
        == 400
    )
    assert client.post("/api/v1/licenses/MISSING-KEY/check", json={"feature": "x"}).status_code == 404


def test_checks_fail_for_revoked_license(client):
    created = issue(client).get_json()["license"]
    key = created["license_key"]
    client.post(f"/api/v1/licenses/{key}/revoke", json={"reason": "fraud"}, headers=ADMIN)

    result = client.post(f"/api/v1/licenses/{key}/check", json={"feature": "ip_discovery"}).get_json()
    assert result["active"] is False
    assert result["feature_allowed"] is False
