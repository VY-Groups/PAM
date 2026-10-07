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
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from licensing_bridge import (  # noqa: E402
    MODULE_CATALOG,
    License,
    LicenseType,
    get_generator,
    get_validator,
    sig,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        # Ed25519 keys are created on demand; keep them inside tmp_path so the
        # suite never writes key material into the repository root.
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
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


def sample_claims(**overrides):
    """Base claims for a vendor-signed subscription license.

    Tests play the vendor: they sign their own files because the shipped
    server only ever verifies (Phase 3a — issuing lives in PAM-MASTER).
    """
    claims = {
        "license_key": str(uuid.uuid4()).upper(),
        "license_type": "subscription",
        "issued_to": "Acme Ltd",
        "issued_date": datetime.now().isoformat(),
        "expires_on": (datetime.now() + timedelta(days=365)).isoformat(),
    }
    claims.update(overrides)
    return claims


def vendor_sign(client, claims, **envelope_overrides):
    """Sign claims with the trusted vendor key (test stand-in for PAM-MASTER)."""
    config = client.application.config["LICENSE_CONFIG"]
    envelope = {
        "license_data": claims,
        "signature": get_generator(config).sign_license(claims),
        "algorithm": sig.DEFAULT_ALGORITHM,
        "format": sig.FORMAT_JSON,
    }
    envelope.update(envelope_overrides)
    return envelope


def import_signed(client, claims, **envelope_overrides):
    """POST pre-signed claims to the import endpoint with the admin token."""
    return client.post(
        "/api/v1/licenses/import",
        json=vendor_sign(client, claims, **envelope_overrides),
        headers=ADMIN,
    )


def install(client, **overrides):
    """Vendor-side install: sign with the shared engine, then import.

    The helper plays PAM-MASTER — it applies the catalog/quota normalisation
    the old issuing form did (module names from the catalog, a `nodes` ceiling
    derived from pools), signs, and installs through the import endpoint.
    """
    config = client.application.config["LICENSE_CONFIG"]
    fields = {"license_type": "subscription", "issued_to": "Acme Ltd"}
    fields.update(overrides)
    if isinstance(fields.get("license_type"), str):
        fields["license_type"] = LicenseType(fields["license_type"])
    algorithm = fields.pop("algorithm", sig.DEFAULT_ALGORITHM)
    file_format = fields.pop("format", sig.FORMAT_JSON)
    fields.setdefault("trial_days", config.default_trial_days)

    modules = fields.get("modules")
    if isinstance(modules, list):
        by_id = {entry["id"]: entry for entry in MODULE_CATALOG}
        normalized = []
        for entry in modules:
            catalog = by_id.get(entry.get("id")) if isinstance(entry, dict) else None
            if catalog is None:
                normalized.append(entry)
                continue
            normalized.append(
                {
                    "id": entry["id"],
                    "name": entry.get("name") or catalog["name"],
                    "status": entry.get("status", "entitled"),
                    "detail": entry.get("detail") or catalog["detail"],
                }
            )
        fields["modules"] = normalized

    quotas = fields.get("quotas")
    if isinstance(quotas, dict) and "nodes" not in quotas:
        pools = quotas.get("pools")
        if isinstance(pools, list):
            total = sum(
                pool["quota_nodes"]
                for pool in pools
                if isinstance(pool, dict)
                and isinstance(pool.get("quota_nodes"), int)
                and not isinstance(pool.get("quota_nodes"), bool)
            )
            if total:
                fields["quotas"] = dict(quotas, nodes=total)

    generator = get_generator(config)
    license_obj = generator.generate_license(**fields)
    envelope = generator.build_license_file(license_obj, algorithm, file_format)
    return client.post("/api/v1/licenses/import", json=envelope, headers=ADMIN)


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
        assert "Enterprise Licensing, Tier Entitlements &amp; Node Quotas" in html
        assert "workspace_premium" in html            # sidebar item present
        assert "Licensing &amp; Entitlements" in html  # sidebar label matches the spec
        assert "'api/v1/'" in html                    # wired to this server's API
        assert "cdn.tailwindcss.com" in html          # suite design system
        assert "X-Admin-Token" in html                # admin auth plumbing


def test_admin_endpoints_require_token(client):
    envelope = vendor_sign(client, sample_claims())

    assert client.post("/api/v1/licenses/import", json=envelope).status_code == 401
    bad = client.post(
        "/api/v1/licenses/import",
        json=envelope,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert bad.status_code == 401
    assert "error" in bad.get_json()

    ok = client.post(
        "/api/v1/licenses/import",
        json=envelope,
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
# installing vendor-signed licenses
# ---------------------------------------------------------------------------
def test_import_license_round_trip(client):
    response = install(client, features=["ip_discovery"], usage_limits={"max_users": 10})
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

    # the imported file validates immediately
    validated = client.post("/api/v1/licenses/validate", json=license_file).get_json()
    assert validated["valid"] is True
    assert validated["status"] == "valid"
    assert validated["registered"] is True
    assert validated["matches_registered_record"] is True
    assert validated["license"]["issued_to"] == "Acme Ltd"


def test_install_applies_defaults_per_type(client):
    trial = install(client, license_type="trial", issued_to="Trial Co").get_json()["license"]
    assert trial["days_until_expiry"] == 30
    assert trial["usage_limits"] == {"max_users": 5, "max_subnets": 100, "max_devices": 1000}

    perpetual = install(client, license_type="perpetual", issued_to="Perp Co").get_json()["license"]
    assert perpetual["expires_on"] is None
    assert perpetual["days_until_expiry"] is None
    assert perpetual["effective_status"] == "valid"


# ---------------------------------------------------------------------------
# listing / reading
# ---------------------------------------------------------------------------
def test_list_filter_and_paginate(client):
    install(client, license_type="trial", issued_to="Trial Co")
    install(client, license_type="subscription", issued_to="Sub Co")

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
    created = install(client).get_json()["license"]
    response = client.get(f"/api/v1/licenses/{created['license_key']}")
    assert response.status_code == 200
    detail = response.get_json()["license"]
    assert detail["license_key"] == created["license_key"]
    assert [event["action"] for event in detail["events"]] == ["imported"]

    missing = client.get("/api/v1/licenses/NOT-A-REAL-KEY")
    assert missing.status_code == 404


def test_download_license_file_round_trip(client, config):
    created = install(client).get_json()["license"]
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
    created = install(client).get_json()["license"]
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
    assert [event["action"] for event in detail["events"]] == ["imported", "revoked", "restored"]


def test_revoke_requires_token(client):
    created = install(client).get_json()["license"]
    response = client.post(f"/api/v1/licenses/{created['license_key']}/revoke", json={})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def test_validate_tampered_payload_fails(client):
    license_file = install(client).get_json()["license_file"]
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
    created = install(
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
    created = install(client).get_json()["license"]
    key = created["license_key"]
    client.post(f"/api/v1/licenses/{key}/revoke", json={"reason": "fraud"}, headers=ADMIN)

    result = client.post(f"/api/v1/licenses/{key}/check", json={"feature": "ip_discovery"}).get_json()
    assert result["active"] is False
    assert result["feature_allowed"] is False


# ---------------------------------------------------------------------------
# enterprise spec: algorithms, formats, tiers, quotas, modules, usage
# ---------------------------------------------------------------------------
def test_meta_endpoint_lists_capabilities(client):
    meta = client.get("/api/v1/meta").get_json()
    assert meta["algorithms"] == ["RSA-PSS-SHA256", "Ed25519"]
    assert meta["formats"] == ["json", "jwt"]
    assert meta["license_types"] == ["trial", "subscription", "perpetual", "enterprise"]
    assert "hard-block" in meta["enforcement_levels"]
    assert len(meta["modules"]) == 8
    assert {"id", "name", "icon", "detail", "description"} <= set(meta["modules"][0])
    assert "nodes" in meta["quota_fields"] and "sessions_active" in meta["usage_fields"]


def test_health_reports_algorithms_and_key_state(client):
    data = client.get("/health").get_json()
    assert data["algorithms"] == ["RSA-PSS-SHA256", "Ed25519"]
    assert data["formats"] == ["json", "jwt"]
    # Ed25519 keys are created on first use, so a fresh instance reports False
    assert data["ed25519_key"] is False


@pytest.mark.parametrize(
    "algorithm,file_format",
    [
        ("RSA-PSS-SHA256", "json"),
        ("RSA-PSS-SHA256", "jwt"),
        ("Ed25519", "json"),
        ("Ed25519", "jwt"),
    ],
)
def test_import_with_algorithm_and_format_round_trips(client, algorithm, file_format):
    created = install(client, algorithm=algorithm, format=file_format).get_json()
    license_file = created["license_file"]
    record = created["license"]

    assert license_file["algorithm"] == algorithm
    assert license_file["format"] == file_format
    assert license_file["fingerprint"].startswith("sha256:")
    assert record["algorithm"] == algorithm
    assert record["signature_format"] == file_format
    assert record["fingerprint"] == license_file["fingerprint"]

    payload = license_file if file_format == "json" else {"token": created["token"]}
    result = client.post("/api/v1/licenses/validate", json=payload).get_json()
    assert result["valid"] is True, result
    assert result["algorithm"] == algorithm
    assert result["format"] == file_format
    assert result["matches_registered_record"] is True

    # Downloaded bytes validate too: a compact token can be POSTed raw.
    download = client.get(
        f"/api/v1/licenses/{record['license_key']}/file?format={file_format}",
        headers=ADMIN,
    )
    assert download.status_code == 200
    raw = download.get_data(as_text=True)
    if file_format == "jwt":
        assert len(raw.strip().split(".")) == 3
        from_raw = client.post(
            "/api/v1/licenses/validate", data=raw, content_type="text/plain"
        ).get_json()
        assert from_raw["valid"] is True
    else:
        assert json.loads(raw)["license_data"]["license_key"] == record["license_key"]


def test_import_rejects_unknown_algorithm_or_format(client):
    bad_algorithm = import_signed(client, sample_claims(), algorithm="DSA-1024")
    assert bad_algorithm.status_code == 400
    assert bad_algorithm.get_json()["details"]["allowed"] == [
        "RSA-PSS-SHA256", "Ed25519"
    ]
    assert import_signed(client, sample_claims(), format="xml").status_code == 400


def test_enterprise_spec_fields_are_signed_and_returned(client):
    created = install(
        client,
        license_type="enterprise",
        issued_to="Aegis Global Financial Technologies Inc.",
        tier="ENTERPRISE ZSP ULTIMATE",
        plan="Annual Multi-Cloud",
        license_id="LIC-9942-AEGIS-SEC-PROD",
        subject_entity="Aegis Global Financial Technologies Inc.",
        classification="Air-Gapped Production Enterprise (Multi-Region)",
        enclave_binding="TPM 2.0 PCR Registers 0 & 7",
        account={
            "customer_id": "CUST-88219-ENT",
            "tam": "Sarah Jenkins",
            "tam_email": "sjenkins@aegispam.security",
            "sla_response": "15-Minute Priority",
            "po_number": "PO-2025-0914",
        },
        quotas={
            "concurrent_sessions": 40,
            "bastion_tunnels": 1000,
            "max_lease_hours": 4,
            "worm_retention_days": 2555,
            "pools": [
                {"id": "aws-prod", "name": "AWS Production",
                 "regions": ["us-east-1", "us-west-2"], "quota_nodes": 2000,
                 "enforcement": "soft-warning"},
                {"id": "k8s-core", "name": "Kubernetes Clusters",
                 "regions": ["EKS & GKE Core Mesh"], "quota_nodes": 1500,
                 "enforcement": "auto-scale"},
                {"id": "baremetal", "name": "Bare-Metal & Bastions",
                 "regions": ["DirectConnect On-Prem"], "quota_nodes": 800,
                 "enforcement": "audit-log"},
                {"id": "staging", "name": "Multi-Tenant Staging",
                 "regions": ["Sandbox & QA VPCs"], "quota_nodes": 700,
                 "enforcement": "hard-block"},
            ],
        },
        modules=[{"id": "hsm_integration"}, {"id": "zsp_dynamic_leases"}],
    ).get_json()

    record = created["license"]
    assert record["tier"] == "ENTERPRISE ZSP ULTIMATE"
    assert record["plan"] == "Annual Multi-Cloud"
    assert record["license_id"] == "LIC-9942-AEGIS-SEC-PROD"
    assert record["subject_entity"] == "Aegis Global Financial Technologies Inc."
    assert record["classification"].startswith("Air-Gapped Production")
    assert record["issuer"].endswith("(Air-Gap Root)")
    assert record["enclave_binding"] == "TPM 2.0 PCR Registers 0 & 7"
    assert record["account"]["customer_id"] == "CUST-88219-ENT"
    # nodes ceiling derived from the pools when not given explicitly
    assert record["quotas"]["nodes"] == 5000
    # module details are backfilled from the catalog
    assert [m["id"] for m in record["modules"]] == ["hsm_integration", "zsp_dynamic_leases"]
    assert record["modules"][0]["name"] == "HSM Integration"
    assert record["modules"][0]["status"] == "entitled"

    # the spec fields are inside the signed claims, not just the response
    validated = client.post(
        "/api/v1/licenses/validate", json=created["license_file"]
    ).get_json()
    assert validated["valid"] is True
    assert validated["license"]["license_id"] == "LIC-9942-AEGIS-SEC-PROD"
    assert validated["license"]["entitled_modules"] == [
        "hsm_integration", "zsp_dynamic_leases"
    ]
    assert validated["fingerprint"] == record["fingerprint"]


def test_lookup_by_license_id(client):
    created = install(client, license_id="LIC-1234-AEGIS-SEC-PROD").get_json()["license"]
    detail = client.get("/api/v1/licenses/LIC-1234-AEGIS-SEC-PROD").get_json()["license"]
    assert detail["license_key"] == created["license_key"]


@pytest.mark.parametrize(
    "overrides",
    [
        # the issuing form's rules, now enforced where vendor files land:
        {"license_type": None},
        {"license_type": "lifetime"},
        {"issued_to": ""},
        {"features": "ip_discovery"},
        {"usage_limits": {"max_users": "ten"}},
        {"metadata": []},
        {"quotas": {"nonsense": 1}},
        {"quotas": {"nodes": -1}},
        {"quotas": {"pools": [{"id": "x"}]}},
        {
            "quotas": {
                "pools": [
                    {
                        "id": "p",
                        "name": "P",
                        "quota_nodes": 1,
                        "enforcement": "explode",
                    }
                ]
            }
        },
        {"modules": [{"id": "made_up_module"}]},
        {"modules": ["hsm_integration"]},
        {"account": {"customer_id": {"nested": True}}},
        {"tier": 123},
    ],
)
def test_import_rejects_invalid_claims(client, overrides):
    response = import_signed(client, sample_claims(**overrides))
    assert response.status_code == 400, response.get_json()
    assert "error" in response.get_json()


def test_import_rejects_unusable_files(client):
    # not an envelope at all
    assert (
        client.post("/api/v1/licenses/import", json={}, headers=ADMIN).status_code
        == 400
    )
    # an envelope whose signature is not a signature
    assert (
        import_signed(client, sample_claims(), signature="not-a-signature").status_code
        == 400
    )


def test_import_rejects_foreign_signature(client):
    """A file signed with somebody else's key is not installable."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = sample_claims()
    signature = foreign_key.sign(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    response = client.post(
        "/api/v1/licenses/import",
        json={"license_data": claims, "signature": base64.b64encode(signature).decode()},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert "trusted vendor key" in response.get_json()["error"]


def test_import_rejects_expired_license(client):
    claims = sample_claims(
        issued_date=(datetime.now() - timedelta(days=60)).isoformat(),
        expires_on=(datetime.now() - timedelta(days=10)).isoformat(),
    )
    response = import_signed(client, claims)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "expires_on"


def test_import_conflict_for_already_installed_license(client):
    envelope = vendor_sign(client, sample_claims())
    first = client.post("/api/v1/licenses/import", json=envelope, headers=ADMIN)
    assert first.status_code == 201

    second = client.post("/api/v1/licenses/import", json=envelope, headers=ADMIN)
    assert second.status_code == 409
    assert second.get_json()["details"]["status"] == "active"


def test_usage_reporting_requires_admin(client):
    created = install(client, license_type="enterprise").get_json()["license"]
    response = client.post(
        f"/api/v1/licenses/{created['license_key']}/usage",
        json={"sessions_active": 1},
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        {"typo_field": 1},
        {"nodes_consumed": -5},
        {"sessions_active": "many"},
        {"pools": [{"id": "unknown-pool", "nodes_consumed": 1}]},
        {"pools": [{"id": "aws-prod", "nodes_consumed": "lots"}]},
        {"pools": "aws-prod"},
    ],
)
def test_usage_reporting_validates_input(client, payload):
    created = install(client, license_type="enterprise").get_json()["license"]
    response = client.post(
        f"/api/v1/licenses/{created['license_key']}/usage",
        json=payload,
        headers=ADMIN,
    )
    assert response.status_code == 400, payload


def test_usage_reporting_computes_utilisation(client):
    created = install(client, license_type="enterprise").get_json()["license"]
    key = created["license_key"]

    # nothing reported yet: ceilings are known, consumption is zero
    assert created["usage"]["reported"] is False
    assert created["usage"]["nodes"]["quota"] == 5000
    assert created["usage"]["nodes"]["consumed"] == 0
    assert created["usage"]["nodes"]["utilization"] == 0

    response = client.post(
        f"/api/v1/licenses/{key}/usage",
        json={
            "sessions_active": 14,
            "bastion_tunnels_used": 482,
            "pools": [
                {"id": "aws-prod", "nodes_consumed": 1420},
                {"id": "k8s-core", "nodes_consumed": 840},
                {"id": "baremetal", "nodes_consumed": 385},
                {"id": "staging", "nodes_consumed": 230},
            ],
        },
        headers=ADMIN,
    )
    assert response.status_code == 201
    usage = response.get_json()["usage"]

    assert usage["reported"] is True
    assert usage["reported_at"] is not None
    assert usage["nodes"] == {
        "quota": 5000, "consumed": 2875, "headroom": 2125,
        "utilization": 0.575, "over_quota": False,
    }
    assert usage["concurrent_sessions"]["consumed"] == 14
    assert usage["bastion_tunnels"]["consumed"] == 482

    aws = next(pool for pool in usage["pools"] if pool["id"] == "aws-prod")
    assert aws["quota_nodes"] == 2000
    assert aws["consumed"] == 1420
    assert aws["utilization"] == 0.71
    assert aws["headroom"] == 580
    assert aws["enforcement"] == "soft-warning"
    assert aws["regions"] == ["us-east-1", "us-west-2"]

    # an over-quota report is flagged rather than silently clamped
    over = client.post(
        f"/api/v1/licenses/{key}/usage",
        json={"pools": [{"id": "staging", "nodes_consumed": 701}]},
        headers=ADMIN,
    ).get_json()["usage"]
    staging = next(pool for pool in over["pools"] if pool["id"] == "staging")
    assert staging["over_quota"] is True
    assert staging["headroom"] == 0

    events = client.get(f"/api/v1/licenses/{key}").get_json()["license"]["events"]
    assert [event["action"] for event in events] == [
        "imported", "usage_reported", "usage_reported"
    ]


def test_module_access_checks(client):
    enterprise = install(client, license_type="enterprise").get_json()["license"]
    allowed = client.post(
        f"/api/v1/licenses/{enterprise['license_key']}/check",
        json={"module_id": "shamir_breakglass"},
    ).get_json()
    assert allowed["module_allowed"] is True

    trial = install(client, license_type="trial").get_json()["license"]
    denied = client.post(
        f"/api/v1/licenses/{trial['license_key']}/check",
        json={"module_id": "shamir_breakglass"},
    ).get_json()
    assert denied["module_allowed"] is False

    assert (
        client.post(
            f"/api/v1/licenses/{trial['license_key']}/check",
            json={"module_id": "not_a_module"},
        ).status_code
        == 400
    )


def test_quota_limits_are_checkable(client):
    created = install(client, license_type="enterprise").get_json()["license"]
    result = client.post(
        f"/api/v1/licenses/{created['license_key']}/check",
        json={"limit_type": "nodes", "current_usage": 4999},
    ).get_json()
    assert result["limit"] == 5000
    assert result["limit_allowed"] is True

    over = client.post(
        f"/api/v1/licenses/{created['license_key']}/check",
        json={"limit_type": "nodes", "current_usage": 5001},
    ).get_json()
    assert over["limit_allowed"] is False


def test_schema_migration_is_idempotent(client):
    from extensions import db
    from models import ensure_schema

    with client.application.app_context():
        assert ensure_schema(db.engine) == []
        assert ensure_schema(db.engine) == []


def test_record_written_before_the_spec_round_trips(config, client):
    """Rows that predate tier/quotas/modules still serve and verify."""
    from datetime import datetime as dt

    from extensions import db
    from licensing_bridge import LicenseType
    from models import LicenseRecord

    with client.application.app_context():
        generator = get_generator(config)
        license_obj = generator.generate_license(
            license_type=LicenseType.TRIAL, issued_to="Legacy Ltd"
        )
        # a pre-spec record carried none of the commercial fields
        license_obj.tier = None
        license_obj.plan = None
        license_obj.license_id = None
        license_obj.subject_entity = None
        license_obj.classification = None
        license_obj.issuer = None
        license_obj.enclave_binding = None
        license_obj.quotas = {}
        license_obj.modules = []
        license_obj.account = {}
        claims = license_obj.to_dict()

        record = LicenseRecord(
            license_key=claims["license_key"],
            license_type="trial",
            issued_to="Legacy Ltd",
            issued_date=license_obj.issued_date,
            expires_on=license_obj.expires_on,
            features=claims["features"],
            usage_limits=claims["usage_limits"],
            license_metadata={},
            status="active",
            signature=generator.sign_license(claims),
            algorithm="RSA-PSS-SHA256",
        )
        db.session.add(record)
        db.session.commit()
        key = record.license_key

    detail = client.get(f"/api/v1/licenses/{key}").get_json()["license"]
    assert detail["tier"] is None
    assert detail["quotas"] == {}
    assert detail["modules"] == []
    assert detail["fingerprint"].startswith("sha256:")
    assert detail["usage"]["nodes"]["quota"] == 0
    assert detail["signature_format"] == "json"

    # the rebuilt envelope still verifies and matches the stored signature
    envelope = client.get(
        f"/api/v1/licenses/{key}/file", headers=ADMIN
    ).get_json()
    assert "tier" not in envelope["license_data"]
    result = client.post("/api/v1/licenses/validate", json=envelope).get_json()
    assert result["valid"] is True
    assert result["matches_registered_record"] is True
