"""License issuance tests: signed claims, encrypted archive, renewal,
delivery bundle (offline-verifiable), audit trail — all asserted against
exactly what the shared engine and this server produce.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timedelta

from pam_master import crypto
from pam_master.app import create_app
from pam_master.config import Config
from pam_master.keys import load_registry_key
from pam_master.licensing import (
    DEFAULT_MODULE_IDS,
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_IDS,
    LicenseType,
    get_generator,
    sig,
)

CUSTOMER = {
    "name": "Northwind Trading",
    "region": "eu-central",
    "contact_email": "ops@northwind.example",
}


def _create_customer(client) -> str:
    response = client.post("/api/v1/customers", json=dict(CUSTOMER))
    assert response.status_code == 201, response.get_data(as_text=True)
    return response.get_json()["public_id"]


def _issue(client, customer_pid, body):
    response = client.post(
        f"/api/v1/customers/{customer_pid}/licenses", json=body
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    return response.get_json()


def _archive(config, license_id) -> dict:
    """Decrypt the stored archive the way the server itself does."""
    import sqlite3
    from contextlib import closing

    from pam_master import db

    with closing(db.connect(config)) as connection:
        row = connection.execute(
            "SELECT archive_ct FROM licenses WHERE license_id = ?",
            (license_id,),
        ).fetchone()
    return crypto.decrypt_payload(
        load_registry_key(config), license_id, row["archive_ct"]
    )


# ----------------------------------------------------------------- catalog --
def test_license_options_is_the_engine_catalog(client):
    payload = client.get("/api/v1/license-options").get_json()
    assert [t["value"] for t in payload["license_types"]] == [
        t.value for t in LicenseType
    ]
    defaults = {
        t["value"]: t["default_validity_days"]
        for t in payload["license_types"]
    }
    # Real engine behavior: trial 30d, subscription 365d, no expiry for
    # perpetual/enterprise.
    assert defaults == {
        "trial": 30,
        "subscription": 365,
        "perpetual": None,
        "enterprise": None,
    }
    assert [m["id"] for m in payload["modules"]] == MODULE_IDS
    assert payload["algorithms"] == list(sig.SUPPORTED_ALGORITHMS)
    assert payload["enforcement_levels"] == list(ENFORCEMENT_LEVELS)
    trial = next(t for t in payload["license_types"] if t["value"] == "trial")
    assert trial["default_modules"] == DEFAULT_MODULE_IDS[LicenseType.TRIAL]


# ------------------------------------------------------------------ issue --
def test_issue_signs_records_and_verifies(config, client):
    customer_pid = _create_customer(client)
    record = _issue(
        client,
        customer_pid,
        {
            "license_type": "subscription",
            "validity_days": 90,
            "modules": ["zsp_dynamic_leases", "worm_audit_ledger"],
            "environment": "PROD",
        },
    )
    assert record["status"] == "active"
    assert record["license_type"] == "subscription"
    assert record["tier"] == DEFAULT_TIERS[LicenseType.SUBSCRIPTION]
    assert record["format"] == "json"
    assert record["algorithm"] == sig.DEFAULT_ALGORITHM
    assert record["customer_public_id"] == customer_pid
    assert record["license_id"].startswith("LIC-")
    assert record["license_id"].endswith("-PROD")
    assert record["superseded_by"] is None

    # Custom validity: exactly the requested 90 days, from the real claims.
    issued = datetime.fromisoformat(record["issued_date"])
    expires = datetime.fromisoformat(record["expires_on"])
    assert expires - issued == timedelta(days=90)

    # Live signature verification with the shared engine.
    envelope = _archive(config, record["license_id"])
    generator = get_generator(config)
    pem = generator.get_public_key_pem(record["algorithm"])
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
    )

    public_key = load_pem_public_key(pem if isinstance(pem, bytes) else pem.encode("ascii"))
    assert sig.verify_envelope(public_key, envelope)

    claims = envelope["license_data"]
    assert claims["issued_to"] == CUSTOMER["name"]
    assert claims["metadata"]["customer_ref"] == customer_pid
    assert [m["id"] for m in claims["modules"]] == [
        "zsp_dynamic_leases",
        "worm_audit_ledger",
    ]
    assert record["license_id"] == claims["license_id"]

    # History + audit + list all reflect the issuance.
    history = client.get(
        f"/api/v1/customers/{customer_pid}/issuance-history"
    ).get_json()
    assert history["total"] == 1
    assert history["actions"][0]["action"] == "issued"
    assert history["actions"][0]["license_id"] == record["license_id"]
    audit = client.get("/api/v1/audit").get_json()
    assert audit["events"][0]["action"] == "license_issued"
    listing = client.get("/api/v1/licenses").get_json()
    assert listing["total"] == 1
    assert listing["licenses"][0] == record
    detail = client.get(
        f"/api/v1/licenses/{record['license_id']}"
    ).get_json()
    assert detail == record


def test_archive_holds_the_pii_not_the_database(config, client):
    customer_pid = _create_customer(client)
    record = _issue(
        client, customer_pid, {"license_type": "enterprise"}
    )
    database_bytes = config.database_path.read_bytes()
    # The licensee name goes into the signed claims -> encrypted archive.
    assert CUSTOMER["name"].encode("utf-8") not in database_bytes
    assert CUSTOMER["contact_email"].encode("utf-8") not in database_bytes
    # The license id itself is a non-PII lookup key stored in plaintext.
    assert record["license_id"].encode("ascii") in database_bytes

    envelope = _archive(config, record["license_id"])
    assert envelope["license_data"]["issued_to"] == CUSTOMER["name"]
    assert envelope["algorithm"] == record["algorithm"]


def test_perpetual_without_validity_never_expires(config, client):
    customer_pid = _create_customer(client)
    record = _issue(client, customer_pid, {"license_type": "perpetual"})
    assert record["expires_on"] is None
    envelope = _archive(config, record["license_id"])
    assert envelope["license_data"]["expires_on"] is None
    assert record["tier"] == DEFAULT_TIERS[LicenseType.PERPETUAL]


# -------------------------------------------------------------- validation --
def test_issue_validation_is_specific(client):
    customer_pid = _create_customer(client)
    base = f"/api/v1/customers/{customer_pid}/licenses"

    def message_of(body):
        response = client.post(base, json=body)
        assert response.status_code == 400, response.get_data(as_text=True)
        return response.get_json()["error"]["message"]

    assert "license_type" in message_of({})
    assert "one of" in message_of({"license_type": "floating"})
    assert "unknown module" in message_of(
        {"license_type": "trial", "modules": ["teleport"]}
    )
    assert "non-empty" in message_of(
        {"license_type": "trial", "modules": []}
    )
    assert "integer" in message_of(
        {"license_type": "trial", "validity_days": "90"}
    )
    assert "between 1 and 3650" in message_of(
        {"license_type": "trial", "validity_days": 9999}
    )
    assert "between 1 and 3650" in message_of(
        {"license_type": "trial", "validity_days": 0}
    )
    assert "algorithm" in message_of(
        {"license_type": "trial", "algorithm": "DSA"}
    )
    assert "quotas" in message_of(
        {"license_type": "trial", "quotas": [1, 2]}
    )
    assert "quotas" in message_of(
        {"license_type": "trial", "quotas": {"a": {"b": {"c": {"d": 1}}}}}
    )
    assert "environment" in message_of(
        {"license_type": "trial", "environment": "prod east"}
    )
    assert "unknown field" in message_of(
        {"license_type": "trial", "seats": 12}
    )
    no_body = client.post(base, data="not json")
    assert no_body.status_code == 400

    missing = client.post(
        f"/api/v1/customers/{'0' * 32}/licenses",
        json={"license_type": "trial"},
    )
    assert missing.status_code == 404
    assert missing.get_json()["error"]["type"] == "customer_not_found"


# ----------------------------------------------------------------- renew --
def test_renew_supersedes_and_links_history(config, client):
    customer_pid = _create_customer(client)
    first = _issue(
        client, customer_pid, {"license_type": "subscription"}
    )
    renewed = client.post(
        f"/api/v1/licenses/{first['license_id']}/renew",
        json={"license_type": "subscription", "validity_days": 365},
    )
    assert renewed.status_code == 201, renewed.get_data(as_text=True)
    second = renewed.get_json()
    assert second["license_id"] != first["license_id"]
    assert second["customer_public_id"] == customer_pid
    assert second["status"] == "active"

    old = client.get(f"/api/v1/licenses/{first['license_id']}").get_json()
    assert old["status"] == "superseded"
    assert old["superseded_by"] == second["license_id"]

    history = client.get(
        f"/api/v1/customers/{customer_pid}/issuance-history"
    ).get_json()
    assert [entry["action"] for entry in history["actions"]] == [
        "renewed",
        "issued",
    ]
    assert history["actions"][0]["detail"]["renews"] == first["license_id"]

    audit = client.get("/api/v1/audit").get_json()
    renewed_event = next(
        e for e in audit["events"] if e["action"] == "license_renewed"
    )
    assert renewed_event["detail"]["replaces"] == first["license_id"]

    # The new signed claims carry the provenance link.
    envelope = _archive(config, second["license_id"])
    assert envelope["license_data"]["metadata"]["renews"] == (
        first["license_id"]
    )


def test_renew_only_works_on_active_licenses(config, client):
    customer_pid = _create_customer(client)
    first = _issue(
        client, customer_pid, {"license_type": "subscription"}
    )
    client.post(
        f"/api/v1/licenses/{first['license_id']}/renew",
        json={"license_type": "subscription"},
    )
    again = client.post(
        f"/api/v1/licenses/{first['license_id']}/renew",
        json={"license_type": "subscription"},
    )
    assert again.status_code == 409
    assert again.get_json()["error"]["type"] == "license_not_active"

    missing = client.post(
        "/api/v1/licenses/LIC-0000-NOPE/renew",
        json={"license_type": "trial"},
    )
    assert missing.status_code == 404
    assert missing.get_json()["error"]["type"] == "license_not_found"


# ----------------------------------------------------------------- bundle --
def test_bundle_is_offline_verifiable(config, client):
    customer_pid = _create_customer(client)
    record = _issue(
        client, customer_pid, {"license_type": "subscription"}
    )
    response = client.get(
        f"/api/v1/licenses/{record['license_id']}/bundle"
    )
    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    expected_name = f"vy-pam-{record['license_id']}-bundle.zip"
    assert expected_name in response.headers["Content-Disposition"]

    with zipfile.ZipFile(io.BytesIO(response.data)) as bundle:
        assert set(bundle.namelist()) == {
            f"{record['license_id']}.lic",
            "license_public_key.pem",
            "README.txt",
            "SHA256SUMS.txt",
        }
        # License file verifies with ONLY the bundle's own contents —
        # exactly what the customer can do offline.
        envelope = json.loads(
            bundle.read(f"{record['license_id']}.lic")
        )
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )

        public_key = load_pem_public_key(bundle.read("license_public_key.pem"))
        assert sig.verify_envelope(public_key, envelope)
        assert envelope["license_data"]["license_id"] == record["license_id"]

        # Checksums are real: recompute each SHA-256.
        sums = bundle.read("SHA256SUMS.txt").decode("ascii").splitlines()
        parsed = dict(
            reversed(line.split("  ", 1)) for line in sums if line
        )
        for name in (
            f"{record['license_id']}.lic",
            "license_public_key.pem",
            "README.txt",
        ):
            digest = hashlib.sha256(bundle.read(name)).hexdigest()
            assert parsed[name] == digest, name

        readme = bundle.read("README.txt").decode("utf-8")
        assert record["license_id"] in readme
        assert record["algorithm"] in readme

    # The export itself was audited.
    audit = client.get("/api/v1/audit").get_json()
    assert audit["events"][0]["action"] == "license_bundle_exported"
    assert audit["events"][0]["subject"] == record["license_id"]


# ----------------------------------------------------- honest failure modes --
def test_missing_signing_custody_is_503(tmp_path, config):
    customer_pid = _create_customer(create_app(config).test_client())

    # Same database + registry key, but no signing keys at all.
    broken = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{config.database_path}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(
                tmp_path / "absent_rsa.pem"
            ),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(
                tmp_path / "absent_ed.pem"
            ),
            "MASTER_CUSTOMER_KEY_PATH": str(config.customer_key_path),
        }
    )
    broken_client = create_app(broken).test_client()

    issued = broken_client.post(
        f"/api/v1/customers/{customer_pid}/licenses",
        json={"license_type": "trial"},
    )
    assert issued.status_code == 503
    assert issued.get_json()["error"]["type"] == "signing_unavailable"

    # A previously issued license still exports its metadata but not its
    # bundle (the public key comes from custody).
    good = _issue(
        create_app(config).test_client(),
        customer_pid,
        {"license_type": "trial"},
    )
    assert (
        broken_client.get(f"/api/v1/licenses/{good['license_id']}").status_code
        == 200
    )
    bundle = broken_client.get(
        f"/api/v1/licenses/{good['license_id']}/bundle"
    )
    assert bundle.status_code == 503
    assert bundle.get_json()["error"]["type"] == "signing_unavailable"


def test_missing_registry_key_blocks_issuance(tmp_path):
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(tmp_path / "ed.pem"),
            "MASTER_CUSTOMER_KEY_PATH": str(
                tmp_path / "absent_registry.key"
            ),
        }
    )
    client = create_app(config).test_client()
    response = client.post(
        f"/api/v1/customers/{'0' * 32}/licenses",
        json={"license_type": "trial"},
    )
    assert response.status_code == 503
    assert response.get_json()["error"]["type"] == "registry_unavailable"


# ------------------------------------------------------------ list filters --
def test_license_list_filters(config, client):
    alice = _create_customer(client)
    bob = _create_customer(client)
    _issue(client, alice, {"license_type": "trial"})
    _issue(client, alice, {"license_type": "subscription"})
    first_bob = _issue(client, bob, {"license_type": "enterprise"})
    client.post(
        f"/api/v1/licenses/{first_bob['license_id']}/renew",
        json={"license_type": "enterprise"},
    )

    everything = client.get("/api/v1/licenses").get_json()
    assert everything["total"] == 4

    only_bob = client.get(
        f"/api/v1/licenses?customer={bob}"
    ).get_json()
    assert only_bob["total"] == 2
    assert {lic["customer_public_id"] for lic in only_bob["licenses"]} == {
        bob
    }

    active = client.get("/api/v1/licenses?status=active").get_json()
    assert active["total"] == 3
    superseded = client.get(
        "/api/v1/licenses?status=superseded"
    ).get_json()
    assert superseded["total"] == 1
    assert superseded["licenses"][0]["license_id"] == (
        first_bob["license_id"]
    )

    paged = client.get("/api/v1/licenses?limit=2").get_json()
    assert len(paged["licenses"]) == 2
    assert paged["total"] == 4

    assert (
        client.get("/api/v1/licenses?status=revoked").status_code == 400
    )
    assert (
        client.get(f"/api/v1/licenses?customer={'0' * 32}").status_code
        == 404
    )
    assert (
        client.get("/api/v1/licenses?customer=oops").status_code == 400
    )


def test_audit_sequence_is_exact(config, client):
    customer_pid = _create_customer(client)
    first = _issue(
        client, customer_pid, {"license_type": "subscription"}
    )
    second_response = client.post(
        f"/api/v1/licenses/{first['license_id']}/renew",
        json={"license_type": "subscription"},
    )
    second = second_response.get_json()
    client.get(f"/api/v1/licenses/{second['license_id']}/bundle")

    audit = client.get("/api/v1/audit").get_json()
    assert [event["action"] for event in audit["events"]] == [
        "license_bundle_exported",
        "license_renewed",
        "license_issued",
    ]
    assert audit["total"] == 3
