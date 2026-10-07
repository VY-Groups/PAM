"""Customer registry tests: HTTP CRUD, PII encrypted at rest, honest failures.

Fixture data is synthetic (tests are allowed fixtures); assertions compare
against exactly what was written — nothing is inferred.
"""
from __future__ import annotations

import json
from datetime import datetime

import pytest

from pam_master import crypto, registry
from pam_master.app import create_app
from pam_master.config import Config
from pam_master.keys import load_registry_key

SAMPLE = {
    "name": "Acme Heavy Industries",
    "region": "eu-central",
    "contact_name": "Dana Holt",
    "contact_email": "dana.holt@acme.example",
    "contact_phone": "+49 30 555 0142",
    "notes": "air-gapped deployment, renewal Q4",
}


def _create(client, **overrides):
    body = dict(SAMPLE, **overrides)
    response = client.post("/api/v1/customers", json=body)
    assert response.status_code == 201, response.get_data(as_text=True)
    return response.get_json()


def _config_without_registry_key(tmp_path):
    return Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(tmp_path / "ed.pem"),
            "MASTER_CUSTOMER_KEY_PATH": str(
                tmp_path / "absent_registry.key"
            ),
        }
    )


# ------------------------------------------------------------ happy path --
def test_create_returns_201_with_decrypted_record(client):
    response = client.post("/api/v1/customers", json=dict(SAMPLE))
    assert response.status_code == 201
    record = response.get_json()
    assert record["name"] == SAMPLE["name"]
    assert record["region"] == SAMPLE["region"]
    assert record["contact_email"] == SAMPLE["contact_email"]
    assert record["notes"] == SAMPLE["notes"]
    assert len(record["public_id"]) == 32
    assert response.headers["Location"].endswith(record["public_id"])
    created = datetime.fromisoformat(record["created_at"])
    updated = datetime.fromisoformat(record["updated_at"])
    assert created.tzinfo is not None
    assert updated.tzinfo is not None


def test_list_get_edit_cycle(client):
    created = _create(client)
    public_id = created["public_id"]

    listing = client.get("/api/v1/customers").get_json()
    assert listing["total"] == 1
    assert listing["limit"] == 50
    assert listing["offset"] == 0
    assert listing["customers"][0]["public_id"] == public_id

    fetched = client.get(f"/api/v1/customers/{public_id}").get_json()
    assert fetched == created

    edited = client.patch(
        f"/api/v1/customers/{public_id}",
        json={"region": "us-east", "notes": None},
    )
    assert edited.status_code == 200
    record = edited.get_json()
    assert record["region"] == "us-east"
    assert record["notes"] is None
    # untouched fields survive the merge
    assert record["name"] == SAMPLE["name"]
    assert record["contact_email"] == SAMPLE["contact_email"]

    again = client.get(f"/api/v1/customers/{public_id}").get_json()
    assert again == record


def test_pagination_is_real(client):
    for index in range(3):
        _create(client, name=f"Customer {index}")
    page = client.get(
        "/api/v1/customers?limit=2"
    ).get_json()
    assert page["total"] == 3
    assert len(page["customers"]) == 2
    # newest-first ordering
    assert page["customers"][0]["name"] == "Customer 2"
    tail = client.get(
        "/api/v1/customers?limit=2&offset=2"
    ).get_json()
    assert tail["total"] == 3
    assert len(tail["customers"]) == 1
    assert tail["customers"][0]["name"] == "Customer 0"


# ------------------------------------------------- PII encrypted at rest --
def test_pii_is_encrypted_at_rest(config, client):
    created = _create(client)
    database_bytes = config.database_path.read_bytes()
    for value in (
        SAMPLE["name"],
        SAMPLE["contact_name"],
        SAMPLE["contact_email"],
        SAMPLE["contact_phone"],
        SAMPLE["notes"],
    ):
        assert value.encode("utf-8") not in database_bytes, (
            f"plaintext PII leaked into the database file: {value!r}"
        )

    # The stored blob is a real AES-256-GCM envelope, decryptable only with
    # the registry key + the row's public_id (AAD).
    import sqlite3
    from contextlib import closing

    from pam_master import db

    with closing(db.connect(config)) as connection:
        row = connection.execute(
            "SELECT public_id, data_ct FROM customers"
        ).fetchone()
    envelope = json.loads(row["data_ct"])
    assert envelope["v"] == 1
    assert envelope["alg"] == "AES-256-GCM"
    key = load_registry_key(config)
    payload = crypto.decrypt_payload(
        key, row["public_id"], row["data_ct"]
    )
    assert payload["name"] == SAMPLE["name"]
    assert payload["notes"] == SAMPLE["notes"]


def test_edit_does_not_leave_plaintext_behind(config, client):
    created = _create(client)
    new_name = "Globex Renamed Holdings"
    response = client.patch(
        f"/api/v1/customers/{created['public_id']}",
        json={"name": new_name},
    )
    assert response.status_code == 200
    assert response.get_json()["name"] == new_name
    database_bytes = config.database_path.read_bytes()
    assert new_name.encode("utf-8") not in database_bytes
    assert SAMPLE["name"].encode("utf-8") not in database_bytes


def test_ciphertext_is_bound_to_the_row(config):
    key = load_registry_key(config)
    blob = crypto.encrypt_payload(key, "a" * 32, {"name": "Row A"})
    # Same key, different row id -> authentication must fail (no blob swap).
    with pytest.raises(crypto.PayloadIntegrityError):
        crypto.decrypt_payload(key, "b" * 32, blob)


def test_tampered_row_returns_honest_500(config, client):
    created = _create(client)
    import sqlite3
    from contextlib import closing

    from pam_master import db

    with closing(db.connect(config)) as connection:
        row = connection.execute(
            "SELECT data_ct FROM customers"
        ).fetchone()
        envelope = json.loads(row["data_ct"])
        ct = envelope["ct"]
        envelope["ct"] = ("B" if ct[0] != "B" else "C") + ct[1:]
        connection.execute(
            "UPDATE customers SET data_ct = ? WHERE public_id = ?",
            (json.dumps(envelope), created["public_id"]),
        )
        connection.commit()

    response = client.get(
        f"/api/v1/customers/{created['public_id']}"
    )
    assert response.status_code == 500
    error = response.get_json()["error"]
    assert error["type"] == "registry_data_corrupt"
    assert "failed authentication" in error["message"]


# ----------------------------------------------------------- validation --
def test_validation_errors_are_specific(client):
    assert client.post(
        "/api/v1/customers", json={}
    ).status_code == 400
    missing = client.post(
        "/api/v1/customers", json={"name": "Only Name"}
    ).get_json()["error"]["message"]
    assert "region" in missing

    bad_email = client.post(
        "/api/v1/customers",
        json=dict(SAMPLE, contact_email="not-an-email"),
    ).get_json()["error"]["message"]
    assert "email" in bad_email

    unknown = client.post(
        "/api/v1/customers", json=dict(SAMPLE, loyalty_tier="gold")
    ).get_json()["error"]["message"]
    assert "loyalty_tier" in unknown

    non_string = client.post(
        "/api/v1/customers", json=dict(SAMPLE, name=123)
    ).get_json()["error"]["message"]
    assert "string" in non_string

    overlong = client.post(
        "/api/v1/customers", json=dict(SAMPLE, name="x" * 201)
    ).get_json()["error"]["message"]
    assert "200" in overlong

    no_body = client.post(
        "/api/v1/customers", data="not json"
    )
    assert no_body.status_code == 400
    assert "JSON object body" in no_body.get_json()["error"]["message"]


def test_edit_validation_errors(client):
    created = _create(client)
    public_id = created["public_id"]
    empty = client.patch(f"/api/v1/customers/{public_id}", json={})
    assert empty.status_code == 400
    assert "at least one" in empty.get_json()["error"]["message"]

    bad_format = client.get("/api/v1/customers/not-a-real-id")
    assert bad_format.status_code == 400
    assert "32 lowercase hex" in bad_format.get_json()["error"]["message"]

    for query in ("?limit=0", "?limit=abc", "?offset=-1"):
        response = client.get(f"/api/v1/customers{query}")
        assert response.status_code == 400, query
        assert response.get_json()["error"]["type"] == "validation_error"


def test_unknown_customer_is_404(client):
    response = client.get("/api/v1/customers/" + "0" * 32)
    assert response.status_code == 404
    error = response.get_json()["error"]
    assert error["type"] == "customer_not_found"
    history = client.get(
        "/api/v1/customers/" + "f" * 32 + "/issuance-history"
    )
    assert history.status_code == 404


# ------------------------------------------------------ key unavailability --
def test_missing_registry_key_is_honest_503(tmp_path):
    config = _config_without_registry_key(tmp_path)
    client = create_app(config).test_client()

    created = client.post("/api/v1/customers", json=dict(SAMPLE))
    assert created.status_code == 503
    error = created.get_json()["error"]
    assert error["type"] == "registry_unavailable"
    assert "keygen" in error["message"]

    assert client.get(
        "/api/v1/customers"
    ).status_code == 503

    health = client.get("/health").get_json()
    assert health["status"] == "ok"
    assert health["registry"]["pii_key"] == "missing"
    assert health["registry"]["ready"] is False


def test_registry_key_via_b64_env(tmp_path):
    import base64

    valid = base64.b64encode(b"\x01" * 32).decode("ascii")
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(tmp_path / "ed.pem"),
            "MASTER_CUSTOMER_KEY_PATH": str(
                tmp_path / "unused_registry.key"
            ),
            "MASTER_CUSTOMER_KEY_B64": valid,
        }
    )
    client = create_app(config).test_client()
    created = client.post("/api/v1/customers", json=dict(SAMPLE))
    assert created.status_code == 201
    health = client.get("/health").get_json()
    assert health["registry"]["pii_key"] == "present"
    # the file was never consulted or created
    assert not config.customer_key_path.exists()

    invalid = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'x.db'}",
            "MASTER_CUSTOMER_KEY_B64": "not-base64!!",
        }
    )
    invalid_client = create_app(invalid).test_client()
    assert invalid_client.get("/health").get_json()[
        "registry"
    ]["pii_key"] == "invalid"
    assert invalid_client.post(
        "/api/v1/customers", json=dict(SAMPLE)
    ).status_code == 503


# ------------------------------------------------------- issuance history --
def test_issuance_history_roundtrip(config, client):
    created = _create(client)
    public_id = created["public_id"]

    empty = client.get(
        f"/api/v1/customers/{public_id}/issuance-history"
    ).get_json()
    assert empty == {
        "customer_public_id": public_id,
        "actions": [],
        "total": 0,
    }

    registry.record_issuance(
        config, public_id, "LIC-0001", "issued",
        {"tier": "enterprise", "validity_days": 365},
    )
    registry.record_issuance(
        config, public_id, "LIC-0001", "renewed",
        {"tier": "enterprise", "validity_days": 365},
    )
    history = client.get(
        f"/api/v1/customers/{public_id}/issuance-history"
    ).get_json()
    assert history["total"] == 2
    # newest first
    assert history["actions"][0]["action"] == "renewed"
    assert history["actions"][1]["license_id"] == "LIC-0001"
    assert history["actions"][1]["detail"]["tier"] == "enterprise"


def test_issuance_write_validation(config):
    created_public_id = None
    # create through the API on the same config
    from pam_master.app import create_app as _create_app

    client = _create_app(config).test_client()
    created_public_id = _create(client)["public_id"]

    with pytest.raises(registry.ValidationError):
        registry.record_issuance(
            config, created_public_id, "LIC-0002", "teleported"
        )
    with pytest.raises(registry.ValidationError):
        registry.record_issuance(
            config, created_public_id, "  ", "issued"
        )
    with pytest.raises(registry.CustomerNotFound):
        registry.record_issuance(
            config, "0" * 32, "LIC-0003", "issued"
        )


# ---------------------------------------------------------------- health --
def test_health_tables_reflect_real_schema(config, client):
    before = client.get("/health").get_json()
    assert before["database"]["reachable"] is True
    assert before["database"]["tables"] == 0

    _create(client)

    after = client.get("/health").get_json()
    # customers + issuance_history + licenses + master_audit
    assert after["database"]["tables"] == 4
