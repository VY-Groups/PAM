"""Tests for the credential vault, dashboard overview and activity feed.

Run with:  python -m pytest backend/phase2_license_server/tests -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from models import VAULT_TYPES  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

# Seeded workflow rows (insertion order): rotating, failed and checked-out ids.
ROTATING_ID = 4
FAILED_ID = 5
CHECKED_OUT_ID = 2


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
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


def issue(client, **overrides):
    payload = {"license_type": "subscription", "issued_to": "Acme Ltd"}
    payload.update(overrides)
    return client.post("/api/v1/licenses", json=payload, headers=ADMIN)


# ---------------------------------------------------------------------------
# vault inventory
# ---------------------------------------------------------------------------
def test_seed_loads_initial_inventory(client):
    stats = client.get("/api/v1/vault/stats").get_json()
    assert stats["total"] == 20
    assert sum(stats["by_status"].values()) == stats["total"]
    assert set(stats["by_type"]) == set(VAULT_TYPES)
    assert stats["by_status"]["checked_out"] == 2
    assert stats["by_status"]["rotating"] == 1
    assert stats["by_status"]["failed"] == 1
    assert stats["rotation"]["due"] >= 1
    assert 0 < stats["rotation"]["compliance_pct"] <= 100
    assert stats["attention"]["failed"] == 1
    assert stats["events_today"] == {"checkouts": 0, "rotations": 0}


def test_seed_runs_once_per_database(config, tmp_path):
    app = create_app(config)
    app.config["TESTING"] = True
    other = create_app(config)  # same database file: must not duplicate rows
    with app.app_context():
        from models import VaultItem

        assert VaultItem.query.count() == 20
    with other.app_context():
        from models import VaultItem

        assert VaultItem.query.count() == 20


def test_list_items_and_filters(client):
    page = client.get("/api/v1/vault/items").get_json()
    assert page["total"] == 20
    assert len(page["items"]) == 20

    databases = client.get(
        "/api/v1/vault/items", query_string={"type": "database"}
    ).get_json()
    assert databases["total"] >= 2
    assert all(item["secret_type"] == "database" for item in databases["items"])

    checked_out = client.get(
        "/api/v1/vault/items", query_string={"status": "checked_out"}
    ).get_json()
    assert checked_out["total"] == 2

    search = client.get(
        "/api/v1/vault/items", query_string={"q": "postgres"}
    ).get_json()
    assert search["total"] >= 1
    assert any("postgres" in item["name"] for item in search["items"])

    window = client.get(
        "/api/v1/vault/items", query_string={"limit": 5, "offset": 5}
    ).get_json()
    assert len(window["items"]) == 5
    assert window["total"] == 20
    assert window["offset"] == 5


def test_list_items_rejects_unknown_filters(client):
    for query in ({"type": "nope"}, {"status": "nope"}):
        response = client.get("/api/v1/vault/items", query_string=query)
        assert response.status_code == 400
        assert "allowed" in response.get_json()["details"]


def test_detail_includes_item_and_its_events(client):
    detail = client.get("/api/v1/vault/items/1").get_json()
    item = detail["item"]
    assert item["name"] == "prod-postgres-superuser"
    assert item["secret_type"] == "database"
    assert item["rotation_interval_label"] == "Every 1d"
    assert item["events"] == []

    assert client.get("/api/v1/vault/items/999").status_code == 404


def test_checkout_revoke_cycle_writes_audit(client):
    response = client.post(
        f"/api/v1/vault/items/1/checkout",
        json={"reason": "INC-9942"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    item = response.get_json()["item"]
    assert item["status"] == "checked_out"
    assert item["checked_out_by"] == "tester"

    # a second checkout of the same item must fail
    again = client.post("/api/v1/vault/items/1/checkout", headers=ACTOR)
    assert again.status_code == 400

    events = client.get("/api/v1/vault/events").get_json()
    assert events["total"] == 1
    assert events["events"][0]["action"] == "checked_out"
    assert events["events"][0]["actor"] == "tester"
    assert events["events"][0]["detail"]["reason"] == "INC-9942"

    revoke = client.post("/api/v1/vault/items/1/revoke", headers=ACTOR)
    assert revoke.status_code == 200
    revoked = revoke.get_json()["item"]
    assert revoked["status"] == "available"
    assert revoked["checked_out_by"] is None

    assert client.post("/api/v1/vault/items/1/revoke", headers=ACTOR).status_code == 400
    assert client.get("/api/v1/vault/events").get_json()["total"] == 2


def test_vault_actions_require_admin_token(client):
    calls = [
        client.post("/api/v1/vault/items/1/checkout"),
        client.post("/api/v1/vault/items/1/revoke"),
        client.post("/api/v1/vault/items/1/rotate"),
        client.post("/api/v1/vault/items", json={"name": "x", "secret_type": "database",
                                                 "target": "t", "principal": "p"}),
    ]
    assert [response.status_code for response in calls] == [401, 401, 401, 401]
    # reads stay public so the screen renders without a token
    assert client.get("/api/v1/vault/items").status_code == 200
    assert client.get("/api/v1/vault/stats").status_code == 200


def test_rotate_clears_failed_status(client):
    response = client.post(f"/api/v1/vault/items/{FAILED_ID}/rotate", headers=ACTOR)
    assert response.status_code == 200
    item = response.get_json()["item"]
    assert item["status"] == "available"
    assert item["last_rotated_at"] is not None

    stats = client.get("/api/v1/vault/stats").get_json()
    assert stats["by_status"]["failed"] == 0
    events = client.get("/api/v1/vault/events").get_json()
    assert events["events"][0]["action"] == "rotated"
    assert events["events"][0]["detail"]["previous_status"] == "failed"


def test_rotate_rejects_in_flight_states(client):
    rotating = client.post(f"/api/v1/vault/items/{ROTATING_ID}/rotate", headers=ACTOR)
    assert rotating.status_code == 400

    checked_out = client.post(
        f"/api/v1/vault/items/{CHECKED_OUT_ID}/rotate", headers=ACTOR
    )
    assert checked_out.status_code == 400

    assert client.post("/api/v1/vault/items/999/rotate", headers=ACTOR).status_code == 404


def test_onboard_validates_and_persists(client):
    required_fields = [
        {"secret_type": "database", "target": "h", "principal": "p"},  # no name
        {"name": "x", "secret_type": "nope", "target": "h", "principal": "p"},
        {"name": "x", "secret_type": "database", "target": "", "principal": "p"},
        {"name": "x", "secret_type": "database", "target": "h", "principal": ""},
        {"name": "x", "secret_type": "database", "target": "h", "principal": "p",
         "access_tier": "Tier-9"},
        {"name": "x", "secret_type": "database", "target": "h", "principal": "p",
         "rotation_interval_hours": -1},
    ]
    for payload in required_fields:
        response = client.post("/api/v1/vault/items", json=payload, headers=ACTOR)
        assert response.status_code == 400, payload

    created = client.post(
        "/api/v1/vault/items",
        json={
            "name": "backup-vault-token",
            "secret_type": "api_token",
            "description": "Backup vault root token",
            "target": "vault-backup.internal",
            "target_detail": "DR site",
            "principal": "backup-root",
            "access_tier": "Tier-0",
            "auth_method": "Hardware",
            "rotation_interval_hours": 168,
        },
        headers=ACTOR,
    )
    assert created.status_code == 201
    item = created.get_json()["item"]
    assert item["id"] == 21
    assert item["status"] == "available"
    assert item["rotation_interval_label"] == "Every 7d"

    duplicate = client.post(
        "/api/v1/vault/items",
        json={"name": "backup-vault-token", "secret_type": "api_token",
              "target": "h", "principal": "p"},
        headers=ACTOR,
    )
    assert duplicate.status_code == 400

    stats = client.get("/api/v1/vault/stats").get_json()
    assert stats["total"] == 21
    events = client.get("/api/v1/vault/events").get_json()
    assert events["events"][0]["action"] == "onboarded"


def test_vault_events_limit(client):
    assert client.get("/api/v1/vault/events").get_json() == {
        "events": [], "total": 0, "limit": 20,
    }
    client.post("/api/v1/vault/items/1/checkout", headers=ACTOR)
    client.post("/api/v1/vault/items/1/revoke", headers=ACTOR)
    limited = client.get("/api/v1/vault/events", query_string={"limit": 1}).get_json()
    assert len(limited["events"]) == 1
    assert limited["total"] == 2


# ---------------------------------------------------------------------------
# dashboard overview
# ---------------------------------------------------------------------------
def test_overview_shape_and_defaults(client):
    data = client.get("/api/v1/overview").get_json()
    assert data["health"]["auth"] == "token"
    assert data["health"]["status"] == "ok"
    assert data["licenses"]["total"] == 0
    assert data["vault"]["total"] == 20
    assert data["settings"]["groups"] == 4
    assert data["settings"]["worm_retention_days"] == 2555
    assert data["settings"]["zsp_quorum_approvers"] == 2
    assert data["settings"]["sso_provider"] == "okta"
    assert data["counters"]["total_events"] == 0

    posture = data["posture"]
    ids = [control["id"] for control in posture["controls"]]
    assert len(ids) == len(set(ids)) == 8
    assert posture["violations"] == sum(
        1 for control in posture["controls"] if not control["passed"]
    )
    by_id = {control["id"]: control for control in posture["controls"]}
    assert by_id["admin_auth"]["passed"] is True      # token mode
    assert by_id["quantum_safe"]["passed"] is True    # RSA-PSS + Ed25519
    assert by_id["worm_retention"]["passed"] is True  # 2555d COMPLIANCE lock
    assert by_id["rotation_sla"]["passed"] is False   # seed has due + failed rows
    assert 0 <= posture["score"] <= 100


def test_overview_tracks_license_lifecycle_and_activity(client):
    issued = issue(client)
    assert issued.status_code == 201

    data = client.get("/api/v1/overview").get_json()
    assert data["licenses"]["total"] == 1
    assert data["licenses"]["active"] == 1
    assert data["counters"]["license_events"] == 1
    assert data["posture"]["violations"] == sum(
        1 for control in data["posture"]["controls"] if not control["passed"]
    )
    assert data["activity"][0]["source"] == "license"
    assert data["activity"][0]["action"] == "issued"

    key = issued.get_json()["license"]["license_key"]
    client.post(f"/api/v1/licenses/{key}/revoke", headers=ADMIN)
    data = client.get("/api/v1/overview").get_json()
    assert data["licenses"]["revoked"] == 1
    assert data["licenses"]["active"] == 0


def test_overview_sums_reported_usage(client):
    issued = issue(client).get_json()["license"]
    key = issued["license_key"]
    client.post(
        f"/api/v1/licenses/{key}/usage",
        json={"nodes_consumed": 12, "sessions_active": 3,
              "bastion_tunnels_used": 2},
        headers=ADMIN,
    )
    data = client.get("/api/v1/overview").get_json()
    usage = data["licenses"]["usage"]
    assert usage["nodes"] == 12
    assert usage["sessions"] == 3
    assert usage["bastion_tunnels"] == 2
    assert usage["reported_licenses"] == 1


def test_overview_flags_open_auth_mode(tmp_path: Path):
    config = Config(
        database_uri=f"sqlite:///{(tmp_path / 'open.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
        secret_key="test-secret",
        admin_token="",  # open/dev mode
        autogenerate_keys=False,
        default_trial_days=30,
    )
    app = create_app(config)
    app.config["TESTING"] = True
    client = app.test_client()

    data = client.get("/api/v1/overview").get_json()
    assert data["health"]["auth"] == "open"
    by_id = {control["id"]: control for control in data["posture"]["controls"]}
    assert by_id["admin_auth"]["passed"] is False
    assert by_id["admin_auth"]["evidence"] == "open dev mode"
    assert data["posture"]["violations"] >= 1


# ---------------------------------------------------------------------------
# unified activity feed
# ---------------------------------------------------------------------------
def test_events_empty_on_fresh_database(client):
    data = client.get("/api/v1/events").get_json()
    assert data == {"events": [], "total": 0, "limit": 20, "source": "all"}


def test_unified_feed_merges_all_sources_newest_first(client):
    client.post("/api/v1/vault/items/1/checkout", headers=ACTOR)
    client.put("/api/v1/settings/zsp", json={"tier0_quorum_approvers": 3},
               headers=ACTOR)
    issue(client)

    data = client.get("/api/v1/events").get_json()
    assert data["total"] == 3
    assert [event["source"] for event in data["events"]] == [
        "license", "settings", "vault",
    ]
    newest = data["events"][0]
    assert newest["action"] == "issued"
    settings_event = data["events"][1]
    assert settings_event["actor"] == "tester"
    assert "tier0_quorum_approvers" in settings_event["detail"]


def test_events_source_filter_and_validation(client):
    client.post("/api/v1/vault/items/1/checkout", headers=ACTOR)
    issue(client)

    vault_only = client.get(
        "/api/v1/events", query_string={"source": "vault"}
    ).get_json()
    assert vault_only["total"] == 1
    assert vault_only["source"] == "vault"
    assert all(event["source"] == "vault" for event in vault_only["events"])

    license_only = client.get(
        "/api/v1/events", query_string={"source": "license"}
    ).get_json()
    assert license_only["total"] == 1

    bad = client.get("/api/v1/events", query_string={"source": "nope"})
    assert bad.status_code == 400
    assert bad.get_json()["details"]["allowed"] == ["license", "settings", "vault"]

    limited = client.get("/api/v1/events", query_string={"limit": 1}).get_json()
    assert len(limited["events"]) == 1
    assert limited["total"] == 2
