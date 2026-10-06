"""Tests for the Discovery Engine (module 3): real probing, classify, onboard.

Everything asserted here is produced by the real pipeline - TCP-connect
scans against a local listener, operator onboarding through the public API,
or model-level inserts for already-discovered rows. No fixture fabricates a
scan result the scanner could not produce.

Run with:  python -m pytest backend/phase2_license_server/tests -q
"""
from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from models import (  # noqa: E402
    ACCOUNT_KINDS,
    ASSET_PAM_STATUSES,
    ASSET_RISKS,
    ASSET_SECRET_TYPES,
    ASSET_TYPES,
    BASE_RISK,
    RECOMMENDED_POLICY,
    DiscoveredAsset,
    DiscoveryScan,
    classify_account_kind,
    db,
)
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}


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
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, address, principal="root", **overrides):
    """Manual onboarding through the public API (the only way in)."""
    payload = {"address": address, "principal": principal}
    payload.update(overrides)
    response = client.post("/api/v1/discovery/assets", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def insert_asset(app, address, *, asset_type="linux", pam_status="unmanaged",
                 risk=None, **extra):
    """Model-level insert for already-discovered rows (no API creates them)."""
    with app.app_context():
        asset = DiscoveredAsset(
            address=address,
            asset_type=asset_type,
            risk=risk or BASE_RISK.get(asset_type, "LOW"),
            pam_status=pam_status,
            **extra,
        )
        db.session.add(asset)
        db.session.commit()
        return asset.id


class Listener:
    """A real local TCP endpoint that greets with an SSH banner."""

    def __init__(self, banner: bytes = b"SSH-2.0-OpenSSH_9.9\r\n"):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            while True:
                conn, _ = self.sock.accept()
                try:
                    conn.settimeout(2.0)
                    conn.sendall(self.banner)
                except OSError:
                    pass
                finally:
                    conn.close()
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2.0)


def free_port() -> int:
    """A port with nothing listening on it right now (closed = refused)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# ---------------------------------------------------------------------------
# honest empty state + validation
# ---------------------------------------------------------------------------
def test_stats_start_empty_honest(client):
    stats = client.get("/api/v1/discovery/stats").get_json()
    assert stats["total"] == 0
    assert stats["by_type"] == {kind: 0 for kind in ASSET_TYPES}
    assert stats["by_risk"] == {level: 0 for level in ASSET_RISKS}
    assert stats["by_pam_status"] == {s: 0 for s in ASSET_PAM_STATUSES}
    assert stats["accounts_total"] == 0
    assert stats["scans"] == {"total": 0, "last": None}

    page = client.get("/api/v1/discovery/assets").get_json()
    assert page == {"assets": [], "total": 0, "limit": 50, "offset": 0}


def test_list_filters_reject_unknown_values(client):
    for query in (
        "?type=toaster",
        "?risk=APOCALYPSE",
        "?pam_status=maybe",
    ):
        response = client.get(f"/api/v1/discovery/assets{query}")
        assert response.status_code == 400, query
        assert "allowed" in response.get_json()["details"]


def test_onboard_validation(client):
    for payload, field in (
        ({}, "address"),
        ({"address": "10.0.0.5"}, "principal"),
        ({"address": "10.0.0.0/24", "principal": "root"}, "address"),
        ({"address": "224.0.0.1", "principal": "root"}, "address"),
        ({"address": "0.0.0.0", "principal": "root"}, "address"),
        ({"address": "10.0.0.7", "principal": "root", "asset_type": "toaster"},
         "asset_type"),
        ({"address": "10.0.0.7", "principal": "root", "access_tier": "Tier-9"},
         "access_tier"),
        ({"address": "10.0.0.7", "principal": "root",
          "rotation_interval_hours": -1}, "rotation_interval_hours"),
    ):
        response = client.post(
            "/api/v1/discovery/assets", json=payload, headers=ACTOR
        )
        assert response.status_code == 400, payload
        assert response.get_json()["details"]["field"] == field, payload


def test_admin_token_required(client):
    response = client.post(
        "/api/v1/discovery/assets",
        json={"address": "10.0.0.9", "principal": "root"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# manual onboarding: discover -> classify -> recommend -> onboard pipeline
# ---------------------------------------------------------------------------
def test_manual_onboard_creates_asset_vault_and_account(client):
    body = register(
        client, "10.10.0.5", "svc_backup_nightly",
        hostname="db01.corp", asset_type="database", detail="PostgreSQL",
        access_tier="Tier-1", rotation_interval_hours=12,
    )

    asset = body["asset"]
    assert asset["pam_status"] == "managed"
    assert asset["source"] == "manual"
    assert asset["method"] == "manual"
    assert asset["risk"] == BASE_RISK["database"] == "CRITICAL"
    assert asset["recommended_policy"] == RECOMMENDED_POLICY["database"]

    item = body["vault_item"]
    assert item["target"] == "10.10.0.5"
    assert item["principal"] == "svc_backup_nightly"
    assert item["secret_type"] == ASSET_SECRET_TYPES["database"]
    assert item["access_tier"] == "Tier-1"
    assert item["rotation_interval_hours"] == 12

    page = client.get("/api/v1/discovery/accounts").get_json()
    assert page["total"] == 1
    account = page["accounts"][0]
    assert account["username"] == "svc_backup_nightly"
    assert account["kind"] == "service_account"
    assert account["asset_address"] == "10.10.0.5"

    # both audit trails recorded the event
    feed = client.get("/api/v1/events?source=discovery").get_json()
    assert feed["events"][0]["action"] == "asset_onboarded"
    vault_feed = client.get("/api/v1/events?source=vault").get_json()
    assert any(
        event["detail"].get("via") == "discovery"
        for event in vault_feed["events"]
    )

    stats = client.get("/api/v1/discovery/stats").get_json()
    assert stats["total"] == 1
    assert stats["by_type"]["database"] == 1
    assert stats["accounts_total"] == 1


def test_onboard_duplicate_address_rejected(client):
    register(client, "10.10.0.6")
    response = client.post(
        "/api/v1/discovery/assets",
        json={"address": "10.10.0.6", "principal": "root"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert "already exists" in response.get_json()["error"]


def test_vault_counts_by_target_in_list(client):
    register(client, "10.10.0.7")
    page = client.get("/api/v1/discovery/assets").get_json()
    assert page["total"] == 1
    assert page["assets"][0]["vault_count"] == 1


# ---------------------------------------------------------------------------
# adopting a discovered asset
# ---------------------------------------------------------------------------
def test_adopt_discovered_asset_pipeline(app, client):
    asset_id = insert_asset(app, "192.168.5.10", asset_type="linux")

    response = client.post(
        f"/api/v1/discovery/assets/{asset_id}/onboard",
        json={"principal": "root", "access_tier": "Tier-0"},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["asset"]["pam_status"] == "managed"
    assert body["vault_item"]["principal"] == "root"
    assert body["vault_item"]["secret_type"] == "ssh_key"

    # adopting again is rejected
    again = client.post(
        f"/api/v1/discovery/assets/{asset_id}/onboard",
        json={"principal": "root"},
        headers=ACTOR,
    )
    assert again.status_code == 400
    assert "already managed" in again.get_json()["error"]

    missing = client.post(
        "/api/v1/discovery/assets/999999/onboard",
        json={"principal": "root"},
        headers=ACTOR,
    )
    assert missing.status_code == 404


def test_patch_ignore_and_reclassify(app, client):
    asset_id = insert_asset(app, "192.168.5.11", asset_type="unknown")

    response = client.patch(
        f"/api/v1/discovery/assets/{asset_id}",
        json={"pam_status": "ignored"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    assert response.get_json()["asset"]["pam_status"] == "ignored"

    response = client.patch(
        f"/api/v1/discovery/assets/{asset_id}",
        json={"asset_type": "database"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    patched = response.get_json()["asset"]
    assert patched["asset_type"] == "database"
    assert patched["risk"] == "CRITICAL"  # risk recomputed from the family

    # nothing effective supplied -> 400 (same values count as no change)
    response = client.patch(
        f"/api/v1/discovery/assets/{asset_id}",
        json={"pam_status": "ignored"},
        headers=ACTOR,
    )
    assert response.status_code == 400

    assert client.patch(
        f"/api/v1/discovery/assets/{asset_id}",
        json={"pam_status": "floating"},
        headers=ACTOR,
    ).status_code == 400
    assert client.patch(
        "/api/v1/discovery/assets/999999",
        json={"pam_status": "ignored"},
        headers=ACTOR,
    ).status_code == 404


# ---------------------------------------------------------------------------
# real scanning
# ---------------------------------------------------------------------------
def test_real_scan_of_local_listener(app, client):
    """A genuine TCP scan: discover a live local listener, read its banner."""
    listener = Listener()
    closed = free_port()
    try:
        response = client.post(
            "/api/v1/discovery/scans",
            json={"scope": "127.0.0.1", "ports": [listener.port, closed]},
            headers=ACTOR,
        )
        assert response.status_code == 201, response.get_json()
        scan = response.get_json()["scan"]
        assert scan["status"] == "completed"
        assert scan["hosts_probed"] == 1
        assert scan["hosts_open"] == 1
        assert scan["services_found"] == 1
        assert scan["findings"] == 1
        assert scan["finished_at"] is not None

        # the discovered asset carries the real probe output
        page = client.get("/api/v1/discovery/assets").get_json()
        assert page["total"] == 1
        asset = page["assets"][0]
        assert asset["address"] == "127.0.0.1"
        assert asset["pam_status"] == "unmanaged"
        assert asset["source"] == "scan"
        assert asset["method"] == "tcp_probe"
        assert [entry["port"] for entry in asset["ports"]] == [listener.port]
        assert "OpenSSH_9.9" in asset["detail"]  # banner read, not invented
        assert asset["asset_type"] == "linux"
        assert asset["risk"] == BASE_RISK["linux"]
        assert closed not in [entry["port"] for entry in asset["ports"]]

        # a second scan of the same host refreshes instead of duplicating
        again = client.post(
            "/api/v1/discovery/scans",
            json={"scope": "127.0.0.1", "ports": [listener.port, closed]},
            headers=ACTOR,
        ).get_json()["scan"]
        assert again["findings"] == 0
        assert again["hosts_open"] == 1
        with app.app_context():
            assert DiscoveredAsset.query.count() == 1
            assert DiscoveryScan.query.count() == 2
    finally:
        listener.close()


def test_scan_writes_discovery_events(app, client):
    listener = Listener()
    try:
        client.post(
            "/api/v1/discovery/scans",
            json={"scope": "127.0.0.1", "ports": [listener.port]},
            headers=ACTOR,
        )
    finally:
        listener.close()

    feed = client.get("/api/v1/events?source=discovery").get_json()
    actions = [event["action"] for event in feed["events"]]
    assert "scan_started" in actions
    assert "scan_completed" in actions
    assert "asset_discovered" in actions

    history = client.get("/api/v1/discovery/scans").get_json()
    assert history["total"] == 1
    assert history["scans"][0]["scope"] == "127.0.0.1"
    assert history["scans"][0]["triggered_by"] == "tester"

    stats = client.get("/api/v1/discovery/stats").get_json()
    assert stats["scans"]["total"] == 1
    assert stats["scans"]["last"]["scope"] == "127.0.0.1"

    overview = client.get("/api/v1/overview").get_json()
    assert overview["counters"]["discovery_events"] >= 3


def test_scan_scope_and_port_validation(client):
    for payload in (
        {},
        {"scope": ""},
        {"scope": "999.1.1.1"},          # neither IP nor hostname (no letter)
        {"scope": "not a scope!"},
        {"scope": "10.0.0.0/8"},         # far beyond the 256-host cap
        {"scope": "224.0.0.1"},          # multicast
        {"scope": "255.255.255.255"},    # broadcast
        {"scope": "0.0.0.0"},
        {"scope": "2001:db8::1"},        # IPv6 not supported (honest 400)
        {"scope": "10.0.0.0/24", "ports": []},
        {"scope": "10.0.0.1", "ports": [0]},
        {"scope": "10.0.0.1", "ports": [70000]},
        {"scope": "10.0.0.1", "ports": ["22"]},
        {"scope": "10.0.0.1", "ports": list(range(1, 31))},  # > 24 ports
    ):
        response = client.post(
            "/api/v1/discovery/scans", json=payload, headers=ACTOR
        )
        assert response.status_code == 400, payload
        assert "error" in response.get_json(), payload

    # a valid single-host shape passes validation and just finds nothing
    response = client.post(
        "/api/v1/discovery/scans",
        json={"scope": "127.0.0.1", "ports": [free_port()]},
        headers=ACTOR,
    )
    assert response.status_code == 201
    scan = response.get_json()["scan"]
    assert scan["hosts_open"] == 0
    assert scan["findings"] == 0


def test_scan_requires_admin(client):
    response = client.post(
        "/api/v1/discovery/scans", json={"scope": "127.0.0.1"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# classification rules (unit - the same code the scanner runs)
# ---------------------------------------------------------------------------
def test_classify_service_families():
    classify = service._classify_service

    # reference-architecture families from open ports
    assert classify([{"port": 445}, {"port": 135}])[0] == "windows"
    assert classify([{"port": 5432}])[0] == "database"
    assert classify([{"port": 6443}])[0] == "kubernetes"
    assert classify([{"port": 2375}])[0] == "docker"
    assert classify([{"port": 443}]) == ("unknown", "HTTPS")

    # database detail prefers a real banner, falls back to service labels
    assert classify([{"port": 3306, "banner": "9.5.0-mysql"}]) == (
        "database",
        "9.5.0-mysql",
    )
    assert classify([{"port": 5432}, {"port": 6379}]) == (
        "database",
        "PostgreSQL \u00b7 Redis",
    )

    # SSH greeting refines the OS family
    assert classify([{"port": 22, "banner": "SSH-2.0-OpenSSH_9.2"}])[0] == "linux"
    assert classify([{"port": 22, "banner": "SSH-2.0-Sun_SSH_8.7"}])[0] == "solaris"
    assert classify([{"port": 22, "banner": "SSH-2.0-HP-UX_SSH"}])[0] == "unix"
    assert classify([{"port": 22}]) == ("unknown", "SSH")  # silent: no OS guess
    # SSH banner on a nonstandard port is still SSH evidence
    assert classify([{"port": 2222, "banner": "SSH-2.0-OpenSSH_9.9"}])[0] == "linux"
    assert classify([]) == ("unknown", "")


def test_risk_and_policy_rules_cover_every_type():
    for asset_type in ASSET_TYPES:
        assert asset_type in BASE_RISK, asset_type
        assert asset_type in RECOMMENDED_POLICY, asset_type
        assert asset_type in ASSET_SECRET_TYPES, asset_type
        assert BASE_RISK[asset_type] in ASSET_RISKS
    # architecture-doc example scores
    assert BASE_RISK["linux"] == "HIGH"
    assert BASE_RISK["windows"] == "CRITICAL"
    assert BASE_RISK["database"] == "CRITICAL"
    assert BASE_RISK["firewall"] == "HIGH"
    assert BASE_RISK["cloud"] == "CRITICAL"


def test_account_kind_classification():
    for name in ("root", "Administrator", "admin"):
        assert classify_account_kind(name) == "builtin_admin"
    for name in ("postgres", "ORACLE", "sa", "mysql"):
        assert classify_account_kind(name) == "database_admin"
    for name in ("svc_deploy", "backup_nightly", "SVC-Web"):
        assert classify_account_kind(name) == "service_account"
    assert classify_account_kind("alice") == "other"
    assert set(ACCOUNT_KINDS) >= {"builtin_admin", "database_admin",
                                  "service_account", "other"}


def test_expand_scope_shapes():
    assert service._expand_scope("10.0.0.5") == ["10.0.0.5"]
    assert service._expand_scope("db.corp.local") == ["db.corp.local"]
    assert service._expand_scope("192.168.1.0/30") == [
        "192.168.1.1",
        "192.168.1.2",
    ]  # network/broadcast addresses excluded
    for bad in (
        "",
        "10.0.0.0/9",       # 512 hosts > 256 cap
        "10.0.0.0/8",       # far beyond cap
        "300.1.1.1",        # no letters -> not a hostname either
        "negative.host!",   # illegal hostname characters
        "224.0.0.5",        # multicast
        "2001:db8::1",      # IPv6 unsupported in v1
    ):
        with pytest.raises(Exception):
            service._expand_scope(bad)


# ---------------------------------------------------------------------------
# accounts listing
# ---------------------------------------------------------------------------
def test_accounts_list_and_kind_filter(app, client):
    register(client, "10.20.0.1", "root")
    register(client, "10.20.0.2", "postgres")
    register(client, "10.20.0.3", "svc_metrics")
    register(client, "10.20.0.4", "bob")

    page = client.get("/api/v1/discovery/accounts").get_json()
    assert page["total"] == 4
    kinds = {account["username"]: account["kind"] for account in page["accounts"]}
    assert kinds == {
        "root": "builtin_admin",
        "postgres": "database_admin",
        "svc_metrics": "service_account",
        "bob": "other",
    }

    filtered = client.get("/api/v1/discovery/accounts?kind=service_account")
    assert filtered.get_json()["total"] == 1
    searched = client.get("/api/v1/discovery/accounts?q=postgres")
    assert searched.get_json()["total"] == 1
    assert client.get("/api/v1/discovery/accounts?kind=wizard").status_code == 400


def test_asset_list_search_and_paging(app, client):
    register(client, "10.30.0.1", hostname="alpha")
    register(client, "10.30.0.2", hostname="beta")

    page = client.get("/api/v1/discovery/assets?limit=1").get_json()
    assert page["total"] == 2
    assert len(page["assets"]) == 1
    page2 = client.get(
        "/api/v1/discovery/assets?limit=1&offset=1"
    ).get_json()
    assert len(page2["assets"]) == 1
    assert page["assets"][0]["id"] != page2["assets"][0]["id"]

    assert client.get(
        "/api/v1/discovery/assets?q=alpha"
    ).get_json()["total"] == 1
    assert client.get(
        "/api/v1/discovery/assets?q=nothing-matches"
    ).get_json()["total"] == 0
