"""Phase 6a - HA / DC / DR (architecture section 18) coverage.

Every claim here is checked against a real second node (served over HTTP
by werkzeug, with its own database and its own vault key), a real SQLite
file on disk, or the immutable ledger itself: probes measure, replication
re-hashes record by record, the passive gate refuses product writes, the
monitor counts real probe failures, and a backup is a file whose bytes
and whose chain both check out.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any, Dict

import pytest
from werkzeug.serving import make_server

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
import audit as audit_module  # noqa: E402
import service as service_module  # noqa: E402
from models import (  # noqa: E402
    ClusterAuditReplica,
    ClusterSecretReplica,
    ClusterSessionReplica,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}

# RFC 6761 reserves the .invalid TLD, so this name can never resolve: a
# probe or sync against it fails fast with the resolver's own error - the
# honest unreachable-peer case (this machine runs Simple TCP/IP services
# that accept-and-hold low ports, and loopback refusals take ~2s).
CLOSED_URL = "https://pam-no-such-node.invalid"


# ---------------------------------------------------------------------------
# fixtures: this node, plus real second nodes served over HTTP
# ---------------------------------------------------------------------------
def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public_key.pem",
        secret_key="test-cluster-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-1",
        node_site="dc",
        cluster_backup_dir=tmp_path / "backups",
    )


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return _config(tmp_path)


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


class _Httpd:
    """Serves WSGI apps on ephemeral loopback ports and shuts them down."""

    def __init__(self) -> None:
        self.servers = []

    def serve(self, application) -> str:
        server = make_server("127.0.0.1", 0, application, threaded=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()


@pytest.fixture
def httpd():
    helper = _Httpd()
    yield helper
    helper.close()


class _Peer:
    """A second real PAM node: own config, own database, own HTTP base."""

    def __init__(self, app, config: Config, base_url: str) -> None:
        self.app = app
        self.config = config
        self.base_url = base_url
        self.client = app.test_client()

    @property
    def headers(self) -> Dict[str, str]:
        headers = {"X-Actor": "admin"}
        if self.config.admin_token:
            headers["Authorization"] = f"Bearer {self.config.admin_token}"
        return headers


@pytest.fixture
def make_peer(tmp_path: Path, httpd: _Httpd):
    """Factory for real peer nodes. Defaults: open auth, its own vault key
    (so its ciphertext stays sealed to this node), served over HTTP."""
    counter = {"value": 0}

    def factory(**overrides) -> _Peer:
        index = counter["value"]
        counter["value"] += 1
        directory = tmp_path / f"peer{index}"
        directory.mkdir(parents=True, exist_ok=True)
        values = dict(
            database_uri=f"sqlite:///{(directory / 'peer.db').as_posix()}",
            private_key_path=REPO_ROOT / "license_private_key.pem",
            public_key_path=REPO_ROOT / "license_public_key.pem",
            ed25519_private_key_path=directory / "ed25519_private.pem",
            ed25519_public_key_path=directory / "ed25519_public_key.pem",
            secret_key="peer-cluster-secret",
            admin_token="",
            autogenerate_keys=False,
            default_trial_days=30,
            vault_key_path=directory / "vault.key",
            node_name="pam-node-2",
            node_site="dr",
            cluster_backup_dir=directory / "backups",
        )
        values.update(overrides)
        peer_config = Config(**values)
        peer_app = create_app(peer_config)
        peer_app.config["TESTING"] = True
        return _Peer(peer_app, peer_config, httpd.serve(peer_app))

    return factory


def _json_wsgi(status: str, payload: Dict[str, Any]):
    """A minimal WSGI app that always answers `status` with `payload`."""
    body = json.dumps(payload).encode("utf-8")

    def application(environ, start_response):
        start_response(
            status,
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]

    return application


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def register(client, name: str, **overrides) -> Dict[str, Any]:
    payload = {"name": name, "base_url": "https://peer.example/pam"}
    payload.update(overrides)
    response = client.post("/api/v1/cluster/nodes", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["node"]


def sync(client, node_id: int, **payload) -> Dict[str, Any]:
    response = client.post(
        f"/api/v1/cluster/nodes/{node_id}/sync", json=payload, headers=ACTOR
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def probe(client, node_id: int) -> Dict[str, Any]:
    response = client.post(
        f"/api/v1/cluster/nodes/{node_id}/probe", headers=ACTOR
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def failover(client, action: str, **body):
    payload = {"action": action}
    payload.update(body)
    return client.post("/api/v1/cluster/failover", json=payload, headers=ACTOR)


def tick(client) -> Dict[str, Any]:
    response = client.post("/api/v1/cluster/monitor/tick", headers=ACTOR)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def self_node(client) -> Dict[str, Any]:
    nodes = client.get("/api/v1/cluster/nodes", headers=ADMIN).get_json()["nodes"]
    assert nodes, "the deployment always registers itself"
    return nodes[0]


def cluster_events(client) -> list:
    page = client.get(
        "/api/v1/events", query_string={"source": "cluster", "limit": 100}
    ).get_json()
    assert page["source"] == "cluster"
    return page["events"]


def event_actions(client) -> list:
    return [event["action"] for event in cluster_events(client)]


def onboard(client, name: str, *, secret: str) -> Dict[str, Any]:
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": "db.prod:5432",
            "principal": "dba",
            "access_tier": "Tier-2",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
            "secret": secret,
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def start_session(client) -> Dict[str, Any]:
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "web-01.prod:22"},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["session"]


def seed_peer(peer, *, secret: str = "peer-sealed-4c7a") -> Dict[str, Any]:
    """Real history on the peer: a sealed credential, a started session and
    a settings write - so its ledger has something honest to replicate."""
    vault = peer.client.post(
        "/api/v1/vault/items",
        json={
            "name": "peer-db-cred",
            "secret_type": "database",
            "target": "db.peer.internal:5432",
            "principal": "peer-dba",
            "access_tier": "Tier-2",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
            "secret": secret,
        },
        headers=peer.headers,
    )
    assert vault.status_code == 201, vault.get_json()
    session = peer.client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "web-01.prod:22"},
        headers=peer.headers,
    )
    assert session.status_code == 201, session.get_json()
    settings = peer.client.put(
        "/api/v1/settings/zsp",
        json={"tier0_quorum_approvers": 3},
        headers=peer.headers,
    )
    assert settings.status_code in (200, 201), settings.get_json()
    return session.get_json()["session"]


# ---------------------------------------------------------------------------
# node registry: identity, registration, updates, removal
# ---------------------------------------------------------------------------
def test_self_is_seeded_at_startup_without_a_trail_row(client):
    body = client.get("/api/v1/cluster", headers=ADMIN).get_json()
    assert body["self"] == {
        "name": "pam-node-1",
        "site": "dc",
        "role": "active",
        "auth": "token",
    }
    # this node first, provenance is the deployment env - not an operator
    assert body["nodes"][0]["name"] == "pam-node-1"
    assert body["nodes"][0]["created_by"] == "deployment"
    assert body["nodes"][0]["health"] == "unknown"  # never probed, never assumed
    assert body["peers"]["total"] == 0
    # startup is not an admin action: the cluster trail starts empty
    assert cluster_events(client) == []


def test_register_peer_records_topology_and_health_is_never_assumed(client):
    node = register(
        client, "pam-dr-2", site="dr", role="passive",
        base_url="https://dr.example/pam/",
    )
    assert node["site"] == "dr" and node["role"] == "passive"
    assert node["base_url"] == "https://dr.example/pam"  # trailing slash trimmed
    assert node["health"] == "unknown"
    assert node["last_probe_at"] is None
    assert node["consecutive_failures"] == 0
    assert node["created_by"] == "admin"

    # on the cluster trail with the topology it recorded
    registered = [
        e for e in cluster_events(client) if e["action"] == "node-registered"
    ]
    assert len(registered) == 1
    assert registered[0]["detail"] == {
        "site": "dr",
        "role": "passive",
        "base_url": "https://dr.example/pam",
    }

    # listed self first, then peers by name; single fetch agrees
    names = [
        n["name"]
        for n in client.get("/api/v1/cluster/nodes", headers=ADMIN)
        .get_json()["nodes"]
    ]
    assert names == ["pam-node-1", "pam-dr-2"]
    single = client.get(f"/api/v1/cluster/nodes/{node['id']}", headers=ADMIN)
    assert single.status_code == 200
    assert single.get_json()["node"]["name"] == "pam-dr-2"


def test_register_validates_site_role_and_url_honestly(client):
    def rejected(payload):
        response = client.post(
            "/api/v1/cluster/nodes", json=payload, headers=ACTOR
        )
        assert response.status_code == 400, response.get_json()
        return response.get_json()

    assert rejected({"base_url": "https://x.example"})["details"]["field"] == "name"
    assert rejected({"name": "no-url"})["error"] == "'base_url' is required"
    assert "must be an http(s) URL" in rejected(
        {"name": "n1", "base_url": "dr.example"}
    )["error"]
    plain_http = rejected({"name": "n2", "base_url": "http://dr.example"})
    assert plain_http["details"] == {"field": "base_url", "scheme": "https"}
    assert "must be https" in plain_http["error"]
    assert "must be an http(s) URL" in rejected(
        {"name": "n3", "base_url": "ftp://dr.example"}
    )["error"]
    bad_site = rejected({"name": "n4", "base_url": "https://x.example", "site": "eu"})
    assert bad_site["details"]["allowed"] == ["dc", "dr"]
    bad_role = rejected(
        {"name": "n5", "base_url": "https://x.example", "role": "leader"}
    )
    assert bad_role["details"]["allowed"] == ["active", "passive"]
    not_object = rejected([1, 2, 3])
    assert not_object["error"] == "Request body must be a JSON object"

    # loopback http is allowed (an internal DR link), https everywhere
    assert register(client, "loopback-peer", base_url="http://localhost:5001")
    # names are trimmed, not silently mangled
    assert register(client, "  spaced-peer  ")["name"] == "spaced-peer"


def test_register_conflicts_on_duplicates_and_this_nodes_own_name(
    client, config
):
    register(client, "dup-peer")
    duplicate = client.post(
        "/api/v1/cluster/nodes",
        json={"name": "dup-peer", "base_url": "https://two.example"},
        headers=ACTOR,
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.get_json()["error"]

    # this deployment's own name is already in the registry (startup seeded
    # it), so the duplicate rule answers for it first
    own = client.post(
        "/api/v1/cluster/nodes",
        json={"name": "pam-node-1", "base_url": "https://self.example"},
        headers=ACTOR,
    )
    assert own.status_code == 409
    assert "already exists" in own.get_json()["error"]

    # the dedicated self-name guard: a name this node answers to whose row
    # is not in the registry yet (startup ensure has not run) still refuses
    original = client.application.config["LICENSE_CONFIG"]
    client.application.config["LICENSE_CONFIG"] = dataclasses.replace(
        config, node_name="phantom-node"
    )
    try:
        phantom = client.post(
            "/api/v1/cluster/nodes",
            json={"name": "phantom-node", "base_url": "https://p.example"},
            headers=ACTOR,
        )
        assert phantom.status_code == 409
        assert "is this node" in phantom.get_json()["error"]
    finally:
        client.application.config["LICENSE_CONFIG"] = original


def test_update_node_records_the_values_it_replaced(client):
    node = register(client, "peer-x")
    updated = client.patch(
        f"/api/v1/cluster/nodes/{node['id']}",
        json={
            "site": "dr",
            "role": "passive",
            "base_url": "https://dr2.example/pam",
        },
        headers=ACTOR,
    )
    assert updated.status_code == 200, updated.get_json()
    row = updated.get_json()["node"]
    assert (row["site"], row["role"]) == ("dr", "passive")

    changed = next(
        e for e in cluster_events(client) if e["action"] == "node-updated"
    )["detail"]["changed"]
    assert changed["site"] == {"from": "dc", "to": "dr"}
    assert changed["role"] == {"from": "active", "to": "passive"}
    assert changed["base_url"] == {
        "from": "https://peer.example/pam",
        "to": "https://dr2.example/pam",
    }

    # conflicts still apply on update
    steal_own = client.patch(
        f"/api/v1/cluster/nodes/{node['id']}",
        json={"name": "pam-node-1"},
        headers=ACTOR,
    )
    assert steal_own.status_code == 409
    renamed = client.patch(
        f"/api/v1/cluster/nodes/{node['id']}",
        json={"name": "peer-y"},
        headers=ACTOR,
    )
    assert renamed.status_code == 200
    assert renamed.get_json()["node"]["name"] == "peer-y"

    # a no-op patch adds no trail row
    before = len(cluster_events(client))
    assert client.patch(
        f"/api/v1/cluster/nodes/{node['id']}", json={}, headers=ACTOR
    ).status_code == 200
    assert len(cluster_events(client)) == before

    # unknown nodes are honest 404s on every verb
    assert client.get("/api/v1/cluster/nodes/9999", headers=ADMIN).status_code == 404
    assert (
        client.patch(
            "/api/v1/cluster/nodes/9999", json={"site": "dr"}, headers=ACTOR
        ).status_code
        == 404
    )
    assert (
        client.delete("/api/v1/cluster/nodes/9999", headers=ACTOR).status_code == 404
    )


def test_delete_peer_keeps_replicated_evidence_and_refuses_self(
    client, make_peer
):
    peer = make_peer()
    seed_peer(peer)
    node = register(client, "drop-peer", base_url=peer.base_url)
    assert sync(client, node["id"])["ok"] is True

    with client.application.app_context():
        held_before = ClusterAuditReplica.query.count()
    assert held_before >= 3

    removed = client.delete(
        f"/api/v1/cluster/nodes/{node['id']}", headers=ACTOR
    )
    assert removed.status_code == 200
    body = removed.get_json()
    assert body["removed"] == "drop-peer"
    # the response says exactly how much evidence outlives the entry
    assert body["replicas_left"]["audit"] == held_before
    assert body["replicas_left"]["vault"] == 1
    assert body["replicas_left"]["sessions"] == 1

    # the replicated rows really are still on disk - they are this node's
    # own DR record, not the peer's registry entry
    with client.application.app_context():
        assert ClusterAuditReplica.query.count() == held_before
    assert (
        client.get(f"/api/v1/cluster/nodes/{node['id']}", headers=ADMIN)
        .status_code
        == 404
    )

    # but this node cannot unregister itself
    own = client.delete(
        f"/api/v1/cluster/nodes/{self_node(client)['id']}", headers=ACTOR
    )
    assert own.status_code == 409
    assert "cannot be removed" in own.get_json()["error"]


# ---------------------------------------------------------------------------
# probes: real HTTP, measured latency, honest errors
# ---------------------------------------------------------------------------
def test_probe_reports_an_unreachable_peer_verbatim(client):
    node = register(client, "dead-probe-peer", base_url=CLOSED_URL)

    first = probe(client, node["id"])
    assert first["probe"]["url"] == f"{CLOSED_URL}/health"
    assert first["probe"]["health"] == "unreachable"
    assert first["probe"]["error"].startswith("connection failed:")
    assert first["probe"]["state_changed"] is True  # unknown -> unreachable
    assert isinstance(first["probe"]["latency_ms"], int)
    assert first["probe"]["latency_ms"] >= 0
    assert first["node"]["health"] == "unreachable"
    assert first["node"]["consecutive_failures"] == 1

    # a second failed probe counts again but adds no trail row (no change)
    second = probe(client, node["id"])
    assert second["node"]["consecutive_failures"] == 2
    assert second["probe"]["state_changed"] is False
    probe_events = [e for e in cluster_events(client) if e["action"] == "probe"]
    assert len(probe_events) == 1
    assert probe_events[0]["detail"]["from"] == "unknown"


def test_probe_measures_a_real_peer_and_captures_its_identity(
    client, make_peer
):
    peer = make_peer()  # own DB, open auth, node_name pam-node-2
    node = register(client, "live-peer", base_url=peer.base_url)

    body = probe(client, node["id"])
    assert body["probe"]["health"] == "healthy"
    assert body["probe"]["error"] == ""
    assert body["probe"]["latency_ms"] >= 0
    # the peer's own /health payload, not an assumption
    assert body["probe"]["peer"]["status"] == "ok"
    assert body["probe"]["peer"]["database"] == "ok"
    assert body["probe"]["peer"]["node"] == "pam-node-2"
    assert body["probe"]["peer"]["auth"] == "open"
    assert body["node"]["health"] == "healthy"
    assert body["node"]["consecutive_failures"] == 0
    assert body["node"]["last_error"] == ""


def test_probe_calls_a_200_that_is_not_ok_degraded(client, httpd):
    sick = httpd.serve(_json_wsgi("200 OK", {"status": "degraded", "database": "error"}))
    node = register(client, "sick-peer", base_url=sick)
    body = probe(client, node["id"])
    assert body["probe"]["health"] == "degraded"
    assert body["probe"]["error"] == "peer reported no healthy status"
    assert body["probe"]["state_changed"] is True
    assert body["node"]["consecutive_failures"] == 1

    # a peer answering 503 is degraded with the status verbatim
    down = httpd.serve(_json_wsgi("503 Service Unavailable", {"status": "error"}))
    failing = register(client, "down-peer", base_url=down)
    body = probe(client, failing["id"])
    assert body["probe"]["health"] == "degraded"
    assert body["probe"]["error"] == "HTTP 503"


def test_probe_trail_records_only_state_changes(client, make_peer):
    peer = make_peer()
    node = register(client, "quiet-peer", base_url=peer.base_url)

    assert probe(client, node["id"])["probe"]["state_changed"] is True
    assert probe(client, node["id"])["probe"]["state_changed"] is False
    assert probe(client, node["id"])["probe"]["state_changed"] is False

    probe_events = [e for e in cluster_events(client) if e["action"] == "probe"]
    assert len(probe_events) == 1  # a quiet healthy clock adds no rows


def test_probe_refuses_a_node_without_a_base_url(client):
    response = client.post(
        f"/api/v1/cluster/nodes/{self_node(client)['id']}/probe", headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "base_url"


# ---------------------------------------------------------------------------
# pull replication: re-hashed chains, sealed vault, session metadata
# ---------------------------------------------------------------------------
def test_sync_pulls_the_peer_chain_verifies_it_and_never_merges(
    client, make_peer
):
    peer = make_peer()
    seed_peer(peer)
    node = register(client, "peer-a", base_url=peer.base_url)

    first = sync(client, node["id"])  # default kinds: audit + vault + sessions
    assert first["ok"] is True
    chain = first["kinds"]["audit"]
    assert chain["pulled"] >= 3  # settings + vault + session history, real
    assert chain["new"] == chain["pulled"]
    assert chain["verified"] == chain["pulled"]  # re-hashed here, record by record
    assert chain["unverified"] == 0
    assert chain["first_break_seq"] is None and chain["intact"] is True

    # the sync landed on the trail with its real counts
    synced = next(e for e in cluster_events(client) if e["action"] == "synced")
    assert synced["detail"]["kinds"] == ["audit", "vault", "sessions"]
    assert synced["detail"]["audit_pulled"] == chain["pulled"]

    # replica posture: what this DR node holds
    replicas = client.get("/api/v1/cluster/replicas", headers=ADMIN).get_json()
    held = replicas["nodes"]["peer-a"]
    assert held["audit"]["records"] == chain["pulled"]
    assert held["audit"]["verified"] == chain["pulled"]
    assert held["audit"]["unverified"] == 0
    assert held["audit"]["head_seq"] == chain["pulled"]  # contiguous from seq 1
    assert held["audit"]["head_hash"]
    assert held["vault"]["secrets"] == 1
    assert held["sessions"] == 1
    assert held["last_synced_at"] is not None
    assert replicas["totals"] == {
        "audit": chain["pulled"],
        "vault": 1,
        "sessions": 1,
    }

    # nothing from the peer merged into this node's live product tables
    assert (
        client.get("/api/v1/events", query_string={"source": "vault"})
        .get_json()["total"]
        == 0
    )
    assert client.get("/api/v1/sessions", headers=ADMIN).get_json()["total"] == 0

    # re-syncing stores nothing twice
    second = sync(client, node["id"])
    assert second["kinds"]["audit"]["new"] == 0
    assert second["kinds"]["vault"]["new"] == 0
    assert second["kinds"]["sessions"]["new"] == 0
    assert second["kinds"]["audit"]["pulled"] == chain["pulled"]


def test_sync_stores_a_tampered_peer_chain_as_unverified_evidence(
    client, make_peer
):
    peer = make_peer()
    seed_peer(peer)
    export = peer.client.get("/api/v1/audit/export").get_data(as_text=True)
    records = [json.loads(line) for line in export.splitlines() if line.strip()]
    assert len(records) >= 3
    target_seq = records[1]["seq"]

    # tamper with storage-level access: exactly the edit the append-only
    # trigger exists to stop - a record's content changed behind its hash
    db_file = Path(peer.config.database_uri[len("sqlite:///"):])
    connection = sqlite3.connect(str(db_file))
    try:
        connection.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        cursor = connection.execute(
            "UPDATE audit_events SET detail = ? WHERE seq = ?",
            ('{"tampered": true}', target_seq),
        )
        assert cursor.rowcount == 1
        connection.commit()
    finally:
        connection.close()

    node = register(client, "tampered-peer", base_url=peer.base_url)
    chain = sync(client, node["id"], kinds=["audit"])["kinds"]["audit"]

    # the break is located, and trust stops there - everything after the
    # break is stored unverified, because chain trust is transitive
    assert chain["intact"] is False
    assert chain["first_break_seq"] == target_seq
    assert chain["verified"] == target_seq - 1
    assert chain["unverified"] == chain["pulled"] - target_seq + 1

    replicas = client.get("/api/v1/cluster/replicas", headers=ADMIN).get_json()
    assert (
        replicas["nodes"]["tampered-peer"]["audit"]["unverified"]
        == chain["pulled"] - target_seq + 1
    )
    with client.application.app_context():
        rows = ClusterAuditReplica.query.order_by(ClusterAuditReplica.seq).all()
    assert [row.verified for row in rows] == (
        [True] * (target_seq - 1) + [False] * (len(rows) - target_seq + 1)
    )


def test_sync_shared_vault_key_opens_the_replicated_ciphertext(
    client, config, make_peer
):
    # the runbook's explicit shared-key deployment: both nodes point at the
    # same vault key file, so the pulled ciphertext actually opens here
    peer = make_peer(vault_key_path=config.vault_key_path)
    seed_peer(peer, secret="shared-key-plaintext-77")

    node = register(client, "shared-peer", base_url=peer.base_url)
    part = sync(client, node["id"], kinds=["vault"])["kinds"]["vault"]
    assert part == {"pulled": 1, "new": 1, "decryptable_here": 1}

    held = client.get("/api/v1/cluster/replicas", headers=ADMIN).get_json()
    assert held["nodes"]["shared-peer"]["vault"] == {
        "secrets": 1,
        "decryptable_here": 1,
    }
    with client.application.app_context():
        row = ClusterSecretReplica.query.first()
        assert row.plaintext_here is True
        # stored as the peer sealed it - the plaintext is not in the row
        assert "shared-key-plaintext-77" not in row.sealed_blob
        assert isinstance(json.loads(row.sealed_blob), dict)


def test_sync_foreign_vault_key_stays_sealed(client, make_peer):
    # the default deployment: each node has its own vault key, so the pulled
    # ciphertext is evidence this node cannot read - honestly recorded
    peer = make_peer()
    seed_peer(peer, secret="peer-only-plaintext-31")

    node = register(client, "sealed-peer", base_url=peer.base_url)
    part = sync(client, node["id"], kinds=["vault"])["kinds"]["vault"]
    assert part["pulled"] == 1 and part["new"] == 1
    assert part["decryptable_here"] == 0

    held = client.get("/api/v1/cluster/replicas", headers=ADMIN).get_json()
    assert held["nodes"]["sealed-peer"]["vault"] == {
        "secrets": 1,
        "decryptable_here": 0,
    }
    with client.application.app_context():
        row = ClusterSecretReplica.query.first()
        assert row.plaintext_here is False
        assert "peer-only-plaintext-31" not in row.sealed_blob


def test_sync_session_metadata_is_evidence_not_a_merge(client, make_peer):
    peer = make_peer()
    session = seed_peer(peer)
    node = register(client, "sess-peer", base_url=peer.base_url)

    part = sync(client, node["id"], kinds=["sessions"])["kinds"]["sessions"]
    assert part == {"pulled": 1, "new": 1}

    # keyed by the peer's session_ref - who had access to what, and when
    with client.application.app_context():
        row = ClusterSessionReplica.query.first()
        assert row.session_id == session["session_ref"]
        assert row.payload["target"] == "web-01.prod:22"
        assert row.payload["protocol"] == "ssh"
    assert (
        client.get("/api/v1/cluster/replicas", headers=ADMIN)
        .get_json()["nodes"]["sess-peer"]["sessions"]
        == 1
    )
    # the live session table on this node stays empty - replicas are
    # evidence, never a merge into this node's product state
    assert client.get("/api/v1/sessions", headers=ADMIN).get_json()["total"] == 0

    assert sync(client, node["id"], kinds=["sessions"])["kinds"]["sessions"]["new"] == 0


def test_sync_transport_failure_is_reported_verbatim(client):
    node = register(client, "dead-sync-peer", base_url=CLOSED_URL)
    result = sync(client, node["id"], kinds=["audit"])

    assert result["ok"] is False
    assert result["error"].startswith("connection failed:")
    assert result["kinds"] == {}  # nothing applied, nothing invented

    row = client.get(
        f"/api/v1/cluster/nodes/{node['id']}", headers=ADMIN
    ).get_json()["node"]
    assert row["health"] == "unreachable"
    assert row["consecutive_failures"] == 1
    assert row["last_error"] == result["error"][:255]

    failed = next(e for e in cluster_events(client) if e["action"] == "sync-failed")
    assert failed["detail"]["error"] == result["error"][:255]
    assert failed["detail"]["applied"] == []


def test_sync_refuses_to_pull_from_this_node(client):
    own_id = self_node(client)["id"]
    no_url = client.post(
        f"/api/v1/cluster/nodes/{own_id}/sync", json={}, headers=ACTOR
    )
    assert no_url.status_code == 400
    assert no_url.get_json()["details"]["field"] == "base_url"

    assert client.patch(
        f"/api/v1/cluster/nodes/{own_id}",
        json={"base_url": "https://dc.example/pam"},
        headers=ACTOR,
    ).status_code == 200
    from_itself = client.post(
        f"/api/v1/cluster/nodes/{own_id}/sync", json={}, headers=ACTOR
    )
    assert from_itself.status_code == 400
    assert "cannot sync from itself" in from_itself.get_json()["error"]


def test_sync_validates_its_body_before_touching_the_network(client):
    node = register(client, "validation-peer", base_url=CLOSED_URL)

    def rejected(payload):
        response = client.post(
            f"/api/v1/cluster/nodes/{node['id']}/sync",
            json=payload,
            headers=ACTOR,
        )
        assert response.status_code == 400, response.get_json()
        return response.get_json()

    assert "must be a non-empty list" in rejected({"kinds": "audit"})["error"]
    unknown = rejected({"kinds": ["audit", "telepathy"]})
    assert "unknown sync kind 'telepathy'" in unknown["error"]
    assert unknown["details"]["allowed"] == ["audit", "vault", "sessions"]
    assert "between 1 and 120" in rejected({"timeout_seconds": 0})["error"]
    assert "'peer_token' must be a string" in rejected({"peer_token": 7})["error"]

    # an unknown node is still a 404
    assert (
        client.post(
            "/api/v1/cluster/nodes/9999/sync", json={}, headers=ACTOR
        ).status_code
        == 404
    )


def test_peer_token_is_used_outbound_only(client, make_peer):
    # a peer in token mode: the sealed pulls require its admin credential
    peer = make_peer(admin_token="peer-secret-token")
    seed_peer(peer)
    node = register(client, "token-peer", base_url=peer.base_url)

    # without the token the peer refuses the sealed pulls (audit export is
    # public, so that half applies first and stays applied - honest partial)
    without = sync(client, node["id"], kinds=["audit", "vault"])
    assert without["ok"] is False
    assert without["error"].startswith("HTTP 401 from ")
    assert "audit" in without["kinds"] and "vault" not in without["kinds"]
    failed = next(e for e in cluster_events(client) if e["action"] == "sync-failed")
    assert failed["detail"]["applied"] == ["audit"]
    row = client.get(
        f"/api/v1/cluster/nodes/{node['id']}", headers=ADMIN
    ).get_json()["node"]
    assert row["health"] == "unreachable"

    # with the token every kind pulls
    with_token = sync(client, node["id"], peer_token="peer-secret-token")
    assert with_token["ok"] is True
    assert with_token["kinds"]["vault"]["new"] == 1
    assert with_token["kinds"]["sessions"]["new"] == 1

    # the token went outbound only: never echoed, never stored, never trailed
    everything = json.dumps(with_token) + json.dumps(cluster_events(client))
    assert "peer-secret-token" not in everything
    assert "peer-secret-token" not in json.dumps(row)


# ---------------------------------------------------------------------------
# failover: the role is enforced, not decoration
# ---------------------------------------------------------------------------
def test_demote_gates_every_product_write_but_not_reads_or_cluster_ops(client):
    # writes work on the active node
    onboard(client, "pre-demote-cred", secret="active-node-plaintext")

    demoted = failover(client, "demote", reason="DR drill")
    assert demoted.status_code == 200
    assert demoted.get_json() == {
        "node": "pam-node-1",
        "from": "active",
        "to": "passive",
    }

    # every product write outside the cluster module is refused 409 ...
    vault = client.post(
        "/api/v1/vault/items",
        json={
            "name": "while-passive",
            "secret_type": "database",
            "target": "db.prod:5432",
            "principal": "dba",
        },
        headers=ACTOR,
    )
    assert vault.status_code == 409
    assert vault.get_json()["details"] == {
        "role": "passive",
        "promote": "POST /api/v1/cluster/failover",
    }
    # ... even without credentials: the gate consults this node's own row
    # before auth, so the refusal explains itself instead of a bare 401
    unauthenticated = client.post(
        "/api/v1/vault/items", json={"name": "anonymous-write"}
    )
    assert unauthenticated.status_code == 409
    assert client.put(
        "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 5}, headers=ACTOR
    ).status_code == 409
    assert (
        client.post(
            "/api/v1/sessions", json={"protocol": "ssh", "target": "w:22"},
            headers=ACTOR,
        ).status_code
        == 409
    )
    # read-shaped POSTs are gated too - blunt by design: the load balancer
    # keeps traffic on the active node, and this node does not replicate
    # license state, so it does not answer entitlement questions either
    assert (
        client.post("/api/v1/licenses/validate", json={}, headers=ACTOR).status_code
        == 409
    )

    # reads still answer - that is what a standby is for
    assert client.get("/api/v1/audit/stats", headers=ADMIN).status_code == 200
    assert client.get("/api/v1/vault/items", headers=ADMIN).status_code == 200
    assert client.get("/health").get_json()["role"] == "passive"
    # so does authentication: a passive node must stay inspectable
    login = client.post("/api/v1/auth/ldap", json={})
    assert login.status_code == 400  # reached the handler, not the gate
    assert login.get_json()["details"]["field"] == "username"
    # and the cluster module stays writable: the standby's own job
    assert register(client, "drill-peer")["health"] == "unknown"


def test_promote_restores_writes(client):
    assert failover(client, "demote").status_code == 200
    assert (
        client.put(
            "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 4}, headers=ACTOR
        ).status_code
        == 409
    )

    promoted = failover(client, "promote")
    assert promoted.get_json() == {
        "node": "pam-node-1",
        "from": "passive",
        "to": "active",
    }
    assert (
        client.put(
            "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 4}, headers=ACTOR
        ).status_code
        == 200
    )
    assert client.get("/health").get_json()["role"] == "active"


def test_failover_validates_actions_and_records_from_to_on_the_trail(client):
    bad = failover(client, "sideways")
    assert bad.status_code == 400
    assert bad.get_json()["details"]["field"] == "action"

    # already active: a promote is a conflict, not a silent no-op
    already = failover(client, "promote")
    assert already.status_code == 409
    assert "already active" in already.get_json()["error"]

    demoted = failover(client, "demote", reason="DR drill")
    assert demoted.status_code == 200
    again = failover(client, "demote")
    assert again.status_code == 409
    assert "already passive" in again.get_json()["error"]

    assert failover(client, "promote").status_code == 200

    events = {
        event["action"]: event
        for event in cluster_events(client)
        if event["action"] in ("demoted", "promoted")
    }
    assert set(events) == {"demoted", "promoted"}
    assert events["demoted"]["actor"] == "admin"
    assert events["demoted"]["detail"] == {
        "from": "active",
        "to": "passive",
        "reason": "DR drill",
    }
    assert events["promoted"]["detail"] == {"from": "passive", "to": "active"}


# ---------------------------------------------------------------------------
# automatic failover: opt-in, threshold-counted, never a silent demote
# ---------------------------------------------------------------------------
def test_monitor_tick_is_a_noop_on_an_active_node(client):
    assert tick(client) == {"role": "active", "probed": [], "promoted": False}
    # and it added no trail row - nothing happened
    assert cluster_events(client) == []


def test_monitor_promotes_only_after_the_failure_threshold(client):
    node = register(client, "dead-peer", role="active", base_url=CLOSED_URL)
    assert failover(client, "demote").status_code == 200

    # ticks 1 and 2: real probes fail, failures accumulate, no promotion
    for expected_failures in (1, 2):
        body = tick(client)
        assert body["role"] == "passive" and body["promoted"] is False
        assert body["probed"] == [
            {
                "node": "dead-peer",
                "health": "unreachable",
                "consecutive_failures": expected_failures,
                "error": body["probed"][0]["error"],
            }
        ]
        assert body["probed"][0]["error"].startswith("connection failed:")

    # tick 3 reaches CLUSTER_FAILOVER_FAILURES: this node takes over
    promoted = tick(client)
    assert promoted["promoted"] is True
    assert promoted["role"] == "active"
    assert "3 consecutive probes" in promoted["reason"]

    # the promotion is on the trail with the threshold it counted
    event = next(
        e for e in cluster_events(client) if e["action"] == "promoted"
    )
    assert event["detail"]["automatic"] is True
    assert event["detail"]["threshold"] == 3
    assert event["detail"]["from"] == "passive"
    assert event["detail"]["to"] == "active"

    # the role really flipped: writes work again
    assert (
        client.put(
            "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 3}, headers=ACTOR
        ).status_code
        == 200
    )
    # an active node never auto-demotes - failback is an operator decision
    assert tick(client) == {"role": "active", "probed": [], "promoted": False}
    assert client.get(
        f"/api/v1/cluster/nodes/{node['id']}", headers=ADMIN
    ).status_code == 200


def test_monitor_waits_for_every_active_peer_to_fail(client, make_peer):
    register(client, "monitor-dead-peer", role="active", base_url=CLOSED_URL)
    live = make_peer()
    register(client, "monitor-live-peer", role="active", base_url=live.base_url)
    assert failover(client, "demote").status_code == 200

    # three ticks: the dead peer fails all three, the live one never does -
    # promotion needs ALL registered active peers down, not just one
    for _ in range(3):
        body = tick(client)
        assert body["promoted"] is False
        assert body["role"] == "passive"
        assert {entry["node"] for entry in body["probed"]} == {
            "monitor-dead-peer",
            "monitor-live-peer",
        }
    health = {
        entry["node"]: entry["health"]
        for entry in body["probed"]
    }
    assert health == {
        "monitor-dead-peer": "unreachable",
        "monitor-live-peer": "healthy",
    }
    assert self_node(client)["role"] == "passive"


def test_monitor_notes_the_absence_of_a_registered_peer(client):
    assert failover(client, "demote").status_code == 200
    body = tick(client)
    assert body == {
        "role": "passive",
        "probed": [],
        "promoted": False,
        "note": "no active peer with a base_url is registered",
    }


# ---------------------------------------------------------------------------
# backups: a real file, hashed, and re-verified from the copy itself
# ---------------------------------------------------------------------------
def test_backup_is_a_real_verified_file(client, config):
    assert client.put(
        "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 3}, headers=ACTOR
    ).status_code == 200

    created = client.post("/api/v1/cluster/backups", headers=ACTOR)
    assert created.status_code == 201, created.get_json()
    backup = created.get_json()["backup"]

    path = Path(backup["path"])
    assert path.parent == config.cluster_backup_dir
    assert path.exists() and path.is_file()
    raw = path.read_bytes()
    assert len(raw) > 0
    assert backup["size_bytes"] == len(raw)
    assert backup["sha256"] == hashlib.sha256(raw).hexdigest()
    assert backup["audit_seq"] >= 1
    # the copy was re-opened read-only and its chain re-walked
    assert backup["verified"] is True
    assert backup["verify_detail"] == (
        f"chain intact over {backup['audit_seq']} records"
    )
    assert backup["created_by"] == "admin"

    listed = client.get("/api/v1/cluster/backups", headers=ADMIN).get_json()
    assert listed["backups"][0]["id"] == backup["id"]
    event = next(e for e in cluster_events(client) if e["action"] == "backup")
    assert event["detail"]["sha256"] == backup["sha256"]
    assert event["detail"]["verified"] is True

    overview = client.get("/api/v1/cluster", headers=ADMIN).get_json()["backups"]
    assert overview["total"] == 1
    assert overview["verified"] == 1
    assert overview["latest"]["sha256"] == backup["sha256"]


def test_backup_verifier_detects_a_tampered_copy(client):
    # real history first: the copy must hold at least one chain record
    assert client.put(
        "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 3}, headers=ACTOR
    ).status_code == 200
    created = client.post("/api/v1/cluster/backups", headers=ACTOR)
    path = Path(created.get_json()["backup"]["path"])

    # storage-level tamper inside the copy: the append-only trigger would
    # stop it on the live store, so drop it - the re-walk must still catch it
    connection = sqlite3.connect(str(path))
    try:
        connection.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        cursor = connection.execute(
            "UPDATE audit_events SET detail = ? WHERE seq = 1",
            ('{"tampered": true}',),
        )
        assert cursor.rowcount == 1
        connection.commit()
    finally:
        connection.close()

    with client.application.app_context():
        verified, detail = service_module._verify_backup_chain(path)
    assert verified is False
    assert detail == "content hash mismatch at seq 1"


def test_backup_verifier_reports_a_file_without_a_chain(tmp_path, client):
    not_a_backup = tmp_path / "unrelated.db"
    connection = sqlite3.connect(str(not_a_backup))
    connection.execute("CREATE TABLE unrelated (id INTEGER)")
    connection.close()

    with client.application.app_context():
        verified, detail = service_module._verify_backup_chain(not_a_backup)
    assert verified is False
    assert detail.startswith("backup has no readable audit_events table")


def test_backup_refuses_a_non_sqlite_storage_engine(client, config):
    swapped = dataclasses.replace(
        config, database_uri="postgresql://pam@db-host/pam"
    )
    original = client.application.config["LICENSE_CONFIG"]
    client.application.config["LICENSE_CONFIG"] = swapped
    try:
        response = client.post("/api/v1/cluster/backups", headers=ACTOR)
        assert response.status_code == 503
        body = response.get_json()
        assert "SQLite" in body["error"]
        assert body["details"] == {"scheme": "postgresql"}
    finally:
        client.application.config["LICENSE_CONFIG"] = original


# ---------------------------------------------------------------------------
# overview, exports, health identity, ledger fan-in, credentials
# ---------------------------------------------------------------------------
def test_overview_aggregates_the_real_topology(client):
    register(client, "ov-peer")
    body = client.get("/api/v1/cluster", headers=ADMIN).get_json()

    assert body["self"] == {
        "name": "pam-node-1",
        "site": "dc",
        "role": "active",
        "auth": "token",
    }
    assert len(body["nodes"]) == 2
    assert body["peers"] == {
        "total": 1,
        "by_health": {"unknown": 1, "healthy": 0, "degraded": 0, "unreachable": 0},
    }
    assert body["replication"]["totals"] == {"audit": 0, "vault": 0, "sessions": 0}
    # this node is never its own replication source: the posture table lists
    # registered peers only (zero-filled until the first sync), never self
    assert "pam-node-1" not in body["replication"]["nodes"]
    assert list(body["replication"]["nodes"]) == ["ov-peer"]
    assert body["backups"] == {"total": 0, "verified": 0, "latest": None}
    assert body["monitor"] == {
        "failover_failures": 3,
        "probe_timeout_seconds": 5,
        "sync_timeout_seconds": 30,
    }


def test_exports_carry_ciphertext_and_metadata_only(client):
    item = onboard(client, "export-cred", secret="export-plaintext-8d3f")
    session = start_session(client)

    vault = client.get("/api/v1/cluster/export/vault", headers=ADMIN).get_json()
    assert vault["count"] == 1
    entry = vault["items"][0]
    assert entry["item_id"] == item["id"]
    assert entry["secret_type"] == "database"
    assert isinstance(entry["blob"], dict)
    # the plaintext never crosses the replication endpoint
    assert "export-plaintext-8d3f" not in json.dumps(vault)

    sessions = client.get(
        "/api/v1/cluster/export/sessions", headers=ADMIN
    ).get_json()
    assert sessions["count"] == 1
    metadata = sessions["sessions"][0]
    assert metadata["session_ref"] == session["session_ref"]
    assert metadata["target"] == "web-01.prod:22"
    assert metadata["protocol"] == "ssh"


def test_health_advertises_this_nodes_identity(client):
    payload = client.get("/health").get_json()
    assert payload["node"] == "pam-node-1"
    assert payload["site"] == "dc"
    assert payload["role"] == "active"
    assert payload["status"] == "ok"


def test_cluster_is_the_sixteenth_ledger_source(client):
    assert len(audit_module.AUDIT_SOURCES) == 16
    assert audit_module.AUDIT_SOURCES[-1] == "cluster"

    stats = client.get("/api/v1/audit/stats").get_json()
    assert set(stats["by_source"]) == set(audit_module.AUDIT_SOURCES)
    assert stats["by_source"]["cluster"] == 0  # startup seeded no rows

    register(client, "ledger-peer")
    assert client.get("/api/v1/audit/stats").get_json()["by_source"]["cluster"] >= 1

    feed = client.get(
        "/api/v1/events", query_string={"source": "cluster"}
    ).get_json()
    assert feed["total"] >= 1
    assert all(row["source"] == "cluster" for row in feed["events"])
    assert all(row["id"].startswith("cluster:") for row in feed["events"])

    # unknown sources are still refused, and the chain still verifies
    assert (
        client.get("/api/v1/events", query_string={"source": "clusters"}).status_code
        == 400
    )
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_cluster_endpoints_require_the_admin_credential(client):
    assert client.get("/api/v1/cluster").status_code == 401
    assert client.get("/api/v1/cluster/nodes").status_code == 401
    assert client.get("/api/v1/cluster/backups").status_code == 401
    assert (
        client.post(
            "/api/v1/cluster/nodes",
            json={"name": "sneaky", "base_url": "https://s.example"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/cluster/nodes",
            json={"name": "sneaky", "base_url": "https://s.example"},
        ).status_code
        == 401  # the gate (active) passes, auth still refuses
    )
    assert client.get("/api/v1/cluster", headers=ADMIN).status_code == 200
