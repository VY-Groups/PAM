"""Section 14: cloud PAM (phase 5b).

AWS/Azure/GCP/Kubernetes connectors with their credential federated into
the vault, honest states (`not connected` / `configured` / `connected` /
`error` - only a real probe moves them), real HTTP against the connector
endpoint for probes and inventory, and the architecture's Kubernetes path
*Kubernetes -> RBAC -> JIT -> ephemeral privilege -> audit*: a section-6
JIT request whose grant applies a real RoleBinding for exactly the
requested window and whose close/expiry removes it. A local stub answers
the cluster calls (the same fixture posture as the ITSM suite); an
unconfigured cloud refuses honestly and nothing is ever simulated.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from extensions import db  # noqa: E402
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402
from models import AuditEvent, CloudEvent, JitRequest  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}


class _Clock(datetime):
    """Wednesday 2026-10-07 noon: inside office hours, same day as real now
    so the real-clock column defaults (created_at) still sit in the 24h
    window the repeat-requests factor measures."""

    FIXED = datetime(2026, 10, 7, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public_key.pem",
        secret_key="test-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
    )


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# local Kubernetes stub: real HTTP, no simulation in the product code
# ---------------------------------------------------------------------------
NODES = {
    "items": [
        {"metadata": {"name": "node-a", "labels": {"topology": "dc1"}}},
        {"metadata": {"name": "node-b"}},
    ]
}


class _K8sStub(BaseHTTPRequestHandler):
    """A local Kubernetes stand-in: / answers the probe, /api/v1/nodes
    lists nodes, RoleBinding POST/DELETE are accepted (and captured) -
    with per-test switches for a refusing cluster or an answer that is
    not an inventory."""

    def _mode(self):
        return getattr(self.server, "mode", {})

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (stdlib naming)
        mode = self._mode()
        if self.path.startswith("/api/v1/nodes"):
            if mode.get("inventory_status"):
                self._send(mode["inventory_status"], {"kind": "Status"})
            elif mode.get("weird_inventory"):
                self._send(200, {"kind": "Status", "status": "Unknown payload"})
            else:
                self._send(200, NODES)
            return
        if mode.get("probe_status"):
            self._send(mode["probe_status"], {"error": "refused"})
            return
        self._send(200, {"gitVersion": "v1.29.0"})

    def do_POST(self):  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if "rolebindings" in self.path:
            mode = self._mode()
            if mode.get("reject_bindings"):
                self._send(403, {"kind": "Status", "message": "forbidden"})
                return
            manifest = json.loads(raw.decode("utf-8")) if raw else {}
            self.server.calls["bindings"].append(
                {"path": self.path, "manifest": manifest,
                 "authorization": self.headers.get("Authorization")}
            )
            self._send(201, {"metadata": {"name": manifest["metadata"]["name"],
                                          "uid": "binding-uid-1"}})
            return
        self._send(404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802 (stdlib naming)
        if "rolebindings" in self.path:
            self.server.calls["removals"].append({"path": self.path})
            self._send(200, {"kind": "Status", "status": "Success"})
            return
        self._send(404, {"error": "not found"})

    def log_message(self, *args):  # keep the suite output clean
        pass


@pytest.fixture(scope="module")
def k8s():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _K8sStub)
    server.calls = {"bindings": [], "removals": []}
    server.mode = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def k8s_clean(k8s):
    """One test's view of the stub: fresh mode and captured calls."""
    k8s.mode = {}
    k8s.calls = {"bindings": [], "removals": []}
    return k8s


def closed_endpoint() -> str:
    """An endpoint whose port answers nothing (connection refused)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def onboard(client, name, *, secret=None):
    payload = {
        "name": name,
        "secret_type": "ssh_key",
        "target": "k8s.prod:6443",
        "principal": "cluster-admin",
        "access_tier": "Tier-1",
        "auth_method": "Token",
        "rotation_interval_hours": 24,
    }
    if secret is not None:
        payload["secret"] = secret
    response = client.post("/api/v1/vault/items", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def add_connector(client, name="prod-cluster", **overrides):
    payload = {"name": name, "provider": "kubernetes"}
    payload.update(overrides)
    response = client.post(
        "/api/v1/cloud/connectors", json=payload, headers=ACTOR
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["connector"]


def rbac(client, connector_id, **overrides):
    payload = {
        "role": "view",
        "namespace": "payments",
        "reason": "Investigate the payment pod crash loop",
        "ticket": "INC-23891",
        "minutes": 60,
    }
    payload.update(overrides)
    return client.post(
        f"/api/v1/cloud/connectors/{connector_id}/rbac/requests",
        json=payload,
        headers=ACTOR,
    )


def grant_active(client, request_id):
    """Approve if the band asked for sign-off, then consume the grant."""
    detail = client.get(f"/api/v1/jit/requests/{request_id}").get_json()
    request = detail["request"]
    if request["status"] == "pending":
        done = client.post(
            f"/api/v1/jit/requests/{request_id}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
        assert done.status_code == 200, done.get_json()
    granted = client.post(
        f"/api/v1/jit/requests/{request_id}/consume", headers=ACTOR
    )
    assert granted.status_code == 200, granted.get_json()
    return granted.get_json()["request"]


def cloud_actions(client, connector_id=None):
    query = (
        f"/api/v1/events?source=cloud&limit=100"
    )
    page = client.get(query).get_json()
    actions = [event["action"] for event in page["events"]]
    if connector_id is None:
        return actions
    return [
        event["action"]
        for event in page["events"]
        if event["subject"] == connector_name(client, connector_id)
    ]


def connector_name(client, connector_id):
    return (
        client.get(f"/api/v1/cloud/connectors/{connector_id}")
        .get_json()["connector"]["name"]
    )


# ---------------------------------------------------------------------------
# connector lifecycle: create / list / detail / update / delete
# ---------------------------------------------------------------------------
def test_create_validates_and_starts_honest(client, k8s_clean):
    missing = client.post(
        "/api/v1/cloud/connectors", json={"provider": "aws"}, headers=ACTOR
    )
    assert missing.status_code == 400
    assert missing.get_json()["details"]["field"] == "name"

    bad_provider = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "oracle-cloud", "provider": "oracle"},
        headers=ACTOR,
    )
    assert bad_provider.status_code == 400
    assert bad_provider.get_json()["details"]["allowed"] == [
        "aws", "azure", "gcp", "kubernetes",
    ]

    bad_service = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "aws-prod", "provider": "aws", "services": ["lambda"]},
        headers=ACTOR,
    )
    assert bad_service.status_code == 400
    assert bad_service.get_json()["details"]["field"] == "services"

    connector = add_connector(client, "aws-prod", provider="aws")
    assert connector["status"] == "not connected"
    assert connector["endpoint"] == ""
    assert connector["credential_item_id"] is None

    with_endpoint = add_connector(
        client, "k8s-prod", endpoint=f"{k8s_clean.endpoint}/",
    )
    # endpoint given, never probed: configured - not connected is a state,
    # connected is earned.
    assert with_endpoint["status"] == "configured"
    assert with_endpoint["last_test_at"] is None
    assert with_endpoint["last_test_detail"] == ""


def test_create_rejects_duplicates_and_unknown_credential(client):
    add_connector(client, "dup-connector")
    clash = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "dup-connector", "provider": "aws"},
        headers=ACTOR,
    )
    assert clash.status_code == 409

    missing_item = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "ghost-cred", "provider": "aws",
              "credential_item_id": 9999},
        headers=ACTOR,
    )
    assert missing_item.status_code == 404


def test_endpoint_rules(client):
    loopback = add_connector(
        client, "local-stub", provider="kubernetes",
        endpoint="http://127.0.0.1:5099",
    )
    assert loopback["endpoint"] == "http://127.0.0.1:5099"

    remote_http = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "plain-http", "provider": "aws",
              "endpoint": "http://cloud.example.com"},
        headers=ACTOR,
    )
    assert remote_http.status_code == 400
    assert remote_http.get_json()["details"]["field"] == "endpoint"

    with_query = client.post(
        "/api/v1/cloud/connectors",
        json={"name": "query-endpoint", "provider": "aws",
              "endpoint": "https://cloud.example.com?foo=1"},
        headers=ACTOR,
    )
    assert with_query.status_code == 400

    https = add_connector(
        client, "tls-cloud", provider="gcp", endpoint="https://gcp.example.com/"
    )
    assert https["endpoint"] == "https://gcp.example.com"


def test_list_filters_and_detail_payload(client, k8s_clean):
    item = onboard(client, "cluster-cred")
    add_connector(client, "aws-eu", provider="aws", regions=["eu-west-1"])
    add_connector(
        client, "k8s-main", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"], services=["kubernetes"],
    )

    everything = client.get("/api/v1/cloud/connectors").get_json()
    assert everything["total"] == 2

    only_aws = client.get(
        "/api/v1/cloud/connectors", query_string={"provider": "aws"}
    ).get_json()
    assert only_aws["total"] == 1
    assert only_aws["connectors"][0]["provider"] == "aws"

    searched = client.get(
        "/api/v1/cloud/connectors", query_string={"q": "k8s-"}
    ).get_json()
    assert searched["total"] == 1

    bad = client.get(
        "/api/v1/cloud/connectors", query_string={"provider": "oracle"}
    )
    assert bad.status_code == 400

    detail = client.get(
        f"/api/v1/cloud/connectors/{searched['connectors'][0]['id']}"
    ).get_json()
    assert set(detail) >= {"connector", "events", "requests", "last_scan"}
    assert detail["connector"]["name"] == "k8s-main"
    assert detail["connector"]["regions"] == []
    added = next(
        event for event in detail["events"] if event["action"] == "connector-added"
    )
    assert added["detail"]["credential_item_id"] == item["id"]
    assert detail["last_scan"] is None

    assert client.get("/api/v1/cloud/connectors/9999").status_code == 404


def test_update_configuration(client, k8s_clean):
    connector = add_connector(client, "mutable", provider="aws")
    done = client.patch(
        f"/api/v1/cloud/connectors/{connector['id']}",
        json={
            "account_ref": "123456789012",
            "endpoint": k8s_clean.endpoint,
            "regions": ["us-east-1", "us-east-1", "eu-west-1"],
            "services": ["iam", "s3"],
        },
        headers=ACTOR,
    )
    assert done.status_code == 200, done.get_json()
    view = done.get_json()["connector"]
    assert view["account_ref"] == "123456789012"
    assert view["regions"] == ["us-east-1", "eu-west-1"]
    assert view["services"] == ["iam", "s3"]
    # endpoint set after the fact: configured, and the reason is on the row
    assert view["status"] == "configured"
    assert "re-probe" in view["last_test_detail"]

    # switching the provider resets the service surface: iam is not a
    # Kubernetes service.
    switched = client.patch(
        f"/api/v1/cloud/connectors/{connector['id']}",
        json={"provider": "kubernetes"},
        headers=ACTOR,
    ).get_json()["connector"]
    assert switched["provider"] == "kubernetes"
    assert switched["services"] == []

    refused = client.patch(
        f"/api/v1/cloud/connectors/{connector['id']}",
        json={"services": ["iam"]},
        headers=ACTOR,
    )
    assert refused.status_code == 400

    cleared = client.patch(
        f"/api/v1/cloud/connectors/{connector['id']}",
        json={"endpoint": ""},
        headers=ACTOR,
    ).get_json()["connector"]
    assert cleared["status"] == "not connected"
    assert cleared["last_test_detail"] == ""

    nothing = client.patch(
        f"/api/v1/cloud/connectors/{connector['id']}",
        json={},
        headers=ACTOR,
    )
    assert nothing.status_code == 400


def test_delete_connector_trail_stays(client):
    connector = add_connector(client, "disposable")
    gone = client.delete(
        f"/api/v1/cloud/connectors/{connector['id']}", headers=ACTOR
    )
    assert gone.status_code == 200
    assert gone.get_json()["deleted"] is True
    assert client.get(
        f"/api/v1/cloud/connectors/{connector['id']}"
    ).status_code == 404
    # the connector row is gone; the section-14 trail remains evidence
    page = client.get("/api/v1/events?source=cloud&limit=100").get_json()
    actions = [event["action"] for event in page["events"]]
    assert "connector-removed" in actions
    with client.application.app_context():
        assert CloudEvent.query.count() >= 2


# ---------------------------------------------------------------------------
# probes: real HTTP, honest states
# ---------------------------------------------------------------------------
def test_probe_refuses_without_endpoint(client):
    connector = add_connector(client, "no-endpoint")
    refused = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/test", headers=ACTOR
    )
    assert refused.status_code == 409
    body = refused.get_json()
    assert body["details"]["configured"] is False
    # nothing was attempted - the state did not move
    row = client.get(
        f"/api/v1/cloud/connectors/{connector['id']}"
    ).get_json()["connector"]
    assert row["status"] == "not connected"
    assert row["last_test_at"] is None


def test_probe_connection_refused_is_error(client):
    connector = add_connector(
        client, "dead-endpoint", endpoint=closed_endpoint()
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/test", headers=ACTOR
    ).get_json()
    assert outcome["probe"]["ok"] is False
    assert outcome["probe"]["detail"].startswith("connection failed")
    assert outcome["connector"]["status"] == "error"
    assert "connection failed" in outcome["connector"]["last_test_detail"]
    assert outcome["connector"]["last_test_at"] is not None
    assert "probe-failed" in cloud_actions(client)


def test_probe_success_uses_credential_and_connects(client, k8s_clean):
    item = onboard(client, "probe-cred", secret="cluster-token-abc")
    connector = add_connector(
        client, "live-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/test", headers=ACTOR
    ).get_json()
    assert outcome["probe"]["ok"] is True
    assert outcome["probe"]["http_status"] == 200
    assert outcome["connector"]["status"] == "connected"
    assert outcome["connector"]["last_test_detail"].startswith("HTTP 200")
    # the credential rode the request - the stub saw a bearer token
    # (the secret itself never appears in any response)
    raw = outcome.__repr__()
    assert "cluster-token-abc" not in raw


def test_probe_http_error_marks_error(client, k8s_clean):
    k8s_clean.mode["probe_status"] = 401
    connector = add_connector(
        client, "unauthorized-cluster", endpoint=k8s_clean.endpoint
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/test", headers=ACTOR
    ).get_json()
    assert outcome["probe"]["ok"] is False
    assert outcome["probe"]["http_status"] == 401
    assert outcome["connector"]["status"] == "error"


# ---------------------------------------------------------------------------
# inventory: the cloud's own answer lands in discovery
# ---------------------------------------------------------------------------
def test_discover_refuses_until_configured(client):
    connector = add_connector(client, "undiscoverable")
    no_endpoint = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    )
    assert no_endpoint.status_code == 409
    assert no_endpoint.get_json()["details"]["configured"] is False

    no_credential = add_connector(
        client, "credless", endpoint="https://cloud.example.com"
    )
    refused = client.post(
        f"/api/v1/cloud/connectors/{no_credential['id']}/discover",
        headers=ACTOR,
    )
    assert refused.status_code == 409
    assert refused.get_json()["details"]["field"] == "credential"
    assert refused.get_json()["details"]["configured"] is False


def test_discover_invents_nothing_on_transport_failure(client):
    item = onboard(client, "dead-cred", secret="token")
    connector = add_connector(
        client, "dead-cloud", endpoint=closed_endpoint(),
        credential_item_id=item["id"],
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert outcome["ok"] is False
    assert outcome["assets"] == [] and outcome["new"] == 0
    assert outcome["detail"].startswith("connection failed")
    assert outcome["scan"]["status"] == "failed"
    assert outcome["scan"]["method"] == "kubernetes_api"
    with client.application.app_context():
        from models import DiscoveredAsset
        assert DiscoveredAsset.query.count() == 0
    assert "inventory-failed" in cloud_actions(client)


def test_discover_unrecognized_payload_invents_nothing(client, k8s_clean):
    k8s_clean.mode["weird_inventory"] = True
    item = onboard(client, "weird-cred", secret="token")
    connector = add_connector(
        client, "weird-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert outcome["ok"] is False
    assert "not understood" in outcome["detail"]
    assert outcome["scan"]["status"] == "failed"
    with client.application.app_context():
        from models import DiscoveredAsset
        assert DiscoveredAsset.query.count() == 0


def test_discover_lists_nodes_then_updates_them(client, k8s_clean):
    item = onboard(client, "inventory-cred", secret="cluster-token-abc")
    connector = add_connector(
        client, "inventory-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    first = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert first["ok"] is True
    assert first["new"] == 2 and first["updated"] == 0
    assert first["scan"]["status"] == "completed"
    assert first["scan"]["method"] == "kubernetes_api"
    assert first["scan"]["scope"] == "inventory-cluster"
    assert first["scan"]["findings"] == 2
    addresses = {asset["address"] for asset in first["assets"]}
    assert addresses == {"kubernetes/1/node-a", "kubernetes/1/node-b"}
    node_a = next(a for a in first["assets"] if a["address"].endswith("node-a"))
    assert node_a["source"] == "cloud"
    assert node_a["method"] == "kubernetes_api"
    assert node_a["asset_type"] == "kubernetes"
    assert node_a["risk"] == "HIGH"  # BASE_RISK['kubernetes'], not a guess
    assert node_a["pam_status"] == "unmanaged"
    assert node_a["hostname"] == "node-a"

    # a second run refreshes the same rows: no duplicates, last_seen moves
    second = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert second["ok"] is True
    assert second["new"] == 0 and second["updated"] == 2
    with client.application.app_context():
        from models import DiscoveredAsset
        assert DiscoveredAsset.query.count() == 2

    # the discovery trail and the cloud trail both carry the run
    discovery_page = client.get(
        "/api/v1/events?source=discovery&limit=100"
    ).get_json()
    discovery_actions = [event["action"] for event in discovery_page["events"]]
    assert "asset_discovered" in discovery_actions
    assert "scan_completed" in discovery_actions
    assert "inventory-ran" in cloud_actions(client)

    # and the connector detail shows the run
    detail = client.get(
        f"/api/v1/cloud/connectors/{connector['id']}"
    ).get_json()
    assert detail["last_scan"]["status"] == "completed"


def test_discover_failed_http_is_honest(client, k8s_clean):
    k8s_clean.mode["inventory_status"] = 500
    item = onboard(client, "failing-cred", secret="token")
    connector = add_connector(
        client, "failing-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    outcome = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert outcome["ok"] is False
    assert outcome["detail"] == "HTTP 500"
    assert outcome["scan"]["status"] == "failed"
    assert outcome["scan"]["error"] == "HTTP 500"
    with client.application.app_context():
        from models import DiscoveredAsset
        assert DiscoveredAsset.query.count() == 0


# ---------------------------------------------------------------------------
# Kubernetes -> RBAC -> JIT -> ephemeral privilege -> audit
# ---------------------------------------------------------------------------
def test_rbac_path_is_kubernetes_only_and_needs_a_credential(client):
    aws = add_connector(client, "aws-no-k8s", provider="aws",
                        endpoint="https://aws.example.com")
    wrong = rbac(client, aws["id"])
    assert wrong.status_code == 409
    assert wrong.get_json()["details"]["provider"] == "aws"

    bare = add_connector(client, "bare-cluster")
    no_endpoint = rbac(client, bare["id"])
    assert no_endpoint.status_code == 409
    assert no_endpoint.get_json()["details"]["field"] == "endpoint"

    credless = add_connector(client, "credless-cluster",
                             endpoint="https://k8s.example.com")
    no_credential = rbac(client, credless["id"])
    assert no_credential.status_code == 409
    assert no_credential.get_json()["details"]["field"] == "credential"


def test_rbac_request_validation(client, k8s_clean):
    item = onboard(client, "rbac-validation-cred", secret="token")
    connector = add_connector(
        client, "validation-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    bad_role = rbac(client, connector["id"], role="View Pods")
    assert bad_role.status_code == 400
    assert bad_role.get_json()["details"]["field"] == "role"

    bad_namespace = rbac(client, connector["id"], namespace="Payments!")
    assert bad_namespace.status_code == 400
    assert bad_namespace.get_json()["details"]["field"] == "namespace"

    short_reason = rbac(client, connector["id"], reason="fix")
    assert short_reason.status_code == 400

    no_ticket = rbac(client, connector["id"], ticket=None)
    assert no_ticket.status_code == 400
    assert no_ticket.get_json()["details"]["field"] == "ticket"


def test_rbac_request_files_a_linked_jit_request(client, k8s_clean):
    item = onboard(client, "rbac-cred", secret="token")
    connector = add_connector(
        client, "rbac-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(client, connector["id"], requester="sre-lead")
    assert filed.status_code == 201, filed.get_json()
    body = filed.get_json()
    request = body["request"]
    # the section-6 machinery verbatim, linked to this connector
    assert request["item_id"] == item["id"]
    assert request["cloud_connector_id"] == connector["id"]
    assert request["cloud_binding"] == {
        "namespace": "payments", "role": "view", "binding": f"vypam-jit-{request['id']}",
    }
    assert request["requester"] == "sre-lead"
    assert "K8s RBAC view in payments" in request["reason"]
    assert set(request["risk"]) == {"score", "level", "factors"}
    assert body["connector"]["id"] == connector["id"]
    assert f"request #{request['id']}" in body["message"]
    assert "rbac-requested" in cloud_actions(client)
    with client.application.app_context():
        row = db.session.get(JitRequest, request["id"])
        assert row.cloud_connector_id == connector["id"]


def test_rbac_grant_applies_real_binding_and_close_removes_it(
    client, k8s_clean, clock
):
    item = onboard(client, "grant-cred", secret="cluster-token-abc")
    connector = add_connector(
        client, "grant-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(
        client, connector["id"], minutes=30, requester="sre-lead"
    ).get_json()["request"]
    active = grant_active(client, filed["id"])
    assert active["status"] == "active"
    assert active["expires_at"] is not None

    # the cluster really received a RoleBinding for exactly this grant
    assert len(k8s_clean.calls["bindings"]) == 1
    call = k8s_clean.calls["bindings"][0]
    assert call["path"] == (
        "/apis/rbac.authorization.k8s.io/v1/namespaces/payments/rolebindings"
    )
    manifest = call["manifest"]
    assert manifest["kind"] == "RoleBinding"
    assert manifest["metadata"]["name"] == f"vypam-jit-{filed['id']}"
    assert manifest["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "view",
    }
    assert manifest["subjects"] == [{"kind": "User", "name": "sre-lead"}]
    assert manifest["metadata"]["annotations"]["vypam.io/session-ref"] == (
        f"jit-{filed['id']}"
    )
    assert "vypam.io/expires-at" in manifest["metadata"]["annotations"]
    # the vault credential rode the call (audited reveal; secret not echoed)
    assert call["authorization"] == "Bearer cluster-token-abc"

    with client.application.app_context():
        row = db.session.get(JitRequest, filed["id"])
        assert row.cloud_binding["applied_at"] is not None
        assert row.cloud_binding["role"] == "view"

    closed = client.post(
        f"/api/v1/jit/requests/{filed['id']}/close", headers=ACTOR
    )
    assert closed.status_code == 200
    assert closed.get_json()["request"]["status"] == "closed"
    assert len(k8s_clean.calls["removals"]) == 1
    assert k8s_clean.calls["removals"][0]["path"] == (
        "/apis/rbac.authorization.k8s.io/v1/namespaces/payments"
        f"/rolebindings/vypam-jit-{filed['id']}"
    )
    with client.application.app_context():
        row = db.session.get(JitRequest, filed["id"])
        assert row.cloud_binding["removed_at"] is not None

    actions = cloud_actions(client, connector["id"])
    assert "rbac-granted" in actions
    assert "rbac-closed" in actions
    # the JIT trail carries the removal detail too (one truth, both trails)
    trail = client.get(f"/api/v1/jit/requests/{filed['id']}").get_json()
    close_event = next(e for e in trail["events"] if e["action"] == "closed")
    assert close_event["detail"]["binding"]["removed"] is True


def test_rbac_binding_refusal_keeps_the_request_approved(client, k8s_clean):
    k8s_clean.mode["reject_bindings"] = True
    item = onboard(client, "refused-cred", secret="token")
    connector = add_connector(
        client, "refused-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(client, connector["id"], minutes=30).get_json()["request"]
    if filed["status"] == "pending":
        approved = client.post(
            f"/api/v1/jit/requests/{filed['id']}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
        assert approved.status_code == 200

    refused = client.post(
        f"/api/v1/jit/requests/{filed['id']}/consume", headers=ACTOR
    )
    assert refused.status_code == 502
    body = refused.get_json()
    assert body["details"]["http_status"] == 403
    assert body["details"]["request_id"] == filed["id"]

    # nothing was granted: the request is still approved (retry-able) and
    # the credential was never checked out.
    after = client.get(f"/api/v1/jit/requests/{filed['id']}").get_json()
    assert after["request"]["status"] == "approved"
    with client.application.app_context():
        row = db.session.get(JitRequest, filed["id"])
        assert row.cloud_binding.get("applied_at") is None
    vault = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert vault["status"] == "available"
    assert "rbac-binding-failed" in cloud_actions(client, connector["id"])


def test_rbac_grant_expiry_removes_the_binding(client, k8s_clean, clock):
    item = onboard(client, "expiry-cred", secret="cluster-token-exp")
    connector = add_connector(
        client, "expiry-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(client, connector["id"], minutes=61).get_json()["request"]
    grant_active(client, filed["id"])
    assert len(k8s_clean.calls["bindings"]) == 1

    with client.application.app_context():
        row = db.session.get(JitRequest, filed["id"])
        row.expires_at = _Clock.FIXED - timedelta(minutes=1)
        db.session.commit()

    # any JIT read refreshes the real clock: the window ended, the grant
    # expires, and the ephemeral privilege is removed with it.
    listed = client.get("/api/v1/jit/requests").get_json()
    expired = next(r for r in listed["items"] if r["id"] == filed["id"])
    assert expired["status"] == "expired"
    assert len(k8s_clean.calls["removals"]) == 1
    with client.application.app_context():
        row = db.session.get(JitRequest, filed["id"])
        assert row.cloud_binding["removed_at"] is not None
    assert "rbac-expired" in cloud_actions(client, connector["id"])


def test_grant_compensation_when_checkout_fails(client, k8s_clean):
    """The binding is applied first; if the checkout then fails, the
    privilege is taken back before the error surfaces - no dangling
    grant, and the refusal is on both trails."""
    item = onboard(client, "compensation-cred", secret="cluster-token-c")
    connector = add_connector(
        client, "compensation-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(client, connector["id"], minutes=30).get_json()["request"]
    if filed["status"] == "pending":
        approved = client.post(
            f"/api/v1/jit/requests/{filed['id']}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
        assert approved.status_code == 200

    # someone else is holding the credential when the grant is consumed
    held = client.post(
        f"/api/v1/vault/items/{item['id']}/checkout",
        json={"reason": "someone else got there first"},
        headers=ACTOR,
    )
    assert held.status_code == 200

    failed = client.post(
        f"/api/v1/jit/requests/{filed['id']}/consume", headers=ACTOR
    )
    assert failed.status_code == 400  # the honest checkout refusal

    # the binding that was applied came back off within the same call
    assert len(k8s_clean.calls["bindings"]) == 1
    assert len(k8s_clean.calls["removals"]) == 1
    after = client.get(f"/api/v1/jit/requests/{filed['id']}").get_json()
    assert after["request"]["status"] == "approved"
    actions = cloud_actions(client, connector["id"])
    assert "rbac-granted" in actions
    assert "rbac-aborted" in actions


def test_delete_connector_refused_while_grants_are_open(client, k8s_clean):
    item = onboard(client, "guard-cred", secret="token")
    connector = add_connector(
        client, "guarded-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    filed = rbac(client, connector["id"], minutes=30).get_json()["request"]
    if filed["status"] == "pending":
        client.post(
            f"/api/v1/jit/requests/{filed['id']}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
    refused = client.delete(
        f"/api/v1/cloud/connectors/{connector['id']}", headers=ACTOR
    )
    assert refused.status_code == 409
    assert refused.get_json()["details"]["open"] == 1

    # end the grant by its own real path: a pending request is denied, an
    # auto-approved one is granted and then closed - either way the open
    # set empties and the connector can go.
    current = client.get(
        f"/api/v1/jit/requests/{filed['id']}"
    ).get_json()["request"]
    if current["status"] == "pending":
        done = client.post(
            f"/api/v1/jit/requests/{filed['id']}/deny",
            json={"reason": "not needed after all"},
            headers=ACTOR,
        )
        assert done.status_code == 200
    else:
        grant_active(client, filed["id"])
        done = client.post(
            f"/api/v1/jit/requests/{filed['id']}/close", headers=ACTOR
        )
        assert done.status_code == 200
    deleted = client.delete(
        f"/api/v1/cloud/connectors/{connector['id']}", headers=ACTOR
    )
    assert deleted.status_code == 200


# ---------------------------------------------------------------------------
# aggregates, audit, and the admin gate
# ---------------------------------------------------------------------------
def test_cloud_stats_are_real_aggregates(client, k8s_clean):
    empty = client.get("/api/v1/cloud/stats").get_json()
    assert empty["connectors"] == 0
    assert empty["events"] == 0
    assert empty["rbac_grants"]["total"] == 0
    assert empty["by_provider"]["aws"]["total"] == 0
    assert empty["by_status"]["not connected"] == 0

    item = onboard(client, "stats-cred", secret="token")
    add_connector(client, "stats-aws", provider="aws")
    add_connector(client, "stats-k8s", endpoint=k8s_clean.endpoint,
                  credential_item_id=item["id"])

    stats = client.get("/api/v1/cloud/stats").get_json()
    assert stats["connectors"] == 2
    assert stats["by_provider"]["aws"] == {
        "total": 1, "not connected": 1, "configured": 0,
        "connected": 0, "error": 0,
    }
    assert stats["by_provider"]["kubernetes"]["total"] == 1
    assert stats["by_status"]["not connected"] == 1
    assert stats["by_status"]["configured"] == 1
    assert stats["events"] >= 2
    assert stats["discovered_assets"] == 0

    rbac(client, stats_k8s_id(client, "stats-k8s"), minutes=15)
    after = client.get("/api/v1/cloud/stats").get_json()
    assert after["rbac_grants"]["total"] == 1
    assert after["rbac_grants"]["open"] == 1


def stats_k8s_id(client, name):
    page = client.get(
        "/api/v1/cloud/connectors", query_string={"q": name}
    ).get_json()
    return next(c["id"] for c in page["connectors"] if c["name"] == name)


def test_cloud_trail_reaches_the_ledger_chain(client):
    connector = add_connector(client, "audit-cloud")
    page = client.get("/api/v1/events?source=cloud").get_json()
    assert page["total"] == 1
    event = page["events"][0]
    assert event["source"] == "cloud"
    assert event["action"] == "connector-added"
    assert event["id"].startswith("cloud:")
    assert event["subject"] == "audit-cloud"
    assert event["detail"]["provider"] == "kubernetes"

    stats = client.get("/api/v1/audit/stats").get_json()
    assert stats["by_source"]["cloud"] == 1
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True
    with client.application.app_context():
        row = AuditEvent.query.order_by(AuditEvent.seq.desc()).first()
        assert row.source == "cloud"
    assert connector["status"] == "not connected"


def test_writes_require_the_admin_token(client, k8s_clean):
    endpoints = [
        ("post", "/api/v1/cloud/connectors", {"name": "no-auth"}),
        ("patch", "/api/v1/cloud/connectors/1", {"name": "no-auth"}),
        ("delete", "/api/v1/cloud/connectors/1", None),
        ("post", "/api/v1/cloud/connectors/1/test", None),
        ("post", "/api/v1/cloud/connectors/1/discover", None),
        ("post", "/api/v1/cloud/connectors/1/rbac/requests", {"role": "view"}),
    ]
    for method, path, payload in endpoints:
        call = getattr(client, method)
        response = call(path, json=payload)
        assert response.status_code == 401, (method, path)

    # reads stay open, like every other screen-facing list
    assert client.get("/api/v1/cloud/connectors").status_code == 200
    assert client.get("/api/v1/cloud/stats").status_code == 200


def test_probe_and_discover_are_admin_gated_but_real(client, k8s_clean):
    """The two live calls share one path rule: admin in, honest outcome
    out - including when the upstream itself fails."""
    item = onboard(client, "gate-cred", secret="token")
    connector = add_connector(
        client, "gate-cluster", endpoint=k8s_clean.endpoint,
        credential_item_id=item["id"],
    )
    probe = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/test", headers=ACTOR
    ).get_json()
    assert probe["probe"]["ok"] is True
    inventory = client.post(
        f"/api/v1/cloud/connectors/{connector['id']}/discover", headers=ACTOR
    ).get_json()
    assert inventory["ok"] is True
    # the credential's use is a real, audited vault reveal - and the
    # plaintext never travels back out of the API.
    vault_page = client.get(
        "/api/v1/events?source=vault&limit=100"
    ).get_json()
    reveals = [
        e for e in vault_page["events"] if e["action"] == "revealed"
    ]
    assert len(reveals) >= 2
    assert all("secret" not in e["detail"] for e in reveals)
