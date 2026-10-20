"""Phase 8a - session gateway & recording (the data plane).

The guacd wire protocol is exercised against an in-thread stub that speaks
the real framing (length-prefixed elements, `select` -> `args` ->
`connect` -> `ready`, blob/end acks) using the product's own codec; the
broker is driven through the public API (maker-checker registration, zone
dispatch that fails closed, one-shot credential injection with the admin
token refused by name); and the recording round trip runs the daemon's own
seal code - gzip + AES-256-GCM per segment under the per-recording
envelope key, SHA-256 per segment in the ledger - so playback decrypts and
decompresses the native stream, retention prunes files and crypto-shreds
keys while the rows stay as evidence, and no figure is mocked that can be
real.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri  # noqa: E402
from extensions import db  # noqa: E402
import gateway_daemon  # noqa: E402
import guacd  # noqa: E402
import identity  # noqa: E402
import service  # noqa: E402
from models import (  # noqa: E402
    CommandIncident,
    GatewayNode,
    GatewaySession,
    RecordingKey,
    RecordingSegment,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}
KNOWN_SECRET = "known-injected-secret-8a"
TARGET_HOST = "web-01.lab"


# ---------------------------------------------------------------------------
# the in-thread guacd stub (real protocol, real sockets, product codec)
# ---------------------------------------------------------------------------
class _GuacdStub:
    """A real guacd-protocol TCP server in a thread.

    It answers the handshake exactly like guacd's user handshake does
    (`args` lists the version first, then the parameter names it wants;
    `connect` must echo the version and carry the values in that order),
    then streams a video declaration, a blob, an end and a sync. Whatever
    the client sends back (acks, syncs, disconnect) is collected on
    `seen`. `behavior` switches to `error` (answer `error` to select) or
    `garbage` (raw non-protocol bytes).
    """

    def __init__(
        self,
        behavior: str = "answer",
        args: tuple = ("hostname", "port", "username", "password"),
    ):
        self.behavior = behavior
        self.args = args
        self.seen: list = []  # (opcode, args) received from the client
        self.connect_values: list = []
        self.selected: str = ""
        self.frames = [
            guacd.encode_instruction("video", "1", "0", "video/jpeg"),
            guacd.encode_instruction(
                "blob", "1", base64.b64encode(b"frame-bytes").decode("ascii")
            ),
            guacd.encode_instruction("end", "1"),
            guacd.encode_instruction("sync", "12345", "0"),
        ]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        self.sock.close()

    # -- serving -------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True
            ).start()

    def _read(self, parser: guacd.GuacdParser, conn: socket.socket, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            instruction = parser.next_instruction()
            if instruction is not None:
                self.seen.append(instruction)
                return instruction
            conn.settimeout(max(deadline - time.monotonic(), 0.05))
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            parser.feed(chunk)
        return None

    def _handle(self, conn: socket.socket) -> None:  # noqa: C901 - wire steps
        try:
            parser = guacd.GuacdParser()
            first = self._read(parser, conn)
            if first is None:
                return
            if self.behavior == "garbage":
                conn.sendall(b"this is not the guacd protocol;\n")
                return
            if self.behavior == "error":
                conn.sendall(
                    guacd.encode_instruction("error", "protocol denied", "2")
                )
                return
            opcode, args = first
            if opcode != "select" or not args:
                return
            self.selected = args[0]
            conn.sendall(
                guacd.encode_instruction("args", "VERSION_1_5_0", *self.args)
            )
            second = self._read(parser, conn)
            if second is None or second[0] != "connect":
                return
            self.connect_values = second[1]
            conn.sendall(guacd.encode_instruction("ready", "c-stub-1"))
            for frame in self.frames:
                conn.sendall(frame)
            # collect client flow-control replies until disconnect/close
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline and not self._stop.is_set():
                instruction = parser.next_instruction()
                if instruction is not None:
                    self.seen.append(instruction)
                    if instruction[0] == "disconnect":
                        return
                    continue
                conn.settimeout(0.2)
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                parser.feed(chunk)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# fixtures + helpers
# ---------------------------------------------------------------------------
def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-gateway-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-gateway",
        node_site="dc",
        recording_storage_dir=tmp_path / "recordings",
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


@pytest.fixture(autouse=True)
def _limiter(app):
    identity.reset_windows_for_tests()
    with app.app_context():
        service.update_settings("auth", {"progressive_delay": False}, actor="test")
    yield
    identity.reset_windows_for_tests()


@pytest.fixture
def stub():
    server = _GuacdStub()
    server.start()
    yield server
    server.close()


def enable_gateway(client, **fields):
    payload = {"enabled": True}
    payload.update(fields)
    response = client.put(
        "/api/v1/settings/gateway", json=payload, headers=ADMIN
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def make_zone(client, name="lab"):
    response = client.post(
        "/api/v1/zones",
        json={"name": name, "description": "test network"},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def make_asset(client, hostname=TARGET_HOST, address="10.77.0.11"):
    response = client.post(
        "/api/v1/discovery/assets",
        json={
            "address": address,
            "hostname": hostname,
            "asset_type": "linux",
            "principal": "root",
        },
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["asset"]["id"]


def bind_zone(client, asset_id, zone_id):
    response = client.put(
        f"/api/v1/discovery/assets/{asset_id}/zone",
        json={"zone_id": zone_id},
        headers=ADMIN,
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def make_item(client, name="gw-cred", secret=KNOWN_SECRET):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": TARGET_HOST,
            "principal": "svc-admin",
            "access_tier": "Tier-1",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
            "secret": secret,
        },
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]["id"]


def register_node(client, zone_id, name="gw-1", actor="maker", port=4822):
    response = client.post(
        "/api/v1/gateway/nodes",
        json={
            "name": name,
            "zone_id": zone_id,
            "endpoint_host": "127.0.0.1",
            "endpoint_port": port,
        },
        headers={**ADMIN, "X-Actor": actor},
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["node"]["id"], body["token"]


def approve(client, node_id, decision="approve", actor="checker", note="ok"):
    return client.post(
        f"/api/v1/gateway/nodes/{node_id}/approve",
        json={"decision": decision, "note": note},
        headers={**ADMIN, "X-Actor": actor},
    )


def node_headers(token):
    return {"Authorization": f"Bearer {token}"}


def heartbeat(client, node_id, token, **payload):
    body = {"capacity_active": 0, "version": "8a-test"}
    body.update(payload)
    response = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json=body,
        headers=node_headers(token),
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def full_node(client, zone_id, name="gw-1", **heartbeat_payload):
    """Register -> approve (distinct actors) -> heartbeat: dispatchable."""
    node_id, token = register_node(client, zone_id, name=name)
    decision = approve(client, node_id)
    assert decision.status_code == 200, decision.get_json()
    heartbeat(client, node_id, token, **heartbeat_payload)
    return node_id, token


def start_session(client, item_id=None, target=f"{TARGET_HOST}:22", **payload):
    body = {"protocol": "ssh", "target": target, "record": True}
    if item_id is not None:
        body["item_id"] = item_id
    body.update(payload)
    return client.post("/api/v1/sessions", json=body, headers=ADMIN)


def connect_args(client, gateway_session_id, token):
    return client.get(
        f"/api/v1/gateway/sessions/{gateway_session_id}/connect-args",
        headers=node_headers(token),
    )


def progress(client, gateway_session_id, token, payload):
    return client.post(
        f"/api/v1/gateway/sessions/{gateway_session_id}/progress",
        json=payload,
        headers=node_headers(token),
    )


def bring_up_session(client, item_id, token, **payload):
    """The daemon's real order: brokered -> connect-args fetched (single
    use, before the state moves) -> progressed to `active`."""
    created = start_session(client, item_id, **payload)
    assert created.status_code == 201, created.get_json()
    info = created.get_json()["gateway"]
    assert info["required"] is True
    gws_id = info["gateway_session_id"]
    session_id = created.get_json()["session"]["id"]
    fetched = connect_args(client, gws_id, token)
    assert fetched.status_code == 200, fetched.get_json()
    assert progress(client, gws_id, token, {"state": "connecting"}).status_code == 200
    assert progress(client, gws_id, token, {"state": "active"}).status_code == 200
    return gws_id, session_id, fetched.get_json()


# ---------------------------------------------------------------------------
# the guacd wire protocol (verified against guacamole-server's writers)
# ---------------------------------------------------------------------------
def test_guacd_encode_matches_apache_writers():
    """Instruction bytes transcribed from libguac's protocol.c writers."""
    assert guacd.encode_instruction("nop") == b"3.nop;"
    assert guacd.encode_instruction("disconnect") == b"10.disconnect;"
    assert guacd.encode_instruction("ack", "42", "", "14") == b"3.ack,2.42,0.,2.14;"
    assert guacd.encode_instruction("select", "ssh") == b"6.select,3.ssh;"
    assert (
        guacd.encode_instruction("args", "VERSION_1_5_0", "hostname", "port")
        == b"4.args,13.VERSION_1_5_0,8.hostname,4.port;"
    )
    assert (
        guacd.encode_instruction("connect", "VERSION_1_5_0", "h1", "22")
        == b"7.connect,13.VERSION_1_5_0,2.h1,2.22;"
    )
    assert guacd.encode_instruction("ready", "c1") == b"5.ready,2.c1;"
    assert guacd.encode_instruction("key", "65", "1", "12345") == b"3.key,2.65,1.1,5.12345;"
    assert guacd.encode_instruction("sync", "12345", "0") == b"4.sync,5.12345,1.0;"


def test_guacd_parser_fragmented_round_trip():
    """TCP fragmentation is transparent; several instructions per chunk too."""
    wire = (
        b"6.select,3.ssh;"
        b"4.args,13.VERSION_1_5_0,8.hostname,4.port;"
        b"5.ready,2.c1;"
    )
    parser = guacd.GuacdParser()
    out = []
    for index in range(len(wire)):
        parser.feed(wire[index : index + 1])
        instruction = parser.next_instruction()
        while instruction is not None:
            out.append(instruction)
            instruction = parser.next_instruction()
    assert out == [
        ("select", ["ssh"]),
        ("args", ["VERSION_1_5_0", "hostname", "port"]),
        ("ready", ["c1"]),
    ]


def test_guacd_parser_counts_characters_not_bytes():
    """Element lengths are UTF-8 character counts (guac_utf8_strlen)."""
    expected = "4.name,4.caf\u00e9;".encode("utf-8")
    assert guacd.encode_instruction("name", "caf\u00e9") == expected
    parser = guacd.GuacdParser()
    parser.feed(expected)
    assert parser.next_instruction() == ("name", ["caf\u00e9"])


def test_guacd_parser_rejects_malformed_wire():
    for bad in (b"garbage;", b"6.selectx3.ssh;", b"99999.x;", b"6.select,3.ssh"):
        parser = guacd.GuacdParser()
        if bad == b"6.select,3.ssh":
            parser.feed(bad)  # no terminator: stays pending, never parses
            assert parser.next_instruction() is None
            continue
        parser.feed(bad)
        with pytest.raises(guacd.GuacdProtocolError):
            parser.next_instruction()
    # a non-terminating flood exhausts the buffer like libguac's 32KB cap
    flood = guacd.GuacdParser()
    with pytest.raises(guacd.GuacdProtocolError):
        for _ in range(40):
            flood.feed(b"9." * 1000)
    # element overflow: more than 128 elements is refused by the encoder
    with pytest.raises(guacd.GuacdProtocolError):
        guacd.encode_instruction("x", *(["y"] * guacd.MAX_ELEMENTS))


def test_guacd_client_handshake_streaming_and_flow_control(stub):
    """A real socket handshake against the stub; the client acks streams."""
    client = guacd.GuacdClient("127.0.0.1", stub.port, timeout=5.0)
    connection_id = client.connect_protocol(
        "ssh",
        {
            "hostname": TARGET_HOST,
            "port": "22",
            "username": "svc-admin",
            "password": KNOWN_SECRET,
        },
    )
    assert connection_id == "c-stub-1"
    assert stub.selected == "ssh"
    # the connect instruction echoed the version, then the values in the
    # exact order the stub's `args` asked for them
    assert stub.connect_values[0] == "VERSION_1_5_0"
    assert stub.connect_values[1:] == [
        TARGET_HOST,
        "22",
        "svc-admin",
        KNOWN_SECRET,
    ]

    received = []
    for _ in range(4):
        received.append(client.read_instruction(timeout=5.0))
    assert [op for op, _ in received] == ["video", "blob", "end", "sync"]
    assert received[1][1][0] == "1"  # the blob's stream id
    client.send_ack("1")
    client.send_sync(int(time.monotonic() * 1000))
    client.send_disconnect()
    client.close()

    # the stub saw the flow-control replies: an ack for stream 1, a sync
    time.sleep(0.3)
    opcodes = [op for op, _ in stub.seen]
    assert "ack" in opcodes and "sync" in opcodes and "disconnect" in opcodes
    ack = next(args for op, args in stub.seen if op == "ack")
    assert ack[0] == "1"


def test_guacd_client_protocol_error_is_honest(stub):
    stub.behavior = "error"
    client = guacd.GuacdClient("127.0.0.1", stub.port, timeout=5.0)
    with pytest.raises(guacd.GuacdConnectionError) as excinfo:
        client.connect_protocol("ssh", {})
    assert str(excinfo.value) == "protocol denied"
    assert excinfo.value.status == 2
    client.close()


def test_guacd_client_garbage_wire_fails_closed(stub):
    stub.behavior = "garbage"
    client = guacd.GuacdClient("127.0.0.1", stub.port, timeout=5.0)
    with pytest.raises(guacd.GuacdProtocolError):
        client.connect_protocol("ssh", {})
    client.close()


# ---------------------------------------------------------------------------
# zones + pools
# ---------------------------------------------------------------------------
def test_zone_lifecycle_and_conflicts(client):
    zone = make_zone(client)
    assert zone["name"] == "lab"
    listed = client.get("/api/v1/zones", headers=ADMIN).get_json()["zones"]
    assert [row["name"] for row in listed] == ["lab"]
    assert listed[0]["node_count"] == 0 and listed[0]["asset_count"] == 0

    duplicate = client.post(
        "/api/v1/zones", json={"name": "lab"}, headers=ADMIN
    )
    assert duplicate.status_code == 409

    detail = client.get(f"/api/v1/zones/{zone['id']}", headers=ADMIN)
    assert detail.status_code == 200
    assert detail.get_json()["nodes"] == []

    deleted = client.delete(f"/api/v1/zones/{zone['id']}", headers=ADMIN)
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/zones/{zone['id']}", headers=ADMIN).status_code == 404


def test_zone_delete_refuses_live_nodes_and_frees_after_revoke(client, app):
    """A live node claims its zone (fail-closed); terminal rows (pending is
    not terminal - it still claims the zone until a checker decides) block
    deletion, while a revoked node is evidence, not a resident."""
    enable_gateway(client)

    pending_zone = make_zone(client, name="pendingzone")
    register_node(client, pending_zone["id"], name="gw-pending")
    blocked_pending = client.delete(
        f"/api/v1/zones/{pending_zone['id']}", headers=ADMIN
    )
    assert blocked_pending.status_code == 409
    assert blocked_pending.get_json()["details"]["node_count"] == 1

    live_zone = make_zone(client, name="livezone")
    node_id, _token = full_node(client, live_zone["id"], name="gw-live")
    blocked_live = client.delete(f"/api/v1/zones/{live_zone['id']}", headers=ADMIN)
    assert blocked_live.status_code == 409
    assert blocked_live.get_json()["details"]["node_count"] == 1

    revoked = client.delete(f"/api/v1/gateway/nodes/{node_id}", headers=ADMIN)
    assert revoked.status_code == 200
    gone = client.delete(f"/api/v1/zones/{live_zone['id']}", headers=ADMIN)
    assert gone.status_code == 200
    # the revoked row keeps its zone_id as where the node once lived - the
    # row outlives its zone (EVIDENCE_FOREIGN_KEYS keeps that possible)
    with app.app_context():
        survivor = db.session.get(GatewayNode, node_id)
        assert survivor is not None
        assert survivor.zone_id == live_zone["id"]
    listed = client.get("/api/v1/zones", headers=ADMIN).get_json()["zones"]
    assert [row["name"] for row in listed] == ["pendingzone"]


def test_node_name_frees_after_revoke_and_stays_while_live(client):
    """A revoked node is history, not an occupant: a replacement may reuse
    its name; a live row keeps the name reserved."""
    enable_gateway(client)
    zone = make_zone(client, name="reusezone")
    node_id, _token = register_node(client, zone["id"], name="gw-reuse")

    clash = client.post(
        "/api/v1/gateway/nodes",
        json={
            "name": "gw-reuse",
            "zone_id": zone["id"],
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 4822,
        },
        headers={**ADMIN, "X-Actor": "maker"},
    )
    assert clash.status_code == 409  # a pending row still occupies the name

    revoked = client.delete(f"/api/v1/gateway/nodes/{node_id}", headers=ADMIN)
    assert revoked.status_code == 200

    again = client.post(
        "/api/v1/gateway/nodes",
        json={
            "name": "gw-reuse",
            "zone_id": zone["id"],
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 4823,
        },
        headers={**ADMIN, "X-Actor": "maker"},
    )
    assert again.status_code == 201, again.get_json()
    body = again.get_json()
    # the stored prefix is exactly what the issued token starts with
    assert body["node"]["token_prefix"] == f'vypam-gwn1.{body["node"]["id"]}.'
    assert body["token"].startswith(body["node"]["token_prefix"])


def test_pool_requires_live_zone_and_clears(client):
    zone = make_zone(client, name="poolzone")
    response = client.post(
        "/api/v1/gateway/pools",
        json={"name": "lab-pool", "zone_id": zone["id"], "lb_policy": "least-loaded"},
        headers=ADMIN,
    )
    assert response.status_code == 201
    pool_id = response.get_json()["id"]

    wrong_zone = client.post(
        "/api/v1/gateway/pools",
        json={"name": "other", "zone_id": 9999},
        headers=ADMIN,
    )
    assert wrong_zone.status_code == 404
    bad_policy = client.post(
        "/api/v1/gateway/pools",
        json={"name": "bad", "zone_id": zone["id"], "lb_policy": "random"},
        headers=ADMIN,
    )
    assert bad_policy.status_code == 400

    listed = client.get("/api/v1/gateway/pools", headers=ADMIN).get_json()["pools"]
    assert listed[0]["node_count"] == 0
    deleted = client.delete(f"/api/v1/gateway/pools/{pool_id}", headers=ADMIN)
    assert deleted.status_code == 200


def test_asset_zone_binding_and_unbind(client):
    zone = make_zone(client, name="bindzone")
    asset_id = make_asset(client)
    bound = bind_zone(client, asset_id, zone["id"])
    assert bound == {"asset_id": asset_id, "zone_id": zone["id"], "bound": True}

    detail = client.get(f"/api/v1/zones/{zone['id']}", headers=ADMIN).get_json()
    assert detail["assets"][0]["asset_id"] == asset_id
    assert detail["assets"][0]["hostname"] == TARGET_HOST

    unbound = client.put(
        f"/api/v1/discovery/assets/{asset_id}/zone",
        json={"zone_id": None},
        headers=ADMIN,
    )
    assert unbound.status_code == 200
    assert unbound.get_json()["bound"] is False
    again = client.put(
        f"/api/v1/discovery/assets/{asset_id}/zone",
        json={"zone_id": None},
        headers=ADMIN,
    )
    assert again.status_code == 404  # nothing left to unbind
    missing = client.put(
        "/api/v1/discovery/assets/9999/zone",
        json={"zone_id": zone["id"]},
        headers=ADMIN,
    )
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# nodes: maker-checker, token custody, liveness
# ---------------------------------------------------------------------------
def test_node_register_is_pending_with_sha256_token(client, app):
    zone = make_zone(client, name="regzone")
    node_id, token = register_node(client, zone["id"])
    secret = token.split(".")[2]

    with app.app_context():
        row = GatewayNode.query.get(node_id)
        assert row.status == "pending"
        # only the sha256 of the secret rests in the database, never the token
        assert row.token_sha256 == hashlib.sha256(secret.encode()).hexdigest()
        assert secret not in json.dumps(row.to_dict())

    listed = client.get("/api/v1/gateway/nodes", headers=ADMIN).get_json()["nodes"]
    assert listed[0]["state"] == "pending" and listed[0]["online"] is False
    assert token not in json.dumps(listed)


def test_node_maker_checker_self_approval_refused(client):
    zone = make_zone(client, name="mcczone")
    node_id, _token = register_node(client, zone["id"], actor="maker")

    self_approval = approve(client, node_id, actor="maker")
    assert self_approval.status_code == 403
    assert "never approve their own" in self_approval.get_json()["error"]

    refused = approve(client, node_id, decision="deny", actor="checker")
    assert refused.status_code == 200
    assert refused.get_json()["state"] == "denied"

    late = approve(client, node_id, actor="another")
    assert late.status_code == 409  # no longer pending


def test_node_token_auth_matrix(client, app):
    zone = make_zone(client, name="authzone")
    node_id, token = register_node(client, zone["id"])

    # pending: the token exists but does not authenticate yet
    pending = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json={"capacity_active": 0},
        headers=node_headers(token),
    )
    assert pending.status_code == 401
    assert "awaiting approval" in pending.get_json()["error"]

    approve(client, node_id)
    ok = heartbeat(client, node_id, token)
    assert ok["status"] == "active"

    # a wrong secret, an admin credential and a foreign node id all fail
    forged = f"vypam-gwn1.{node_id}.deadbeef"
    bad = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json={"capacity_active": 0},
        headers=node_headers(forged),
    )
    assert bad.status_code == 401
    admin_on_node = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json={"capacity_active": 0},
        headers=ADMIN,
    )
    assert admin_on_node.status_code == 401

    node2_id, token2 = register_node(client, zone["id"], name="gw-2", actor="maker")
    approve(client, node2_id)
    foreign = client.get(
        f"/api/v1/gateway/nodes/{node2_id}/work", headers=node_headers(token)
    )
    assert foreign.status_code == 404  # node 1 may not read node 2's queue

    with app.app_context():
        row = GatewayNode.query.get(node_id)
        row.status = "revoked"
        row.token_sha256 = None
        db.session.commit()
    revoked = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json={"capacity_active": 0},
        headers=node_headers(token),
    )
    assert revoked.status_code == 401


def test_heartbeat_updates_capacity_and_offline_derives_from_ttl(client, app):
    zone = make_zone(client, name="hbzone")
    node_id, token = full_node(client, zone["id"], capacity_active=2)

    listed = client.get("/api/v1/gateway/nodes", headers=ADMIN).get_json()["nodes"]
    row = listed[0]
    assert row["state"] == "active" and row["online"] is True
    assert row["capacity_active"] == 2
    assert row["version"] == "8a-test"
    assert isinstance(row["heartbeat_age_seconds"], int)

    # a stale heartbeat derives `offline` - it is never written to the row
    with app.app_context():
        node = GatewayNode.query.get(node_id)
        node.last_heartbeat_at = datetime.now() - timedelta(seconds=600)
        db.session.commit()
    listed = client.get("/api/v1/gateway/nodes", headers=ADMIN).get_json()["nodes"]
    assert listed[0]["state"] == "offline" and listed[0]["online"] is False
    assert listed[0]["heartbeat_age_seconds"] >= 600
    with app.app_context():
        assert GatewayNode.query.get(node_id).status == "active"  # stored


def test_drain_stops_dispatch_and_revoke_kills_live_sessions(client):
    enable_gateway(client)
    zone = make_zone(client, name="drainzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="drain-cred")
    node_id, token = full_node(client, zone["id"])
    gws_id, session_id, connect = bring_up_session(client, item_id, token)

    drained = client.post(
        f"/api/v1/gateway/nodes/{node_id}/drain", json={}, headers=ADMIN
    )
    assert drained.status_code == 200 and drained.get_json()["state"] == "draining"
    second_item = make_item(client, name="drain-cred-2")
    second = start_session(client, second_item)
    assert second.status_code == 503  # a draining node takes no new work

    revoked = client.delete(f"/api/v1/gateway/nodes/{node_id}", headers=ADMIN)
    assert revoked.status_code == 200
    assert revoked.get_json()["sessions_terminated"] == 1

    detail = client.get(f"/api/v1/sessions/{session_id}", headers=ADMIN).get_json()
    assert detail["session"]["status"] == "terminated"
    assert detail["gateway"]["state"] == "ended"
    assert detail["gateway"]["end_reason"] == "node-revoked"
    dead = client.post(
        f"/api/v1/gateway/nodes/{node_id}/heartbeat",
        json={"capacity_active": 0},
        headers=node_headers(token),
    )
    assert dead.status_code == 401


# ---------------------------------------------------------------------------
# the broker
# ---------------------------------------------------------------------------
def test_gateway_off_is_the_plain_4c_session(client):
    """The default (disabled) gateway never touches session creation."""
    created = start_session(client, item_id=None, target="db.internal:22")
    assert created.status_code == 201
    assert created.get_json()["gateway"] is None


def test_broker_requires_a_healthy_node_in_the_zone(client):
    enable_gateway(client)
    zone = make_zone(client, name="dispatchzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="dispatch-cred")

    no_node = start_session(client, item_id)
    assert no_node.status_code == 503
    assert "No healthy gateway node" in no_node.get_json()["error"]

    node_id, token = register_node(client, zone["id"])
    still_pending = approve(client, node_id)
    assert still_pending.status_code == 200
    not_heartbeating = start_session(client, item_id)
    assert not_heartbeating.status_code == 503  # approved but never alive

    heartbeat(client, node_id, token)
    created = start_session(client, item_id)
    assert created.status_code == 201, created.get_json()
    info = created.get_json()["gateway"]
    assert info["required"] is True
    assert info["node"]["name"] == "gw-1" and info["node"]["zone"] == "dispatchzone"
    assert info["recording"] is True and info["credential_injected"] is False

    # the work queue shows the pending session to its node, and only to it
    work = client.get(
        f"/api/v1/gateway/nodes/{node_id}/work", headers=node_headers(token)
    ).get_json()
    assert [row["gateway_session_id"] for row in work["pending"]] == [
        info["gateway_session_id"]
    ]
    assert work["pending"][0]["protocol"] == "ssh"
    assert work["pending"][0]["record"] is True


def test_non_gateway_protocol_reports_an_honest_reason(client):
    enable_gateway(client)
    created = client.post(
        "/api/v1/sessions",
        json={"protocol": "http", "target": "portal.lab", "record": True},
        headers=ADMIN,
    )
    assert created.status_code == 201
    info = created.get_json()["gateway"]
    assert info["required"] is False
    assert info["reason"] == "protocol-not-gateway-capable"
    assert "rdp" in info["protocols"]


def test_require_zone_refuses_unmapped_targets(client):
    enable_gateway(client, require_zone=True)
    refused = start_session(client, item_id=None)
    assert refused.status_code == 503
    assert "not mapped to any gateway zone" in refused.get_json()["error"]

    enable_gateway(client, require_zone=False)
    allowed = start_session(client, item_id=None)
    assert allowed.status_code == 201
    assert allowed.get_json()["gateway"]["reason"] == "target-not-mapped-to-a-zone"


def test_brokered_session_requires_a_vault_credential(client):
    enable_gateway(client)
    zone = make_zone(client, name="credzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    full_node(client, zone["id"])

    bare = start_session(client, item_id=None)
    assert bare.status_code == 503
    assert "require a vault credential" in bare.get_json()["error"]


# ---------------------------------------------------------------------------
# credential injection: node token only, exactly once
# ---------------------------------------------------------------------------
def test_connect_args_admin_token_is_refused_by_name(client):
    enable_gateway(client)
    zone = make_zone(client, name="refusezone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="refuse-cred")
    _node_id, token = full_node(client, zone["id"])
    gws_id, _session_id, connect = bring_up_session(client, item_id, token)

    as_admin = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/connect-args", headers=ADMIN
    )
    assert as_admin.status_code == 403
    assert "admin token is refused" in as_admin.get_json()["error"]

    anonymous = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/connect-args"
    )
    assert anonymous.status_code == 401


def test_connect_args_single_use_and_injects_the_vault_secret(client):
    enable_gateway(client)
    zone = make_zone(client, name="injectzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="inject-cred")
    _node_id, token = full_node(client, zone["id"])
    created = start_session(client, item_id)
    gws_id = created.get_json()["gateway"]["gateway_session_id"]

    response = connect_args(client, gws_id, token)
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["protocol"] == "ssh"
    params = body["params"]
    assert params["hostname"] == TARGET_HOST
    assert params["port"] == "22"
    assert params["username"] == "svc-admin"  # the vault item's principal
    assert params["password"] == KNOWN_SECRET  # injected from the vault
    assert len(bytes.fromhex(body["recording"]["data_key"])) == 32
    assert body["recording"]["format"] == "guacd-native"

    second = connect_args(client, gws_id, token)
    assert second.status_code == 409  # single use
    assert "already consumed" in second.get_json()["error"]

    # the injected secret never reaches the ledger or any listing
    export = client.get("/api/v1/audit/export", headers=ADMIN).get_data(as_text=True)
    assert KNOWN_SECRET not in export
    actions = {
        json.loads(line)["action"]
        for line in export.splitlines()
        if json.loads(line).get("source") == "gateway"
    }
    assert "credential-injected" in actions


def test_connect_args_of_another_nodes_session_is_404(client):
    enable_gateway(client)
    zone = make_zone(client, name="crosszone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="cross-cred")
    node_a, token_a = full_node(client, zone["id"], name="gw-a")
    node_b, token_b = full_node(client, zone["id"], name="gw-b")
    created = start_session(client, item_id)
    gws_id = created.get_json()["gateway"]["gateway_session_id"]
    # least-loaded dispatch put it on the lower id (gw-a)
    assert created.get_json()["gateway"]["node"]["id"] == node_a
    stolen = connect_args(client, gws_id, token_b)
    assert stolen.status_code == 404


# ---------------------------------------------------------------------------
# lifecycle + control
# ---------------------------------------------------------------------------
def test_progress_state_machine_and_end_cascade(client):
    enable_gateway(client)
    zone = make_zone(client, name="cascadezone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="cascade-cred")
    _node_id, token = full_node(client, zone["id"])
    gws_id, session_id, connect = bring_up_session(client, item_id, token)

    backward = progress(client, gws_id, token, {"state": "connecting"})
    assert backward.status_code == 409
    unknown = progress(client, gws_id, token, {"state": "flying"})
    assert unknown.status_code == 400

    ended = progress(
        client, gws_id, token, {"state": "ended", "end_reason": "client-disconnected"}
    )
    assert ended.status_code == 200

    detail = client.get(f"/api/v1/sessions/{session_id}", headers=ADMIN).get_json()
    assert detail["session"]["status"] == "completed"
    assert detail["gateway"]["state"] == "ended"
    assert detail["gateway"]["end_reason"] == "client-disconnected"

    # the 4c release-and-rotate cascade ran: the checkout is released
    item = client.get(f"/api/v1/vault/items/{item_id}", headers=ADMIN).get_json()["item"]
    assert item["status"] == "available"


def test_pause_and_terminate_reach_the_node_without_an_inbound_port(client):
    enable_gateway(client)
    zone = make_zone(client, name="controlzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="control-cred")
    node_id, token = full_node(client, zone["id"])
    gws_id, session_id, connect = bring_up_session(client, item_id, token)

    paused = client.post(f"/api/v1/sessions/{session_id}/pause", headers=ADMIN)
    assert paused.status_code == 200

    work = client.get(
        f"/api/v1/gateway/nodes/{node_id}/work", headers=node_headers(token)
    ).get_json()
    assert work["live"][0]["control"] == "pause"
    beat = heartbeat(client, node_id, token)
    assert "pause" in beat["directives"]
    reply = progress(client, gws_id, token, {"state": "active"})
    assert reply.status_code == 200
    assert reply.get_json()["directives"] == ["pause"]

    resumed = client.post(f"/api/v1/sessions/{session_id}/resume", headers=ADMIN)
    assert resumed.status_code == 200
    work = client.get(
        f"/api/v1/gateway/nodes/{node_id}/work", headers=node_headers(token)
    ).get_json()
    assert work["live"][0]["control"] == "run"

    # admin terminate: the next progress call ends the gateway session
    terminated = client.post(
        f"/api/v1/sessions/{session_id}/terminate",
        json={"reason": "supervisor stop"},
        headers=ADMIN,
    )
    assert terminated.status_code == 200
    reply = progress(client, gws_id, token, {"state": "active"})
    assert reply.get_json()["terminate"] == [gws_id]
    meta = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording", headers=ADMIN
    ).get_json()
    assert meta["state"] == "ended"


# ---------------------------------------------------------------------------
# recording: real seal code, real playback, real integrity checks
# ---------------------------------------------------------------------------
def _seal_and_report(
    client, app, config, gws_id, token, seq, plaintext: bytes, connect, *, sha_override=None
):
    """Seal a segment exactly like the daemon does and report it."""
    data_key = bytes.fromhex(connect["recording"]["data_key"])
    blob = gateway_daemon.seal_segment(data_key, plaintext, gws_id, seq)
    subdir = connect["recording"]["storage_subdir"]
    path = Path(config.recording_storage_dir) / subdir / f"seg-{seq:05d}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    reported = progress(
        client,
        gws_id,
        token,
        {
            "segments": [
                {
                    "seq": seq,
                    "sha256": sha_override or hashlib.sha256(blob).hexdigest(),
                    "size_bytes": len(blob),
                    "duration_seconds": 1.5,
                    "tier": "hot",
                }
            ]
        },
    )
    assert reported.status_code == 200, reported.get_json()
    return blob, path


def test_segment_seal_and_playback_round_trip(client, app, config):
    enable_gateway(client)
    zone = make_zone(client, name="recordzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="record-cred")
    _node_id, token = full_node(client, zone["id"])
    gws_id, _session_id, connect = bring_up_session(client, item_id, token)

    plaintext = (
        guacd.encode_instruction("img", "0", "image/png", "1", "1", "4", "10", "AAAA")
        + guacd.encode_instruction("sync", "999", "0")
    )
    blob, _path = _seal_and_report(
        client, app, config, gws_id, token, 0, plaintext, connect
    )

    meta = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording", headers=ADMIN
    ).get_json()
    assert meta["segment_count"] == 1
    assert meta["total_bytes"] == len(blob)
    assert meta["segments"][0]["sha256"] == hashlib.sha256(blob).hexdigest()
    assert meta["key"]["state"] == "wrapped"
    # pointers and hashes only: the database never carries recording bytes
    # or discloses storage layout
    assert "data_key" not in json.dumps(meta)
    assert "wrapped_key" not in json.dumps(meta)
    assert "path" not in json.dumps(meta["segments"][0])
    assert set(meta["segments"][0]) == {
        "id", "gateway_session_id", "seq", "storage_tier",
        "size_bytes", "sha256", "duration_seconds", "format",
        "created_at", "deleted_at",
    }

    played = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording/0/data", headers=ADMIN
    )
    assert played.status_code == 200, played.get_json()
    body = played.get_json()
    assert body["stream"] == plaintext.decode("utf-8")
    assert body["bytes"] == len(plaintext)
    assert body["sha256"] == hashlib.sha256(blob).hexdigest()


def test_playback_detects_tamper_and_lies(client, app, config):
    enable_gateway(client)
    zone = make_zone(client, name="tamperzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="tamper-cred")
    _node_id, token = full_node(client, zone["id"])
    gws_id, _session_id, connect = bring_up_session(client, item_id, token)

    plaintext = guacd.encode_instruction("sync", "1", "0")
    _blob, path = _seal_and_report(
        client, app, config, gws_id, token, 0, plaintext, connect
    )
    with open(path, "ab") as handle:
        handle.write(b"tampered")
    tampered = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording/0/data", headers=ADMIN
    )
    assert tampered.status_code == 500
    assert "SHA-256" in tampered.get_json()["error"]

    _blob, _path = _seal_and_report(
        client,
        app,
        config,
        gws_id,
        token,
        1,
        plaintext,
        connect,
        sha_override="f" * 64,  # the node lied about the hash
    )
    lied = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording/1/data", headers=ADMIN
    )
    assert lied.status_code == 500


def test_destroyed_key_answers_410_and_rows_remain_as_evidence(
    client, app, config
):
    enable_gateway(client)
    zone = make_zone(client, name="shredzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="shred-cred")
    _node_id, token = full_node(client, zone["id"])
    gws_id, _session_id, connect = bring_up_session(client, item_id, token)
    _seal_and_report(client, app, config, gws_id, token, 0, b"3.nop;", connect)

    with app.app_context():
        key = RecordingKey.query.filter_by(gateway_session_id=gws_id).first()
        key.destroyed_at = datetime.now()
        key.destroy_reason = "crypto-shred-test"
        db.session.commit()

    gone = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording/0/data", headers=ADMIN
    )
    assert gone.status_code == 410
    assert "destroyed" in gone.get_json()["error"]

    meta = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording", headers=ADMIN
    ).get_json()
    assert meta["key"]["state"] == "destroyed"
    assert meta["segment_count"] == 1  # the rows survive as evidence


# ---------------------------------------------------------------------------
# retention: prune files, crypto-shred keys, hold on incidents
# ---------------------------------------------------------------------------
def test_retention_dry_run_prune_and_incident_hold(client, app, config):
    enable_gateway(client)
    zone = make_zone(client, name="retentionzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="retention-cred")
    _node_id, token = full_node(client, zone["id"])

    # session 1: aged out, prunable
    gws_id, _sid, connect1 = bring_up_session(client, item_id, token)
    blob, path = _seal_and_report(
        client, app, config, gws_id, token, 0, b"3.nop;", connect1
    )
    progress(
        client, gws_id, token, {"state": "ended", "end_reason": "client-disconnected"}
    )
    # session 2: aged out but linked to a command incident (the hold)
    gws2_id, sid2, connect2 = bring_up_session(client, item_id, token)
    _seal_and_report(client, app, config, gws2_id, token, 0, b"3.nop;", connect2)
    progress(
        client, gws2_id, token, {"state": "ended", "end_reason": "client-disconnected"}
    )

    with app.app_context():
        for old_gws in (gws_id, gws2_id):
            row = GatewaySession.query.get(old_gws)
            row.ended_at = datetime.now() - timedelta(days=200)
        db.session.add(
            CommandIncident(
                incident_ref="inc-retention-test",
                session_id=sid2,
                event_seq=1,
                command="dangerous command",
                actor="tester",
            )
        )
        db.session.commit()

    dry = client.post(
        "/api/v1/gateway/recordings/retention/run",
        json={"dry_run": True},
        headers=ADMIN,
    )
    assert dry.status_code == 200, dry.get_json()
    dry_body = dry.get_json()
    assert dry_body["dry_run"] is True
    assert dry_body["pruned"] == 1
    assert dry_body["sessions"][0]["gateway_session_id"] == gws_id
    assert path.exists()  # a dry run touches nothing

    real = client.post(
        "/api/v1/gateway/recordings/retention/run", json={}, headers=ADMIN
    )
    assert real.status_code == 200
    body = real.get_json()
    assert body["pruned"] == 1
    assert body["skipped_under_incident_hold"] == 1
    assert body["bytes_freed"] == len(blob)
    assert not path.exists()  # the file is gone

    with app.app_context():
        key = RecordingKey.query.filter_by(gateway_session_id=gws_id).first()
        assert key.destroyed and key.destroy_reason == "retention-expired"
        held = RecordingKey.query.filter_by(gateway_session_id=gws2_id).first()
        assert not held.destroyed  # the incident-linked session was spared
        assert RecordingSegment.query.filter_by(
            gateway_session_id=gws_id, seq=0
        ).count() == 1  # rows remain as unreadable evidence

    export = client.get("/api/v1/audit/export", headers=ADMIN).get_data(as_text=True)
    actions = [
        json.loads(line)["action"]
        for line in export.splitlines()
        if json.loads(line).get("source") == "gateway"
    ]
    assert "retention-expired" in actions

    gone = client.get(
        f"/api/v1/gateway/sessions/{gws_id}/recording/0/data", headers=ADMIN
    )
    assert gone.status_code == 410


def test_stats_reflect_real_storage(client, app, config):
    enable_gateway(client, spool_max_bytes=1048576)
    zone = make_zone(client, name="statszone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="stats-cred")
    _node_id, token = full_node(client, zone["id"], capacity_active=1)
    gws_id, _sid, connect = bring_up_session(client, item_id, token)
    blob, _path = _seal_and_report(
        client, app, config, gws_id, token, 0, b"3.nop;", connect
    )

    stats = client.get("/api/v1/gateway/stats", headers=ADMIN).get_json()
    assert stats["enabled"] is True
    assert stats["nodes"]["by_state"] == {"active": 1}
    assert stats["sessions"]["by_state"].get("active") == 1
    assert stats["recordings"]["segments"] == 1
    assert stats["recordings"]["bytes_by_tier"]["hot"] == len(blob)
    assert stats["recordings"]["segments_by_tier"]["hot"] == 1
    assert stats["spool"]["hot_bytes"] == len(blob)
    assert stats["spool"]["max_bytes"] == 1048576
    # the sealed blob is bigger than the 1 MiB volume only if it is - the
    # alert flag must equal the measured math, not a constant
    expected_pct = round(len(blob) * 100.0 / 1048576, 2)
    assert stats["spool"]["usage_pct"] == expected_pct
    assert stats["spool"]["alert"] == (expected_pct >= 70)


# ---------------------------------------------------------------------------
# the ledger + the monitoring surfaces
# ---------------------------------------------------------------------------
def test_gateway_trail_folds_into_the_ledger(client):
    enable_gateway(client)
    zone = make_zone(client, name="ledgerzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="ledger-cred")
    node_id, token = full_node(client, zone["id"])
    gws_id, _sid, connect = bring_up_session(client, item_id, token)
    _seal_and_report_raw(client, gws_id, token, connect)

    verify = client.get("/api/v1/audit/verify", headers=ADMIN).get_json()
    assert verify["intact"] is True

    export = client.get("/api/v1/audit/export", headers=ADMIN).get_data(as_text=True)
    gateway_rows = [
        json.loads(line)
        for line in export.splitlines()
        if json.loads(line).get("source") == "gateway"
    ]
    actions = {row["action"] for row in gateway_rows}
    assert {
        "zone-created",
        "asset-zone-bound",
        "node-registered",
        "node-approved",
        "session-brokered",
        "credential-injected",
    } <= actions
    assert all(row["event_ref"].startswith("gateway:") for row in gateway_rows)
    # the ledger carries facts, never key material or credentials
    assert KNOWN_SECRET not in export
    injected = next(
        row for row in gateway_rows if row["action"] == "credential-injected"
    )
    assert injected["detail"]["secret_version"] >= 1


def _seal_and_report_raw(client, gws_id, token, connect):
    data_key = bytes.fromhex(connect["recording"]["data_key"])
    blob = gateway_daemon.seal_segment(data_key, b"3.nop;", gws_id, 0)
    progress(
        client,
        gws_id,
        token,
        {
            "segments": [
                {
                    "seq": 0,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "size_bytes": len(blob),
                    "duration_seconds": 0.5,
                }
            ]
        },
    )


def test_session_list_and_detail_carry_gateway_state(client):
    enable_gateway(client)
    zone = make_zone(client, name="hubzone")
    asset_id = make_asset(client)
    bind_zone(client, asset_id, zone["id"])
    item_id = make_item(client, name="hub-cred")
    node_id, token = full_node(client, zone["id"])
    gws_id, session_id, connect = bring_up_session(client, item_id, token)

    listed = client.get("/api/v1/sessions", headers=ADMIN).get_json()["items"]
    row = next(row for row in listed if row["id"] == session_id)
    assert row["gateway"]["state"] == "active"
    assert row["gateway"]["node"]["name"] == "gw-1"
    # bring-up fetched the one-shot connect args: the injection happened
    assert row["gateway"]["credential_injected"] is True

    detail = client.get(f"/api/v1/sessions/{session_id}", headers=ADMIN).get_json()
    assert detail["gateway"]["gateway_session_id"] == gws_id
    assert detail["gateway"]["recording"]["key_state"] == "wrapped"

    # a session without a gateway half reports null (4c sessions)
    plain = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "db.internal:22"},
        headers=ADMIN,
    )
    assert plain.status_code == 201
    plain_detail = client.get(
        f"/api/v1/sessions/{plain.get_json()['session']['id']}", headers=ADMIN
    ).get_json()
    assert plain_detail["gateway"] is None
