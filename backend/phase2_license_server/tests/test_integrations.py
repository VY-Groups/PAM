"""Tests for enterprise integrations (architecture section 20).

Nothing here simulates an external system: the TOTP factor is checked
against RFC 6238 vectors and live codes, the ITSM connector GETs a local
HTTP stub, the SIEM push ships the real committed ledger records as
HMAC-signed NDJSON to a local collector, and LDAP login is a real BER
BindRequest against a local directory stub. Every unconfigured path
honestly reports `not connected`, a refused connector never looks like a
different verdict, and no secret (TOTP seed, API token, password, signing
secret) ever reaches a response, a changelog entry or a ledger detail.

The medium-band gate is exercised with a deterministic fixture: an
unmanaged discovered CRITICAL asset (30) + an unknown device (15) = 45 at
business hours, squarely in the `mfa` band regardless of the real clock.

Run with:  python -m pytest backend/phase2_license_server/tests/test_integrations.py -q
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from models import BASE_RISK, AuditEvent, DiscoveredAsset, db  # noqa: E402
import audit as audit_module  # noqa: E402
import integrations  # noqa: E402
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

MFA_ASSET = "10.77.0.9"          # unmanaged CRITICAL -> 25 + 5 = 30 points
SIEM_SECRET = "s1cret-signing"
ITSM_TOKEN = "itsm-api-token"
LDAP_PASSWORD = "Directory-Passw0rd!"

# the module-global drain state must start (and end) honest in every test
SIEM_STATUS_DEFAULTS = {
    "last_push_at": None,
    "last_push_status": "never",
    "last_http_status": None,
    "last_error": None,
    "batches_ok": 0,
    "batches_failed": 0,
    "records_pushed": 0,
}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
def make_config(tmp_path: Path, **overrides) -> Config:
    kwargs = dict(
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
    kwargs.update(overrides)
    return Config(**kwargs)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def open_app(tmp_path: Path):
    """Open/dev mode: no admin token, so LDAP has nothing to grant."""
    application = create_app(make_config(tmp_path, admin_token=None))
    application.config["TESTING"] = True
    return application


@pytest.fixture
def open_client(open_app):
    return open_app.test_client()


@pytest.fixture(autouse=True)
def clean_siem_drain_state():
    """The SIEM queue/status are process-global; keep every test honest."""
    defaults = dict(SIEM_STATUS_DEFAULTS)
    audit_module._PENDING_PUSH.clear()
    audit_module._SIEM_STATUS.update(defaults)
    yield
    audit_module._PENDING_PUSH.clear()
    audit_module._SIEM_STATUS.update(defaults)


class _Clock(datetime):
    """Wednesday 2026-10-07 noon: business hours, the time component is 0
    (so the medium-band fixture scores a clock-independent 45)."""

    FIXED = datetime(2026, 10, 7, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)


# ---------------------------------------------------------------------------
# local stubs (real sockets; no domain behavior is mocked)
# ---------------------------------------------------------------------------
class _HttpStub:
    """A local HTTP collector: records every request verbatim (method, path,
    headers, body) and answers with a configurable status."""

    def __init__(self, status: int = 200, body: bytes = b'{"result": []}'):
        self.status = status
        self.body = body
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep pytest output clean
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                stub.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                self.send_response(stub.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(stub.body)))
                self.end_headers()
                self.wfile.write(stub.body)

            do_GET = _handle
            do_POST = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    def url(self, path: str = "") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 128  # the stub's responses are tiny
    return bytes([tag, len(value)]) + value


def _ldap_bind_response(result_code: int) -> bytes:
    """A real BER BindResponse (SEQUENCE { msgid 1, BindResponse { code } })."""
    inner = (
        _tlv(0x0A, bytes([result_code]))  # ENUMERATED resultCode
        + _tlv(0x04, b"")                 # matchedDN
        + _tlv(0x04, b"")                 # diagnosticMessage
    )
    return _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x61, inner))


class _LdapStub:
    """A local directory endpoint: accepts bind requests, records the raw
    bytes (the DN and password really travelled), answers the configured
    result code (0 success, 49 invalidCredentials)."""

    def __init__(self, result_code: int = 0):
        self.result_code = result_code
        self.requests = []
        self._stop = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)  # accepting before the thread starts: no race
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    data = conn.recv(4096)
                    if data:
                        self.requests.append(data)
                        conn.sendall(_ldap_bind_response(self.result_code))
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def http_stub():
    stub = _HttpStub()
    yield stub
    stub.close()


# ---------------------------------------------------------------------------
# API + domain helpers
# ---------------------------------------------------------------------------
def as_actor(name: str) -> dict:
    return {"X-Actor": name, "Authorization": "Bearer test-admin-token"}


def get_status(client):
    response = client.get("/api/v1/integrations/status")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def put_settings(client, group, values, *, headers=None):
    response = client.put(
        f"/api/v1/settings/{group}", json=values, headers=headers or ACTOR
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def get_settings(client, group):
    response = client.get("/api/v1/settings")
    assert response.status_code == 200
    return response.get_json()["settings"][group]


def enrol(client, *, headers=None):
    response = client.post("/api/v1/mfa/enroll", json={}, headers=headers or ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def verify_code(client, code, *, headers=None):
    return client.post(
        "/api/v1/mfa/verify", json={"code": code}, headers=headers or ACTOR
    )


def integration_events(client):
    response = client.get("/api/v1/events", query_string={"source": "integration"})
    assert response.status_code == 200, response.get_json()
    return response.get_json()["events"]


def insert_unmanaged_asset(app, address=MFA_ASSET, asset_type="database"):
    """The row a real scan leaves behind: unmanaged, CRITICAL base risk."""
    with app.app_context():
        asset = DiscoveredAsset(
            address=address,
            asset_type=asset_type,
            risk=BASE_RISK.get(asset_type, "LOW"),
            pam_status="unmanaged",
        )
        db.session.add(asset)
        db.session.commit()
        return asset.id


def start_session(client, **payload):
    base = {
        "protocol": "ssh",
        "target": f"{MFA_ASSET}:22",
        "device": "unknown-laptop",  # not in the inventory -> +15
    }
    base.update(payload)
    return client.post("/api/v1/sessions", json=base, headers=ACTOR)


def onboard(client, name, *, target):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": target,
            "principal": "admin",
            "access_tier": "Tier-1",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def file_break_glass(client, *, actor="alice", target="db-01.corp"):
    response = client.post(
        "/api/v1/break-glass/requests",
        json={
            "reason": "Production database unreachable; DBA on call needs "
            "direct access to recover replication.",
            "target": target,
            "severity": "sev1",
            "protocol": "postgresql",
        },
        headers=as_actor(actor),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["request"]


def dual_approve(client, request_id):
    for approver, note in (
        ("bob", "confirmed with on-call"),
        ("carol", "incident channel agrees"),
    ):
        response = client.post(
            f"/api/v1/break-glass/requests/{request_id}/approve",
            json={"note": note},
            headers=as_actor(approver),
        )
        assert response.status_code == 200, response.get_json()
    return response.get_json()["request"]


def open_break_glass(client, request_id, body=None, *, actor="alice"):
    return client.post(
        f"/api/v1/break-glass/requests/{request_id}/open",
        json={} if body is None else body,
        headers=as_actor(actor),
    )


def bg_detail(client, request_id):
    response = client.get(f"/api/v1/break-glass/requests/{request_id}")
    assert response.status_code == 200, response.get_json()
    return response.get_json()["request"]


# ---------------------------------------------------------------------------
# RFC 6238 TOTP (the crypto itself, independent of the app)
# ---------------------------------------------------------------------------
def test_rfc6238_sha1_vectors():
    # RFC 6238 Appendix B: seed ASCII "12345678901234567890", SHA-1, 8 digits
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    for at, expected in (
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
    ):
        assert integrations.hotp(secret, at // 30, digits=8) == expected


def test_verify_totp_accepts_the_adjacent_window_only():
    secret = integrations.generate_totp_secret()
    assert integrations.verify_totp(secret, integrations.totp_now(secret))  # live
    # deterministic window, anchored at an exact step boundary (59400s = step 1980)
    at = 59400.0
    assert integrations.verify_totp(secret, integrations.hotp(secret, 1980), at=at)
    assert integrations.verify_totp(secret, integrations.hotp(secret, 1979), at=at)  # T-1
    assert integrations.verify_totp(secret, integrations.hotp(secret, 1981), at=at)  # T+1
    assert not integrations.verify_totp(secret, integrations.hotp(secret, 1978), at=at)
    wrong = "000000" if integrations.totp_now(secret) != "000000" else "111111"
    assert not integrations.verify_totp(secret, wrong)


def test_totp_helpers_shapes():
    secret = integrations.generate_totp_secret()
    assert integrations.verify_totp(secret, integrations.totp_now(secret))
    uri = integrations.otpauth_uri(secret, account="alice")
    assert uri.startswith("otpauth://totp/")
    assert "secret=" + secret in uri
    assert not integrations.verify_totp(secret, "")       # empty never verifies
    assert not integrations.verify_totp(secret, 123456)   # non-string never does


# ---------------------------------------------------------------------------
# GET /integrations/status: every connector, honest before configuration
# ---------------------------------------------------------------------------
def test_status_reports_every_connector_not_connected(client):
    status = get_status(client)
    assert set(status) == {"mfa", "itsm", "siem", "ldap"}

    assert status["mfa"]["configured"] is False
    assert "not configured" in status["mfa"]["gate"]
    assert status["itsm"]["configured"] is False
    assert status["itsm"]["detail"] == "not connected - set itsm.base_url"
    assert status["siem"]["configured"] is False
    assert status["siem"]["state"] == "not connected"
    assert status["siem"]["last_push"]["last_push_status"] == "never"
    assert status["ldap"]["configured"] is False
    assert "not connected" in status["ldap"]["detail"]


def test_status_is_public(client):
    assert client.get("/api/v1/integrations/status").status_code == 200


def test_status_reflects_a_configured_connector(client, http_stub):
    put_settings(
        client,
        "itsm",
        {
            "vendor": "servicenow",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )
    status = get_status(client)
    assert status["itsm"]["configured"] is True
    assert status["itsm"]["credentials_configured"] is True
    assert status["itsm"]["detail"] is None
    # the token stays sealed - the status only says it exists
    assert ITSM_TOKEN not in json.dumps(status)


# ---------------------------------------------------------------------------
# MFA enrol / verify / settings discipline
# ---------------------------------------------------------------------------
def test_enrol_returns_the_secret_once_and_seals_it(client):
    body = enrol(client)

    seed = body["secret"]
    assert integrations.verify_totp(seed, integrations.totp_now(seed))
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert "secret=" + seed in body["otpauth_uri"]
    assert body["factor"]["configured"] is True
    assert body["factor"]["enrolled_for"] == "tester"

    # at rest: <set> everywhere it is read back
    stored = get_settings(client, "mfa")
    assert stored["values"]["factor_secret"] == "<set>"
    assert stored["values"]["factor_enrolled_for"] == "tester"
    assert get_status(client)["mfa"]["configured"] is True


def test_enrol_replaces_the_factor_and_says_so(client):
    first = enrol(client)
    second = enrol(client)
    assert first["secret"] != second["secret"]
    events = [e for e in integration_events(client) if e["action"] == "mfa-enrolled"]
    assert len(events) == 2
    assert events[0]["detail"]["replaced_existing"] is True   # newest first
    assert events[1]["detail"]["replaced_existing"] is False


def test_factor_settings_fields_are_read_only(client):
    for values in (
        {"factor_enrolled_for": "mallory"},
        {"factor_secret": "attacker-seed"},
    ):
        response = client.put("/api/v1/settings/mfa", json=values, headers=ACTOR)
        assert response.status_code == 400, response.get_json()
        details = response.get_json()["details"]
        assert details["fields"] == sorted(values)
        assert "/mfa/enroll" in details["hint"]


def test_mfa_schema_marks_the_factor_fields(client):
    schema = client.get("/api/v1/settings").get_json()["schema"]
    assert schema["mfa"]["factor_secret"]["type"] == "secret"
    assert schema["mfa"]["factor_secret"]["readonly"] is True
    assert schema["mfa"]["factor_enrolled_for"]["readonly"] is True
    assert schema["siem"]["signing_secret"]["type"] == "secret"
    assert schema["itsm"]["base_url"]["allow_http"] is True


def test_verify_accepts_a_live_code(client):
    seed = enrol(client)["secret"]
    response = verify_code(client, integrations.totp_now(seed))
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["verified"] is True
    assert body["factor"]["last_verified_at"] is not None

    events = [e for e in integration_events(client) if e["action"] == "mfa-verified"]
    assert len(events) == 1
    assert events[0]["actor"] == "tester"


def test_verify_rejects_a_wrong_code_with_evidence(client):
    seed = enrol(client)["secret"]
    wrong = "000000" if integrations.totp_now(seed) != "000000" else "111111"

    response = verify_code(client, wrong)
    assert response.status_code == 401
    assert response.get_json()["details"]["field"] == "code"

    events = [
        e for e in integration_events(client) if e["action"] == "mfa-verify-failed"
    ]
    assert len(events) == 1
    assert events[0]["detail"]["reason"] == "invalid or expired TOTP code"
    assert wrong not in json.dumps(events[0])  # the code itself never lands


def test_verify_without_a_factor_is_409_and_without_a_code_is_400(client):
    response = verify_code(client, "123456")
    assert response.status_code == 409
    assert "not configured" in response.get_json()["error"]

    enrol(client)
    response = client.post("/api/v1/mfa/verify", json={}, headers=ACTOR)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "code"


def test_no_secret_reaches_any_read_path(client):
    seed = enrol(client)["secret"]
    verify_code(client, integrations.totp_now(seed))  # trail with events too

    reads = [
        client.get("/api/v1/settings").get_data(as_text=True),
        client.get("/api/v1/settings/audit").get_data(as_text=True),
        client.get("/api/v1/integrations/status").get_data(as_text=True),
        client.get("/api/v1/audit/export").get_data(as_text=True),
        client.get("/api/v1/events", query_string={"source": "integration"}).get_data(
            as_text=True
        ),
    ]
    for text in reads:
        assert seed not in text
    # the changelog records the factor state change, marked, not material
    changelog = client.get("/api/v1/settings/audit").get_json()["events"]
    factor_events = [
        e for e in changelog if e.get("group") == "mfa"
    ]
    assert factor_events
    for event in factor_events:
        secret_change = (event.get("changes") or {}).get("factor_secret")
        if secret_change is not None:
            assert secret_change["new"] == "<set>"


# ---------------------------------------------------------------------------
# the medium-band gate (deterministic fixture: asset 30 + device 15 = 45)
# ---------------------------------------------------------------------------
def test_no_factor_keeps_the_mfa_band_advisory(app, client, clock):
    insert_unmanaged_asset(app)

    response = start_session(client)
    assert response.status_code == 201, response.get_json()
    risk = response.get_json()["risk"]
    assert risk["score"] == 45
    assert risk["band"] == "medium"
    assert risk["decision"] == "mfa"
    assert risk["result"] == "allowed"

    gates = [e for e in integration_events(client) if e["action"] == "mfa-gate"]
    assert len(gates) == 1
    assert gates[0]["detail"]["outcome"] == "no-factor"


def test_factor_gates_a_medium_band_start_without_a_code(app, client, clock):
    insert_unmanaged_asset(app)
    enrol(client)

    refused = start_session(client)
    assert refused.status_code == 403
    details = refused.get_json()["details"]
    assert details["risk"]["band"] == "medium"
    assert details["risk"]["decision"] == "mfa"
    assert details["mfa"] == "TOTP code required - a factor is enrolled"

    assert client.get("/api/v1/sessions").get_json()["total"] == 0
    # the refusal is kept: evaluation + gate reason, both committed
    page = client.get("/api/v1/risk/evaluations").get_json()
    assert page["total"] == 1 and page["evaluations"][0]["result"] == "refused"
    gates = [e for e in integration_events(client) if e["action"] == "mfa-gate"]
    assert gates[0]["detail"]["outcome"] == "refused"
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_a_wrong_code_refuses_the_start(app, client, clock):
    insert_unmanaged_asset(app)
    seed = enrol(client)["secret"]
    wrong = "000000" if integrations.totp_now(seed) != "000000" else "111111"

    refused = start_session(client, mfa_code=wrong)
    assert refused.status_code == 403
    assert refused.get_json()["details"]["mfa"] == "invalid or expired TOTP code"
    assert client.get("/api/v1/sessions").get_json()["total"] == 0


def test_a_valid_code_unlocks_the_medium_band_start(app, client, clock):
    insert_unmanaged_asset(app)
    seed = enrol(client)["secret"]

    response = start_session(client, mfa_code=integrations.totp_now(seed))
    assert response.status_code == 201, response.get_json()
    risk = response.get_json()["risk"]
    assert risk["band"] == "medium"
    assert risk["decision"] == "mfa"
    assert risk["result"] == "allowed"
    assert client.get("/api/v1/sessions").get_json()["total"] == 1

    gates = [e for e in integration_events(client) if e["action"] == "mfa-gate"]
    assert gates[0]["detail"]["outcome"] == "verified"
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_manual_evaluation_stays_advisory(app, client, clock):
    insert_unmanaged_asset(app)
    enrol(client)

    response = client.post(
        "/api/v1/risk/evaluate",
        json={"subject": "tester", "target": f"{MFA_ASSET}:22"},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    assert response.get_json()["evaluation"]["result"] == "advisory"
    gates = [e for e in integration_events(client) if e["action"] == "mfa-gate"]
    assert gates == []  # the gate runs at session starts, not at console advice


# ---------------------------------------------------------------------------
# break-glass: the honest mfa field becomes real
# ---------------------------------------------------------------------------
def test_break_glass_records_honestly_without_a_factor(client):
    onboard(client, "bg-item", target="db-01.corp:5432")
    request = file_break_glass(client)
    assert request["mfa"] == "not configured"

    dual_approve(client, request["id"])
    response = open_break_glass(client, request["id"])
    assert response.status_code == 201, response.get_json()
    assert bg_detail(client, request["id"])["mfa"] == "not configured"


def test_break_glass_demands_a_code_when_a_factor_exists(client):
    onboard(client, "bg-item", target="db-01.corp:5432")
    enrol(client, headers=as_actor("alice"))

    request = file_break_glass(client)
    assert request["mfa"] == "required at open"
    dual_approve(client, request["id"])

    refused = open_break_glass(client, request["id"])
    assert refused.status_code == 401
    assert refused.get_json()["details"]["field"] == "mfa_code"

    state = bg_detail(client, request["id"])
    assert state["status"] == "approved"          # nothing was released
    assert state["session_id"] is None
    assert client.get("/api/v1/sessions").get_json()["total"] == 0

    gates = [e for e in integration_events(client) if e["action"] == "mfa-gate"]
    assert gates[0]["detail"]["flow"] == "break-glass-open"
    assert gates[0]["detail"]["outcome"] == "refused"


def test_break_glass_records_verified_when_the_code_checks_out(client):
    onboard(client, "bg-item", target="db-01.corp:5432")
    seed = enrol(client, headers=as_actor("alice"))["secret"]

    request = file_break_glass(client)
    dual_approve(client, request["id"])

    response = open_break_glass(
        client, request["id"], {"mfa_code": integrations.totp_now(seed)}
    )
    assert response.status_code == 201, response.get_json()
    state = bg_detail(client, request["id"])
    assert state["status"] == "used"
    assert state["mfa"] == "verified"
    assert state["session_id"] is not None


# ---------------------------------------------------------------------------
# ITSM: a real GET against a local instance
# ---------------------------------------------------------------------------
def test_itsm_verify_is_409_when_not_configured(client):
    response = client.post(
        "/api/v1/itsm/verify", json={"ticket": "INC-001"}, headers=ACTOR
    )
    assert response.status_code == 409
    assert response.get_json()["details"]["configured"] is False


def test_itsm_verify_uses_the_vendor_preset_over_real_http(client, http_stub):
    put_settings(
        client,
        "itsm",
        {
            "vendor": "servicenow",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )

    response = client.post(
        "/api/v1/itsm/verify", json={"ticket": "INC-001"}, headers=ACTOR
    )
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["configured"] is True
    assert body["verified"] is True
    assert body["http_status"] == 200

    sent = http_stub.requests[0]
    assert sent["path"] == "/api/now/table/incident/INC-001"
    expected = base64.b64encode(f"api:{ITSM_TOKEN}".encode()).decode()
    assert sent["headers"].get("authorization") == f"Basic {expected}"

    events = [e for e in integration_events(client) if e["action"] == "itsm-verified"]
    assert len(events) == 1
    assert ITSM_TOKEN not in json.dumps(events[0])


def test_itsm_verify_reports_404_as_not_verified(client, http_stub):
    put_settings(
        client,
        "itsm",
        {
            "vendor": "servicenow",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )
    http_stub.status = 404

    response = client.post(
        "/api/v1/itsm/verify", json={"ticket": "INC-404"}, headers=ACTOR
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["verified"] is False
    assert body["detail"] == "HTTP 404 - ticket not found"
    events = [
        e for e in integration_events(client) if e["action"] == "itsm-verify-failed"
    ]
    assert len(events) == 1


def test_itsm_refused_connection_is_not_an_invalid_ticket(client, http_stub):
    put_settings(
        client,
        "itsm",
        {
            "vendor": "servicenow",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )
    http_stub.close()

    response = client.post(
        "/api/v1/itsm/verify", json={"ticket": "INC-005"}, headers=ACTOR
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["verified"] is False
    assert body["detail"].startswith("connection failed:")


def test_itsm_bmc_without_a_path_template_says_why(client, http_stub):
    put_settings(
        client,
        "itsm",
        {
            "vendor": "bmc",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )
    response = client.post(
        "/api/v1/itsm/verify", json={"ticket": "INC-001"}, headers=ACTOR
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["verified"] is False
    assert "path_template" in body["detail"]
    assert http_stub.requests == []  # never guessed a REST surface


def test_risk_ticket_component_gains_verified_only_when_itsm_is_configured(
    client, http_stub
):
    # unconfigured: shape-only, no `verified` key, honest detail
    response = client.post(
        "/api/v1/risk/evaluate",
        json={"subject": "tester", "ticket": "INC-001"},
        headers=ACTOR,
    )
    component = next(
        c
        for c in response.get_json()["evaluation"]["components"]
        if c["component"] == "ticket"
    )
    assert component["points"] == 0
    assert "verified" not in component
    assert "matches the ITSM reference shape" in component["detail"]

    # configured + a real 200: the verdict rides along
    put_settings(
        client,
        "itsm",
        {
            "vendor": "servicenow",
            "base_url": http_stub.url(""),
            "username": "api",
            "api_token": ITSM_TOKEN,
            "timeout_seconds": 2,
        },
    )
    response = client.post(
        "/api/v1/risk/evaluate",
        json={"subject": "tester", "ticket": "INC-001"},
        headers=ACTOR,
    )
    component = next(
        c
        for c in response.get_json()["evaluation"]["components"]
        if c["component"] == "ticket"
    )
    assert component["verified"] is True
    assert component["points"] == 0
    assert "verified against servicenow" in component["detail"]


# ---------------------------------------------------------------------------
# SIEM: signed NDJSON of the real committed records
# ---------------------------------------------------------------------------
def test_siem_settings_secrets_are_sealed_and_redacted(client):
    put_settings(client, "siem", {"signing_secret": SIEM_SECRET})

    stored = get_settings(client, "siem")
    assert stored["values"]["signing_secret"] == "<set>"
    assert SIEM_SECRET not in client.get("/api/v1/settings").get_data(as_text=True)

    changelog = client.get("/api/v1/settings/audit").get_json()["events"]
    secret_events = [
        e for e in changelog if (e.get("changes") or {}).get("signing_secret")
    ]
    assert secret_events
    assert secret_events[0]["changes"]["signing_secret"] == {
        "old": "",
        "new": "<set>",
    }
    assert SIEM_SECRET not in client.get("/api/v1/settings/audit").get_data(
        as_text=True
    )

    # sealed at rest: the same field unseals back to the exact plaintext
    with client.application.app_context():
        assert (
            service_module.unseal_setting_secret("siem", "signing_secret")
            == SIEM_SECRET
        )

    # clearing is a real, recorded transition - and unseals to empty
    cleared = put_settings(client, "siem", {"signing_secret": ""})
    assert cleared["changes"]["signing_secret"] == {"old": "<set>", "new": ""}
    assert get_settings(client, "siem")["values"]["signing_secret"] == ""
    with client.application.app_context():
        assert service_module.unseal_setting_secret("siem", "signing_secret") == ""


def test_siem_push_ships_the_committed_records_signed(client, http_stub):
    put_settings(
        client,
        "siem",
        {
            "webhook_url": http_stub.url("/collector"),
            "signing_secret": SIEM_SECRET,
            "enabled": True,
            "timeout_seconds": 2,
        },
    )
    http_stub.requests.clear()  # the settings commit already drained once
    audit_module._SIEM_STATUS.update(
        dict(SIEM_STATUS_DEFAULTS)
    )  # count exactly the batch under test

    response = client.post(
        "/api/v1/risk/evaluate", json={"subject": "tester"}, headers=ACTOR
    )
    assert response.status_code == 201, response.get_json()

    assert len(http_stub.requests) == 1
    sent = http_stub.requests[0]
    assert sent["method"] == "POST"
    assert sent["path"] == "/collector"
    assert sent["headers"]["content-type"] == "application/x-ndjson"

    # the signature covers the exact bytes on the wire
    expected_sig = hmac.new(
        SIEM_SECRET.encode(), sent["body"], hashlib.sha256
    ).hexdigest()
    assert sent["headers"]["x-vy-pam-signature"] == f"sha256={expected_sig}"

    records = [
        json.loads(line) for line in sent["body"].decode().splitlines() if line
    ]
    assert records
    assert any(row["source"] == "risk" for row in records)
    for row in records:
        assert row["event_hash"] and isinstance(row["seq"], int)

    status = get_status(client)
    assert status["siem"]["state"] == "connected"
    push = status["siem"]["last_push"]
    assert push["last_push_status"] == "ok"
    assert push["batches_ok"] == 1
    assert push["records_pushed"] == len(records)
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_siem_failing_collector_is_honest_and_never_loops(client, http_stub):
    put_settings(
        client,
        "siem",
        {
            "webhook_url": http_stub.url("/collector"),
            "signing_secret": SIEM_SECRET,
            "enabled": True,
            "timeout_seconds": 2,
        },
    )
    http_stub.status = 500
    http_stub.requests.clear()
    audit_module._SIEM_STATUS.update(
        dict(SIEM_STATUS_DEFAULTS)
    )  # the collector starts failing from this batch on

    # a failed push must not break the request that committed
    first = client.post(
        "/api/v1/risk/evaluate", json={"subject": "tester"}, headers=ACTOR
    )
    assert first.status_code == 201, first.get_json()

    status = get_status(client)
    assert status["siem"]["state"] == "error"
    assert status["siem"]["last_push"]["last_push_status"] == "error"
    assert status["siem"]["last_push"]["batches_failed"] == 1
    assert status["siem"]["last_push"]["last_error"] == "HTTP 500"

    failures = [
        e for e in integration_events(client) if e["action"] == "siem-push-failed"
    ]
    assert len(failures) == 1
    assert failures[0]["detail"]["error"] == "HTTP 500"

    # one batch, one attempt, one event - the failure never feeds itself
    second = client.post(
        "/api/v1/risk/evaluate", json={"subject": "tester"}, headers=ACTOR
    )
    assert second.status_code == 201
    status = get_status(client)
    assert status["siem"]["last_push"]["batches_failed"] == 2
    assert status["siem"]["last_push"]["batches_ok"] == 0
    failures = [
        e for e in integration_events(client) if e["action"] == "siem-push-failed"
    ]
    assert len(failures) == 2
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_siem_status_is_honest_about_being_configured_but_unpushed(client):
    put_settings(
        client,
        "siem",
        {
            "webhook_url": "http://127.0.0.1:9/collector",  # nothing listening
            "signing_secret": SIEM_SECRET,
            "enabled": True,
            "timeout_seconds": 1,
        },
    )
    # simulate the honest restart state: configured, but nothing pushed yet
    audit_module._SIEM_STATUS.update(dict(SIEM_STATUS_DEFAULTS))

    status = get_status(client)["siem"]
    assert status["configured"] is True
    assert status["state"] == "configured"
    assert "awaiting" in status["detail"]
    assert status["last_push"]["last_push_status"] == "never"


def test_siem_disabled_never_calls_the_collector(client, http_stub):
    put_settings(
        client,
        "siem",
        {
            "webhook_url": http_stub.url("/collector"),
            "signing_secret": SIEM_SECRET,
            "enabled": False,
            "timeout_seconds": 2,
        },
    )
    http_stub.requests.clear()
    client.post("/api/v1/risk/evaluate", json={"subject": "tester"}, headers=ACTOR)

    assert http_stub.requests == []
    status = get_status(client)["siem"]
    assert status["configured"] is False
    assert status["state"] == "not connected"
    assert status["last_push"]["last_push_status"] == "never"


# ---------------------------------------------------------------------------
# LDAP: a real bind against a local directory
# ---------------------------------------------------------------------------
def put_ldap(client, stub, **overrides):
    values = {
        "server": "127.0.0.1",
        "port": stub.port,
        "use_ssl": False,
        "user_bind_template": "uid={user},ou=people,dc=corp",
        "timeout_seconds": 2,
        "ticket_ttl_seconds": 60,
    }
    values.update(overrides)
    return put_settings(client, "ldap", values)


def test_ldap_login_is_409_when_not_configured(client):
    response = client.post(
        "/api/v1/auth/ldap",
        json={"username": "alice", "password": LDAP_PASSWORD},
    )
    assert response.status_code == 409
    assert response.get_json()["details"]["configured"] is False


def test_ldap_login_binds_for_real_and_mints_a_ticket(client):
    stub = _LdapStub(result_code=0)
    try:
        put_ldap(client, stub)

        response = client.post(
            "/api/v1/auth/ldap",
            json={"username": "alice", "password": LDAP_PASSWORD},
        )
        assert response.status_code == 200, response.get_json()
        body = response.get_json()
        assert body["verified"] is True
        assert body["mode"] == "token"
        assert body["ticket"].startswith("vypam-ldap1.")
        assert body["expires_in"] == 60

        # the request really carried the DN and the password (and the stub
        # never had to be told either - the wire is the proof)
        wire = stub.requests[0]
        assert b"uid=alice,ou=people,dc=corp" in wire
        assert LDAP_PASSWORD.encode() in wire

        # nowhere to be found afterwards
        assert LDAP_PASSWORD not in response.get_data(as_text=True)
        assert LDAP_PASSWORD not in client.get("/api/v1/audit/export").get_data(
            as_text=True
        )
        events = integration_events(client)
        assert events[0]["action"] == "ldap-login"
        assert LDAP_PASSWORD not in json.dumps(events)

        # the minted ticket authenticates to an admin route on its own
        probe = client.post(
            "/api/v1/risk/evaluate",
            json={"subject": "alice"},
            headers={"Authorization": f"Bearer {body['ticket']}"},
        )
        assert probe.status_code == 201, probe.get_json()
    finally:
        stub.close()


def test_ldap_bind_failure_is_401_with_the_directory_result(client):
    stub = _LdapStub(result_code=49)
    try:
        put_ldap(client, stub)
        response = client.post(
            "/api/v1/auth/ldap",
            json={"username": "alice", "password": "wrong-password"},
        )
        assert response.status_code == 401
        details = response.get_json()["details"]
        assert details["detail"] == "invalidCredentials"
        assert details["configured"] is True

        events = [
            e for e in integration_events(client) if e["action"] == "ldap-login-failed"
        ]
        assert len(events) == 1
        assert events[0]["detail"]["result_code"] == 49
        assert "wrong-password" not in json.dumps(events)
    finally:
        stub.close()


def test_bad_credentials_get_no_ticket(client):
    stub = _LdapStub(result_code=49)
    try:
        put_ldap(client, stub)
        response = client.post(
            "/api/v1/auth/ldap",
            json={"username": "alice", "password": LDAP_PASSWORD},
        )
        assert response.status_code == 401
        assert "ticket" not in response.get_json().get("details", {})
    finally:
        stub.close()


def test_tampered_and_expired_tickets_are_refused(app, client):
    stub = _LdapStub(result_code=0)
    try:
        put_ldap(client, stub)
        login = client.post(
            "/api/v1/auth/ldap",
            json={"username": "alice", "password": LDAP_PASSWORD},
        )
        ticket = login.get_json()["ticket"]

        head, _, sig = ticket.rpartition(".")
        tampered = head + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
        refused = client.post(
            "/api/v1/risk/evaluate",
            json={"subject": "alice"},
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert refused.status_code == 401

        # and an expired one, minted honestly in the past
        config = app.config["LICENSE_CONFIG"]
        with app.app_context():
            expired = service_module.mint_ldap_ticket("alice", -30, config)
        refused = client.post(
            "/api/v1/risk/evaluate",
            json={"subject": "alice"},
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert refused.status_code == 401

        # no credential at all is still refused in token mode
        bare = client.post("/api/v1/risk/evaluate", json={"subject": "alice"})
        assert bare.status_code == 401
    finally:
        stub.close()


def test_ldap_open_mode_verifies_but_grants_nothing(open_client):
    stub = _LdapStub(result_code=0)
    try:
        put_ldap(open_client, stub)
        response = open_client.post(
            "/api/v1/auth/ldap",
            json={"username": "alice", "password": LDAP_PASSWORD},
        )
        assert response.status_code == 200, response.get_json()
        body = response.get_json()
        assert body["verified"] is True
        assert body["mode"] == "open"
        assert body["ticket"] is None
        assert "open dev mode" in body["note"]
    finally:
        stub.close()


def test_ldap_login_validates_its_input(client):
    stub = _LdapStub(result_code=0)
    try:
        put_ldap(client, stub)
        for payload, field in (
            ({"password": LDAP_PASSWORD}, "username"),
            ({"username": "alice"}, "password"),
            ({"username": "alice", "password": ""}, "password"),
        ):
            response = client.post("/api/v1/auth/ldap", json=payload)
            assert response.status_code == 400, response.get_json()
            assert response.get_json()["details"]["field"] == field
        assert stub.requests == []  # nothing was even attempted
    finally:
        stub.close()


# ---------------------------------------------------------------------------
# fan-in and contract lockstep for the eleventh trail
# ---------------------------------------------------------------------------
def test_integration_trail_reaches_the_ledger_and_the_feed(client):
    enrol(client)
    with client.application.app_context():
        total = AuditEvent.query.count()
        assert total >= 1

    stats = client.get("/api/v1/audit/stats").get_json()
    assert "integration" in stats["by_source"]
    assert stats["by_source"]["integration"] >= 1
    assert len(audit_module.AUDIT_SOURCES) == 13
    assert audit_module.AUDIT_SOURCES[-1] == "cloud"

    feed = client.get("/api/v1/events", query_string={"source": "integration"})
    assert feed.status_code == 200
    assert feed.get_json()["events"]
    assert feed.get_json()["events"][0]["id"].startswith("integration:")
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True
