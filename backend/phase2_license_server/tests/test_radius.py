"""Phase 7 - RADIUS factor (Addendum C): a real RFC 2865 Access-Request
over UDP against an in-thread stub server that answers with a properly
authenticated Response Authenticator. Access-Accept passes the factor
(and the real login challenge), Access-Reject fails it, a bad response
authenticator or a timeout is an honest 503 - never a pass. Packet-level
invariants are asserted directly: the code rides masked as User-Password,
never in the clear, and the shared secret is sealed at rest.
"""
from __future__ import annotations

import hashlib
import socket
import struct
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from extensions import db  # noqa: E402
from models import AuthEvent, ConsoleSession, MfaFactor  # noqa: E402
import identity  # noqa: E402
import radius_client  # noqa: E402
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
RADIUS_SECRET = "s3cret-radius-beam"
ACCEPTED_CODE = "49381250"


# ---------------------------------------------------------------------------
# the in-thread RADIUS stub (independent RFC 2865 implementation)
# ---------------------------------------------------------------------------
def _unmask_password(masked: bytes, secret: bytes, request_auth: bytes) -> str:
    """RFC 2865 5.2 decoding - the inverse of the product's masking."""
    plain = b""
    prev = request_auth
    for offset in range(0, len(masked), 16):
        block = masked[offset : offset + 16]
        mask = hashlib.md5(secret + prev).digest()
        plain += bytes(a ^ b for a, b in zip(block, mask))
        prev = block
    return plain.rstrip(b"\x00").decode("utf-8")


class _RadiusStub:
    """A real UDP RADIUS server in a thread: parses the Access-Request,
    unmasks User-Password, and answers Access-Accept/Reject with a correct
    Response Authenticator (MD5 over Code+ID+Length+RequestAuth+Attributes
    + secret). `behavior` switches to `garbage` (valid length, wrong
    authenticator) or `silent` (drops the request)."""

    def __init__(self, secret: str = RADIUS_SECRET):
        self.secret = secret.encode("utf-8")
        self.accept_passwords: set = set()
        self.behavior = "answer"
        self.seen: list = []  # (username, password) as decoded from the wire
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
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

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 20:
                continue
            code, rid, length = struct.unpack(">BBH", data[:4])
            if code != 1 or length != len(data):
                continue
            request_auth = data[4:20]
            username, password = self._decode(data[20:], request_auth)
            self.seen.append((username, password))
            if self.behavior == "silent":
                continue
            if self.behavior == "garbage":
                # right length field, response authenticator that cannot verify
                bad = bytes([2, rid]) + struct.pack(">H", 20) + b"\x00" * 16
                self.sock.sendto(bad, addr)
                continue
            response_code = 2 if password in self.accept_passwords else 3
            attributes = b""
            total = 20 + len(attributes)
            response_auth = hashlib.md5(
                bytes([response_code, rid])
                + struct.pack(">H", total)
                + request_auth
                + attributes
                + self.secret
            ).digest()
            # response = header + Response Authenticator + attributes (the
            # request authenticator goes into the MD5, never onto the wire)
            self.sock.sendto(
                bytes([response_code, rid])
                + struct.pack(">H", total)
                + response_auth
                + attributes,
                addr,
            )

    def _decode(self, attributes: bytes, request_auth: bytes):
        username, password = "", ""
        offset = 0
        while offset + 2 <= len(attributes):
            attr_type = attributes[offset]
            attr_len = attributes[offset + 1]
            if attr_len < 2 or offset + attr_len > len(attributes):
                break
            value = attributes[offset + 2 : offset + attr_len]
            if attr_type == 1:
                username = value.decode("utf-8", "replace")
            elif attr_type == 2:
                password = _unmask_password(value, self.secret, request_auth)
            offset += attr_len
        return username, password


# ---------------------------------------------------------------------------
# fixtures + helpers
# ---------------------------------------------------------------------------
def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-radius-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-radius",
        node_site="dc",
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
    server = _RadiusStub()
    server.start()
    yield server
    server.close()


def create_user(client, username="alice", password=GOOD_PASSWORD, **fields):
    response = client.post(
        "/api/v1/users",
        json={"username": username, "password": password, **fields},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def login(client, username, password, **extra):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, **extra},
    )


def enable_radius(client, stub, secret=RADIUS_SECRET, enabled=True):
    response = client.put(
        "/api/v1/settings/radius",
        json={
            "enabled": enabled,
            "host": "127.0.0.1",
            "port": stub.port,
            "timeout_seconds": 1,  # fail honest, fail fast
            "secret": secret,
        },
        headers=ADMIN,
    )
    assert response.status_code == 200, response.get_json()


def enrol_radius_factor(client, stub, username="alice"):
    """Configure + sign in with MFA off + enrol; re-enable MFA after.
    Returns the mint (csrf for the held session)."""
    enable_radius(client, stub)
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200
    minted = login(client, username, GOOD_PASSWORD)
    assert minted.status_code == 200, minted.get_json()
    mint = minted.get_json()
    enrolled = client.post(
        "/api/v1/auth/mfa/enroll/radius",
        json={},
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert enrolled.status_code == 201, enrolled.get_json()
    assert enrolled.get_json()["factor"]["kind"] == "radius"
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": True}, headers=ADMIN
    ).status_code == 200
    return mint


def mfa_challenge(app, username="alice"):
    response = login(app.test_client(), username, GOOD_PASSWORD)
    assert response.status_code == 403, response.get_json()
    return response.get_json()


def action_count(app, action, subject=""):
    with app.app_context():
        query = AuthEvent.query.filter(AuthEvent.action == action)
        if subject:
            query = query.filter(AuthEvent.subject == subject)
        return query.count()


# ---------------------------------------------------------------------------
# packet-level invariants (the wire itself)
# ---------------------------------------------------------------------------


def test_access_request_is_wellformed_and_never_sends_the_code_in_the_clear():
    packet, request_auth = radius_client.build_access_request(
        "alice", ACCEPTED_CODE, RADIUS_SECRET
    )
    code, rid, length = struct.unpack(">BBH", packet[:4])
    assert code == radius_client.ACCESS_REQUEST
    assert 0 <= rid <= 255
    assert length == len(packet)
    assert len(request_auth) == 16
    # User-Name rides in the clear (RFC), the password never does
    assert b"alice" in packet
    assert ACCEPTED_CODE.encode() not in packet
    # sequential attribute parse: User-Password exists, masked, 16-byte blocks
    offset = 20
    password_values = []
    while offset + 2 <= len(packet):
        attr_len = packet[offset + 1]
        if attr_len < 2 or offset + attr_len > len(packet):
            break
        if packet[offset] == 2:
            password_values.append(packet[offset + 2 : offset + attr_len])
        offset += attr_len
    assert password_values, "User-Password attribute missing"
    assert all(len(value) % 16 == 0 for value in password_values)


def test_parse_response_requires_a_valid_response_authenticator():
    request_auth = b"\x11" * 16
    attributes = b""
    total = 20 + len(attributes)
    response_auth = hashlib.md5(
        bytes([2, 7])
        + struct.pack(">H", total)
        + request_auth
        + attributes
        + RADIUS_SECRET.encode()
    ).digest()
    good = bytes([2, 7]) + struct.pack(">H", total) + response_auth + attributes
    assert radius_client.parse_response(good, request_auth, RADIUS_SECRET) == (2, "")

    tampered = bytes([2, 7]) + struct.pack(">H", total) + b"\x00" * 16 + attributes
    code, reason = radius_client.parse_response(tampered, request_auth, RADIUS_SECRET)
    assert code is None
    assert reason == "response authenticator does not verify"

    short, reason = radius_client.parse_response(b"\x02\x00", request_auth, RADIUS_SECRET)
    assert short is None
    assert "shorter than the RADIUS header" in reason

    mismatched = bytes([2, 7]) + struct.pack(">H", 99) + b"\x00" * 16
    code, reason = radius_client.parse_response(mismatched, request_auth, RADIUS_SECRET)
    assert code is None
    assert "length field" in reason


def test_masked_password_decodes_with_the_rfc_rule():
    """The product's masking round-trips through the independent decoder a
    real RADIUS server would use."""
    packet, request_auth = radius_client.build_access_request(
        "alice", ACCEPTED_CODE, RADIUS_SECRET
    )
    offset = 20
    masked = b""
    while offset + 2 <= len(packet):
        attr_len = packet[offset + 1]
        if packet[offset] == 2:
            masked = packet[offset + 2 : offset + attr_len]
            break
        offset += attr_len
    assert masked
    assert (
        _unmask_password(masked, RADIUS_SECRET.encode(), request_auth) == ACCEPTED_CODE
    )


# ---------------------------------------------------------------------------
# enrolment
# ---------------------------------------------------------------------------


def test_enrol_refused_honestly_while_unconfigured(client, app):
    create_user(client)
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200
    minted = login(client, "alice", GOOD_PASSWORD)
    assert minted.status_code == 200
    refused = client.post(
        "/api/v1/auth/mfa/enroll/radius",
        json={},
        headers={"X-CSRF-Token": minted.get_json()["csrf_token"]},
    )
    assert refused.status_code == 503
    assert refused.get_json()["details"]["configured"] is False


def test_enrol_creates_the_factor_and_the_secret_stays_sealed(client, app, stub):
    create_user(client)
    mint = enrol_radius_factor(client, stub)

    factors = client.get("/api/v1/auth/mfa/factors").get_json()["factors"]
    assert [row["kind"] for row in factors] == ["radius"]
    assert factors[0]["name"] == "RADIUS push/OTP"
    assert action_count(app, "auth.mfa.enrolled", subject="alice") == 1

    # the settings reply never carries the secret; the store does, sealed
    settings = client.get("/api/v1/settings", headers=ADMIN).get_json()["settings"]["radius"]
    assert RADIUS_SECRET not in str(settings)
    with app.app_context():
        assert service.unseal_setting_secret("radius", "secret") == RADIUS_SECRET
    assert mint["csrf_token"]  # session alive for later assertions


def test_echoing_the_set_sentinel_keeps_the_stored_secret(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)

    # a naive GET -> PUT round-trip sends `<set>` back; that must never
    # overwrite the sealed secret with the literal sentinel
    echoed = client.put(
        "/api/v1/settings/radius",
        json={
            "enabled": True,
            "host": "127.0.0.1",
            "port": stub.port,
            "timeout_seconds": 1,
            "secret": "<set>",
        },
        headers=ADMIN,
    )
    assert echoed.status_code == 200, echoed.get_json()
    with app.app_context():
        assert service.unseal_setting_secret("radius", "secret") == RADIUS_SECRET


# ---------------------------------------------------------------------------
# the factor over real UDP
# ---------------------------------------------------------------------------


def test_access_accept_passes_the_real_login_challenge(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)
    stub.accept_passwords = {ACCEPTED_CODE}

    challenged = mfa_challenge(app)
    assert challenged["methods"] == ["radius"]

    minted = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged["challenge"],
        radius_code=ACCEPTED_CODE,
    )
    assert minted.status_code == 200, minted.get_json()
    assert minted.get_json()["mfa_methods"] == ["radius"]
    # the stub decoded the wire: the exact code arrived as User-Password
    assert stub.seen == [("alice", ACCEPTED_CODE)]


def test_access_reject_fails_the_factor_and_is_alerted(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)
    stub.accept_passwords = set()  # reject everything

    challenged = mfa_challenge(app)
    refused = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged["challenge"],
        radius_code="00000000",
    )
    assert refused.status_code == 401
    assert refused.get_json()["error"] == "MFA assertion failed"
    assert action_count(app, "auth.mfa.failed", subject="alice") == 1
    assert stub.seen == [("alice", "00000000")]


def test_bad_response_authenticator_is_an_honest_503_never_a_pass(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)
    stub.behavior = "garbage"

    challenged = mfa_challenge(app)
    failed = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged["challenge"],
        radius_code=ACCEPTED_CODE,
    )
    assert failed.status_code == 503
    assert "RADIUS server unreachable" in failed.get_json()["error"]
    # RETRIES: the client re-sent the request, then reported honestly
    assert len(stub.seen) == 2
    assert action_count(app, "auth.mfa.radius-unreachable", subject="alice") == 1


def test_timeout_is_an_honest_503_never_a_pass(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)
    stub.behavior = "silent"

    challenged = mfa_challenge(app)
    failed = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged["challenge"],
        radius_code=ACCEPTED_CODE,
    )
    assert failed.status_code == 503
    assert "RADIUS server unreachable" in failed.get_json()["error"]
    assert len(stub.seen) == 2  # both attempts reached the wire
    assert action_count(app, "auth.mfa.radius-unreachable", subject="alice") == 1


def test_disabling_the_group_makes_the_assertion_refuse_honestly(client, app, stub):
    create_user(client)
    enrol_radius_factor(client, stub)
    enable_radius(client, stub, enabled=False)

    challenged = mfa_challenge(app)
    failed = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged["challenge"],
        radius_code=ACCEPTED_CODE,
    )
    assert failed.status_code == 503
    assert failed.get_json()["details"]["configured"] is False
    assert stub.seen == []  # nothing even went on the wire


def test_stepup_accepts_the_radius_code_over_udp(client, app, stub):
    create_user(client)
    mint = enrol_radius_factor(client, stub)
    stub.accept_passwords = {ACCEPTED_CODE}

    with app.app_context():
        row = ConsoleSession.query.order_by(ConsoleSession.id.desc()).first()
        row.mfa_at = datetime.now() - timedelta(minutes=10)
        db.session.commit()

    stepped = client.post(
        "/api/v1/auth/mfa/stepup",
        json={"radius_code": ACCEPTED_CODE},
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert stepped.status_code == 200, stepped.get_json()
    assert stepped.get_json() == {
        "status": "verified",
        "method": "radius",
        "mfa_at": stepped.get_json()["mfa_at"],
    }
    assert stub.seen == [("alice", ACCEPTED_CODE)]


def test_wrong_radius_code_at_stepup_is_refused(client, app, stub):
    create_user(client)
    mint = enrol_radius_factor(client, stub)
    stub.accept_passwords = {ACCEPTED_CODE}

    with app.app_context():
        row = ConsoleSession.query.order_by(ConsoleSession.id.desc()).first()
        row.mfa_at = datetime.now() - timedelta(minutes=10)
        db.session.commit()

    refused = client.post(
        "/api/v1/auth/mfa/stepup",
        json={"radius_code": "12345678"},
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert refused.status_code == 401
    assert refused.get_json()["error"] == "MFA assertion failed"
    assert action_count(app, "auth.mfa.failed", subject="alice") == 1
