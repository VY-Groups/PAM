"""Phase 7 - e-mail OTP (Addendum C): the uniform 202 for known, unknown,
inactive and emergency accounts (no enumeration, cooldown-stable ids),
suppressed delivery with a real HMAC-stored code, attempt caps and expiry
through the recovery flow, measured delivery failures with rotation-on-
retry, the honest SMTP test-send outcomes, and the auth report.

Every send is monkeypatched at `otp._send_via_smtp` - the product's own
challenge/code/HMAC machinery runs unchanged; only the socket leaves.
"""
from __future__ import annotations

import re
import sys
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
from errors import ServiceUnavailable  # noqa: E402
from extensions import db  # noqa: E402
from models import AuthEvent, AuthOtp, SmtpDelivery  # noqa: E402
import identity  # noqa: E402
import otp as otp_module  # noqa: E402
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
NEW_PASSWORD = "copper-forest-lantern9"
CHALLENGE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-otp-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-otp",
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


def create_user(client, username="alice", password=GOOD_PASSWORD, **fields):
    response = client.post(
        "/api/v1/users",
        json={"username": username, "password": password, **fields},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def enable_smtp(client):
    response = client.put(
        "/api/v1/settings/smtp",
        json={
            "enabled": True,
            "host": "smtp.test.local",
            "port": 587,
            "from_address": "noreply@vypam.test",
            "use_tls": True,
        },
        headers=ADMIN,
    )
    assert response.status_code == 200, response.get_json()


def capture_sends(monkeypatch):
    """Replace the SMTP socket with a capturing stub - the product's own
    challenge/code machinery runs unchanged."""
    sent = []
    monkeypatch.setattr(
        otp_module,
        "_send_via_smtp",
        lambda to, subject, body: sent.append((to, subject, body)),
    )
    return sent


def mailed_code(message_body: str) -> str:
    return re.search(r"\b(\d{8})\b", message_body).group(1)


def action_count(app, action, subject=""):
    with app.app_context():
        query = AuthEvent.query.filter(AuthEvent.action == action)
        if subject:
            query = query.filter(AuthEvent.subject == subject)
        return query.count()


# ---------------------------------------------------------------------------
# the uniform answer (no enumeration)
# ---------------------------------------------------------------------------


def test_start_answers_identically_for_known_and_unknown(client, app):
    unknown = client.post("/api/v1/auth/otp/start", json={"username": "ghost-user"})
    unknown_again = client.post("/api/v1/auth/otp/start", json={"username": "ghost-user"})
    create_user(client, "alice")
    known = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    known_again = client.post("/api/v1/auth/otp/start", json={"username": "alice"})

    for response in (unknown, unknown_again, known, known_again):
        assert response.status_code == 202
        body = response.get_json()
        assert body["status"] == "sent"
        assert CHALLENGE_ID_RE.match(body["challenge_id"])
    # the cooldown re-supplies the live challenge for both shapes alike
    assert unknown.get_json()["challenge_id"] == unknown_again.get_json()["challenge_id"]
    assert known.get_json()["challenge_id"] == known_again.get_json()["challenge_id"]
    assert set(known.get_json()) == set(unknown.get_json())
    assert action_count(app, "otp-suppressed", subject="ghost-user") >= 1


def test_start_validates_its_input(client):
    assert client.post("/api/v1/auth/otp/start", json={}).status_code == 400
    bad_purpose = client.post(
        "/api/v1/auth/otp/start", json={"username": "alice", "purpose": "nope"}
    )
    assert bad_purpose.status_code == 400
    assert bad_purpose.get_json()["details"]["allowed"] == ["login", "stepup", "recovery"]


# ---------------------------------------------------------------------------
# suppression (inactive + emergency + unconfigured)
# ---------------------------------------------------------------------------


def test_inactive_and_emergency_accounts_get_a_real_challenge_but_no_mail(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    created = create_user(client, "alice", email="alice@example.test")
    client.patch(
        f"/api/v1/users/{created['user']['id']}", json={"active": False}, headers=ADMIN
    )

    inactive = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    assert inactive.status_code == 202
    assert CHALLENGE_ID_RE.match(inactive.get_json()["challenge_id"])
    # cooldown-stable for the inactive account too - same shape, same id
    again = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    assert again.get_json()["challenge_id"] == inactive.get_json()["challenge_id"]

    emergency = client.post(
        "/api/v1/auth/otp/start", json={"username": "emergency-admin"}
    )
    assert emergency.status_code == 202
    assert CHALLENGE_ID_RE.match(emergency.get_json()["challenge_id"])

    # nothing was ever handed to a socket, and no delivery row pretends otherwise
    assert sent == []
    assert client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ] == []
    assert action_count(app, "otp-suppressed", subject="alice") >= 1
    assert action_count(app, "otp-suppressed", subject="emergency-admin") == 1


def test_unconfigured_smtp_or_missing_mailbox_is_a_measured_suppression(client, app):
    create_user(client, "alice", email="alice@example.test")
    create_user(client, "bob")  # no mailbox

    alice = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    bob = client.post("/api/v1/auth/otp/start", json={"username": "bob"})
    assert alice.status_code == 202 and bob.status_code == 202

    deliveries = client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ]
    assert len(deliveries) == 2
    for row in deliveries:
        assert row["status"] == "failed"
        assert "not configured" in row["last_error"]
        assert row["attempts"] == 1
    masked = {row["recipient_masked"] for row in deliveries}
    assert "a***@example.test" in masked and "***" in masked


# ---------------------------------------------------------------------------
# attempt cap + expiry through the recovery flow
# ---------------------------------------------------------------------------


def test_attempt_cap_locks_the_challenge_even_for_the_right_code(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    started = client.post("/api/v1/auth/recovery/start", json={"username": "alice"})
    assert started.status_code == 202
    challenge_id = started.get_json()["challenge_id"]
    code = mailed_code(sent[-1][2])

    for _ in range(5):
        wrong = client.post(
            "/api/v1/auth/recovery/reset",
            json={
                "username": "alice",
                "challenge_id": challenge_id,
                "code": "00000000" if code != "00000000" else "11111111",
                "new_password": NEW_PASSWORD,
            },
        )
        assert wrong.status_code == 401

    # the correct code arrives too late: the cap is a cap
    late = client.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": code,
            "new_password": NEW_PASSWORD,
        },
    )
    assert late.status_code == 401
    assert action_count(app, "otp-locked", subject="alice") >= 1


def test_expired_challenge_is_refused_for_the_right_code(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    challenge_id = client.post(
        "/api/v1/auth/recovery/start", json={"username": "alice"}
    ).get_json()["challenge_id"]
    code = mailed_code(sent[-1][2])
    with app.app_context():
        row = AuthOtp.query.filter(AuthOtp.challenge_id == challenge_id).first()
        row.expires_at = datetime.now() - timedelta(seconds=1)
        db.session.commit()

    refused = client.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": code,
            "new_password": NEW_PASSWORD,
        },
    )
    assert refused.status_code == 401
    assert action_count(app, "otp-failed", subject="alice") >= 1


def test_recovery_ends_in_a_real_reset_with_the_landed_code(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    challenge_id = client.post(
        "/api/v1/auth/recovery/start", json={"username": "alice"}
    ).get_json()["challenge_id"]
    reset = client.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": mailed_code(sent[-1][2]),
            "new_password": NEW_PASSWORD,
        },
    )
    assert reset.status_code == 200, reset.get_json()
    assert reset.get_json()["sessions_revoked"] == 0  # none existed
    assert action_count(app, "otp-verified", subject="alice") == 1


# ---------------------------------------------------------------------------
# delivery failures, retry and rotation-on-retry
# ---------------------------------------------------------------------------


def test_failed_delivery_is_measured_and_honestly_capped(client, app, monkeypatch):
    def always_down(to, subject, body):
        raise ServiceUnavailable("connection refused", {"host": "smtp.test.local"})

    monkeypatch.setattr(otp_module, "_send_via_smtp", always_down)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    started = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    assert started.status_code == 202  # the answer never leaks the failure

    deliveries = client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ]
    assert deliveries[0]["status"] == "queued"
    assert deliveries[0]["attempts"] == 1
    assert "connection refused" in deliveries[0]["last_error"]
    assert action_count(app, "otp-failed", subject="alice") == 1

    with app.app_context():
        assert otp_module.retry_failed_deliveries() == {"retried": 1}
        assert otp_module.retry_failed_deliveries() == {"retried": 1}
        # after OTP_MAX_DELIVERY_ATTEMPTS the row is failed, not retried forever
        assert otp_module.retry_failed_deliveries() == {"retried": 0}
    deliveries = client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ]
    assert deliveries[0]["status"] == "failed"
    assert deliveries[0]["attempts"] == 3


def test_retry_rotates_the_code_and_the_newest_message_lands(client, app, monkeypatch):
    attempts = {"count": 0}
    sent = []

    def flaky(to, subject, body):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ServiceUnavailable("connection reset", {})
        sent.append((to, subject, body))

    monkeypatch.setattr(otp_module, "_send_via_smtp", flaky)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    challenge_id = client.post(
        "/api/v1/auth/recovery/start", json={"username": "alice"}
    ).get_json()["challenge_id"]

    with app.app_context():
        assert otp_module.retry_failed_deliveries() == {"retried": 1}
    assert len(sent) == 1  # the retry's message is the one that landed
    code = mailed_code(sent[0][2])

    reset = client.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": code,
            "new_password": NEW_PASSWORD,
        },
    )
    assert reset.status_code == 200, reset.get_json()
    deliveries = client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ]
    assert deliveries[0]["status"] == "sent"
    assert deliveries[0]["attempts"] == 2
    assert deliveries[0]["last_error"] == ""


def test_delivery_status_never_carries_a_code(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")
    client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    code = mailed_code(sent[-1][2])

    deliveries = client.get("/api/v1/auth/deliveries", headers=ADMIN).get_json()[
        "deliveries"
    ]
    assert len(deliveries) == 1
    row = deliveries[0]
    assert "code" not in row and code not in str(row.values())
    assert row["recipient_masked"] == "a***@example.test"
    assert row["status"] == "sent"


# ---------------------------------------------------------------------------
# the SMTP test-send + mask + report
# ---------------------------------------------------------------------------


def test_smtp_test_send_reports_the_measured_outcome(client, app, monkeypatch):
    unconfigured = client.post(
        "/api/v1/settings/smtp/test", json={"to": "ops@example.test"}, headers=ADMIN
    )
    assert unconfigured.status_code == 503
    assert unconfigured.get_json()["details"]["configured"] is False

    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    ok = client.post(
        "/api/v1/settings/smtp/test", json={"to": "ops@example.test"}, headers=ADMIN
    )
    assert ok.status_code == 200, ok.get_json()
    assert ok.get_json()["delivery"]["status"] == "sent"
    assert sent[0][0] == "ops@example.test"

    def down(to, subject, body):
        raise ServiceUnavailable("mailbox unreachable", {})

    monkeypatch.setattr(otp_module, "_send_via_smtp", down)
    failed = client.post(
        "/api/v1/settings/smtp/test", json={"to": "ops@example.test"}, headers=ADMIN
    )
    assert failed.status_code == 503
    assert "mailbox unreachable" in failed.get_json()["error"]
    assert action_count(app, "settings.smtp.test-failed") == 1
    assert action_count(app, "settings.smtp.test-sent") == 1


def test_mask_email_keeps_the_status_without_the_mailbox():
    assert otp_module.mask_email("alice@example.test") == "a***@example.test"
    assert otp_module.mask_email("no-at-sign") == "***"
    assert otp_module.mask_email("") == "***"


def test_auth_report_counts_the_otp_trail(client, app, monkeypatch):
    sent = capture_sends(monkeypatch)
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")
    client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    challenge_id = client.post(
        "/api/v1/auth/recovery/start", json={"username": "alice"}
    ).get_json()["challenge_id"]
    client.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": mailed_code(sent[-1][2]),
            "new_password": NEW_PASSWORD,
        },
    )

    report = client.get("/api/v1/auth/report?window_hours=24", headers=ADMIN)
    assert report.status_code == 200
    body = report.get_json()
    assert body["window_hours"] == 24
    assert body["by_action"]["otp-verified"] >= 1
    assert body["total_events"] >= body["by_action"]["otp-verified"]
    assert any(row["action"] == "otp-verified" for row in body["events"])
    for row in body["events"]:
        assert "code" not in row
