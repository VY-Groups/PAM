"""Phase 7 - MFA factors (Addendum C): TOTP enrolment with replay-protected
first verification and rotation, the two-step login challenge (status-403
continuation, single-use, wrong assertion does not consume it), single-use
backup codes, e-mail OTP enrolment + login through a real (captured) code,
fail-closed last-factor deletion, step-up refresh, and the remembered-device
token (issued for low-privilege only, skips the second factor).

SMTP is configured and the send monkeypatched with a capturing stub - the
code is the product's own; only the delivery leaves the process. Every
login attempt runs on a cookie-free client: the CSRF guard is a real
control and must never trip over the test's own cookie.
"""
from __future__ import annotations

import re
import sys
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
from models import AuthEvent, ConsoleSession, MfaFactor  # noqa: E402
import identity  # noqa: E402
import integrations  # noqa: E402
import otp as otp_module  # noqa: E402
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
BACKUP_CODE_RE = re.compile(r"^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$")


def totp_code(seed: str) -> str:
    """A live RFC-6238 code for the seed, via the product's own HOTP."""
    return integrations.hotp(seed, int(time.time() // integrations.TOTP_PERIOD))


def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-mfa-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-mfa",
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


def login(client, username, password, **extra):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, **extra},
    )


def bind(client, principal, role, kind="user"):
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": principal, "role": role, "kind": kind},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def enrol_totp(client, username="alice", password=GOOD_PASSWORD):
    """Ticket-based TOTP enrolment - the fail-closed first-login path.
    Returns (seed, mint). The client holds the minted session afterwards."""
    ticket = login(client, username, password).get_json()["enrol_ticket"]
    enrolled = client.post(
        "/api/v1/auth/mfa/enroll/totp", json={"enrol_ticket": ticket}
    )
    assert enrolled.status_code == 201, enrolled.get_json()
    secret = enrolled.get_json()["secret"]
    verified = client.post(
        "/api/v1/auth/mfa/enroll/totp/verify",
        json={"enrol_ticket": ticket, "code": totp_code(secret)},
    )
    assert verified.status_code == 200, verified.get_json()
    return secret, verified.get_json()


def action_count(app, action):
    with app.app_context():
        return AuthEvent.query.filter(AuthEvent.action == action).count()


def stale_stepup(app):
    """Age the current session's step-up window past the TTL."""
    with app.app_context():
        row = ConsoleSession.query.order_by(ConsoleSession.id.desc()).first()
        row.mfa_at = datetime.now() - timedelta(minutes=10)
        db.session.commit()


def reset_totp_step(app):
    """Time travel for the replay counter: pretend the consumed TOTP time
    step is old, so the next current-step code verifies honestly (the
    replay protection itself is asserted where it is the subject)."""
    with app.app_context():
        for factor in MfaFactor.query.filter(MfaFactor.kind == "totp").all():
            factor.last_step = 0
        db.session.commit()


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


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------


def test_totp_first_verification_is_replay_protected_and_rotation_resets_it(client, app):
    create_user(client)
    secret, mint = enrol_totp(client)
    csrf = {"X-CSRF-Token": mint["csrf_token"]}

    # the enrolled factor is listed without any secret material
    factors = client.get("/api/v1/auth/mfa/factors").get_json()["factors"]
    assert [row["kind"] for row in factors] == ["totp"]
    for row in factors:
        assert "secret" not in row and "secret_sealed" not in row

    # the same time step cannot verify twice
    assert client.post(
        "/api/v1/auth/mfa/enroll/totp/verify",
        json={"code": totp_code(secret)},
        headers=csrf,
    ).status_code == 401
    assert action_count(app, "auth.mfa.replay-refused") == 1

    # rotation: a new seed arrives, the replay counter resets with it
    rotated = client.post("/api/v1/auth/mfa/enroll/totp", json={}, headers=csrf)
    assert rotated.status_code == 201, rotated.get_json()
    new_secret = rotated.get_json()["secret"]
    assert new_secret != secret
    assert rotated.get_json()["factor"]["id"] == factors[0]["id"]
    verified = client.post(
        "/api/v1/auth/mfa/enroll/totp/verify",
        json={"code": totp_code(new_secret)},
        headers=csrf,
    )
    assert verified.status_code == 200, verified.get_json()
    assert verified.get_json() == {"status": "verified", "method": "totp"}
    assert action_count(app, "auth.mfa.re-enrolled") == 1


def test_enrol_ticket_holders_may_enrol_without_a_session(client, app):
    create_user(client)
    ticket = login(client, "alice", GOOD_PASSWORD).get_json()["enrol_ticket"]
    # no cookie, no session - the ticket alone is the credential
    enrolled = client.post("/api/v1/auth/mfa/enroll/totp", json={"enrol_ticket": ticket})
    assert enrolled.status_code == 201

    # the factor is active now: the next login asks for the second factor,
    # not for enrolment
    next_login = login(app.test_client(), "alice", GOOD_PASSWORD)
    assert next_login.status_code == 403
    assert next_login.get_json()["status"] == "mfa_required"


# ---------------------------------------------------------------------------
# the two-step login challenge
# ---------------------------------------------------------------------------


def test_login_challenge_is_carried_in_a_status_403_and_is_single_use(client, app):
    create_user(client)
    secret, _mint = enrol_totp(client)
    probe = app.test_client()

    # step 1: password ok, factor missing - a status-carrying 403, not a bare 401
    challenged = login(probe, "alice", GOOD_PASSWORD)
    assert challenged.status_code == 403
    body = challenged.get_json()
    assert body["status"] == "mfa_required"
    assert body["challenge"].startswith("vypam-mfa1.")
    assert body["methods"] == ["totp"]
    assert body["expires_in_seconds"] == 300

    # step 2, wrong assertion: refused - and the challenge survives it
    wrong = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        login_challenge=body["challenge"],
        totp_code="000000" if totp_code(secret) != "000000" else "111111",
    )
    assert wrong.status_code == 401
    assert wrong.get_json()["error"] == "MFA assertion failed"

    # the same challenge still completes with the right code (fresh time
    # step - the enrolment verify consumed the previous one)
    reset_totp_step(app)
    minted = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        login_challenge=body["challenge"],
        totp_code=totp_code(secret),
    )
    assert minted.status_code == 200, minted.get_json()
    assert minted.get_json()["mfa_methods"] == ["totp"]

    # and the challenge is spent: a replay of the whole second step fails
    replay = login(
        app.test_client(),
        "alice",
        GOOD_PASSWORD,
        login_challenge=body["challenge"],
        totp_code=totp_code(secret),
    )
    assert replay.status_code == 401
    assert replay.get_json()["error"] == "MFA challenge invalid or expired"


def test_wrong_totp_code_in_stepup_is_refused(client, app):
    create_user(client)
    secret, mint = enrol_totp(client)
    csrf = {"X-CSRF-Token": mint["csrf_token"]}
    stale_stepup(app)

    refused = client.post(
        "/api/v1/auth/mfa/stepup",
        json={"totp_code": "000000" if totp_code(secret) != "000000" else "111111"},
        headers=csrf,
    )
    assert refused.status_code == 401
    assert refused.get_json()["error"] == "MFA assertion failed"

    # the `code` alias works the same (the documented shape)
    reset_totp_step(app)
    stepped = client.post(
        "/api/v1/auth/mfa/stepup", json={"code": totp_code(secret)}, headers=csrf
    )
    assert stepped.status_code == 200, stepped.get_json()
    assert stepped.get_json()["status"] == "verified"
    assert stepped.get_json()["method"] == "totp"
    # a fresh step-up no longer blocks the sensitive action
    assert client.post("/api/v1/auth/mfa/backup-codes", headers=csrf).status_code == 200


# ---------------------------------------------------------------------------
# backup codes
# ---------------------------------------------------------------------------


def test_backup_codes_are_single_use_and_regeneration_kills_the_old(client, app):
    create_user(client)
    secret, _mint = enrol_totp(client)
    reset_totp_step(app)  # the enrolment verify consumed the current step
    probe = app.test_client()

    challenged = login(probe, "alice", GOOD_PASSWORD)
    assert challenged.status_code == 403
    minted = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged.get_json()["challenge"],
        totp_code=totp_code(secret),
    ).get_json()
    csrf = {"X-CSRF-Token": minted["csrf_token"]}

    first = probe.post("/api/v1/auth/mfa/backup-codes", headers=csrf)
    assert first.status_code == 200, first.get_json()
    codes = first.get_json()["codes"]
    assert len(codes) == 10
    assert all(BACKUP_CODE_RE.match(code) for code in codes)

    # one code completes a login on its own, then it is gone
    used = login(app.test_client(), "alice", GOOD_PASSWORD, backup_code=codes[0])
    assert used.status_code == 200, used.get_json()
    assert used.get_json()["mfa_methods"] == ["backup-code"]
    reuse = login(app.test_client(), "alice", GOOD_PASSWORD, backup_code=codes[0])
    assert reuse.status_code == 401

    # regeneration invalidates every earlier code (dashes optional)
    second = probe.post("/api/v1/auth/mfa/backup-codes", headers=csrf)
    assert second.status_code == 200
    assert second.get_json()["codes"] != codes
    stale = login(
        app.test_client(), "alice", GOOD_PASSWORD, backup_code=codes[1].replace("-", "")
    )
    assert stale.status_code == 401


# ---------------------------------------------------------------------------
# e-mail OTP factor (real code, captured delivery)
# ---------------------------------------------------------------------------


def test_email_factor_enrolment_and_login_with_the_emailed_code(client, app, monkeypatch):
    sent = []
    monkeypatch.setattr(
        otp_module, "_send_via_smtp", lambda to, subject, body: sent.append((to, subject, body))
    )
    enable_smtp(client)
    create_user(client, "alice", email="alice@example.test")

    ticket = login(client, "alice", GOOD_PASSWORD).get_json()["enrol_ticket"]
    started = client.post("/api/v1/auth/mfa/enroll/email", json={"enrol_ticket": ticket})
    assert started.status_code == 202, started.get_json()
    enrol_id = started.get_json()["challenge_id"]
    assert started.get_json()["status"] == "sent"
    enrol_code = re.search(r"\b(\d{8})\b", sent[-1][2]).group(1)

    enrolled = client.post(
        "/api/v1/auth/mfa/enroll/email/verify",
        json={"enrol_ticket": ticket, "challenge_id": enrol_id, "code": enrol_code},
    )
    assert enrolled.status_code == 200, enrolled.get_json()
    assert enrolled.get_json() == {"status": "enrolled", "kind": "email"}
    assert action_count(app, "auth.mfa.enrolled") == 1

    # an e-mail factor backs a real login: the OTP challenge is started at
    # /auth/otp/start and its code asserted inline
    probe = app.test_client()
    otp_start = probe.post("/api/v1/auth/otp/start", json={"username": "alice"})
    assert otp_start.status_code == 202, otp_start.get_json()
    otp_code = re.search(r"\b(\d{8})\b", sent[-1][2]).group(1)
    minted = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        otp_challenge_id=otp_start.get_json()["challenge_id"],
        otp_code=otp_code,
    )
    assert minted.status_code == 200, minted.get_json()
    assert minted.get_json()["mfa_methods"] == ["email"]

    # the same mailed code cannot be used twice
    reuse = login(app.test_client(), "alice", GOOD_PASSWORD, otp_code=otp_code)
    assert reuse.status_code == 401


def test_email_enrolment_refused_without_a_mailbox(client):
    create_user(client)
    ticket = login(client, "alice", GOOD_PASSWORD).get_json()["enrol_ticket"]
    refused = client.post("/api/v1/auth/mfa/enroll/email", json={"enrol_ticket": ticket})
    assert refused.status_code == 400
    assert "e-mail address" in refused.get_json()["error"]


# ---------------------------------------------------------------------------
# fail-closed factor management
# ---------------------------------------------------------------------------


def test_last_factor_delete_is_refused_while_mfa_required(client, app):
    create_user(client)
    _secret, mint = enrol_totp(client)
    csrf = {"X-CSRF-Token": mint["csrf_token"]}
    factor_id = client.get("/api/v1/auth/mfa/factors").get_json()["factors"][0]["id"]

    refused = client.delete(f"/api/v1/auth/mfa/factors/{factor_id}", headers=csrf)
    assert refused.status_code == 403
    assert refused.get_json()["details"]["mfa_required"] is True

    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200
    removed = client.delete(f"/api/v1/auth/mfa/factors/{factor_id}", headers=csrf)
    assert removed.status_code == 200
    assert removed.get_json()["factor"] == {"deleted": True, "factor_id": factor_id}
    assert client.get("/api/v1/auth/mfa/factors").get_json()["factors"] == []
    assert action_count(app, "auth.mfa.factor-deleted") == 1


def test_unknown_factor_delete_is_404(client):
    create_user(client)
    _secret, mint = enrol_totp(client)
    refused = client.delete(
        "/api/v1/auth/mfa/factors/9999", headers={"X-CSRF-Token": mint["csrf_token"]}
    )
    assert refused.status_code == 404


# ---------------------------------------------------------------------------
# remembered device
# ---------------------------------------------------------------------------


def test_remember_device_issues_a_token_only_for_low_privilege(client, app):
    create_user(client, "alice")
    create_user(client, "bob")
    bind(client, "bob", "admin")
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200

    minted = login(client, "alice", GOOD_PASSWORD, remember_device=True).get_json()
    token = minted["device_token"]
    assert token.startswith("vypam-dev1.")
    assert minted["device_expires_at"]
    assert action_count(app, "auth.device.remembered") == 1

    # an admin-bound login is refused a device token (Addendum C)
    admin_login = login(
        app.test_client(), "bob", GOOD_PASSWORD, remember_device=True
    ).get_json()
    assert "device_token" not in admin_login
    assert action_count(app, "auth.device.remembered") == 1  # unchanged


def test_remembered_device_token_skips_the_second_factor(client, app):
    create_user(client)
    secret, _mint = enrol_totp(client)
    probe = app.test_client()

    # the token is issued on the MFA-completed login when asked for
    challenged = login(probe, "alice", GOOD_PASSWORD)
    assert challenged.status_code == 403
    reset_totp_step(app)  # the enrolment verify consumed the current step
    minted = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged.get_json()["challenge"],
        totp_code=totp_code(secret),
        remember_device=True,
    ).get_json()
    device_token = minted["device_token"]

    # from then on the remembered device completes the login without a factor
    skipped = login(
        app.test_client(), "alice", GOOD_PASSWORD, device_token=device_token
    )
    assert skipped.status_code == 200, skipped.get_json()
    assert skipped.get_json()["mfa_methods"] == ["remembered-device"]

    # a forged token does not skip anything
    forged = login(
        app.test_client(), "alice", GOOD_PASSWORD, device_token=f"vypam-dev1.1.{'x' * 40}"
    )
    assert forged.status_code == 403
    assert forged.get_json()["status"] == "mfa_required"
