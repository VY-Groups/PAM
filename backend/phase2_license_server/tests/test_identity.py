"""Phase 7 - real identity and login security (Addendum C): local users,
console sessions with HttpOnly cookies + the CSRF double-submit, NIST
password rules, lockout / rate limits / spray refusals, forced MFA
enrolment, e-mail recovery, the sealed emergency admin, actor binding and
the `auth` report.

Everything runs against the real code paths: scrypt hashes, real session
rows, the in-process sliding windows and the `auth` ledger. The
progressive login delay is switched off (a knob for slow networks, not the
subject here) and SMTP stays unconfigured unless a test proves that path.
"""
from __future__ import annotations

import json
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
from models import AuthEvent, ConsoleSession, User  # noqa: E402
import identity  # noqa: E402
import integrations  # noqa: E402
import otp as otp_module  # noqa: E402
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
NEW_PASSWORD = "copper-forest-lantern9"


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
        secret_key="test-identity-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-identity",
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
    """Fresh sliding windows per test, no progressive sleep."""
    identity.reset_windows_for_tests()
    with app.app_context():
        service.update_settings("auth", {"progressive_delay": False}, actor="test")
    yield
    identity.reset_windows_for_tests()


def create_user(client, username="alice", password=GOOD_PASSWORD, **fields):
    payload = {"username": username, "password": password, **fields}
    response = client.post("/api/v1/users", json=payload, headers=ADMIN)
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def login(client, username, password, **extra):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, **extra},
    )


def disable_mfa(client):
    response = client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    )
    assert response.status_code == 200, response.get_json()


def bind(client, principal, role, kind="user"):
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": principal, "role": role, "kind": kind},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def action_count(app, action):
    with app.app_context():
        return AuthEvent.query.filter(AuthEvent.action == action).count()


# ---------------------------------------------------------------------------
# boot seeding + password policy
# ---------------------------------------------------------------------------


def test_emergency_admin_is_seeded_sealed(client, app):
    listed = client.get("/api/v1/users", headers=ADMIN).get_json()["users"]
    names = [row["username"] for row in listed]
    assert "emergency-admin" in names
    with app.app_context():
        user = identity.get_user("emergency-admin")
        assert user is not None
        assert user.is_emergency is True
        assert user.is_active is True
        assert user.password_hash.startswith("sealed$")
        plaintext = identity._unseal_emergency_password(
            json.loads(user.password_hash[len("sealed$") :])
        )
        assert plaintext.startswith("emg-") and len(plaintext) > 20


def test_password_too_short_refused(client):
    response = client.post(
        "/api/v1/users",
        json={"username": "shorty", "password": "short1234567"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert "at least" in response.get_json()["error"]


def test_breached_password_refused(client):
    response = client.post(
        "/api/v1/users",
        json={"username": "breezy", "password": "password123456"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert "denylist" in response.get_json()["error"]


def test_password_may_not_contain_the_username(client):
    response = client.post(
        "/api/v1/users",
        json={"username": "contained-user", "password": "contained-user-99x"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert "username" in response.get_json()["error"]


def test_generated_password_is_shown_once_and_forces_change(client):
    created = client.post(
        "/api/v1/users", json={"username": "genuser"}, headers=ADMIN
    )
    assert created.status_code == 201
    body = created.get_json()
    generated = body["generated_password"]
    assert len(generated) >= 14
    assert body["user"]["must_change_password"] is True

    blocked = login(client, "genuser", generated)
    assert blocked.status_code == 403
    assert blocked.get_json()["details"]["reason"] == "password-change-required"

    changed = client.post(
        "/api/v1/auth/password",
        json={
            "username": "genuser",
            "old_password": generated,
            "new_password": NEW_PASSWORD,
        },
    )
    assert changed.status_code == 200, changed.get_json()

    # the new password is accepted: the reply is the fail-closed enrolment
    # step (the default policy demands MFA), not a credential refusal
    accepted = login(client, "genuser", NEW_PASSWORD)
    assert accepted.status_code == 403
    assert accepted.get_json()["status"] == "enrolment_required"


# ---------------------------------------------------------------------------
# login outcomes
# ---------------------------------------------------------------------------


def test_login_without_a_factor_fails_closed_with_an_enrolment_ticket(client):
    create_user(client)
    response = login(client, "alice", GOOD_PASSWORD)
    assert response.status_code == 403
    body = response.get_json()
    assert body["status"] == "enrolment_required"
    assert body["enrol_ticket"].startswith("vypam-enr1.")
    assert body["methods_allowed"] == ["totp", "webauthn", "email"]
    assert "vypam_session=" not in response.headers.get("Set-Cookie", "")


def test_enrolment_ticket_completes_a_real_totp_flow(client, app):
    create_user(client)
    ticket = login(client, "alice", GOOD_PASSWORD).get_json()["enrol_ticket"]

    enrolled = client.post(
        "/api/v1/auth/mfa/enroll/totp", json={"enrol_ticket": ticket}
    )
    assert enrolled.status_code == 201, enrolled.get_json()
    secret = enrolled.get_json()["secret"]
    assert enrolled.get_json()["shown_once"] is True

    verified = client.post(
        "/api/v1/auth/mfa/enroll/totp/verify",
        json={"enrol_ticket": ticket, "code": totp_code(secret)},
    )
    assert verified.status_code == 200, verified.get_json()
    minted = verified.get_json()
    assert minted["session_token"].startswith("vypam-ui1.")
    assert minted["mfa_methods"] == ["totp"]
    assert "vypam_session=" in verified.headers.get("Set-Cookie", "")

    # the ticket is single-use: the same code cannot replay the enrolment
    probe = app.test_client()
    replay = probe.post(
        "/api/v1/auth/mfa/enroll/totp/verify",
        json={"enrol_ticket": ticket, "code": totp_code(secret)},
    )
    assert replay.status_code == 401
    assert action_count(app, "auth.mfa.enrolled") == 1


def test_login_mints_a_console_session_when_mfa_not_required(client):
    create_user(client)
    disable_mfa(client)
    response = login(client, "alice", GOOD_PASSWORD)
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["session_token"].startswith("vypam-ui1.")
    assert body["csrf_token"]
    assert body["mfa_methods"] == []
    assert body["is_emergency"] is False
    assert body["user"]["username"] == "alice"
    cookie = response.headers.get("Set-Cookie", "")
    assert "vypam_session=" in cookie and "HttpOnly" in cookie
    assert body["expires_at"] and body["idle_expires_at"]


def test_login_refusals_are_identical_for_unknown_wrong_and_inactive(client):
    created = create_user(client, "alice")
    client.patch(
        f"/api/v1/users/{created['user']['id']}", json={"active": False}, headers=ADMIN
    )

    unknown = login(client, "ghost", "whatever-here-1234")
    wrong = login(client, "alice", "not-the-password-9")
    inactive = login(client, "alice", GOOD_PASSWORD)
    for response in (unknown, wrong, inactive):
        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid username or password"}


def test_emergency_admin_cannot_use_the_password_path(client):
    response = login(client, "emergency-admin", "anything-at-all-123")
    assert response.status_code == 403
    assert response.get_json()["details"]["reason"] == "emergency-sealed"


def test_admin_token_alone_has_no_console_session(client):
    response = client.get("/api/v1/auth/sessions", headers=ADMIN)
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# sessions, actor binding and CSRF
# ---------------------------------------------------------------------------


def test_sessions_list_revoke_and_logout(client, app):
    create_user(client)
    disable_mfa(client)
    first = login(client, "alice", GOOD_PASSWORD).get_json()
    second_client = app.test_client()
    second = login(second_client, "alice", GOOD_PASSWORD).get_json()
    assert first["session_id"] != second["session_id"]

    listed = client.get("/api/v1/auth/sessions").get_json()
    assert len(listed["sessions"]) == 2
    assert listed["current_session_id"] == first["session_id"]

    revoked = client.delete(
        f"/api/v1/auth/sessions/{second['session_id']}",
        headers={"X-CSRF-Token": first["csrf_token"]},
    )
    assert revoked.status_code == 200, revoked.get_json()
    assert second_client.get("/api/v1/auth/sessions").status_code == 401
    assert client.get("/api/v1/auth/sessions").status_code == 200

    logged_out = client.post(
        "/api/v1/auth/logout", headers={"X-CSRF-Token": first["csrf_token"]}
    )
    assert logged_out.status_code == 200
    assert logged_out.get_json()["status"] == "logged_out"
    assert client.get("/api/v1/auth/sessions").status_code == 401


def test_logout_all_keeps_only_the_calling_session(client, app):
    create_user(client)
    disable_mfa(client)
    minted = login(client, "alice", GOOD_PASSWORD).get_json()
    second_client = app.test_client()
    second = login(second_client, "alice", GOOD_PASSWORD).get_json()

    response = client.post(
        "/api/v1/auth/logout-all",
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert response.status_code == 200
    assert response.get_json()["revoked"] == 1
    assert second_client.get("/api/v1/auth/sessions").status_code == 401
    assert client.get("/api/v1/auth/sessions").status_code == 200


def test_cookie_mutations_require_the_csrf_double_submit(client):
    create_user(client)
    disable_mfa(client)
    minted = login(client, "alice", GOOD_PASSWORD).get_json()

    refused = client.post("/api/v1/auth/logout-all")
    assert refused.status_code == 403
    assert refused.get_json()["details"]["reason"] == "csrf"

    allowed = client.post(
        "/api/v1/auth/logout-all",
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert allowed.status_code == 200

    # a bearer client is not an ambient credential: it skips the double-submit
    bearer = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {minted['session_token']}"},
    )
    assert bearer.status_code == 200


def test_x_actor_never_overrides_the_session_identity(client, app):
    create_user(client)
    disable_mfa(client)
    bind(client, "alice", "admin")
    minted = login(client, "alice", GOOD_PASSWORD).get_json()

    whoami = client.get("/api/v1/auth/whoami", headers={"X-Actor": "mallory"})
    assert whoami.status_code == 200
    data = whoami.get_json()
    assert data["principal"] == "alice"
    assert data["role"] == "admin"
    assert data["kind"] == "user"
    assert data["mode"] == "token"

    logged_out = client.post(
        "/api/v1/auth/logout",
        headers={"X-Actor": "mallory", "X-CSRF-Token": minted["csrf_token"]},
    )
    assert logged_out.status_code == 200
    with app.app_context():
        liars = AuthEvent.query.filter(AuthEvent.actor == "mallory").count()
    assert liars == 0


def test_unbound_console_session_is_refused_the_admin_surface(client):
    create_user(client)
    disable_mfa(client)
    login(client, "alice", GOOD_PASSWORD)

    whoami = client.get("/api/v1/auth/whoami")
    assert whoami.status_code == 403
    details = whoami.get_json()["details"]
    assert details["principal"] == "alice"
    assert details["role_required"] is True

    assert client.get("/api/v1/users").status_code == 403


def test_expired_session_is_refused(client, app):
    create_user(client)
    disable_mfa(client)
    minted = login(client, "alice", GOOD_PASSWORD).get_json()
    with app.app_context():
        row = db.session.get(ConsoleSession, minted["session_id"])
        row.idle_expires_at = row.idle_expires_at.replace(year=2020)
        db.session.commit()
    assert client.get("/api/v1/auth/sessions").status_code == 401
    assert client.get("/api/v1/auth/sessions").status_code == 401


def test_stepup_gates_sensitive_actions_for_human_sessions(client, app):
    create_user(client)
    disable_mfa(client)
    bind(client, "alice", "admin")
    minted = login(client, "alice", GOOD_PASSWORD).get_json()
    csrf = {"X-CSRF-Token": minted["csrf_token"]}

    fresh = client.post("/api/v1/auth/mfa/backup-codes", headers=csrf)
    assert fresh.status_code == 200, fresh.get_json()
    codes = fresh.get_json()["codes"]
    assert len(codes) == 10

    with app.app_context():
        row = ConsoleSession.query.order_by(ConsoleSession.id.desc()).first()
        row.mfa_at = datetime.now() - timedelta(minutes=10)
        db.session.commit()

    stale = client.post("/api/v1/auth/mfa/backup-codes", headers=csrf)
    assert stale.status_code == 403
    assert stale.get_json()["details"]["reason"] == "stepup_required"

    stepped = client.post(
        "/api/v1/auth/mfa/stepup", json={"backup_code": codes[0]}, headers=csrf
    )
    assert stepped.status_code == 200, stepped.get_json()
    assert stepped.get_json()["method"] == "backup-code"

    again = client.post("/api/v1/auth/mfa/backup-codes", headers=csrf)
    assert again.status_code == 200
    # the used backup code is gone: a second step-up with it fails
    replay = client.post(
        "/api/v1/auth/mfa/stepup", json={"backup_code": codes[0]}, headers=csrf
    )
    assert replay.status_code == 401


# ---------------------------------------------------------------------------
# lockout, rate limits, spray
# ---------------------------------------------------------------------------


def test_lockout_after_repeated_failures_then_admin_unlock(client, app):
    created = create_user(client, "alice")
    for _ in range(5):
        assert login(client, "alice", "wrong-password-x").status_code == 401

    locked = login(client, "alice", GOOD_PASSWORD)
    assert locked.status_code == 403
    details = locked.get_json()["details"]
    assert details["reason"] == "locked"
    assert details["locked_until"]
    assert action_count(app, "auth.lockout") == 1

    unlocked = client.post(f"/api/v1/users/{created['user']['id']}/unlock", headers=ADMIN)
    assert unlocked.status_code == 200
    accepted = login(client, "alice", GOOD_PASSWORD)
    assert accepted.status_code == 403  # password path open: fail-closed MFA
    assert accepted.get_json()["status"] == "enrolment_required"
    assert action_count(app, "auth.user.unlocked") == 1


def test_per_account_rate_limit(client, app):
    codes = [
        login(client, "ghost", "some-guess-here-1", environ_base={"REMOTE_ADDR": f"10.1.0.{i}"}).status_code
        for i in range(1, 16)
    ]
    assert codes == [401] * 15
    limited = login(
        client, "ghost", "some-guess-here-2", environ_base={"REMOTE_ADDR": "10.1.0.99"}
    )
    assert limited.status_code == 403
    assert limited.get_json()["details"]["retry_after_seconds"] == 300
    assert action_count(app, "auth.rate-limited") == 1


def test_credential_spray_from_one_address_is_blocked(client, app):
    last = None
    for i in range(1, 11):
        last = login(client, f"spray-target-{i}", "no-such-password-1")
    assert last.status_code == 403
    assert last.get_json()["details"]["blocked_minutes"] == 15
    assert action_count(app, "auth.spray-alert") == 1

    blocked = login(client, "alice", GOOD_PASSWORD)
    assert blocked.status_code == 403
    assert "this address" in blocked.get_json()["error"]


# ---------------------------------------------------------------------------
# passwords and recovery
# ---------------------------------------------------------------------------


def test_password_change_revokes_other_sessions(client, app):
    create_user(client)
    disable_mfa(client)
    minted = login(client, "alice", GOOD_PASSWORD).get_json()
    csrf = {"X-CSRF-Token": minted["csrf_token"]}
    second_client = app.test_client()
    login(second_client, "alice", GOOD_PASSWORD)

    assert (
        client.post(
            "/api/v1/auth/password",
            json={"old_password": "wrong-current-123", "new_password": NEW_PASSWORD},
            headers=csrf,
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/password",
            json={"old_password": GOOD_PASSWORD, "new_password": "tiny"},
            headers=csrf,
        ).status_code
        == 400
    )
    same = client.post(
        "/api/v1/auth/password",
        json={"old_password": GOOD_PASSWORD, "new_password": GOOD_PASSWORD},
        headers=csrf,
    )
    assert same.status_code == 400
    assert "differ" in same.get_json()["error"]

    changed = client.post(
        "/api/v1/auth/password",
        json={"old_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf,
    )
    assert changed.status_code == 200
    assert changed.get_json()["sessions_revoked"] == 1
    assert second_client.get("/api/v1/auth/sessions").status_code == 401
    assert client.get("/api/v1/auth/sessions").status_code == 200

    probe = app.test_client()
    assert login(probe, "alice", GOOD_PASSWORD).status_code == 401
    assert login(probe, "alice", NEW_PASSWORD).status_code == 200


def _enable_smtp(client):
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


def test_recovery_reset_with_a_real_emailed_code(client, app, monkeypatch):
    sent = []

    monkeypatch.setattr(
        otp_module, "_send_via_smtp", lambda to, subject, body: sent.append((to, subject, body))
    )
    _enable_smtp(client)
    created = create_user(client, "alice", email="alice@example.test")
    disable_mfa(client)
    login(client, "alice", GOOD_PASSWORD)

    # recovery is a signed-out flow: a separate client, no cookie
    rec = app.test_client()
    started = rec.post("/api/v1/auth/recovery/start", json={"username": "alice"})
    assert started.status_code == 202
    challenge_id = started.get_json()["challenge_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", challenge_id)
    assert len(sent) == 1 and sent[0][0] == "alice@example.test"
    code = re.search(r"\b(\d{8})\b", sent[0][2]).group(1)

    wrong = rec.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": "00000000" if code != "00000000" else "11111111",
            "new_password": NEW_PASSWORD,
        },
    )
    assert wrong.status_code == 401

    reset = rec.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": code,
            "new_password": NEW_PASSWORD,
        },
    )
    assert reset.status_code == 200, reset.get_json()
    assert reset.get_json()["sessions_revoked"] == 1

    replay = rec.post(
        "/api/v1/auth/recovery/reset",
        json={
            "username": "alice",
            "challenge_id": challenge_id,
            "code": code,
            "new_password": "another-passphrase-77",
        },
    )
    assert replay.status_code == 401
    probe = app.test_client()
    assert login(probe, "alice", GOOD_PASSWORD).status_code == 401
    assert login(probe, "alice", NEW_PASSWORD).status_code == 200
    assert created["user"]["username"] == "alice"


def test_recovery_answers_are_identical_for_known_and_unknown(client):
    unknown_first = client.post(
        "/api/v1/auth/recovery/start", json={"username": "nobody-at-all"}
    )
    unknown_again = client.post(
        "/api/v1/auth/recovery/start", json={"username": "nobody-at-all"}
    )
    create_user(client, "alice")
    known_first = client.post("/api/v1/auth/recovery/start", json={"username": "alice"})
    known_again = client.post("/api/v1/auth/recovery/start", json={"username": "alice"})

    for response in (unknown_first, unknown_again, known_first, known_again):
        assert response.status_code == 202
        assert response.get_json()["status"] == "sent"
        assert re.fullmatch(r"[0-9a-f]{32}", response.get_json()["challenge_id"])
    # the cooldown re-supplies the live challenge for both shapes alike
    assert (
        unknown_first.get_json()["challenge_id"]
        == unknown_again.get_json()["challenge_id"]
    )
    assert (
        known_first.get_json()["challenge_id"] == known_again.get_json()["challenge_id"]
    )
    assert set(known_first.get_json()) == set(unknown_first.get_json())


def test_inactive_account_otp_answers_uniformly_and_never_delivers(client, app):
    created = create_user(client, "alice", email="alice@example.test")
    client.patch(
        f"/api/v1/users/{created['user']['id']}", json={"active": False}, headers=ADMIN
    )
    first = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    again = client.post("/api/v1/auth/otp/start", json={"username": "alice"})
    assert first.status_code == 202 and again.status_code == 202
    challenge_id = first.get_json()["challenge_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", challenge_id)
    assert again.get_json()["challenge_id"] == challenge_id
    assert action_count(app, "otp-suppressed") >= 1


# ---------------------------------------------------------------------------
# users admin surface
# ---------------------------------------------------------------------------


def test_users_admin_crud_and_role_gates(client):
    create_user(client)
    assert client.get("/api/v1/users").status_code == 401

    listed = client.get("/api/v1/users", headers=ADMIN).get_json()["users"]
    names = {row["username"] for row in listed}
    assert {"alice", "emergency-admin"} <= names

    binding = bind(client, "vera", "auditor", kind="local")
    auditor = {"Authorization": f"Bearer {binding['token']}"}
    assert client.get("/api/v1/users", headers=auditor).status_code == 200
    refused = client.post(
        "/api/v1/users", json={"username": "nope-user", "password": GOOD_PASSWORD}, headers=auditor
    )
    assert refused.status_code == 403


def test_deactivating_a_user_revokes_sessions_and_blocks_login(client, app):
    created = create_user(client)
    disable_mfa(client)
    login(client, "alice", GOOD_PASSWORD)

    patched = client.patch(
        f"/api/v1/users/{created['user']['id']}", json={"active": False}, headers=ADMIN
    )
    assert patched.status_code == 200
    assert patched.get_json()["user"]["is_active"] is False

    assert client.get("/api/v1/auth/sessions").status_code == 401
    probe = app.test_client()
    blocked = login(probe, "alice", GOOD_PASSWORD)
    assert blocked.status_code == 401
    assert blocked.get_json() == {"error": "Invalid username or password"}


def test_admin_can_require_then_clear_the_password_change(client, app):
    created = create_user(client)
    user_id = created["user"]["id"]

    marked = client.patch(
        f"/api/v1/users/{user_id}", json={"must_change_password": True}, headers=ADMIN
    )
    assert marked.status_code == 200
    assert marked.get_json()["message"] == "User updated"
    assert marked.get_json()["user"]["must_change_password"] is True

    # the mark is live: the next sign-in demands the change (contract 403)
    disable_mfa(client)
    blocked = login(client, "alice", GOOD_PASSWORD)
    assert blocked.status_code == 403
    assert blocked.get_json()["details"]["reason"] == "password-change-required"

    # the diff lands on the existing user trail (ADR-0017 batch 11.10)
    with app.app_context():
        event = (
            AuthEvent.query.filter(
                AuthEvent.action == "auth.user.updated", AuthEvent.subject == "alice"
            )
            .order_by(AuthEvent.id.desc())
            .first()
        )
        assert event is not None
        assert event.detail["must_change_password"] is True

    cleared = client.patch(
        f"/api/v1/users/{user_id}", json={"must_change_password": False}, headers=ADMIN
    )
    assert cleared.status_code == 200
    assert cleared.get_json()["user"]["must_change_password"] is False

    # cleared: the untouched password signs in with no forced change
    resumed = login(client, "alice", GOOD_PASSWORD)
    assert resumed.status_code == 200, resumed.get_json()
    assert resumed.get_json()["session_id"]


def test_scim_user_is_refused_the_force_change_flag_only(client, app):
    created = create_user(client)
    user_id = created["user"]["id"]
    with app.app_context():
        user = db.session.get(User, user_id)
        user.source = "scim"
        db.session.commit()

    refused = client.patch(
        f"/api/v1/users/{user_id}", json={"must_change_password": True}, headers=ADMIN
    )
    assert refused.status_code == 403
    assert refused.get_json()["error"] == (
        "This user is managed by the identity provider (SCIM) - "
        "reset the password there"
    )

    # the refusal is scoped to the flag: contact edits still work
    editable = client.patch(
        f"/api/v1/users/{user_id}",
        json={"display_name": "Directory Person"},
        headers=ADMIN,
    )
    assert editable.status_code == 200
    assert editable.get_json()["user"]["display_name"] == "Directory Person"


def test_emergency_admin_is_refused_the_force_change_flag(client):
    listed = client.get("/api/v1/users", headers=ADMIN).get_json()["users"]
    emergency_id = next(
        row["id"] for row in listed if row["username"] == "emergency-admin"
    )

    refused = client.patch(
        f"/api/v1/users/{emergency_id}",
        json={"must_change_password": True},
        headers=ADMIN,
    )
    assert refused.status_code == 403
    assert refused.get_json()["error"] == (
        "The emergency admin's password is sealed - rotate it, never set it"
    )

    # unknown user still 404s unchanged
    missing = client.patch(
        "/api/v1/users/999999", json={"must_change_password": True}, headers=ADMIN
    )
    assert missing.status_code == 404


def test_admin_password_reset_forces_change_and_kills_sessions(client, app):
    created = create_user(client)
    disable_mfa(client)
    login(client, "alice", GOOD_PASSWORD)

    # no body at all: the contract marks it optional, the password generates
    reset = client.post(
        f"/api/v1/users/{created['user']['id']}/password-reset", headers=ADMIN
    )
    assert reset.status_code == 200
    body = reset.get_json()
    generated = body["generated_password"]
    assert len(generated) >= 14
    assert body["user"]["must_change_password"] is True

    assert client.get("/api/v1/auth/sessions").status_code == 401
    probe = app.test_client()
    assert login(probe, "alice", GOOD_PASSWORD).status_code == 401
    forced = login(probe, "alice", generated)
    assert forced.status_code == 403
    assert forced.get_json()["details"]["reason"] == "password-change-required"


# ---------------------------------------------------------------------------
# emergency admin
# ---------------------------------------------------------------------------


def _request_grant(client, requester="carl", reason="dc fire drill"):
    response = client.post(
        "/api/v1/auth/emergency/open",
        json={"reason": reason},
        headers={**ADMIN, "X-Actor": requester},
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["grant"]


def _approve_grant(client, grant_id, approver, decision="approve"):
    return client.post(
        f"/api/v1/auth/emergency/grants/{grant_id}/approve",
        json={"decision": decision},
        headers={**ADMIN, "X-Actor": approver},
    )


def test_emergency_grant_dual_approval_and_single_use_login(client, app):
    grant = _request_grant(client)
    assert grant["status"] == "pending"
    assert grant["requested_by"] == "carl"

    self_approve = _approve_grant(client, grant["id"], "carl")
    assert self_approve.status_code == 403
    assert "may not approve" in self_approve.get_json()["error"]

    first = _approve_grant(client, grant["id"], "alice")
    assert first.status_code == 200
    assert first.get_json()["grant"]["status"] == "pending"
    duplicate = _approve_grant(client, grant["id"], "alice")
    assert duplicate.get_json()["grant"]["status"] == "pending"

    second = _approve_grant(client, grant["id"], "bob")
    assert second.get_json()["grant"]["status"] == "open"
    assert action_count(app, "auth.emergency.opened") == 1

    with app.app_context():
        user = identity.get_user("emergency-admin")
        plaintext = identity._unseal_emergency_password(
            json.loads(user.password_hash[len("sealed$") :])
        )

    logged_in = client.post("/api/v1/auth/emergency/login", json={"password": plaintext})
    assert logged_in.status_code == 200, logged_in.get_json()
    session = logged_in.get_json()
    assert session["is_emergency"] is True
    assert session["user"]["username"] == "emergency-admin"
    assert action_count(app, "auth.emergency.used") == 1

    # the used credential never works twice: the grant is spent and the
    # seal has rotated (fresh client - the first login holds the cookie)
    probe = app.test_client()
    again = probe.post("/api/v1/auth/emergency/login", json={"password": plaintext})
    assert again.status_code == 403
    assert again.get_json()["details"]["reason"] == "no-open-grant"
    with app.app_context():
        db.session.expire_all()
        rotated = identity.get_user("emergency-admin")
        fresh = identity._unseal_emergency_password(
            json.loads(rotated.password_hash[len("sealed$") :])
        )
    assert fresh != plaintext


def test_emergency_login_refused_without_a_grant(client, app):
    with app.app_context():
        user = identity.get_user("emergency-admin")
        plaintext = identity._unseal_emergency_password(
            json.loads(user.password_hash[len("sealed$") :])
        )
    refused = client.post("/api/v1/auth/emergency/login", json={"password": plaintext})
    assert refused.status_code == 403
    assert refused.get_json()["details"]["reason"] == "no-open-grant"
    assert action_count(app, "auth.emergency.refused") == 1

    grant = _request_grant(client)
    _approve_grant(client, grant["id"], "alice")
    _approve_grant(client, grant["id"], "bob")
    wrong = client.post("/api/v1/auth/emergency/login", json={"password": "not-the-seal-1"})
    assert wrong.status_code == 401
    assert wrong.get_json()["error"] == "Emergency password incorrect"
    assert action_count(app, "auth.emergency.refused") == 2


def test_emergency_grant_denial_closes_it(client):
    grant = _request_grant(client)
    denied = _approve_grant(client, grant["id"], "alice", decision="deny")
    assert denied.status_code == 200
    assert denied.get_json()["grant"]["status"] == "denied"
    late = _approve_grant(client, grant["id"], "bob")
    assert late.status_code == 409


def test_short_emergency_reason_is_refused(client):
    response = client.post(
        "/api/v1/auth/emergency/open",
        json={"reason": "fire"},
        headers={**ADMIN, "X-Actor": "carl"},
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# the auth report
# ---------------------------------------------------------------------------


def test_auth_report_counts_the_auth_trail(client):
    create_user(client)
    disable_mfa(client)
    login(client, "alice", "wrong-password-x")
    login(client, "alice", GOOD_PASSWORD)

    report = client.get("/api/v1/auth/report", headers=ADMIN)
    assert report.status_code == 200
    body = report.get_json()
    assert body["by_action"]["auth.login.failed"] >= 1
    assert body["by_action"]["auth.login.succeeded"] >= 1
    assert body["total_events"] >= 2
    assert body["events"]

    binding = bind(client, "vera", "auditor", kind="local")
    auditor = {"Authorization": f"Bearer {binding['token']}"}
    assert client.get("/api/v1/auth/report", headers=auditor).status_code == 200
    assert client.get("/api/v1/auth/deliveries", headers=ADMIN).status_code == 200
