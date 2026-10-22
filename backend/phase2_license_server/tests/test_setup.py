"""First-run setup (ADR-0018): the bootstrap officers, the officer-gated
profile write, the logo bound and the two-password completion.

Everything runs against the real code paths: the bootstrap hook fires
during `create_app` exactly like any other install, the officers sign in
through the shipped forced-change path, and every refusal is the bytes
the route really answers with. The generated officer passwords exist only
in the boot log, so a test pins its own through the product's own hashing
- never by reading the log back.
"""
from __future__ import annotations

import base64
import logging
import sys
from datetime import datetime
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri as _db_uri  # noqa: E402
from extensions import db  # noqa: E402
from models import AuthEvent, RoleBinding, User  # noqa: E402
import identity  # noqa: E402
import service  # noqa: E402
import setup as first_run  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
# the shipped accounts' passwords live only in the boot log; these are the
# test-pinned replacements (NIST-14, no username inside)
SHIPPED_PW = "quartz-harbor-vessel"
OFFICER_PW = "marble-canyon-lantern9"
MAKER_PW = "foundry-copper-passphrase"
CHECKER_PW = "granite-orchard-passphrase"


def _config(tmp_path: Path, db_name: str = "setup.db") -> Config:
    return Config(
        database_uri=_db_uri(tmp_path, db_name),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-setup-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        node_name="pam-node-setup",
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


def _set_password(app, username: str, password: str) -> None:
    """Rehash an officer's password through the product's own function -
    the generated one exists only in the boot log, never in a test."""
    with app.app_context():
        user = identity.get_user(username)
        assert user is not None, f"{username} missing - bootstrap did not run"
        user.password_hash = identity.hash_password(password)
        db.session.commit()


def officer_session(app, username: str):
    """Sign in as a bootstrap officer along the shipped first-run path,
    on a fresh client (a cookie from an earlier sign-in would turn the
    login itself into a CSRF-protected mutation): the account ships with
    must_change_password, so attempt one refuses, the self-service change
    sets the real password, attempt two mints the session. Returns the
    client and the CSRF headers for cookie-carrying mutations."""
    agent = app.test_client()
    _set_password(app, username, SHIPPED_PW)
    refused = login(agent, username, SHIPPED_PW)
    assert refused.status_code == 403, refused.get_json()
    assert refused.get_json()["details"]["reason"] == "password-change-required"
    changed = agent.post(
        "/api/v1/auth/password",
        json={
            "username": username,
            "old_password": SHIPPED_PW,
            "new_password": OFFICER_PW,
        },
    )
    assert changed.status_code == 200, changed.get_json()
    minted = login(agent, username, OFFICER_PW)
    assert minted.status_code == 200, minted.get_json()
    return agent, {"X-CSRF-Token": minted.get_json()["csrf_token"]}


# ---------------------------------------------------------------------------
# the first-boot hook
# ---------------------------------------------------------------------------


def test_boot_creates_the_two_officers_admin_bound_and_audited(client, app):
    listed = client.get("/api/v1/users", headers=ADMIN).get_json()["users"]
    names = [row["username"] for row in listed]
    assert {"vypam-maker", "vypam-checker", "emergency-admin"} <= set(names)

    with app.app_context():
        for username in ("vypam-maker", "vypam-checker"):
            user = identity.get_user(username)
            assert user.is_active and user.source == "local"
            assert user.must_change_password is True
            # scrypt at rest, never a usable copy of the generated value
            assert user.password_hash.startswith("scrypt$")
            binding = RoleBinding.query.filter(
                RoleBinding.principal == username,
                RoleBinding.revoked_at.is_(None),
            ).one()
            assert binding.role == "admin" and binding.kind == "user"
        audited = AuthEvent.query.filter(
            AuthEvent.action == "auth.bootstrap.created"
        ).count()
        assert audited == 1


def test_bootstrap_is_idempotent_and_never_falls_back(client, app):
    with app.app_context():
        # officers exist now -> the hook is a no-op on every later boot
        assert first_run.ensure_bootstrap_officers() is None

        # any other console identity means somebody already owns this
        # instance: remove the pair, seed an unrelated user, and the hook
        # must still stay out (no silent re-bootstrap behind an operator)
        RoleBinding.query.filter(
            RoleBinding.principal.in_(first_run.BOOTSTRAP_OFFICERS)
        ).delete(synchronize_session=False)
        User.query.filter(
            User.username.in_(first_run.BOOTSTRAP_OFFICERS)
        ).delete(synchronize_session=False)
        identity.create_user(
            username="alice", actor="test", password=GOOD_PASSWORD
        )
        assert first_run.ensure_bootstrap_officers() is None
        assert identity.get_user("vypam-maker") is None

        # a completed instance never bootstraps either
        row = first_run.InstanceProfile(id=1, company_name="Acme")
        row.setup_completed_at = datetime.now()
        db.session.add(row)
        db.session.commit()
        User.query.filter(User.username == "alice").delete(
            synchronize_session=False
        )
        assert first_run.ensure_bootstrap_officers() is None
        assert identity.get_user("vypam-maker") is None


def test_boot_discloses_the_generated_passwords_exactly_once(tmp_path, caplog):
    config = _config(tmp_path, db_name="disclosure.db")  # virgin database
    with caplog.at_level(logging.WARNING):
        create_app(config)
    text = caplog.text
    assert "vypam-maker" in text and "vypam-checker" in text
    assert "Shown once - store it now." in text

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        create_app(config)  # same database, already populated
    assert "Shown once - store it now." not in caplog.text


# ---------------------------------------------------------------------------
# the public state
# ---------------------------------------------------------------------------


def test_state_is_public_and_never_carries_a_secret(client):
    response = client.get("/api/v1/setup/state")  # no headers at all
    assert response.status_code == 200
    state = response.get_json()
    assert set(state) == {
        "configured",
        "company_name",
        "logo_data_uri",
        "contact_email",
        "smtp_configured",
        "bootstrap",
    }
    assert state["configured"] is False
    assert state["bootstrap"] == {
        "maker": "vypam-maker",
        "checker": "vypam-checker",
    }
    assert state["smtp_configured"] is False
    assert "password" not in str(state).lower()


# ---------------------------------------------------------------------------
# the profile write, both phases
# ---------------------------------------------------------------------------


def test_profile_write_is_officer_gated_while_setup_runs(client, app):
    disable_mfa(client)
    # a non-officer (even a freshly minted admin) is refused verbatim
    created = client.post(
        "/api/v1/users",
        json={"username": "alice", "password": GOOD_PASSWORD},
        headers=ADMIN,
    )
    assert created.status_code == 201, created.get_json()
    bound = client.post(
        "/api/v1/role-bindings",
        json={"principal": "alice", "role": "admin", "kind": "user"},
        headers=ADMIN,
    )
    assert bound.status_code == 201, bound.get_json()
    alice = login(client, "alice", GOOD_PASSWORD)
    assert alice.status_code == 200, alice.get_json()
    alice_csrf = {"X-CSRF-Token": alice.get_json()["csrf_token"]}

    refused = client.put(
        "/api/v1/setup/profile",
        json={"company_name": "Not Yours Inc"},
        headers=alice_csrf,
    )
    assert refused.status_code == 403, refused.get_json()
    assert refused.get_json() == {
        "error": "Setup is still running - only the VY-PAM bootstrap "
        "officers may configure this instance",
        "details": {
            "phase": "first-run",
            "officers": ["vypam-maker", "vypam-checker"],
        },
    }

    # the officer's own session is the key
    officer, officer_csrf = officer_session(app, "vypam-maker")
    stored = officer.put(
        "/api/v1/setup/profile",
        json={
            "company_name": "Acme Industrial",
            "contact_email": "ops@acme.example",
        },
        headers=officer_csrf,
    )
    assert stored.status_code == 200, stored.get_json()
    state = stored.get_json()
    assert state["company_name"] == "Acme Industrial"
    assert state["contact_email"] == "ops@acme.example"
    assert state["configured"] is False

    with app.app_context():
        audited = AuthEvent.query.filter(
            AuthEvent.action == "setup.profile.updated"
        ).all()
        assert len(audited) == 1
        assert audited[0].actor == "vypam-maker"
        assert audited[0].detail["fields"] == ["company_name", "contact_email"]


def test_profile_validates_the_logo_and_the_company_name(client, app):
    disable_mfa(client)
    officer, officer_csrf = officer_session(app, "vypam-checker")

    # > 64 KB decoded is refused with the bound spelled out
    oversized = base64.b64encode(b"\x89PNG" + b"x" * (70 * 1024)).decode()
    too_big = officer.put(
        "/api/v1/setup/profile",
        json={
            "company_name": "Acme",
            "logo_data_uri": f"data:image/png;base64,{oversized}",
        },
        headers=officer_csrf,
    )
    assert too_big.status_code == 400, too_big.get_json()
    assert too_big.get_json()["details"]["max_bytes"] == 64 * 1024

    # undecodable base64 and a foreign scheme are refused honestly
    broken = officer.put(
        "/api/v1/setup/profile",
        json={
            "company_name": "Acme",
            "logo_data_uri": "data:image/png;base64,@@not-base64@@",
        },
        headers=officer_csrf,
    )
    assert broken.status_code == 400, broken.get_json()

    svg = officer.put(
        "/api/v1/setup/profile",
        json={"company_name": "Acme", "logo_data_uri": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="},
        headers=officer_csrf,
    )
    assert svg.status_code == 400, svg.get_json()

    # a nameless instance is not storable
    blank = officer.put(
        "/api/v1/setup/profile", json={"company_name": "  "}, headers=officer_csrf
    )
    assert blank.status_code == 400, blank.get_json()
    assert blank.get_json()["details"]["field"] == "company_name"

    # a bounded, valid PNG URI stores
    tiny = base64.b64encode(b"\x89PNG\r\n\x1a\nbody").decode()
    stored = officer.put(
        "/api/v1/setup/profile",
        json={
            "company_name": "Acme",
            "logo_data_uri": f"data:image/png;base64,{tiny}",
        },
        headers=officer_csrf,
    )
    assert stored.status_code == 200, stored.get_json()
    assert stored.get_json()["logo_data_uri"] == f"data:image/png;base64,{tiny}"

    # a write that changes nothing records nothing (the settings no-op rule)
    before = stored.get_json()
    noop = officer.put(
        "/api/v1/setup/profile", json={"company_name": "Acme"}, headers=officer_csrf
    )
    assert noop.status_code == 200, noop.get_json()
    assert noop.get_json() == before
    with app.app_context():
        audited = AuthEvent.query.filter(
            AuthEvent.action == "setup.profile.updated"
        ).count()
        assert audited == 1


# ---------------------------------------------------------------------------
# the two-password completion
# ---------------------------------------------------------------------------


def test_complete_needs_both_passwords_and_stamps_once(client, app):
    _set_password(app, "vypam-maker", MAKER_PW)
    _set_password(app, "vypam-checker", CHECKER_PW)

    # maker wrong, checker right - and the mirror: same bytes both times
    wrong_maker = client.post(
        "/api/v1/setup/complete",
        json={"maker_password": "not-the-makers-phrase", "checker_password": CHECKER_PW},
    )
    wrong_checker = client.post(
        "/api/v1/setup/complete",
        json={"maker_password": MAKER_PW, "checker_password": "not-the-checkers-phrase"},
    )
    for response in (wrong_maker, wrong_checker):
        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid username or password"}
    # neither attempt stamped anything
    assert client.get("/api/v1/setup/state").get_json()["configured"] is False

    done = client.post(
        "/api/v1/setup/complete",
        json={"maker_password": MAKER_PW, "checker_password": CHECKER_PW},
    )
    assert done.status_code == 200, done.get_json()
    assert done.get_json() == {
        "message": "Setup completed - sign in with your company admins"
    }

    state = client.get("/api/v1/setup/state").get_json()
    assert state["configured"] is True
    with app.app_context():
        completed = AuthEvent.query.filter(
            AuthEvent.action == "setup.completed"
        ).one()
        assert completed.detail["maker"] == "vypam-maker"
        assert completed.detail["checker"] == "vypam-checker"

    # the stamp is one-way: both passwords again answer 409 forever
    repeat = client.post(
        "/api/v1/setup/complete",
        json={"maker_password": MAKER_PW, "checker_password": CHECKER_PW},
    )
    assert repeat.status_code == 409
    assert repeat.get_json() == {"error": "Setup already completed"}


def test_complete_is_rate_limited_after_the_ip_budget(client, app, monkeypatch):
    """/setup/complete is public by design (the two passwords ARE the
    credential), so it carries the same per-IP budget the login path
    carries - without it a virgin, reachable install is an unthrottled
    two-hash-per-request brute-force surface. After the budget the route
    answers the login path's 403 + retry_after_seconds and records the
    auth.rate-limited event, exactly like identity.login does."""
    _set_password(app, "vypam-maker", MAKER_PW)
    _set_password(app, "vypam-checker", CHECKER_PW)
    budget = 3
    monkeypatch.setattr(first_run, "RATE_LIMIT_PER_IP_SETUP", budget, raising=False)

    wrong = {"maker_password": "not-the-makers-phrase", "checker_password": CHECKER_PW}
    for _ in range(budget):
        assert (
            client.post("/api/v1/setup/complete", json=wrong).status_code == 401
        )

    refused = client.post("/api/v1/setup/complete", json=wrong)
    assert refused.status_code == 403, refused.get_json()
    assert refused.get_json()["error"] == "Too many setup attempts from this address"
    assert refused.get_json()["details"]["retry_after_seconds"] > 0

    with app.app_context():
        event = AuthEvent.query.filter(
            AuthEvent.action == "auth.rate-limited"
        ).one()
        assert event.detail["scope"] == "setup-ip"

    # the budget exhaustion never stamped anything
    assert client.get("/api/v1/setup/state").get_json()["configured"] is False


def test_boot_survives_a_transient_officer_seeding_failure(tmp_path, monkeypatch):
    """ensure_bootstrap_officers() is the one boot seed with no guard: a
    transient DB error (or a duplicate key when two gunicorn workers race a
    virgin database) must not abort create_app, mirroring the fail-open
    guard the emergency-admin seed above it already carries. The officers
    seed on the next boot, once the condition clears."""
    config = _config(tmp_path, db_name="boot-guard.db")

    def _boom():
        raise RuntimeError("transient while seeding officers")

    monkeypatch.setattr(first_run, "ensure_bootstrap_officers", _boom)
    application = create_app(config)
    application.config["TESTING"] = True
    assert application.name


def test_after_setup_the_profile_is_a_normal_admin_write(client, app):
    disable_mfa(client)
    _set_password(app, "vypam-maker", MAKER_PW)
    _set_password(app, "vypam-checker", CHECKER_PW)
    assert (
        client.post(
            "/api/v1/setup/complete",
            json={"maker_password": MAKER_PW, "checker_password": CHECKER_PW},
        ).status_code
        == 200
    )

    # a plain company admin (console session) may rebrand
    created = client.post(
        "/api/v1/users",
        json={"username": "alice", "password": GOOD_PASSWORD},
        headers=ADMIN,
    )
    assert created.status_code == 201, created.get_json()
    bound = client.post(
        "/api/v1/role-bindings",
        json={"principal": "alice", "role": "admin", "kind": "user"},
        headers=ADMIN,
    )
    assert bound.status_code == 201, bound.get_json()
    alice = login(client, "alice", GOOD_PASSWORD)
    assert alice.status_code == 200, alice.get_json()
    alice_csrf = {"X-CSRF-Token": alice.get_json()["csrf_token"]}
    rebranded = client.put(
        "/api/v1/setup/profile",
        json={"company_name": "Renamed Industries"},
        headers=alice_csrf,
    )
    assert rebranded.status_code == 200, rebranded.get_json()
    assert rebranded.get_json()["company_name"] == "Renamed Industries"
    with app.app_context():
        last = (
            AuthEvent.query.filter(AuthEvent.action == "setup.profile.updated")
            .order_by(AuthEvent.id.desc())
            .first()
        )
        assert last.actor == "alice"

    # the machine credential (admin token, no session) may rebrand too
    machine = client.put(
        "/api/v1/setup/profile",
        json={"company_name": "Token Renamed Corp"},
        headers=ADMIN,
    )
    assert machine.status_code == 200, machine.get_json()
    assert machine.get_json()["company_name"] == "Token Renamed Corp"

    # a non-admin role never may (the profile is an admin operation)
    bob = client.post(
        "/api/v1/users",
        json={"username": "bob", "password": GOOD_PASSWORD},
        headers=ADMIN,
    )
    assert bob.status_code == 201, bob.get_json()
    assert (
        client.post(
            "/api/v1/role-bindings",
            json={"principal": "bob", "role": "operator", "kind": "user"},
            headers=ADMIN,
        ).status_code
        == 201
    )
    # alice still holds this client's cookie; bob gets his own client so
    # his login is not a CSRF-protected mutation of her session
    bob_agent = app.test_client()
    bob_login = login(bob_agent, "bob", GOOD_PASSWORD)
    assert bob_login.status_code == 200, bob_login.get_json()
    bob_csrf = {"X-CSRF-Token": bob_login.get_json()["csrf_token"]}
    refused = bob_agent.put(
        "/api/v1/setup/profile",
        json={"company_name": "Operator Sneaks In"},
        headers=bob_csrf,
    )
    assert refused.status_code == 403, refused.get_json()
    assert "may not call PUT /api/v1/setup/profile" in refused.get_json()["error"]
