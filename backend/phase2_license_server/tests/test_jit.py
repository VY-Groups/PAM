"""Tests for JIT/JEA access (architecture module 6).

The whole flow is exercised for real: a request is filed against a real
vault credential, risk is evaluated over measured inputs (target tier,
duration, the local clock, the requester's own 24h history, ticket shape,
credential health) with the factor points summed into the score, approvals
are recorded per risk band (self-approval forbidden), a grant checks the
credential out until expires_at, and expiry/close releases the checkout and
rotates the credential - all read back through the public API.

A fixed clock keeps off-hours/expiry assertions deterministic; the vault
column defaults stay on the real clock (bound at class definition), which
is harmless because every time comparison the flow performs goes through
the patched service/models `datetime.now`.

Run with:  python -m pytest backend/phase2_license_server/tests/test_jit.py -q
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from models import (  # noqa: E402
    JitEvent,
    JitRequest,
    VaultEvent,
    VaultItem,
    db,
)
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

GOOD_TICKET = "INC-1234"
BAD_TICKET = "urgent fix needed"


class _Clock(datetime):
    """Wednesday 2026-10-07 noon: inside office hours, same day as real now
    so the real-clock column defaults (created_at) still sit in the 24h
    window the repeat-requests factor measures."""

    FIXED = datetime(2026, 10, 7, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


class _NightClock(_Clock):
    FIXED = datetime(2026, 10, 7, 22, 0, 0)  # 22:00 -> off-hours


def make_config(tmp_path: Path, **overrides) -> Config:
    kwargs = dict(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
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
def clock(monkeypatch):
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)


def onboard(client, name, **overrides):
    payload = {
        "name": name,
        "secret_type": "database",
        "target": "db.internal",
        "principal": "admin",
        "access_tier": "Tier-1",
        "auth_method": "Password",
        "rotation_interval_hours": 24,
    }
    payload.update(overrides)
    response = client.post("/api/v1/vault/items", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def insert_item(app, name, *, status="failed", access_tier="Tier-0"):
    with app.app_context():
        item = VaultItem(
            name=name,
            secret_type="database",
            description="test fixture",
            target="db.test.internal",
            target_detail="",
            principal="admin",
            access_tier=access_tier,
            auth_method="Password",
            rotation_interval_hours=24,
            last_rotated_at=datetime.now() - timedelta(hours=48),
            status=status,
        )
        db.session.add(item)
        db.session.commit()
        return item.id


def create_request(client, item_id, **overrides):
    payload = {
        "item_id": item_id,
        "reason": "Emergency patch deployment window",
        "ticket": GOOD_TICKET,
        "minutes": 15,
    }
    payload.update(overrides)
    response = client.post("/api/v1/jit/requests", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["request"]


def approve(client, request_id, role, actor="mgr"):
    return client.post(
        f"/api/v1/jit/requests/{request_id}/approve",
        json={"role": role},
        headers={**ACTOR, "X-Actor": actor},
    )


def get_item(client, item_id):
    response = client.get(f"/api/v1/vault/items/{item_id}")
    assert response.status_code == 200
    return response.get_json()["item"]


# --- validation --------------------------------------------------------------


def test_create_validates_context(client, clock):
    onboard(client, "jit-valid")
    for payload, field in (
        ({"reason": "x" * 10, "ticket": GOOD_TICKET}, "item_id"),
        ({"item_id": 1, "reason": "short", "ticket": GOOD_TICKET}, "reason"),
        ({"item_id": 1, "reason": "long enough reason", "ticket": ""}, "ticket"),
        (
            {"item_id": 1, "reason": "long enough reason",
             "ticket": GOOD_TICKET, "minutes": 0},
            "minutes",
        ),
        (
            {"item_id": 1, "reason": "long enough reason",
             "ticket": GOOD_TICKET, "minutes": 481},
            "minutes",
        ),
    ):
        response = client.post("/api/v1/jit/requests", json=payload, headers=ACTOR)
        assert response.status_code == 400, (payload, response.get_json())
        assert response.get_json()["details"]["field"] == field

    response = client.post(
        "/api/v1/jit/requests",
        json={"item_id": 4242, "reason": "long enough reason",
              "ticket": GOOD_TICKET},
        headers=ACTOR,
    )
    assert response.status_code == 404


def test_create_requires_admin_token(client, clock):
    onboard(client, "jit-auth")
    response = client.post(
        "/api/v1/jit/requests",
        json={"item_id": 1, "reason": "long enough reason", "ticket": GOOD_TICKET},
    )
    assert response.status_code == 401
    response = client.post("/api/v1/jit/requests/1/approve", json={"role": "manager"})
    assert response.status_code == 401
    # reads stay public, like the rest of the console's inventory endpoints
    assert client.get("/api/v1/jit/requests").status_code == 200


# --- risk evaluation ---------------------------------------------------------


def test_low_risk_auto_approves_with_visible_factors(client, clock):
    item = onboard(client, "jit-low", access_tier="Tier-2")
    request = create_request(client, item["id"], minutes=15)
    assert request["risk"]["level"] == "low"
    assert request["risk"]["score"] == 0
    assert request["risk"]["factors"] == []
    assert request["status"] == "approved"
    assert request["approvals"]["manager"] is None

    detail = client.get(f"/api/v1/jit/requests/{request['id']}").get_json()
    actions = [event["action"] for event in detail["events"]]
    assert actions.count("requested") == 1
    auto = next(e for e in detail["events"] if e["action"] == "approved")
    assert auto["actor"] == "risk-policy"
    assert auto["detail"]["auto"] is True


def test_score_equals_the_sum_of_its_factors(client, clock):
    item = onboard(client, "jit-score", access_tier="Tier-0")
    request = create_request(client, item["id"], minutes=61, ticket=BAD_TICKET)
    factors = request["risk"]["factors"]
    assert factors, "Tier-0 + long window + odd ticket must produce factors"
    assert request["risk"]["score"] == sum(f["points"] for f in factors)
    names = {f["factor"] for f in factors}
    assert names == {"target_tier", "duration", "ticket_shape"}


def test_off_hours_changes_the_decision_same_request(client, monkeypatch):
    # day (12:00): Tier-1 + 15min + good ticket -> score 15 -> low -> auto
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)
    day_item = onboard(client, "jit-day", access_tier="Tier-1")
    day = create_request(client, day_item["id"], requester="dayshift")
    assert day["risk"]["score"] == 15
    assert day["status"] == "approved"

    # night (22:00): identical request from a different requester, only the
    # clock differs - and the clock alone pushes it into the manager band
    monkeypatch.setattr(service_module, "datetime", _NightClock)
    monkeypatch.setattr(models_module, "datetime", _NightClock)
    night_item = onboard(client, "jit-night", access_tier="Tier-1")
    night = create_request(client, night_item["id"], requester="nightowl")
    off = next(
        (f for f in night["risk"]["factors"] if f["factor"] == "off_hours"), None
    )
    assert off is not None and off["points"] == 20
    assert night["risk"]["score"] == 35  # 15 tier + 20 off-hours
    assert night["risk"]["level"] == "medium"
    assert night["status"] == "pending"


def test_medium_risk_needs_manager_approval(client, clock):
    item = onboard(client, "jit-medium")
    request = create_request(client, item["id"], minutes=61)  # 15 + 15 = 30
    assert request["risk"]["level"] == "medium"
    assert request["status"] == "pending"

    wrong = approve(client, request["id"], "security")
    assert wrong.status_code == 400  # medium band does not ask security

    done = approve(client, request["id"], "manager")
    assert done.status_code == 200
    body = done.get_json()["request"]
    assert body["status"] == "approved"
    assert body["approvals"]["manager"]["actor"] == "mgr"

    again = approve(client, request["id"], "manager")
    assert again.status_code == 400  # no longer pending


def test_high_risk_needs_manager_and_security(client, clock):
    item = onboard(client, "jit-high", access_tier="Tier-0")
    request = create_request(client, item["id"], minutes=61, ticket=BAD_TICKET)
    assert request["risk"]["score"] == 55  # 30 tier + 15 duration + 10 ticket
    assert request["risk"]["level"] == "high"
    assert request["status"] == "pending"

    first = approve(client, request["id"], "security", actor="sec")
    assert first.status_code == 200
    assert first.get_json()["request"]["status"] == "pending"

    duplicate = approve(client, request["id"], "security", actor="sec")
    assert duplicate.status_code == 400  # already recorded

    second = approve(client, request["id"], "manager", actor="mgr")
    assert second.status_code == 200
    assert second.get_json()["request"]["status"] == "approved"


def test_self_approval_forbidden(client, clock):
    item = onboard(client, "jit-self")
    request = create_request(client, item["id"], minutes=61, requester="bob")
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "manager"},
        headers={**ACTOR, "X-Actor": "bob"},
    )
    assert response.status_code == 403
    assert "own access" in response.get_json()["error"]


def test_critical_risk_is_blocked_then_only_deniable(client, app, clock):
    # three prior requests by the same requester -> repeat factor
    low_item = onboard(client, "jit-prior", access_tier="Tier-2")
    for _ in range(3):
        create_request(client, low_item["id"])

    failed_item = insert_item(app, "jit-critical-failed")
    request = create_request(client, failed_item, minutes=121, ticket=BAD_TICKET)
    names = {f["factor"] for f in request["risk"]["factors"]}
    assert names == {
        "target_tier", "duration", "repeat_requests", "ticket_shape",
        "credential_health",
    }
    assert request["risk"]["score"] == 85  # 30 + 20 + 15 + 10 + 10
    assert request["risk"]["level"] == "critical"
    assert request["status"] == "blocked"

    approve = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "manager"},
        headers=ACTOR,
    )
    assert approve.status_code == 400

    deny = client.post(
        f"/api/v1/jit/requests/{request['id']}/deny",
        json={"reason": "standing break-glass covers this"},
        headers=ACTOR,
    )
    assert deny.status_code == 200
    assert deny.get_json()["request"]["status"] == "denied"


# --- deny flow ---------------------------------------------------------------


def test_deny_moves_pending_to_denied_and_stays_there(client, clock):
    item = onboard(client, "jit-deny")
    request = create_request(client, item["id"], minutes=61)
    denied = client.post(
        f"/api/v1/jit/requests/{request['id']}/deny",
        json={"reason": "use the shared account"},
        headers=ACTOR,
    )
    assert denied.status_code == 200
    assert denied.get_json()["request"]["status"] == "denied"

    approve_res = approve(client, request["id"], "manager")
    assert approve_res.status_code == 400
    deny_again = client.post(
        f"/api/v1/jit/requests/{request['id']}/deny", json={}, headers=ACTOR
    )
    assert deny_again.status_code == 400


def test_requester_defaults_to_actor(client, clock):
    item = onboard(client, "jit-requester")
    payload = {
        "item_id": item["id"],
        "reason": "Emergency patch deployment window",
        "ticket": GOOD_TICKET,
    }
    response = client.post("/api/v1/jit/requests", json=payload, headers=ACTOR)
    assert response.status_code == 201
    assert response.get_json()["request"]["requester"] == "tester"


# --- grant / expiry / rotation ----------------------------------------------


def test_grant_checkout_close_rotates(client, clock):
    item = onboard(client, "jit-grant")
    request = create_request(client, item["id"], minutes=61)

    early = client.post(
        f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR
    )
    assert early.status_code == 400  # pending: not approved yet

    approve(client, request["id"], "manager")
    granted = client.post(
        f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR
    )
    assert granted.status_code == 200
    body = granted.get_json()["request"]
    assert body["status"] == "active"
    assert body["session_ref"] == f"jit-{request['id']}"
    assert body["minutes_left"] == 61
    assert body["granted_at"] is not None and body["expires_at"] is not None

    held = get_item(client, item["id"])
    assert held["status"] == "checked_out"
    assert held["checked_out_by"] == "tester"
    version_before = held["secret_version"]

    closed = client.post(
        f"/api/v1/jit/requests/{request['id']}/close", headers=ACTOR
    )
    assert closed.status_code == 200
    final = closed.get_json()["request"]
    assert final["status"] == "closed"
    assert final["closed_at"] is not None
    assert final["minutes_left"] is None

    released = get_item(client, item["id"])
    assert released["status"] == "available"
    assert released["checked_out_by"] is None
    assert released["secret_version"] == version_before + 1

    rotated = [
        e for e in client.get("/api/v1/vault/events?action=rotated").get_json()["events"]
        if e["item_id"] == item["id"]
        and e["detail"].get("session_ref") == f"jit-{request['id']}"
    ]
    assert rotated, "closing a grant must audit a session-end rotation"

    trail = client.get(f"/api/v1/jit/requests/{request['id']}").get_json()
    close_event = next(e for e in trail["events"] if e["action"] == "closed")
    assert close_event["detail"]["rotated"] is True
    assert close_event["detail"]["checkout_released"] is True
    assert close_event["detail"]["secret_version"] == version_before + 1

    again = client.post(f"/api/v1/jit/requests/{request['id']}/close", headers=ACTOR)
    assert again.status_code == 400


def test_expiry_releases_and_rotates_on_read(client, app, clock):
    item = onboard(client, "jit-expiry")
    request = create_request(client, item["id"], minutes=61)
    approve(client, request["id"], "manager")
    client.post(f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR)
    version_before = get_item(client, item["id"])["secret_version"]

    with app.app_context():
        row = db.session.get(JitRequest, request["id"])
        row.expires_at = _Clock.FIXED - timedelta(minutes=1)
        db.session.commit()

    listed = client.get("/api/v1/jit/requests").get_json()
    row = next(r for r in listed["items"] if r["id"] == request["id"])
    assert row["status"] == "expired"
    assert row["minutes_left"] is None

    released = get_item(client, item["id"])
    assert released["status"] == "available"
    assert released["checked_out_by"] is None
    assert released["secret_version"] == version_before + 1

    trail = client.get(f"/api/v1/jit/requests/{request['id']}").get_json()
    expiry = next(e for e in trail["events"] if e["action"] == "expired")
    assert expiry["actor"] == "system"
    assert expiry["detail"]["rotated"] is True


def test_consume_guards(client, clock):
    item = onboard(client, "jit-guards")
    request = create_request(client, item["id"], minutes=61)  # medium -> pending

    pending = client.post(f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR)
    assert pending.status_code == 400

    approve(client, request["id"], "manager")
    # someone else holds the credential first
    taken = client.post(
        f"/api/v1/vault/items/{item['id']}/checkout",
        json={"reason": "manual work"},
        headers={**ACTOR, "X-Actor": "other"},
    )
    assert taken.status_code == 200
    conflict = client.post(f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR)
    assert conflict.status_code == 400
    assert conflict.get_json()["details"]["field"] == "status"


# --- queue reads -------------------------------------------------------------


def test_stats_and_filters_report_real_counts(client, clock):
    low_item = onboard(client, "jit-stats-low", access_tier="Tier-2")
    create_request(client, low_item["id"])  # approved (low)
    pending_item = onboard(client, "jit-stats-pending")
    create_request(client, pending_item["id"], minutes=61)  # pending (medium)

    stats = client.get("/api/v1/jit/stats").get_json()
    assert stats["total"] == 2
    assert stats["by_status"]["approved"] == 1
    assert stats["by_status"]["pending"] == 1
    assert stats["by_risk"]["low"] == 1
    assert stats["by_risk"]["medium"] == 1
    assert sum(stats["by_status"].values()) == stats["total"]
    assert sum(stats["by_risk"].values()) == stats["total"]

    pending = client.get("/api/v1/jit/requests?status=pending").get_json()
    assert pending["total"] == 1
    assert all(r["status"] == "pending" for r in pending["items"])

    filtered = client.get("/api/v1/jit/requests?requester=nomatch").get_json()
    assert filtered["total"] == 0

    bad = client.get("/api/v1/jit/requests?status=nope")
    assert bad.status_code == 400
    assert bad.get_json()["details"]["field"] == "status"


def test_detail_carries_trail_and_unknown_404(client, clock):
    item = onboard(client, "jit-detail")
    request = create_request(client, item["id"], minutes=61)
    detail = client.get(f"/api/v1/jit/requests/{request['id']}").get_json()
    assert detail["request"]["id"] == request["id"]
    assert detail["request"]["minutes_left"] is None  # not granted yet
    actions = [event["action"] for event in detail["events"]]
    assert actions == ["requested"]  # newest first
    assert detail["events"][0]["actor"] == "tester"

    assert client.get("/api/v1/jit/requests/99999").status_code == 404


def test_scheduler_tick_ends_elapsed_grants(app, client, clock):
    from rotation_scheduler import run_due

    item = onboard(client, "jit-sched")
    request = create_request(client, item["id"], minutes=61)
    approve(client, request["id"], "manager")
    client.post(f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR)
    version_before = get_item(client, item["id"])["secret_version"]

    with app.app_context():
        row = db.session.get(JitRequest, request["id"])
        row.expires_at = _Clock.FIXED - timedelta(minutes=1)
        db.session.commit()

    with app.app_context():
        tick = run_due(client.application)
    assert tick["jit_expired"] == 1
    assert tick["rotated"] == []  # the grant's own rotation already happened
    assert get_item(client, item["id"])["secret_version"] == version_before + 1
    listed = client.get("/api/v1/jit/requests").get_json()
    assert next(r for r in listed["items"] if r["id"] == request["id"])["status"] == "expired"


def test_trail_is_persisted_per_request(app, client, clock):
    item = onboard(client, "jit-trail")
    request = create_request(client, item["id"], minutes=61)
    with app.app_context():
        rows = JitEvent.query.filter_by(request_id=request["id"]).all()
        assert [r.action for r in rows] == ["requested"]
        assert rows[0].actor == "tester"
        assert rows[0].detail["required_approvals"] == ["manager"]
