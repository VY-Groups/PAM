"""Tests for the risk-based access engine (architecture module 7).

Every request is scored over the eight components the architecture names -
user, device, asset, time, location, behavior, ticket and command - each
read from a measured input (the subject's own 24h history, the discovered
inventory, the live command policy, the local clock, the source address via
stdlib ipaddress, the ticket's shape). The total picks the band (0-25 low,
26-50 medium, 51-75 high, 76-100 critical) and the band drives policy:
console evaluations advise, session starts are actually gated - CRITICAL is
refused outright, HIGH needs the approval of an active JIT grant - and
every evaluation lands on the risk trail of the immutable audit ledger.

Run with:  python -m pytest backend/phase2_license_server/tests/test_risk.py -q
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from models import BASE_RISK, DiscoveredAsset, db  # noqa: E402
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

ASSET_ADDRESS = "10.77.0.9"

COMPONENT_ORDER = [
    "user", "device", "asset", "time", "location", "behavior", "ticket", "command",
]


class _Clock(datetime):
    """Wednesday 2026-10-07 noon: business hours, time risk scores nothing."""

    FIXED = datetime(2026, 10, 7, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


class _NightClock(datetime):
    """Saturday 2026-09-26 15:00: weekend off-hours, time risk scores 10.

    The instant sits in the past on purpose: history rows carry the real
    wall clock (column defaults bind datetime.now at import), so anchoring
    the fixture before "now" keeps every event a test creates inside the
    engine's rolling 24h window. The weekend also exercises that branch of
    the off-hours rule (hour alone would not fire at 15:00)."""

    FIXED = datetime(2026, 9, 26, 15, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


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
def clock(monkeypatch):
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)


@pytest.fixture
def night_clock(monkeypatch):
    monkeypatch.setattr(service_module, "datetime", _NightClock)
    monkeypatch.setattr(models_module, "datetime", _NightClock)


def evaluate(client, payload):
    return client.post("/api/v1/risk/evaluate", json=payload, headers=ACTOR)


def eval_of(client, payload):
    """Score a request through the public API; return the evaluation."""
    response = evaluate(client, payload)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["evaluation"]


def component(evaluation, name):
    for item in evaluation["components"]:
        if item["component"] == name:
            return item
    raise AssertionError(f"missing component: {evaluation['components']}")


def insert_asset(app, address=ASSET_ADDRESS, *, asset_type="database"):
    """An already-discovered row, the way a real scan leaves it: unmanaged
    until an operator onboards it (model-level insert, as in test_discovery)."""
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


def register_asset(client, address=ASSET_ADDRESS, asset_type="database"):
    """Manual registration through the public API - lands managed (the
    operator onboarded its principal), so no unmanaged exposure points."""
    response = client.post(
        "/api/v1/discovery/assets",
        json={"address": address, "asset_type": asset_type, "principal": "root"},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def start_session(client, **payload):
    base = {"protocol": "ssh", "target": "web-01.example:22"}
    base.update(payload)
    return client.post("/api/v1/sessions", json=base, headers=ACTOR)


def post_blocked_command(client, session_id, command="rm -rf /var"):
    response = client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": "command", "content": command},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


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


def active_grant(client, name):
    """A real approved+consumed JIT grant (the approval HIGH requires)."""
    item = onboard(client, name)
    created = client.post(
        "/api/v1/jit/requests",
        json={
            "item_id": item["id"],
            "reason": "Risk gate verification window",
            "ticket": "INC-4021",
            "minutes": 15,
        },
        headers=ACTOR,
    )
    assert created.status_code == 201, created.get_json()
    request = created.get_json()["request"]
    if request["status"] == "pending":
        approved = client.post(
            f"/api/v1/jit/requests/{request['id']}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
        assert approved.status_code == 200, approved.get_json()
    consumed = client.post(
        f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR
    )
    assert consumed.status_code == 200, consumed.get_json()
    assert consumed.get_json()["request"]["status"] == "active"
    return consumed.get_json()["request"]


# --- validation --------------------------------------------------------------

def test_evaluate_requires_a_subject(client):
    missing = evaluate(client, {})
    assert missing.status_code == 400
    assert missing.get_json()["details"]["field"] == "subject"

    blank = evaluate(client, {"subject": "   "})
    assert blank.status_code == 400
    assert blank.get_json()["details"]["field"] == "subject"

    wrong_type = evaluate(client, {"subject": 42})
    assert wrong_type.status_code == 400
    assert wrong_type.get_json()["details"]["field"] == "subject"

    not_an_object = client.post(
        "/api/v1/risk/evaluate", json=[1, 2, 3], headers=ACTOR
    )
    assert not_an_object.status_code == 400


def test_evaluate_validates_field_shapes(client):
    bad_target = evaluate(client, {"subject": "alice", "target": 5})
    assert bad_target.status_code == 400
    assert bad_target.get_json()["details"]["field"] == "target"

    long_command = evaluate(client, {"subject": "alice", "command": "x" * 1001})
    assert long_command.status_code == 400
    details = long_command.get_json()["details"]
    assert details["field"] == "command" and details["max_length"] == 1000

    long_ticket = evaluate(client, {"subject": "alice", "ticket": "y" * 65})
    assert long_ticket.status_code == 400
    assert long_ticket.get_json()["details"]["field"] == "ticket"


# --- scoring -----------------------------------------------------------------

def test_manual_evaluation_scores_a_clean_request(client, clock):
    evaluation = eval_of(client, {"subject": "bob"})

    assert evaluation["score"] == 0  # business hours, nothing else supplied
    assert evaluation["band"] == "low"
    assert evaluation["decision"] == "allow"
    assert evaluation["result"] == "advisory"
    assert evaluation["context"] == "manual"
    assert evaluation["subject"] == "bob"
    assert [c["component"] for c in evaluation["components"]] == COMPONENT_ORDER
    assert sum(c["points"] for c in evaluation["components"]) == evaluation["score"]
    assert all(c["detail"] for c in evaluation["components"])  # zeros explain too
    assert component(evaluation, "time")["detail"].endswith("business hours")
    assert component(evaluation, "device")["detail"] == "no device reported for this request"
    assert component(evaluation, "asset")["detail"] == "no target supplied"

    page = client.get("/api/v1/risk/evaluations").get_json()
    assert page["total"] == 1 and page["evaluations"][0]["id"] == evaluation["id"]


def test_band_thresholds_match_the_architecture():
    bands = {
        0: "low", 25: "low", 26: "medium", 50: "medium",
        51: "high", 75: "high", 76: "critical", 100: "critical",
    }
    for score, band in bands.items():
        assert service_module._risk_band(score) == band, score


def test_target_host_parsing():
    assert service_module._target_host("web-01.prod:22") == "web-01.prod"
    assert service_module._target_host("10.77.0.9:5432") == "10.77.0.9"
    assert service_module._target_host("db.internal") == "db.internal"
    assert service_module._target_host("[::1]:22") == "::1"


def test_components_trace_to_measured_inputs(client, clock):
    first = eval_of(
        client,
        {
            "subject": "alice",
            "target": "ghost-host:22",
            "device": "thinkpad-x1",
            "source_ip": "10.1.2.3",
            "ticket": "INC-1234",
            "command": "systemctl restart nginx",
        },
    )
    assert first["score"] == 20
    assert component(first, "user")["points"] == 0
    assert "no critical history" in component(first, "user")["detail"]
    assert component(first, "device")["points"] == 15
    assert "not in the discovered inventory" in component(first, "device")["detail"]
    assert component(first, "asset")["points"] == 0
    assert "not in the discovered inventory" in component(first, "asset")["detail"]
    assert component(first, "time")["points"] == 0
    assert component(first, "location")["points"] == 0
    assert "private range" in component(first, "location")["detail"]
    assert component(first, "behavior")["points"] == 0
    assert "0 blocked command(s) and 0 denied request(s)" in component(first, "behavior")["detail"]
    assert component(first, "ticket")["points"] == 0
    assert "ITSM" in component(first, "ticket")["detail"]
    assert component(first, "command")["points"] == 5  # held for approval
    assert "Service restart needs approval" in component(first, "command")["detail"]
    assert sum(c["points"] for c in first["components"]) == first["score"]

    second = eval_of(
        client,
        {
            "subject": "alice",
            "source_ip": "8.8.8.8",
            "ticket": "fix-now",
            "command": "rm -rf /opt",
        },
    )
    assert second["score"] == 20
    assert component(second, "device")["points"] == 0
    assert component(second, "device")["detail"] == "no device reported for this request"
    assert component(second, "asset")["detail"] == "no target supplied"
    assert component(second, "location")["points"] == 5
    assert "outside the private ranges" in component(second, "location")["detail"]
    assert component(second, "ticket")["points"] == 5
    assert "not an ITSM-style" in component(second, "ticket")["detail"]
    assert component(second, "command")["points"] == 10  # the live policy blocks it
    assert "Recursive delete blocked" in component(second, "command")["detail"]


def test_inventory_lookup_scores_the_asset(app, client, clock):
    register_asset(client)  # API registration -> managed with a vault credential

    evaluation = eval_of(
        client,
        {
            "subject": "alice",
            "target": "10.77.0.9:5432",
            "device": "10.77.0.9",  # known to discovery: no device points
        },
    )
    asset = component(evaluation, "asset")
    assert asset["points"] == 25  # CRITICAL severity, managed: no exposure bonus
    for needle in ("database", "CRITICAL", "managed", "10.77.0.9"):
        assert needle in asset["detail"], asset["detail"]
    assert component(evaluation, "device")["points"] == 0
    assert "is in the discovered inventory" in component(evaluation, "device")["detail"]
    assert evaluation["score"] == 25
    assert evaluation["band"] == "low"

    # a row a scan left behind stays unmanaged: +5 of exposure (section 10)
    insert_asset(app, "10.77.0.10")
    second = eval_of(client, {"subject": "alice", "target": "10.77.0.10:22"})
    assert component(second, "asset")["points"] == 30  # 25 + unmanaged 5
    assert "unmanaged" in component(second, "asset")["detail"]
    assert second["score"] == 30


def test_off_hours_costs_time_points(client, night_clock):
    evaluation = eval_of(client, {"subject": "alice"})
    time_risk = component(evaluation, "time")
    assert time_risk["points"] == 10
    assert "Saturday 15:00" in time_risk["detail"]
    assert "outside business hours" in time_risk["detail"]
    assert evaluation["score"] == 10
    assert evaluation["band"] == "low"


def test_behavior_and_user_history_count_real_events(app, client, night_clock):
    insert_asset(app)
    session = start_session(client)
    assert session.status_code == 201, session.get_json()
    post_blocked_command(client, session.get_json()["session"]["id"])

    # critical stack: asset 30 + time 10 + device 15 + location 5 +
    # ticket 5 + command 10 + behavior 10 (the blocked command above)
    critical = eval_of(
        client,
        {
            "subject": "tester",
            "target": "10.77.0.9:22",
            "device": "unmanaged-laptop",
            "source_ip": "8.8.8.8",
            "ticket": "fix-now",
            "command": "rm -rf /opt",
        },
    )
    assert critical["band"] == "critical" and critical["score"] == 85
    assert component(critical, "behavior")["points"] == 10
    assert "1 blocked command(s)" in component(critical, "behavior")["detail"]

    # the same subject now carries that critical in its own24h history
    followup = eval_of(client, {"subject": "tester"})
    user = component(followup, "user")
    assert user["points"] == 5  # 5 points per prior critical (10 cap)
    assert "1 critical evaluation(s)" in user["detail"]
    # user 5 + the blocked command still on record 10 + off-hours 10
    assert followup["score"] == 25
    assert sum(c["points"] for c in followup["components"]) == followup["score"]


# --- the ledger --------------------------------------------------------------

def test_critical_evaluation_reaches_the_ledger(app, client, night_clock):
    insert_asset(app)
    session = start_session(client)
    post_blocked_command(client, session.get_json()["session"]["id"])

    evaluation = eval_of(
        client,
        {
            "subject": "tester",
            "target": "10.77.0.9:22",
            "device": "unmanaged-laptop",
            "source_ip": "8.8.8.8",
            "ticket": "fix-now",
            "command": "rm -rf /opt",
        },
    )
    assert evaluation["band"] == "critical"
    assert evaluation["decision"] == "block"
    assert evaluation["result"] == "advisory"  # console evaluations only advise

    feed = client.get("/api/v1/events", query_string={"source": "risk"}).get_json()
    # two evaluations: the session start above (low) and this one (critical)
    assert feed["total"] == 2
    row = feed["events"][0]
    assert row["id"].startswith("risk:")
    assert row["seq"] >= 1 and len(row["event_hash"]) == 64
    assert row["action"] == "block"
    assert row["detail"]["score"] == evaluation["score"]
    assert row["detail"]["band"] == "critical"
    assert row["detail"]["result"] == "advisory"
    assert len(row["detail"]["components"]) == 8
    assert feed["events"][1]["detail"]["context"] == "session_start"

    assert client.get("/api/v1/audit/stats").get_json()["by_source"]["risk"] == 2
    verify = client.get("/api/v1/audit/verify").get_json()
    assert verify["intact"] is True
    assert verify["total"] == verify["checked"]


# --- aggregates --------------------------------------------------------------

def test_risk_stats_reflect_real_evaluations(app, client, night_clock):
    empty = client.get("/api/v1/risk/stats").get_json()
    assert empty["total"] == 0
    assert empty["avg_score"] is None  # no data, no number
    assert empty["last_evaluated_at"] is None
    assert empty["refused"] == 0
    assert all(count == 0 for count in empty["by_band"].values())

    insert_asset(app)
    eval_of(client, {"subject": "s1"})                      # time 10 -> low
    eval_of(client, {"subject": "s2", "target": "10.77.0.9:22"})  # 10+30 -> medium

    state = client.get("/api/v1/risk/stats").get_json()
    assert state["total"] == 2
    assert state["by_band"] == {"low": 1, "medium": 1, "high": 0, "critical": 0}
    assert state["by_decision"]["allow"] == 1
    assert state["by_decision"]["mfa"] == 1
    assert state["by_result"] == {"advisory": 2, "allowed": 0, "refused": 0}
    assert state["by_context"]["manual"] == 2
    assert state["refused"] == 0
    assert state["avg_score"] == 25.0  # (10 + 40) / 2, real arithmetic
    assert state["last_evaluated_at"] is not None


def test_risk_list_filters_and_pages(app, client, night_clock):
    insert_asset(app)
    eval_of(client, {"subject": "s1"})                              # 10 low
    eval_of(client, {"subject": "s2", "target": "10.77.0.9:22"})    # 40 medium
    eval_of(
        client,
        {"subject": "s3", "target": "10.77.0.9:22", "device": "unmanaged-laptop"},
    )                                                               # 55 high

    page = client.get("/api/v1/risk/evaluations", query_string={"limit": 2}).get_json()
    assert page["total"] == 3 and len(page["evaluations"]) == 2
    assert [row["subject"] for row in page["evaluations"]] == ["s3", "s2"]

    rest = client.get(
        "/api/v1/risk/evaluations", query_string={"limit": 2, "offset": 2}
    ).get_json()
    assert [row["subject"] for row in rest["evaluations"]] == ["s1"]

    high = client.get(
        "/api/v1/risk/evaluations", query_string={"band": "high"}
    ).get_json()
    assert high["total"] == 1
    assert high["evaluations"][0]["band"] == "high"

    assert client.get(
        "/api/v1/risk/evaluations", query_string={"band": "critical"}
    ).get_json()["total"] == 0
    assert client.get(
        "/api/v1/risk/evaluations", query_string={"context": "session_start"}
    ).get_json()["total"] == 0
    assert client.get(
        "/api/v1/risk/evaluations", query_string={"context": "manual"}
    ).get_json()["total"] == 3

    bad_band = client.get(
        "/api/v1/risk/evaluations", query_string={"band": "apocalypse"}
    )
    assert bad_band.status_code == 400
    assert "critical" in bad_band.get_json()["details"]["allowed"]

    bad_context = client.get(
        "/api/v1/risk/evaluations", query_string={"context": "dream"}
    )
    assert bad_context.status_code == 400
    assert "session_start" in bad_context.get_json()["details"]["allowed"]


def test_evaluate_requires_admin_token_but_reads_are_public(client):
    no_token = client.post("/api/v1/risk/evaluate", json={"subject": "alice"})
    assert no_token.status_code == 401
    assert client.get("/api/v1/risk/evaluations").status_code == 200
    assert client.get("/api/v1/risk/stats").status_code == 200


# --- the session-start gate --------------------------------------------------

def test_session_start_records_an_allowed_evaluation(client, clock):
    response = start_session(client, target="web-01.example:22")
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["message"] == "Session started"

    risk = body["risk"]
    assert risk["context"] == "session_start"
    assert risk["result"] == "allowed"
    assert risk["score"] == 0  # clean target, business hours
    assert risk["band"] == "low" and risk["decision"] == "allow"
    assert risk["subject"] == "tester"
    assert sum(c["points"] for c in risk["components"]) == risk["score"]

    page = client.get(
        "/api/v1/risk/evaluations", query_string={"context": "session_start"}
    ).get_json()
    assert page["total"] == 1
    assert page["evaluations"][0]["result"] == "allowed"


def test_session_start_validates_the_device_field(client, clock):
    response = start_session(client, target="h:22", device=42)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "device"
    assert client.get("/api/v1/sessions").get_json()["total"] == 0
    assert client.get("/api/v1/risk/evaluations").get_json()["total"] == 0


def test_session_start_refuses_high_without_an_active_grant(
    app, client, night_clock
):
    insert_asset(app)

    refused = start_session(
        client, target="10.77.0.9:22", device="unmanaged-laptop"
    )
    assert refused.status_code == 403
    details = refused.get_json()["details"]
    assert details["risk"]["band"] == "high"        # asset 30 + time 10 + device 15
    assert details["risk"]["decision"] == "approval"
    assert details["risk"]["result"] == "refused"
    assert details["risk"]["score"] == 55

    assert client.get("/api/v1/sessions").get_json()["total"] == 0

    # the refusal itself is kept as SOC evidence on the risk trail
    page = client.get("/api/v1/risk/evaluations").get_json()
    assert page["total"] == 1
    assert page["evaluations"][0]["result"] == "refused"
    feed = client.get("/api/v1/events", query_string={"source": "risk"}).get_json()
    assert feed["events"][0]["detail"]["result"] == "refused"
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_session_start_medium_band_prescribes_mfa_and_runs(
    app, client, night_clock
):
    insert_asset(app)

    response = start_session(client, target="10.77.0.9:22")
    assert response.status_code == 201, response.get_json()
    risk = response.get_json()["risk"]
    assert risk["score"] == 40 and risk["band"] == "medium"
    assert risk["decision"] == "mfa"  # the policy the band prescribes
    assert risk["result"] == "allowed"


def test_high_band_passes_under_an_active_jit_grant(app, client, night_clock):
    insert_asset(app)
    grant = active_grant(client, "risk-high-grant")

    response = start_session(
        client,
        target="10.77.0.9:22",
        device="unmanaged-laptop",
        jit_request_id=grant["id"],
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["session"]["jit_request_id"] == grant["id"]
    risk = body["risk"]
    assert risk["score"] == 55 and risk["band"] == "high"
    assert risk["decision"] == "approval"
    assert risk["result"] == "allowed"  # the active grant is the approval


def test_critical_band_refuses_even_with_an_active_grant(
    app, client, night_clock
):
    insert_asset(app)
    session = start_session(client)
    post_blocked_command(client, session.get_json()["session"]["id"])

    denied = client.post(
        "/api/v1/jit/requests",
        json={
            "item_id": onboard(client, "risk-denied-item")["id"],
            "reason": "Routine maintenance attempt",
            "ticket": "INC-7712",
            "minutes": 15,
        },
        headers=ACTOR,
    )
    assert denied.status_code == 201
    deny = client.post(
        f"/api/v1/jit/requests/{denied.get_json()['request']['id']}/deny",
        json={},
        headers={**ACTOR, "X-Actor": "sec"},
    )
    assert deny.status_code == 200

    # seed this subject's prior criticals (asset 30 + time 10 + device 15 +
    # location 5 + ticket 5 + command 10 + behavior 15): 90 the first time
    # (no history yet), 95 the second (user component now carries 5)
    stack = {
        "subject": "tester",
        "target": "10.77.0.9:22",
        "device": "unmanaged-laptop",
        "source_ip": "8.8.8.8",
        "ticket": "fix-now",
        "command": "rm -rf /opt",
    }
    prior = eval_of(client, stack)
    assert prior["band"] == "critical" and prior["score"] == 90
    second = eval_of(client, stack)
    assert second["band"] == "critical" and second["score"] == 95

    grant = active_grant(client, "risk-critical-grant")
    refused = start_session(
        client,
        target="10.77.0.9:22",
        device="unmanaged-laptop",
        jit_request_id=grant["id"],
    )
    assert refused.status_code == 403
    risk = refused.get_json()["details"]["risk"]
    # user 10 (two prior criticals at 5 each) + asset 30 + time 10 +
    # behavior 15 + device 15 = 80: critical
    assert risk["score"] == 80
    assert risk["band"] == "critical"
    assert risk["decision"] == "block"
    assert risk["result"] == "refused"

    # only the setup session exists - the refused start created no session
    assert client.get("/api/v1/sessions").get_json()["total"] == 1
    still = client.get(f"/api/v1/jit/requests/{grant['id']}").get_json()
    assert still["request"]["status"] == "active"  # the grant itself survives
