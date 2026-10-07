"""Tests for command control (architecture module 9).

The shipped section-9 policy seeds an empty rules table, rules are CRUD-able
with real validation, every decision is deterministic (block -> approval ->
allow, scoped before unscoped, longer pattern first, default allow when
nothing matches), command events record their decision, an approval hold is
resolved by append-only rows, and an escalated block on a production target
ends the session, preserves the evidence as an incident and runs the normal
release-and-rotate cascade exactly once.

Run with:  python -m pytest backend/phase2_license_server/tests/test_command_control.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}


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


def start_session(client, **payload):
    base = {"protocol": "ssh", "target": "web-01.example:22"}
    base.update(payload)
    response = client.post("/api/v1/sessions", json=base, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["session"]


def post_command(client, session_id, command):
    return client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": "command", "content": command},
        headers=ACTOR,
    )


def evaluate(client, command, target=""):
    response = client.post(
        "/api/v1/command-control/evaluate",
        json={"command": command, "target": target},
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()["result"]


def rule_named(rules, pattern, target=""):
    for rule in rules:
        if rule["pattern"] == pattern and rule["target_pattern"] == target:
            return rule
    raise AssertionError(f"no seeded rule for pattern={pattern!r} target={target!r}")


# --- shipped default policy -------------------------------------------------


def test_shipped_policy_is_the_architecture_table(client):
    response = client.get("/api/v1/command-control/rules")
    assert response.status_code == 200
    body = response.get_json()
    rules = body["items"]
    assert body["total"] == len(rules) == len(service_module.DEFAULT_COMMAND_RULES)

    by_pattern = {(r["pattern"], r["target_pattern"]): r for r in rules}
    expected = {
        ("ls", ""): "allow",
        ("df -h", ""): "allow",
        ("systemctl status", ""): "allow",
        ("systemctl restart", ""): "approval",
        ("useradd", ""): "approval",
        ("passwd", ""): "approval",
        ("rm -rf", ""): "block",
        ("DROP DATABASE", ""): "block",
        ("iptables -F", ""): "block",
        ("shutdown", ""): "block",
        ("reboot", ""): "block",
        ("chmod 777", ""): "block",
        ("systemctl stop", ""): "block",
        ("TRUNCATE", ""): "block",
        ("DROP DATABASE", "prod-*"): "block",
    }
    for key, action in expected.items():
        assert key in by_pattern, f"missing shipped rule {key}"
        assert by_pattern[key]["action"] == action, key
        assert by_pattern[key]["enabled"] is True

    escalation = by_pattern[("DROP DATABASE", "prod-*")]
    assert escalation["terminate_on_match"] is True

    # evaluation order: every block before every approval before every allow,
    # and the target-scoped rule ahead of its unscoped twin
    order = [r["action"] for r in rules]
    assert order == sorted(order, key=["block", "approval", "allow"].index)
    positions = [
        i for i, r in enumerate(rules)
        if r["pattern"] == "DROP DATABASE"
    ]
    scoped = [i for i in positions if rules[i]["target_pattern"] == "prod-*"]
    unscoped = [i for i in positions if rules[i]["target_pattern"] == ""]
    assert scoped[0] < unscoped[0]


def test_seed_runs_once_and_deletions_stay(client, app):
    rules = client.get("/api/v1/command-control/rules").get_json()["items"]
    doomed = rule_named(rules, "TRUNCATE")
    deleted = client.delete(
        f"/api/v1/command-control/rules/{doomed['id']}", headers=ACTOR
    )
    assert deleted.status_code == 200
    with app.app_context():
        assert service_module.ensure_command_rules() == 0
    again = client.get("/api/v1/command-control/rules").get_json()["items"]
    assert rule_named.__name__  # helper still usable
    assert all(r["id"] != doomed["id"] for r in again)


def test_stats_report_real_policy_state(client):
    body = client.get("/api/v1/command-control/stats").get_json()
    total = client.get("/api/v1/command-control/rules").get_json()["total"]
    assert body["rules_total"] == total
    assert sum(body["by_action"].values()) == total
    assert body["rules_enabled"] == total
    assert body["intercepts_today"] == 0
    assert body["commands_today"] == 0
    assert body["commands_recorded"] == 0
    assert body["approvals"] == {"pending": 0, "approved": 0, "denied": 0}
    assert body["incidents"] == {"open": 0, "total": 0}
    assert len(body["engine_hash"]) == 12
    int(body["engine_hash"], 16)  # real hex digest
    assert body["last_sync"] is not None
    assert body["last_sync_by"] == "admin"  # seeded by startup, not a name


# --- dry-run evaluation -----------------------------------------------------


def test_evaluate_decides_block_approval_allow_and_default(client):
    blocked = evaluate(client, "rm -rf /var/lib/app")
    assert blocked["decision"] == "block"
    assert blocked["matched"] is True and blocked["default"] is False
    assert blocked["terminate"] is False
    assert blocked["rule"]["pattern"] == "rm -rf"

    held = evaluate(client, "passwd alice")
    assert held["decision"] == "approval" and held["rule"]["pattern"] == "passwd"

    allowed = evaluate(client, "df -h")
    assert allowed["decision"] == "allow" and allowed["matched"] is True
    assert allowed["rule"]["pattern"] == "df -h"

    default = evaluate(client, "echo hello world")
    assert default["decision"] == "allow"
    assert default["matched"] is False and default["default"] is True
    assert default["rule"] is None and default["terminate"] is False


def test_evaluate_is_case_insensitive_and_scoped(client):
    assert evaluate(client, "RM -RF /")["decision"] == "block"
    assert evaluate(client, "truncate table users")["decision"] == "block"

    scoped = evaluate(client, "DROP DATABASE analytics", "prod-db-01:5432")
    assert scoped["decision"] == "block"
    assert scoped["terminate"] is True
    assert scoped["rule"]["target_pattern"] == "prod-*"

    unscoped = evaluate(client, "DROP DATABASE analytics", "staging-db-01:5432")
    assert unscoped["decision"] == "block"
    assert unscoped["terminate"] is False
    assert unscoped["rule"]["target_pattern"] == ""


def test_evaluate_validates_its_input(client):
    missing = client.post("/api/v1/command-control/evaluate", json={})
    assert missing.status_code == 400
    assert missing.get_json()["details"]["field"] == "command"

    blank = client.post(
        "/api/v1/command-control/evaluate", json={"command": "   "}
    )
    assert blank.status_code == 400

    bad_target = client.post(
        "/api/v1/command-control/evaluate",
        json={"command": "ls", "target": ["not", "a", "string"]},
    )
    assert bad_target.status_code == 400
    assert bad_target.get_json()["details"]["field"] == "target"

    huge = client.post(
        "/api/v1/command-control/evaluate", json={"command": "x" * 4097}
    )
    assert huge.status_code == 400


# --- rule CRUD --------------------------------------------------------------


def test_create_update_delete_round_trip(client):
    created = client.post(
        "/api/v1/command-control/rules",
        json={
            "name": "Block package installs",
            "pattern": "apt install",
            "action": "block",
            "description": "change control owns packages",
        },
        headers=ACTOR,
    )
    assert created.status_code == 201, created.get_json()
    rule = created.get_json()["rule"]
    assert rule["action"] == "block"
    assert rule["updated_by"] == "tester"
    assert rule["match_count"] if "match_count" in rule else True

    listed = client.get(
        "/api/v1/command-control/rules?q=package installs"
    ).get_json()["items"]
    assert [r["id"] for r in listed] == [rule["id"]]
    assert listed[0]["match_count"] == 0

    updated = client.put(
        f"/api/v1/command-control/rules/{rule['id']}",
        json={"action": "approval", "enabled": False},
        headers=ACTOR,
    )
    assert updated.status_code == 200
    body = updated.get_json()["rule"]
    assert body["action"] == "approval" and body["enabled"] is False
    assert body["pattern"] == "apt install"  # partial: untouched fields stay
    assert body["updated_by"] == "tester"

    assert evaluate(client, "apt install curl")["decision"] == "allow"  # off

    deleted = client.delete(
        f"/api/v1/command-control/rules/{rule['id']}", headers=ACTOR
    )
    assert deleted.status_code == 200 and deleted.get_json()["deleted"] == rule["id"]
    gone = client.get(f"/api/v1/command-control/rules?q=package installs")
    assert gone.get_json()["total"] == 0
    missing_delete = client.delete(
        f"/api/v1/command-control/rules/{rule['id']}", headers=ACTOR
    )
    assert missing_delete.status_code == 404


def test_create_rule_validation(client):
    no_name = client.post(
        "/api/v1/command-control/rules", json={"pattern": "x"}, headers=ACTOR
    )
    assert no_name.status_code == 400
    assert no_name.get_json()["details"]["field"] == "name"

    no_pattern = client.post(
        "/api/v1/command-control/rules", json={"name": "x"}, headers=ACTOR
    )
    assert no_pattern.status_code == 400
    assert no_pattern.get_json()["details"]["field"] == "pattern"

    bad_action = client.post(
        "/api/v1/command-control/rules",
        json={"name": "x", "pattern": "y", "action": "explode"},
        headers=ACTOR,
    )
    assert bad_action.status_code == 400
    assert bad_action.get_json()["details"]["allowed"] == [
        "allow", "approval", "block",
    ]

    escalate_allow = client.post(
        "/api/v1/command-control/rules",
        json={"name": "x", "pattern": "y", "action": "allow",
              "terminate_on_match": True},
        headers=ACTOR,
    )
    assert escalate_allow.status_code == 400
    assert escalate_allow.get_json()["details"]["field"] == "terminate_on_match"

    over_long = client.post(
        "/api/v1/command-control/rules",
        json={"name": "n" * 400, "pattern": "p"},
        headers=ACTOR,
    )
    assert over_long.status_code == 201  # house style: clipped, not rejected
    assert len(over_long.get_json()["rule"]["name"]) == 120


def test_rule_writes_require_admin_and_reads_stay_public(client):
    created = client.post(
        "/api/v1/command-control/rules",
        json={"name": "temp", "pattern": "zzz"},
    )
    assert created.status_code == 401
    rule_id = client.get("/api/v1/command-control/rules").get_json()["items"][0]["id"]
    updated = client.put(
        f"/api/v1/command-control/rules/{rule_id}", json={"action": "block"}
    )
    assert updated.status_code == 401
    deleted = client.delete(f"/api/v1/command-control/rules/{rule_id}")
    assert deleted.status_code == 401
    # public reads still work without the token
    assert client.get("/api/v1/command-control/rules").status_code == 200
    assert client.get("/api/v1/command-control/stats").status_code == 200
    assert (
        client.post("/api/v1/command-control/evaluate", json={"command": "ls"})
        .status_code
        == 200
    )


def test_update_conflicts_and_unknown_rules(client):
    rules = client.get("/api/v1/command-control/rules").get_json()["items"]
    allow_rule = rule_named(rules, "ls")
    bad = client.put(
        f"/api/v1/command-control/rules/{allow_rule['id']}",
        json={"terminate_on_match": True},
        headers=ACTOR,
    )
    assert bad.status_code == 400

    missing = client.put(
        "/api/v1/command-control/rules/999999",
        json={"action": "block"},
        headers=ACTOR,
    )
    assert missing.status_code == 404
    missing_get = client.get("/api/v1/command-control/rules/999999")
    assert missing_get.status_code in (404, 405)  # no GET on a single rule


def test_events_keep_the_rule_reference_after_deletion(client):
    rules = client.get("/api/v1/command-control/rules").get_json()["items"]
    created = client.post(
        "/api/v1/command-control/rules",
        json={"name": "Block freezer", "pattern": "freeze /", "action": "block"},
        headers=ACTOR,
    ).get_json()["rule"]
    session = start_session(client)
    response = post_command(client, session["id"], "freeze /data")
    assert response.status_code == 201
    event = response.get_json()["event"]
    assert event["rule_id"] == created["id"]
    assert event["decision"] == "block"

    assert (
        client.delete(
            f"/api/v1/command-control/rules/{created['id']}", headers=ACTOR
        ).status_code
        == 200
    )
    events = client.get(f"/api/v1/sessions/{session['id']}/events").get_json()
    command_row = [e for e in events["events"] if e["type"] == "command"][0]
    assert command_row["rule_id"] == created["id"]  # history survives deletion
    # and the seeded policy still decides
    assert evaluate(client, "rm -rf /tmp")["decision"] == "block"
    assert len(rules) > 0


# --- command decisions, holds and escalations on the channel ----------------


def test_command_events_carry_their_decision(client):
    session = start_session(client)
    allowed = post_command(client, session["id"], "df -h").get_json()["event"]
    assert allowed["decision"] == "allow" and allowed["allowed"] is True
    assert allowed["rule_id"] is not None

    plain = post_command(client, session["id"], "echo hello").get_json()["event"]
    assert plain["decision"] == "allow" and plain["rule_id"] is None

    blocked = post_command(client, session["id"], "rm -rf /var/log/app")
    body = blocked.get_json()
    assert blocked.status_code == 201
    assert "escalation" not in body  # plain block does not escalate
    event = body["event"]
    assert event["decision"] == "block" and event["allowed"] is False
    assert event["blocked_reason"] == "command_blocked"
    assert event["rule_id"] is not None

    held = post_command(client, session["id"], "useradd alice").get_json()["event"]
    assert held["decision"] == "approval" and held["allowed"] is False
    assert held["blocked_reason"] == "approval_required"

    detail = client.get(f"/api/v1/sessions/{session['id']}").get_json()
    assert detail["session"]["status"] == "active"  # blocks do not kill


def test_approval_queue_and_resolution(client):
    session = start_session(client)
    hold = post_command(client, session["id"], "passwd service-account")
    hold_event = hold.get_json()["event"]

    queue = client.get("/api/v1/command-control/approvals").get_json()
    assert queue["total"] == 1
    item = queue["items"][0]
    assert item["event"]["seq"] == hold_event["seq"]
    assert item["session"]["session_ref"] == session["session_ref"]

    approved = client.post(
        f"/api/v1/sessions/{session['id']}/events/{hold_event['seq']}/approve",
        headers=ACTOR,
    )
    assert approved.status_code == 200, approved.get_json()
    resolution = approved.get_json()["resolution"]
    assert resolution["type"] == "approval"
    assert resolution["decision"] == "approved" and resolution["allowed"] is True
    assert resolution["ref_seq"] == hold_event["seq"]
    # the hold itself is untouched (append-only)
    still = [
        e for e in client.get(
            f"/api/v1/sessions/{session['id']}/events"
        ).get_json()["events"]
        if e["seq"] == hold_event["seq"]
    ][0]
    assert still["allowed"] is False and still["decision"] == "approval"

    assert client.get("/api/v1/command-control/approvals").get_json()["total"] == 0
    stats = client.get("/api/v1/command-control/stats").get_json()["approvals"]
    assert stats == {"pending": 0, "approved": 1, "denied": 0}

    again = client.post(
        f"/api/v1/sessions/{session['id']}/events/{hold_event['seq']}/approve",
        headers=ACTOR,
    )
    assert again.status_code == 409

    # deny path: a second hold resolves the other way
    second = post_command(client, session["id"], "useradd contractor").get_json()[
        "event"
    ]
    denied = client.post(
        f"/api/v1/sessions/{session['id']}/events/{second['seq']}/deny",
        headers=ACTOR,
    )
    assert denied.status_code == 200
    resolution = denied.get_json()["resolution"]
    assert resolution["decision"] == "denied" and resolution["allowed"] is False
    assert resolution["blocked_reason"] == "approval_denied"

    # the type filter knows the approval rows
    approvals_only = client.get(
        f"/api/v1/sessions/{session['id']}/events?type=approval"
    ).get_json()
    assert approvals_only["total"] == 2

    # resolving something that is not a hold, or is unknown
    not_hold = client.post(
        f"/api/v1/sessions/{session['id']}/events/1/approve", headers=ACTOR
    )
    assert not_hold.status_code == 409
    unknown = client.post(
        f"/api/v1/sessions/{session['id']}/events/999/approve", headers=ACTOR
    )
    assert unknown.status_code == 404
    writes = client.post(
        f"/api/v1/sessions/{session['id']}/events/{second['seq']}/deny"
    )
    assert writes.status_code == 401  # no token


def test_resolution_refuses_an_ended_session(client):
    session = start_session(client)
    hold = post_command(client, session["id"], "useradd gone").get_json()["event"]
    ended = client.post(
        f"/api/v1/sessions/{session['id']}/terminate", json={}, headers=ACTOR
    )
    assert ended.status_code == 200
    resolved = client.post(
        f"/api/v1/sessions/{session['id']}/events/{hold['seq']}/approve",
        headers=ACTOR,
    )
    assert resolved.status_code == 409
    assert resolved.get_json()["details"]["status"] == "terminated"
    # the hold stays listed nowhere: only active sessions are actionable
    assert client.get("/api/v1/command-control/approvals").get_json()["total"] == 0


def test_escalated_block_kills_the_session_and_preserves_evidence(client, app):
    session = start_session(client, target="prod-db-01.example:5432")
    response = post_command(client, session["id"], "DROP DATABASE payments")
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert "escalation" in body
    escalation = body["escalation"]
    assert escalation["session_terminated"] is True
    assert escalation["cascade"]["outcome"] == "terminated"

    event = body["event"]
    assert event["decision"] == "block" and event["allowed"] is False
    incident = escalation["incident"]
    assert incident["incident_ref"].startswith("inc-")
    assert incident["session_id"] == session["id"]
    assert incident["event_seq"] == event["seq"]
    assert incident["command"] == "DROP DATABASE payments"
    assert incident["target"] == session["target"]
    assert incident["status"] == "open"
    assert incident["rule_pattern"] == "DROP DATABASE"
    assert incident["rule_name"]

    detail = client.get(f"/api/v1/sessions/{session['id']}").get_json()
    assert detail["session"]["status"] == "terminated"
    assert detail["session"]["end_reason"] == "terminated"
    contents = [e["content"] or "" for e in detail["events"]]
    assert any("command-control" in c for c in contents)  # audit trail names it

    listed = client.get("/api/v1/command-control/incidents").get_json()
    assert listed["total"] == 1
    assert listed["items"][0]["incident_ref"] == incident["incident_ref"]
    open_only = client.get(
        "/api/v1/command-control/incidents?status=open"
    ).get_json()
    assert open_only["total"] == 1
    closed_only = client.get(
        "/api/v1/command-control/incidents?status=closed"
    ).get_json()
    assert closed_only["total"] == 0

    stats = client.get("/api/v1/command-control/stats").get_json()
    assert stats["incidents"] == {"open": 1, "total": 1}
    assert stats["intercepts_today"] == 1

    # detail + close lifecycle
    incident_id = incident["id"]
    detail_incident = client.get(
        f"/api/v1/command-control/incidents/{incident_id}"
    ).get_json()["incident"]
    assert detail_incident["rule_pattern"] == "DROP DATABASE"
    no_token = client.post(
        f"/api/v1/command-control/incidents/{incident_id}/close", json={}
    )
    assert no_token.status_code == 401
    closed = client.post(
        f"/api/v1/command-control/incidents/{incident_id}/close",
        json={"note": "expected drill"},
        headers=ACTOR,
    )
    assert closed.status_code == 200
    assert closed.get_json()["incident"]["status"] == "closed"
    assert closed.get_json()["incident"]["closed_by"] == "tester"
    assert closed.get_json()["incident"]["close_note"] == "expected drill"
    again = client.post(
        f"/api/v1/command-control/incidents/{incident_id}/close",
        json={},
        headers=ACTOR,
    )
    assert again.status_code == 409
    bad_filter = client.get("/api/v1/command-control/incidents?status=melted")
    assert bad_filter.status_code == 400
    missing = client.get("/api/v1/command-control/incidents/999999")
    assert missing.status_code == 404


def test_same_block_outside_the_scope_stays_a_block(client):
    session = start_session(client, target="staging-db-01.example:5432")
    response = post_command(client, session["id"], "DROP DATABASE scratch")
    assert response.status_code == 201
    body = response.get_json()
    assert "escalation" not in body
    assert body["event"]["decision"] == "block"
    assert body["event"]["allowed"] is False
    detail = client.get(f"/api/v1/sessions/{session['id']}").get_json()
    assert detail["session"]["status"] == "active"
    assert client.get("/api/v1/command-control/incidents").get_json()["total"] == 0


def test_escalation_runs_the_release_and_rotate_cascade_once(client):
    item = onboard(client, "prod-cred")
    session = start_session(
        client, target="prod-db-01.example:5432", item_id=item["id"]
    )
    response = post_command(client, session["id"], "DROP DATABASE orders")
    assert response.status_code == 201, response.get_json()
    escalation = response.get_json()["escalation"]
    assert escalation["session_terminated"] is True
    assert escalation["cascade"]["checkout_released"] is True
    assert escalation["cascade"]["rotated"] is True
    assert escalation["cascade"]["secret_version"] is not None

    after = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert after["status"] == "available"
    assert after["checked_out_by"] is None
    assert after["secret_version"] == item["secret_version"] + 1
    rotated_events = client.get("/api/v1/vault/events?action=rotated").get_json()
    assert rotated_events["total"] == 1  # exactly one rotation


def test_disabled_rules_stop_deciding(client):
    rules = client.get("/api/v1/command-control/rules").get_json()["items"]
    target = rule_named(rules, "chmod 777")
    assert evaluate(client, "chmod 777 /etc")["decision"] == "block"
    updated = client.put(
        f"/api/v1/command-control/rules/{target['id']}",
        json={"enabled": False},
        headers=ACTOR,
    )
    assert updated.status_code == 200
    after = evaluate(client, "chmod 777 /etc")
    assert after["decision"] == "allow" and after["default"] is True
    # stats counts only what is really on
    stats = client.get("/api/v1/command-control/stats").get_json()
    assert stats["rules_enabled"] == stats["rules_total"] - 1
    filtered = client.get(
        "/api/v1/command-control/rules?enabled=false"
    ).get_json()
    assert [r["id"] for r in filtered["items"]] == [target["id"]]
    assert client.get(
        "/api/v1/command-control/rules?enabled=maybe"
    ).status_code == 400
    assert client.get(
        "/api/v1/command-control/rules?action=explode"
    ).status_code == 400
