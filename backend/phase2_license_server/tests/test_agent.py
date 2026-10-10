"""Section 16: AI-agent PAM (phase 5d).

An AI agent is a first-class principal: it authenticates with an API token
issued once and stored as a sha256 hash, declares the tasks it may perform
as exhaustive allowed-command lists, and requests per-task access through
the same section-7 risk evaluation and section-6 JIT machinery humans use.
The chain the architecture draws is what these tests walk: identity
verification -> task verification -> risk evaluation -> JIT credential ->
task-scoped command restrictions -> monitored session -> expiry.

The headline example is asserted verbatim: `systemctl restart postgresql`
is ALLOWED inside the declared task (the task declaration is the
pre-authorization - section 9 would hold a bare service restart for
approval), while `DROP DATABASE production` is BLOCKED, preserves its
evidence as an incident and terminates the session.
"""
from __future__ import annotations

import json
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
import audit as audit_module  # noqa: E402
import service as service_module  # noqa: E402
import models as models_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}

# Wednesday 2026-10-07 noon - a fixed base the risk and expiry tests pin
# to, so off-hours and the 24h repeat window never move under the asserts.
NOON = datetime(2026, 10, 7, 12, 0, 0)


def _clock_at(monkeypatch, moment):
    """Freeze the service+models clock at `moment` (fresh class per call so
    tests never leak a FIXED into each other)."""

    class _At(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment

    monkeypatch.setattr(service_module, "datetime", _At)
    monkeypatch.setattr(models_module, "datetime", _At)


def _config(tmp_path: Path, admin_token="test-admin-token") -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public_key.pem",
        secret_key="test-secret",
        admin_token=admin_token,
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
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


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def onboard(client, name, *, target="db.prod:5432", access_tier="Tier-2"):
    payload = {
        "name": name,
        "secret_type": "database",
        "target": target,
        "principal": "dba",
        "access_tier": access_tier,
        "auth_method": "Password",
        "rotation_interval_hours": 24,
        "secret": "agent-vault-value-99bb",
    }
    response = client.post("/api/v1/vault/items", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def add_agent(client, name="ops-bot", **overrides):
    payload = {
        "name": name,
        "description": "Automation agent",
        "contact": "sre@example.com",
    }
    payload.update(overrides)
    response = client.post("/api/v1/agents", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["agent"], body["token"]


def agent(token):
    return {"Authorization": f"Bearer {token}"}


def add_task(client, agent_id, name="restart-postgres", **overrides):
    payload = {
        "name": name,
        "allowed_commands": ["systemctl restart postgresql"],
    }
    payload.update(overrides)
    response = client.post(
        f"/api/v1/agents/{agent_id}/tasks", json=payload, headers=ACTOR
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["task"]


def ask(client, token, item_id, **overrides):
    payload = {
        "task": "restart-postgres",
        "item_id": item_id,
        "reason": "Restart the PostgreSQL service",
        "ticket": "INC-23891",
    }
    payload.update(overrides)
    return client.post(
        "/api/v1/agent-access/requests", json=payload, headers=agent(token)
    )


def open_access(client, token, request_id, **payload):
    return client.post(
        f"/api/v1/agent-access/requests/{request_id}/open",
        json=payload,
        headers=agent(token),
    )


def post_event(client, session_id, type_, content):
    return client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": type_, "content": content},
        headers=ACTOR,
    )


def vault_view(client, item_id):
    return client.get(f"/api/v1/vault/items/{item_id}").get_json()["item"]


def agent_detail(client, agent_id):
    return client.get(f"/api/v1/agents/{agent_id}", headers=ADMIN).get_json()


def action_of(detail, name):
    return [event["action"] for event in detail["events"]]


# ---------------------------------------------------------------------------
# identity lifecycle
# ---------------------------------------------------------------------------
def test_agent_create_returns_token_once_and_stores_hash(client):
    row, token = add_agent(client, "ops-bot")
    assert row["id"] >= 1
    assert row["status"] == "active"
    assert row["max_ttl_minutes"] == 15
    assert row["use_count"] == 0
    assert row["last_used_at"] is None
    assert token.startswith(f"vypam-agt1.{row['id']}.")
    assert len(token.split(".")[2]) >= 32
    # stored as a hash prefix only - the list never carries the token
    assert row["token_hash"].startswith("sha256:")
    listed = client.get("/api/v1/agents", headers=ADMIN).get_json()
    assert listed["total"] == 1
    assert token not in json.dumps(listed)
    assert token.split(".")[2] not in json.dumps(listed)


def test_agent_create_validates_inputs(client):
    response = client.post("/api/v1/agents", json={}, headers=ACTOR)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "name"

    response = client.post(
        "/api/v1/agents",
        json={"name": "a1", "max_ttl_minutes": 0},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"] == {
        "field": "max_ttl_minutes",
        "min": 1,
        "max": 480,
    }

    response = client.post(
        "/api/v1/agents", json={"name": "a2", "contact": 7}, headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "contact"

    response = client.post(
        "/api/v1/agents", json={"name": "a3", "description": [1]}, headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "description"


def test_agent_duplicate_name_conflicts(client):
    add_agent(client, "ops-bot")
    response = client.post(
        "/api/v1/agents", json={"name": "ops-bot"}, headers=ACTOR
    )
    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]


def test_agent_list_filters(client):
    add_agent(client, "ops-bot")
    add_agent(client, "batch-runner")
    rows = client.get("/api/v1/agents?status=active", headers=ADMIN).get_json()
    assert rows["total"] == 2
    rows = client.get("/api/v1/agents?q=ops", headers=ADMIN).get_json()
    assert rows["total"] == 1
    assert rows["agents"][0]["name"] == "ops-bot"
    assert client.get("/api/v1/agents?status=maybe", headers=ADMIN).status_code == 400


def test_agent_patch_edits_knobs_and_freezes_after_revoke(client):
    row, _ = add_agent(client, "ops-bot")
    response = client.patch(
        f"/api/v1/agents/{row['id']}",
        json={
            "description": "Database maintenance agent",
            "contact": "dba@example.com",
            "max_ttl_minutes": 30,
        },
        headers=ACTOR,
    )
    assert response.status_code == 200
    view = response.get_json()["agent"]
    assert view["description"] == "Database maintenance agent"
    assert view["contact"] == "dba@example.com"
    assert view["max_ttl_minutes"] == 30

    # the identity itself is never editable, and an empty patch is refused
    response = client.patch(
        f"/api/v1/agents/{row['id']}", json={"name": "renamed"}, headers=ACTOR
    )
    assert response.status_code == 400
    response = client.patch(f"/api/v1/agents/{row['id']}", json={}, headers=ACTOR)
    assert response.status_code == 400
    response = client.patch(
        f"/api/v1/agents/{row['id']}",
        json={"status": "revoked"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["allowed"] == ["active", "disabled"]

    # enable / disable are real, each recorded on the agent's own trail
    response = client.patch(
        f"/api/v1/agents/{row['id']}", json={"status": "disabled"}, headers=ACTOR
    )
    assert response.status_code == 200
    detail = agent_detail(client, row["id"])
    assert action_of(detail, "agent")[:2] == ["agent-disabled", "agent-updated"]

    response = client.delete(
        f"/api/v1/agents/{row['id']}",
        json={"reason": "operator retired"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    response = client.patch(
        f"/api/v1/agents/{row['id']}", json={"contact": "x@example.com"}, headers=ACTOR
    )
    assert response.status_code == 409
    assert "frozen" in response.get_json()["error"]


# ---------------------------------------------------------------------------
# authentication (the API token is the only way in)
# ---------------------------------------------------------------------------
def test_agent_auth_is_real(client):
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-auth-credential")

    payload = {"task": "restart-postgres", "item_id": item["id"]}
    response = client.post("/api/v1/agent-access/requests", json=payload)
    assert response.status_code == 401
    assert "Agent API token required" in response.get_json()["error"]

    # a plain bearer token is the admin credential shape, not an agent token
    response = client.post(
        "/api/v1/agent-access/requests",
        json=payload,
        headers={"Authorization": "Bearer nonsense"},
    )
    assert response.status_code == 401
    assert "Agent API token required" in response.get_json()["error"]

    response = client.post(
        "/api/v1/agent-access/requests",
        json=payload,
        headers={"X-Agent-Token": "nonsense"},
    )
    assert response.status_code == 401
    assert "Not an agent API token" in response.get_json()["error"]

    response = client.post(
        "/api/v1/agent-access/requests",
        json=payload,
        headers=agent("vypam-agt1.9999.secret"),
    )
    assert response.status_code == 401
    assert "Unknown" in response.get_json()["error"]

    response = client.post(
        "/api/v1/agent-access/requests",
        json=payload,
        headers=agent("vypam-agt1.abc.secret"),
    )
    assert response.status_code == 401

    good_id = token.split(".")[1]
    response = client.post(
        "/api/v1/agent-access/requests",
        json=payload,
        headers=agent(f"vypam-agt1.{good_id}.wrong-secret"),
    )
    assert response.status_code == 401
    assert "Invalid" in response.get_json()["error"]

    # the admin token is not an agent credential
    response = client.post(
        "/api/v1/agent-access/requests", json=payload, headers=ADMIN
    )
    assert response.status_code == 401


def test_disabled_and_revoked_tokens_refuse(client):
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-lifecycle-credential")
    assert ask(client, token, item["id"]).status_code == 201

    client.patch(
        f"/api/v1/agents/{row['id']}", json={"status": "disabled"}, headers=ACTOR
    )
    response = ask(client, token, item["id"], ticket="INC-23892")
    assert response.status_code == 401
    assert "disabled" in response.get_json()["error"]

    client.patch(
        f"/api/v1/agents/{row['id']}", json={"status": "active"}, headers=ACTOR
    )
    assert ask(client, token, item["id"], ticket="INC-23893").status_code == 201

    client.delete(
        f"/api/v1/agents/{row['id']}", json={"reason": "retired"}, headers=ACTOR
    )
    response = ask(client, token, item["id"], ticket="INC-23894")
    assert response.status_code == 401
    assert "revoked" in response.get_json()["error"]


def test_valid_agent_token_records_use(client):
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-use-credential")
    assert ask(client, token, item["id"]).status_code == 201
    detail = agent_detail(client, row["id"])
    assert detail["agent"]["use_count"] == 1
    assert detail["agent"]["last_used_at"] is not None


def test_open_dev_mode_waives_admin_but_never_agent_token(tmp_path):
    application = create_app(_config(tmp_path, admin_token=None))
    application.config["TESTING"] = True
    client = application.test_client()
    dev = {"X-Actor": "dev"}

    response = client.post(
        "/api/v1/agents", json={"name": "dev-bot"}, headers=dev
    )
    assert response.status_code == 201
    row, token = response.get_json()["agent"], response.get_json()["token"]
    task = client.post(
        f"/api/v1/agents/{row['id']}/tasks",
        json={"name": "restart-postgres",
              "allowed_commands": ["systemctl restart postgresql"]},
        headers=dev,
    )
    assert task.status_code == 201
    item = onboard(client, "dev-credential")

    # without the agent token the request is still refused
    response = client.post(
        "/api/v1/agent-access/requests",
        json={"task": "restart-postgres", "item_id": item["id"],
              "reason": "dev restart without token", "ticket": "DEV-1001"},
    )
    assert response.status_code == 401
    # with it - the machine identity is the point - the request is served
    response = client.post(
        "/api/v1/agent-access/requests",
        json={"task": "restart-postgres", "item_id": item["id"],
              "reason": "dev restart with token", "ticket": "DEV-1002"},
        headers=agent(token),
    )
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# task scopes (the exhaustive allow-list)
# ---------------------------------------------------------------------------
def test_task_create_declares_exhaustive_allow_list(client):
    row, _ = add_agent(client, "ops-bot")
    task = add_task(
        client,
        row["id"],
        allowed_commands=[
            "systemctl restart postgresql",
            "  systemctl restart postgresql ",
            "df -h",
        ],
        allowed_targets=["db.prod:5432"],
        max_minutes=5,
    )
    assert task["allowed_commands"] == ["systemctl restart postgresql", "df -h"]
    assert task["allowed_targets"] == ["db.prod:5432"]
    assert task["max_minutes"] == 5
    assert task["name"] == "restart-postgres"

    detail = agent_detail(client, row["id"])
    assert [t["id"] for t in detail["tasks"]] == [task["id"]]
    assert detail["open_grants"] == 0
    assert "task-added" in action_of(detail, "agent")


def test_task_create_validation(client):
    row, _ = add_agent(client, "ops-bot")
    base = f"/api/v1/agents/{row['id']}/tasks"

    response = client.post(base, json={}, headers=ACTOR)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "name"

    response = client.post(
        base, json={"name": "t1", "allowed_commands": []}, headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "allowed_commands"

    response = client.post(
        base, json={"name": "t1", "allowed_commands": "restart"}, headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "allowed_commands"

    response = client.post(
        base, json={"name": "t1", "allowed_commands": [5]}, headers=ACTOR
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "allowed_commands"

    response = client.post(
        base,
        json={"name": "t1", "allowed_commands": ["df -h"],
              "allowed_targets": "db.prod:5432"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "allowed_targets"

    response = client.post(
        base,
        json={"name": "t1", "allowed_commands": ["df -h"], "max_minutes": 0},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "max_minutes"

    add_task(client, row["id"], name="t-dup")
    response = client.post(
        base,
        json={"name": "t-dup", "allowed_commands": ["df -h"]},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]

    # the allow-list is bounded: 32 entries is the honest ceiling
    response = client.post(
        base,
        json={"name": "t-wide",
              "allowed_commands": [f"cmd-{i:02d}" for i in range(33)]},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["max"] == 32


def test_task_patch_edits_and_delete_removes(client):
    row, _ = add_agent(client, "ops-bot")
    task = add_task(client, row["id"])

    response = client.patch(
        f"/api/v1/agents/{row['id']}/tasks/{task['id']}",
        json={"allowed_commands": ["systemctl restart postgresql", "df -h"],
              "max_minutes": 10},
        headers=ACTOR,
    )
    assert response.status_code == 200
    view = response.get_json()["task"]
    assert len(view["allowed_commands"]) == 2
    assert view["max_minutes"] == 10

    # the name is never editable (requests reference it by name)
    response = client.patch(
        f"/api/v1/agents/{row['id']}/tasks/{task['id']}",
        json={"name": "renamed"},
        headers=ACTOR,
    )
    assert response.status_code == 400

    response = client.delete(
        f"/api/v1/agents/{row['id']}/tasks/{task['id']}", headers=ACTOR
    )
    assert response.status_code == 200
    assert response.get_json()["grants_closed"] == 0
    assert client.get(
        f"/api/v1/agents/{row['id']}/tasks", headers=ADMIN
    ).get_json() == {"tasks": [], "total": 0}
    response = client.delete(
        f"/api/v1/agents/{row['id']}/tasks/{task['id']}", headers=ACTOR
    )
    assert response.status_code == 404

    # a revoked identity's scopes are frozen
    client.delete(f"/api/v1/agents/{row['id']}", headers=ACTOR)
    response = client.post(
        f"/api/v1/agents/{row['id']}/tasks",
        json={"name": "t2", "allowed_commands": ["df -h"]},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert "frozen" in response.get_json()["error"]


# ---------------------------------------------------------------------------
# task verification: the refusals happen before anything is filed
# ---------------------------------------------------------------------------
def test_request_unknown_task_is_refused_with_evidence(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-unknown-task")

    response = ask(client, token, item["id"], task="not-declared")
    assert response.status_code == 403
    assert response.get_json()["details"]["task"] == "not-declared"
    # nothing was filed...
    assert client.get(
        "/api/v1/agent-access/requests", headers=ADMIN
    ).get_json()["total"] == 0
    # ...but the refusal is on the agent's own trail
    detail = agent_detail(client, row["id"])
    refusals = [e for e in detail["events"] if e["action"] == "access-refused"]
    assert refusals and refusals[0]["detail"]["task"] == "not-declared"
    assert refusals[0]["detail"]["reason"] == "unknown task for this identity"


def test_request_target_outside_task_scope_is_refused(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"], allowed_targets=["db.prod:5432"])
    other = onboard(client, "db-restricted", target="other.host:22")

    response = ask(client, token, other["id"])
    assert response.status_code == 403
    assert response.get_json()["details"]["allowed"] == ["db.prod:5432"]
    detail = agent_detail(client, row["id"])
    refusals = [e for e in detail["events"] if e["action"] == "access-refused"]
    assert refusals
    assert refusals[0]["detail"]["reason"] == (
        "target outside the task's allowed targets"
    )
    assert refusals[0]["detail"]["target"] == "other.host:22"


def test_request_window_cannot_exceed_task_or_identity_cap(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"], max_minutes=5)  # identity cap stays 15
    item = onboard(client, "db-cap")

    response = ask(client, token, item["id"], minutes=6)
    assert response.status_code == 400
    assert response.get_json()["details"] == {"field": "minutes", "cap": 5}

    # the identity cap can be tighter than the task's
    client.patch(
        f"/api/v1/agents/{row['id']}", json={"max_ttl_minutes": 3}, headers=ACTOR
    )
    response = ask(client, token, item["id"], minutes=5, ticket="INC-23895")
    assert response.status_code == 400
    assert response.get_json()["details"] == {"field": "minutes", "cap": 3}

    response = ask(client, token, item["id"], minutes=3, ticket="INC-23896")
    assert response.status_code == 201

    response = ask(
        client, token, item["id"], minutes=0, ticket="INC-23897"
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "minutes"


def test_request_validation(client):
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-validation")

    response = ask(client, token, item["id"], task="")
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "task"

    response = ask(client, token, None)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "item_id"

    response = ask(client, token, item["id"], reason="short")
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "reason"

    response = ask(client, token, item["id"], ticket="")
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "ticket"


# ---------------------------------------------------------------------------
# risk evaluation: the same evaluator decides, the same states come out
# ---------------------------------------------------------------------------
def test_low_risk_request_is_auto_approved_with_a_snapshotted_binding(
    client, monkeypatch
):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    task = add_task(client, row["id"])
    item = onboard(client, "db-auto", access_tier="Tier-2")

    response = ask(client, token, item["id"])
    assert response.status_code == 201
    body = response.get_json()
    request = body["request"]
    # noon on a weekday, Tier-2, five minutes, ITSM-shaped ticket: score 0
    assert request["risk"]["score"] == 0
    assert request["risk"]["level"] == "low"
    assert request["risk"]["factors"] == []
    assert request["status"] == "approved"  # low risk: no sign-off required
    assert request["requester"] == "ops-bot"
    assert request["agent_id"] == row["id"]
    assert request["agent_binding"] == {
        "agent_id": row["id"],
        "agent_name": "ops-bot",
        "task_id": task["id"],
        "task": "restart-postgres",
    }

    detail = client.get(
        f"/api/v1/agent-access/requests/{request['id']}", headers=ADMIN
    ).get_json()
    assert detail["agent"]["id"] == row["id"]
    assert "access-requested" in [e["action"] for e in detail["events"]]
    # the request also rides the normal section-6 trail
    jit = client.get(f"/api/v1/jit/requests/{request['id']}").get_json()
    assert [e["action"] for e in jit["events"]] == ["approved", "requested"]


def test_medium_risk_request_waits_for_a_manager_signoff(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-signoff", access_tier="Tier-0")

    response = ask(client, token, item["id"])
    assert response.status_code == 201
    request = response.get_json()["request"]
    assert request["risk"]["level"] == "medium"
    assert request["risk"]["score"] == 30  # Tier-0 alone, noon, clean ticket
    assert request["status"] == "pending"

    # an unapproved request cannot be opened
    response = open_access(client, token, request["id"])
    assert response.status_code == 409
    assert response.get_json()["details"]["status"] == "pending"

    # the requester never signs off its own access
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "manager"},
        headers={"X-Actor": "ops-bot", "Authorization": "Bearer test-admin-token"},
    )
    assert response.status_code == 403

    # medium risk asks for a manager only
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "security"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "manager"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    assert response.get_json()["request"]["status"] == "approved"


def test_critical_risk_request_is_blocked_with_refusal_evidence(
    client, monkeypatch
):
    # The section-7 evaluator's own bands are covered in test_jit / test_risk;
    # this is the wiring check: a critical band lands `blocked` on the agent
    # chain and nothing can be opened from it.
    monkeypatch.setattr(
        service_module,
        "_jit_risk",
        lambda *args, **kwargs: (
            90,
            "critical",
            [{"factor": "test-double", "points": 90, "detail": "wiring check"}],
        ),
    )
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-critical")

    response = ask(client, token, item["id"])
    assert response.status_code == 201
    request = response.get_json()["request"]
    assert request["risk"]["level"] == "critical"
    assert request["risk"]["score"] == 90
    assert request["status"] == "blocked"

    response = open_access(client, token, request["id"])
    assert response.status_code == 409
    assert response.get_json()["details"]["status"] == "blocked"

    # sign-off cannot rescue a critical band - only a denial is left
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/approve",
        json={"role": "manager"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    response = client.post(
        f"/api/v1/jit/requests/{request['id']}/deny",
        json={"reason": "too risky for an unattended agent"},
        headers=ACTOR,
    )
    assert response.status_code == 200

    detail = agent_detail(client, row["id"])
    actions = action_of(detail, "agent")
    assert "access-requested" in actions
    refusal = next(e for e in detail["events"] if e["action"] == "access-refused")
    assert refusal["detail"]["reason"] == (
        "critical risk - policy blocks this request"
    )


# ---------------------------------------------------------------------------
# the JIT credential: identity -> checkout -> mandatory recorded session
# ---------------------------------------------------------------------------
def test_open_requires_approved_request_and_ownership(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-open-guards")

    # pending -> 409, tested via a Tier-0 request
    tier0 = onboard(client, "db-tier0", access_tier="Tier-0")
    pending = ask(client, token, tier0["id"]).get_json()["request"]
    response = open_access(client, token, pending["id"])
    assert response.status_code == 409

    approved = ask(client, token, item["id"]).get_json()["request"]
    assert approved["status"] == "approved"

    # another identity's request is simply not visible to this token
    other, other_token = add_agent(client, "batch-runner")
    response = open_access(client, other_token, approved["id"])
    assert response.status_code == 404

    # the admin token is not an agent credential
    response = client.post(
        f"/api/v1/agent-access/requests/{approved['id']}/open",
        headers=ADMIN,
    )
    assert response.status_code == 401

    # an unknown protocol is refused before anything is consumed
    response = open_access(client, token, approved["id"], protocol="carrier-pigeon")
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "protocol"

    # still approved - the refusal consumed nothing
    row_now = client.get(
        f"/api/v1/agent-access/requests/{approved['id']}", headers=ADMIN
    ).get_json()["request"]
    assert row_now["status"] == "approved"


def test_open_consumes_grant_and_starts_recorded_session(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-open-chain")

    request = ask(client, token, item["id"]).get_json()["request"]
    response = open_access(client, token, request["id"])
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert "secret" not in body  # the session is the access, never the raw secret

    granted = body["request"]
    assert granted["status"] == "active"
    assert granted["session_ref"] == f"jit-{granted['id']}"
    assert granted["expires_at"] is not None

    session = body["session"]
    assert session["status"] == "active"
    # recording is the contract here, not a preference
    assert session["controls"]["record"] is True
    assert session["protocol"] == "ssh"
    assert session["target"] == item["target"]
    assert session["jit_request_id"] == granted["id"]
    assert session["actor"] == "ops-bot"

    # the credential is checked out under the agent for the window
    vault = vault_view(client, item["id"])
    assert vault["status"] == "checked_out"
    assert vault["checked_out_by"] == "ops-bot"

    detail = agent_detail(client, row["id"])
    opened = next(e for e in detail["events"] if e["action"] == "access-opened")
    assert opened["detail"]["session_ref"] == session["session_ref"]
    assert opened["detail"]["task"] == "restart-postgres"

    # opening twice refuses with the state
    response = open_access(client, token, request["id"])
    assert response.status_code == 409
    assert response.get_json()["details"]["status"] == "active"


def test_spec_example_commands_allow_and_block(client, monkeypatch):
    """Architecture section 16, verbatim: the declared task runs
    `systemctl restart postgresql` ALLOW, `DROP DATABASE production`
    BLOCKs - with the evidence preserved and the session terminated."""
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(
        client,
        row["id"],
        allowed_commands=["systemctl restart postgresql", "rm -rf"],
    )
    item = onboard(client, "db-spec-example")

    request = ask(client, token, item["id"]).get_json()["request"]
    opened = open_access(client, token, request["id"]).get_json()
    session_id = opened["session"]["id"]

    # section 9 on its own would hold a bare service restart for approval...
    dry = client.post(
        "/api/v1/command-control/evaluate",
        json={"command": "systemctl restart postgresql"},
    ).get_json()["result"]
    assert dry["decision"] == "approval"

    # ...but inside the declared task the restart is ALLOW (the spec example)
    allowed = post_event(
        client, session_id, "command", "systemctl restart postgresql"
    )
    assert allowed.status_code == 201
    event = allowed.get_json()["event"]
    assert event["allowed"] is True
    assert event["decision"] == "allow"
    assert "escalation" not in allowed.get_json()

    # deny beats allow: even a task-listed rm -rf stays blocked by section 9
    rules = client.get("/api/v1/command-control/rules").get_json()["items"]
    rm_rule = next(r for r in rules if r["pattern"] == "rm -rf")
    response = post_event(client, session_id, "command", "rm -rf /opt/app/cache")
    assert response.status_code == 201
    event = response.get_json()["event"]
    assert event["allowed"] is False
    assert event["decision"] == "block"
    assert event["rule_id"] == rm_rule["id"]
    assert "escalation" not in response.get_json()  # this rule does not kill

    # out of the task's scope: blocked, incident preserved, session ended
    response = post_event(client, session_id, "command", "service nginx status")
    assert response.status_code == 201
    escalation = response.get_json()["escalation"]
    incident = escalation["incident"]
    assert incident["rule_name"] == "agent task scope: restart-postgres"
    assert incident["rule_id"] is None
    assert incident["command"] == "service nginx status"

    session = client.get(
        f"/api/v1/sessions/{session_id}", headers=ADMIN
    ).get_json()["session"]
    assert session["status"] in ("terminated", "completed")

    # the violation is also on the agent's own trail, tied to the incident
    detail = agent_detail(client, row["id"])
    blocked = next(
        e for e in detail["events"] if e["action"] == "command-blocked"
    )
    assert blocked["detail"]["incident"] == incident["incident_ref"]
    assert blocked["detail"]["task"] == "restart-postgres"
    assert blocked["detail"]["reason"] == (
        "command is not in the task's allowed list"
    )

    # the cascade ended the grant and rotated the credential
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["checked_out_by"] is None
    assert vault["last_rotated_at"] is not None
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_open_refusal_releases_the_grant(client, monkeypatch):
    class _RefusedRisk:
        result = "refused"
        decision = "block"
        band = "high"

        def to_dict(self):
            return {"band": "high", "decision": "block", "result": "refused"}

    monkeypatch.setattr(
        service_module,
        "evaluate_risk",
        lambda *args, **kwargs: _RefusedRisk(),
    )
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-refused-start")

    request = ask(client, token, item["id"]).get_json()["request"]
    response = open_access(client, token, request["id"])
    assert response.status_code == 403
    assert response.get_json()["details"]["risk"]["result"] == "refused"

    # nothing stays checked out on the agent's behalf
    after = client.get(
        f"/api/v1/agent-access/requests/{request['id']}", headers=ADMIN
    ).get_json()
    assert after["request"]["status"] == "closed"
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["last_rotated_at"] is not None
    refusal = next(
        e for e in after["events"] if e["action"] == "access-refused"
    )
    assert refusal["detail"]["reason"] == (
        "risk policy refused the session start"
    )


# ---------------------------------------------------------------------------
# close, revoke, task withdrawal and expiry
# ---------------------------------------------------------------------------
def test_close_is_dual_auth_and_rotates(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-close")

    request = ask(client, token, item["id"]).get_json()["request"]
    open_access(client, token, request["id"])

    # no credential at all
    response = client.post(
        f"/api/v1/agent-access/requests/{request['id']}/close"
    )
    assert response.status_code == 401

    # another identity's token cannot close it
    other, other_token = add_agent(client, "batch-runner")
    response = client.post(
        f"/api/v1/agent-access/requests/{request['id']}/close",
        headers=agent(other_token),
    )
    assert response.status_code == 404

    # the agent closes its own access with its token
    response = client.post(
        f"/api/v1/agent-access/requests/{request['id']}/close",
        headers=agent(token),
    )
    assert response.status_code == 200
    assert response.get_json()["request"]["status"] == "closed"

    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["last_rotated_at"] is not None
    assert vault["secret_version"] >= 2

    detail = agent_detail(client, row["id"])
    ended = next(e for e in detail["events"] if e["action"] == "access-ended")
    assert ended["actor"] == "ops-bot"

    # a closed grant cannot be closed again
    response = client.post(
        f"/api/v1/agent-access/requests/{request['id']}/close",
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "closed"

    # an admin closes any (second grant, opened and closed by the admin)
    second = ask(client, token, item["id"], ticket="INC-23900").get_json()
    if second["request"]["status"] != "approved":
        client.post(
            f"/api/v1/jit/requests/{second['request']['id']}/approve",
            json={"role": "manager"},
            headers=ACTOR,
        )
    open_access(client, token, second["request"]["id"])
    response = client.post(
        f"/api/v1/agent-access/requests/{second['request']['id']}/close",
        headers=ACTOR,
    )
    assert response.status_code == 200


def test_revoke_closes_access_and_blocks_token(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-revoke")
    tier0 = onboard(client, "db-revoke-pending", access_tier="Tier-0")

    active = ask(client, token, item["id"]).get_json()["request"]
    open_access(client, token, active["id"])
    pending = ask(client, token, tier0["id"]).get_json()["request"]
    assert pending["status"] == "pending"

    response = client.delete(
        f"/api/v1/agents/{row['id']}",
        json={"reason": "operator retired"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["grants_closed"] == 2  # the active grant + the queued request
    assert body["agent"]["status"] == "revoked"

    # the active grant went through the real release-and-rotate path
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["last_rotated_at"] is not None

    # the queued request closed without a release
    queued = client.get(
        f"/api/v1/agent-access/requests/{pending['id']}", headers=ADMIN
    ).get_json()["request"]
    assert queued["status"] == "closed"

    # the token stops authenticating, and a second revoke is a 409
    response = ask(client, token, item["id"], ticket="INC-23901")
    assert response.status_code == 401
    assert "revoked" in response.get_json()["error"]
    response = client.delete(f"/api/v1/agents/{row['id']}", headers=ACTOR)
    assert response.status_code == 409

    detail = agent_detail(client, row["id"])
    revoked = next(e for e in detail["events"] if e["action"] == "agent-revoked")
    assert revoked["detail"]["reason"] == "operator retired"
    assert revoked["detail"]["grants_closed"] == 2


def test_task_delete_ends_the_access_riding_it(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    task = add_task(client, row["id"])
    item = onboard(client, "db-task-withdrawn")

    request = ask(client, token, item["id"]).get_json()["request"]
    open_access(client, token, request["id"])

    response = client.delete(
        f"/api/v1/agents/{row['id']}/tasks/{task['id']}", headers=ACTOR
    )
    assert response.status_code == 200
    assert response.get_json()["grants_closed"] == 1

    closed = client.get(
        f"/api/v1/agent-access/requests/{request['id']}", headers=ADMIN
    ).get_json()["request"]
    assert closed["status"] == "closed"
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["last_rotated_at"] is not None
    removed = [
        e for e in agent_detail(client, row["id"])["events"]
        if e["action"] == "task-removed"
    ]
    assert removed and removed[0]["detail"]["grants_closed"] == 1


def test_active_grant_expires_and_rotates(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"], max_minutes=5)
    item = onboard(client, "db-expiry")

    request = ask(client, token, item["id"]).get_json()["request"]
    opened = open_access(client, token, request["id"]).get_json()
    assert opened["request"]["expires_at"].startswith("2026-10-07T12:05")

    _clock_at(monkeypatch, NOON + timedelta(minutes=6))
    rows = client.get(
        "/api/v1/agent-access/requests", headers=ADMIN
    ).get_json()["items"]
    row_now = next(r for r in rows if r["id"] == request["id"])
    assert row_now["status"] == "expired"

    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["checked_out_by"] is None
    assert vault["secret_version"] >= 2

    session = client.get(
        f"/api/v1/sessions/{opened['session']['id']}", headers=ADMIN
    ).get_json()["session"]
    assert session["status"] in ("terminated", "completed")

    stats = client.get("/api/v1/agent-access/stats").get_json()
    assert stats["requests"]["open"] == 0


# ---------------------------------------------------------------------------
# queue, trail, aggregates and the ledger
# ---------------------------------------------------------------------------
def test_access_queue_detail_and_stats_reflect_real_rows(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-queue")
    tier0 = onboard(client, "db-queue-pending", access_tier="Tier-0")

    # a human request stays in the human queue, never this one
    human = client.post(
        "/api/v1/jit/requests",
        json={"item_id": item["id"], "reason": "Human request window",
              "ticket": "INC-7777", "minutes": 15},
        headers=ACTOR,
    )
    assert human.status_code == 201

    approved = ask(client, token, item["id"]).get_json()["request"]
    open_access(client, token, approved["id"])
    pending = ask(client, token, tier0["id"]).get_json()["request"]

    rows = client.get("/api/v1/agent-access/requests", headers=ADMIN).get_json()
    assert rows["total"] == 2  # the human row is not here
    assert all(r["agent_id"] == row["id"] for r in rows["items"])
    assert human.get_json()["request"]["id"] not in [r["id"] for r in rows["items"]]

    rows = client.get(
        "/api/v1/agent-access/requests?status=pending", headers=ADMIN
    ).get_json()
    assert rows["total"] == 1 and rows["items"][0]["id"] == pending["id"]
    rows = client.get(
        f"/api/v1/agent-access/requests?agent_id={row['id']}", headers=ADMIN
    ).get_json()
    assert rows["total"] == 2
    assert client.get(
        "/api/v1/agent-access/requests?status=maybe", headers=ADMIN
    ).status_code == 400

    # the human request is not an agent access detail (404, not a leak)
    assert client.get(
        f"/api/v1/agent-access/requests/{human.get_json()['request']['id']}",
        headers=ADMIN,
    ).status_code == 404

    stats = client.get("/api/v1/agent-access/stats").get_json()
    assert stats["identities"]["total"] == 1
    assert stats["identities"]["by_status"] == {
        "active": 1, "disabled": 0, "revoked": 0,
    }
    assert stats["tasks"] == 1
    assert stats["requests"]["total"] == 2
    assert stats["requests"]["by_status"]["active"] == 1
    assert stats["requests"]["by_status"]["pending"] == 1
    assert stats["requests"]["open"] == 2  # active + pending (approved 0)
    assert stats["events"] >= 5


def test_agent_trail_reaches_the_ledger_as_the_fifteenth_source(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    row, token = add_agent(client, "ops-bot")
    add_task(client, row["id"])
    item = onboard(client, "db-ledger")
    request = ask(client, token, item["id"]).get_json()["request"]
    open_access(client, token, request["id"])

    assert len(audit_module.AUDIT_SOURCES) == 15
    assert audit_module.AUDIT_SOURCES[-1] == "agent"
    events = client.get(
        "/api/v1/events?source=agent&limit=50"
    ).get_json()["events"]
    assert events and all(e["source"] == "agent" for e in events)
    assert all(e["id"].startswith("agent:") for e in events)
    actions = {e["action"] for e in events}
    assert {"agent-created", "task-added", "access-requested",
            "access-opened"} <= actions
    assert client.get("/api/v1/audit/stats").get_json()["by_source"]["agent"] >= 1
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True
