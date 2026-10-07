"""Tests for privileged session management (architecture module 8).

The whole channel is exercised for real: a session starts against a vault
credential (checked out under session_ref sess-<hex>) or attaches to an
active JIT grant, events flow in sequence order with custody watermarks,
the control flags gate transfers/clipboard/screenshots for real (blocked
attempts stay as evidence), keystroke logging can withhold content, pause/
lock refuse events until resumed, and ending a session runs the release-
and-rotate cascade exactly once - including when a linked JIT grant closes
with it or expires under it.

Run with:  python -m pytest backend/phase2_license_server/tests/test_sessions.py -q
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
    JitRequest,
    PrivilegedSession,
    SessionEvent,
    VaultItem,
    db,
)
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

GOOD_TICKET = "INC-1234"


class _Clock(datetime):
    """Wednesday 2026-10-07 noon (only used by the grant-expiry test)."""

    FIXED = datetime(2026, 10, 7, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):
        return cls.FIXED


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


def insert_item(app, name, *, status="available", access_tier="Tier-1"):
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


def get_item(client, item_id):
    response = client.get(f"/api/v1/vault/items/{item_id}")
    assert response.status_code == 200
    return response.get_json()["item"]


def start_session(client, **payload):
    base = {"protocol": "ssh", "target": "web-01.prod:22"}
    base.update(payload)
    response = client.post("/api/v1/sessions", json=base, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["session"]


def post_event(client, session_id, event_type, content="", **extra_headers):
    return client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": event_type, "content": content},
        headers={**ACTOR, **extra_headers},
    )


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


def make_active_grant(client, name):
    """A low-risk (auto-approved) request, granted: returns (item, request)."""
    item = onboard(client, name, access_tier="Tier-2")
    request = create_request(client, item["id"], minutes=15)
    assert request["status"] == "approved", request["risk"]
    granted = client.post(
        f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR
    )
    assert granted.status_code == 200, granted.get_json()
    return item, granted.get_json()["request"]


# --- validation / create ------------------------------------------------------


def test_create_validates_protocol_target_and_controls(client):
    for payload, field in (
        ({"protocol": "smtp", "target": "mail:25"}, "protocol"),
        ({"protocol": "SSH", "target": ""}, "target"),
        ({"protocol": "ssh", "target": " "}, "target"),
        ({"protocol": "ssh", "target": "h:22", "record": "yes"}, "record"),
        ({"protocol": "ssh", "target": "h:22", "item_id": "5"}, "item_id"),
        ({"protocol": "ssh", "target": "h:22", "item_id": True}, "item_id"),
    ):
        response = client.post("/api/v1/sessions", json=payload, headers=ACTOR)
        assert response.status_code == 400, (payload, response.get_json())
        assert response.get_json()["details"]["field"] == field

    # the protocol enum comes straight from the architecture's list
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "smtp", "target": "mail:25"},
        headers=ACTOR,
    )
    allowed = response.get_json()["details"]["allowed"]
    assert "ssh" in allowed and "kubernetes" in allowed and "smtp" not in allowed

    # unknown ids are 404s, not 500s
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "item_id": 4242},
        headers=ACTOR,
    )
    assert response.status_code == 404
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "jit_request_id": 4242},
        headers=ACTOR,
    )
    assert response.status_code == 404

    # a JSON body is mandatory
    response = client.post(
        "/api/v1/sessions", json=["not", "an", "object"], headers=ACTOR
    )
    assert response.status_code == 400


def test_create_requires_admin_and_reads_stay_public(client):
    response = client.post(
        "/api/v1/sessions", json={"protocol": "ssh", "target": "h:22"}
    )
    assert response.status_code == 401
    assert client.post("/api/v1/sessions/1/pause").status_code == 401
    assert (
        client.post(
            "/api/v1/sessions/1/events", json={"type": "command", "content": "ls"}
        ).status_code
        == 401
    )
    # reads render the console without a token, like the other screens
    assert client.get("/api/v1/sessions").status_code == 200
    assert client.get("/api/v1/sessions/stats").status_code == 200


def test_create_checks_out_the_vault_credential(client):
    item = onboard(client, "sess-checkout")
    session = start_session(client, item_id=item["id"], target="db.internal:5432")
    assert session["status"] == "active"
    assert session["session_ref"].startswith("sess-")
    assert session["item_id"] == item["id"]
    assert session["jit_request_id"] is None
    assert session["actor"] == "tester"
    assert session["ended_at"] is None and session["end_reason"] is None
    assert session["duration_seconds"] >= 0
    assert all(session["controls"].values())

    held = get_item(client, item["id"])
    assert held["status"] == "checked_out"
    assert held["checked_out_by"] == "tester"

    # the recording starts with one server-written status event
    detail = client.get(f"/api/v1/sessions/{session['id']}").get_json()
    assert detail["event_count"] == 1 and detail["blocked_count"] == 0
    assert detail["events"][0]["type"] == "status"
    assert detail["events"][0]["content"] == "session started"
    assert detail["events"][0]["seq"] == 1

    # the checkout itself is audited with the session's custody ref
    checked_out = client.get(
        "/api/v1/vault/events?action=checked_out"
    ).get_json()["events"]
    assert any(
        e["item_id"] == item["id"]
        and session["session_ref"] in str(e["detail"].get("reason", ""))
        for e in checked_out
    )


def test_create_conflicts_on_held_or_rotating_credential(client, app):
    held = onboard(client, "sess-held")
    checkout = client.post(
        f"/api/v1/vault/items/{held['id']}/checkout",
        json={"reason": "somebody else"},
        headers=ACTOR,
    )
    assert checkout.status_code == 200
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "item_id": held["id"]},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert response.get_json()["details"]["field"] == "status"

    rotating = insert_item(app, "sess-rotating", status="rotating")
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "item_id": rotating},
        headers=ACTOR,
    )
    assert response.status_code == 409


def test_create_attaches_to_an_active_grant_without_second_checkout(
    client, clock
):
    item, grant = make_active_grant(client, "sess-grant")
    held_before = get_item(client, item["id"])

    session = start_session(client, jit_request_id=grant["id"])
    assert session["jit_request_id"] == grant["id"]
    assert session["item_id"] == item["id"]
    assert session["session_ref"].startswith("sess-")
    assert session["session_ref"] != grant["session_ref"]

    held_after = get_item(client, item["id"])
    assert held_after["status"] == "checked_out"
    assert held_after["checked_out_at"] == held_before["checked_out_at"]


def test_create_rejects_grants_that_are_not_active_or_already_livened(
    client, clock
):
    # pending (medium risk, manager not yet approved): not grantable to a session
    # Tier-0 puts the request at 30 points -> medium, which needs the manager
    pending_item = onboard(client, "sess-pending", access_tier="Tier-0")
    pending = create_request(client, pending_item["id"])
    assert pending["status"] == "pending"
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "jit_request_id": pending["id"]},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "pending"

    # approved but not consumed yet: still not an active grant
    # (approvers must differ from the requester - self-approval is 403)
    approved = client.post(
        f"/api/v1/jit/requests/{pending['id']}/approve",
        json={"role": "manager"},
        headers={**ACTOR, "X-Actor": "mgr"},
    )
    assert approved.status_code == 200
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "h:22", "jit_request_id": pending["id"]},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "approved"

    # an active grant hosts exactly one live session - pausing it does not
    # free the slot
    _, grant = make_active_grant(client, "sess-livewire")
    first = start_session(client, jit_request_id=grant["id"])
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "rdp", "target": "dc-01:389", "jit_request_id": grant["id"]},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert response.get_json()["details"]["session_id"] == first["id"]
    assert (
        client.post(
            f"/api/v1/sessions/{first['id']}/pause", headers=ACTOR
        ).status_code
        == 200
    )
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "rdp", "target": "dc-01:389", "jit_request_id": grant["id"]},
        headers=ACTOR,
    )
    assert response.status_code == 409


# --- recording ----------------------------------------------------------------


def test_events_flow_with_sequence_order_and_watermark(client):
    session = start_session(client, watermark=True)
    sid = session["id"]

    command = post_event(client, sid, "command", "df -h").get_json()["event"]
    assert command["seq"] == 2 and command["allowed"] is True
    assert session["session_ref"] in command["watermark"]
    assert "tester" in command["watermark"]
    typed = post_event(
        client, sid, "keystroke", "deploy", **{"X-Actor": "recorder"}
    ).get_json()["event"]
    assert typed["seq"] == 3
    assert "recorder" in typed["watermark"]  # the posting actor, not the owner
    note = post_event(client, sid, "note", "operator checked the logs").get_json()[
        "event"
    ]
    assert note["seq"] == 4

    playback = client.get(f"/api/v1/sessions/{sid}/events").get_json()
    assert playback["total"] == 4
    assert [e["seq"] for e in playback["events"]] == [1, 2, 3, 4]
    assert [e["type"] for e in playback["events"]] == [
        "status", "command", "keystroke", "note",
    ]

    tail = client.get(f"/api/v1/sessions/{sid}/events?order=desc").get_json()
    assert tail["events"][0]["seq"] == 4
    only_commands = client.get(
        f"/api/v1/sessions/{sid}/events?type=command"
    ).get_json()
    assert only_commands["total"] == 1
    assert only_commands["events"][0]["content"] == "df -h"


def test_controls_gate_transfers_clipboard_and_screenshot_with_evidence(client):
    session = start_session(
        client,
        upload_allowed=False,
        download_allowed=False,
        clipboard_allowed=False,
        screenshot_allowed=False,
    )
    sid = session["id"]

    for event_type, why in (
        ("file_upload", "upload_not_allowed"),
        ("file_download", "download_not_allowed"),
        ("clipboard", "clipboard_not_allowed"),
        ("screenshot", "screenshot_not_allowed"),
    ):
        body = post_event(client, sid, event_type, "payload").get_json()["event"]
        assert body["allowed"] is False, event_type
        assert body["blocked_reason"] == why, event_type
        assert body["content"] == "payload"  # the attempt is kept as evidence

    allowed = post_event(client, sid, "command", "ls").get_json()["event"]
    assert allowed["allowed"] is True

    detail = client.get(f"/api/v1/sessions/{sid}").get_json()
    assert detail["blocked_count"] == 4
    assert client.get("/api/v1/sessions/stats").get_json()["events_blocked"] == 4


def test_keystroke_logging_off_withholds_content(client):
    session = start_session(client, keystroke_log=False)
    body = post_event(client, session["id"], "keystroke", "hunter2").get_json()[
        "event"
    ]
    assert body["withheld"] is True
    assert body["content"] is None
    stats = client.get("/api/v1/sessions/stats").get_json()
    assert stats["events_withheld"] == 1


def test_record_off_refuses_content_but_keeps_the_safety_channel(client):
    session = start_session(client, record=False, keystroke_log=True)

    refused = post_event(client, session["id"], "keystroke", "secret")
    assert refused.status_code == 400
    assert refused.get_json()["details"]["record"] is False
    note_refused = post_event(client, session["id"], "note", "observation")
    assert note_refused.status_code == 400

    # commands still flow: command control (module 9) must see them
    kept = post_event(client, session["id"], "command", "systemctl restart nginx")
    assert kept.status_code == 201
    assert kept.get_json()["event"]["content"] == "systemctl restart nginx"
    assert client.get(
        f"/api/v1/sessions/{session['id']}/events"
    ).get_json()["total"] == 2  # started status + command


def test_event_validation_rejects_type_and_content(client):
    session = start_session(client)
    sid = session["id"]

    response = post_event(client, sid, "keylog", "x")
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "type"
    response = post_event(client, sid, "command", "x" * 4097)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "content"
    response = client.post(
        f"/api/v1/sessions/{sid}/events",
        json={"type": "command", "content": 42},
        headers=ACTOR,
    )
    assert response.status_code == 400
    response = client.post(
        f"/api/v1/sessions/{sid}/events", json=["nope"], headers=ACTOR
    )
    assert response.status_code == 400


def test_controls_update_takes_effect_and_is_audited(client):
    session = start_session(client)
    sid = session["id"]

    allowed_before = post_event(client, sid, "file_upload", "report.csv")
    assert allowed_before.get_json()["event"]["allowed"] is True

    flipped = client.post(
        f"/api/v1/sessions/{sid}/controls",
        json={"upload_allowed": False},
        headers=ACTOR,
    )
    assert flipped.status_code == 200
    assert flipped.get_json()["session"]["controls"]["upload_allowed"] is False
    blocked = post_event(client, sid, "file_upload", "report.csv")
    assert blocked.get_json()["event"]["allowed"] is False

    # the change itself is on the recording
    playback = client.get(f"/api/v1/sessions/{sid}/events").get_json()["events"]
    status_contents = [e["content"] for e in playback if e["type"] == "status"]
    assert any(
        c and c.startswith("controls updated") and "upload_allowed=off" in c
        for c in status_contents
    )


def test_controls_update_validation(client):
    session = start_session(client)
    sid = session["id"]
    for payload, field in (
        ({}, "controls"),
        ({"teleport": True}, "teleport"),
        ({"record": "no"}, "record"),
    ):
        response = client.post(
            f"/api/v1/sessions/{sid}/controls", json=payload, headers=ACTOR
        )
        assert response.status_code == 400, payload
        assert response.get_json()["details"]["field"] == field

    client.post(f"/api/v1/sessions/{sid}/terminate", headers=ACTOR)
    response = client.post(
        f"/api/v1/sessions/{sid}/controls",
        json={"record": False},
        headers=ACTOR,
    )
    assert response.status_code == 400


# --- state machine ------------------------------------------------------------


def test_pause_and_resume_gate_the_channel(client):
    session = start_session(client)
    sid = session["id"]

    paused = client.post(f"/api/v1/sessions/{sid}/pause", headers=ACTOR)
    assert paused.status_code == 200
    assert paused.get_json()["session"]["status"] == "paused"

    refused = post_event(client, sid, "command", "whoami")
    assert refused.status_code == 409
    assert refused.get_json()["details"]["status"] == "paused"
    again = client.post(f"/api/v1/sessions/{sid}/pause", headers=ACTOR)
    assert again.status_code == 400

    resumed = client.post(f"/api/v1/sessions/{sid}/resume", headers=ACTOR)
    assert resumed.status_code == 200
    assert resumed.get_json()["session"]["status"] == "active"
    assert post_event(client, sid, "command", "whoami").status_code == 201

    # resuming a running session is a no-op error, not a silent success
    assert (
        client.post(f"/api/v1/sessions/{sid}/resume", headers=ACTOR).status_code
        == 400
    )

    contents = [
        e["content"]
        for e in client.get(f"/api/v1/sessions/{sid}/events").get_json()["events"]
        if e["type"] == "status"
    ]
    assert "session paused" in contents and "session resumed" in contents


def test_lock_gates_the_channel_until_resume(client):
    session = start_session(client)
    sid = session["id"]

    locked = client.post(f"/api/v1/sessions/{sid}/lock", headers=ACTOR)
    assert locked.status_code == 200
    assert locked.get_json()["session"]["status"] == "locked"
    assert post_event(client, sid, "command", "id").status_code == 409
    assert client.post(
        f"/api/v1/sessions/{sid}/resume", headers=ACTOR
    ).get_json()["session"]["status"] == "active"

    # a paused session can also be locked (review flow)
    client.post(f"/api/v1/sessions/{sid}/pause", headers=ACTOR)
    assert client.post(
        f"/api/v1/sessions/{sid}/lock", headers=ACTOR
    ).get_json()["session"]["status"] == "locked"


def test_ended_session_refuses_events_and_control_changes(client):
    session = start_session(client, item_id=None)
    sid = session["id"]
    client.post(f"/api/v1/sessions/{sid}/terminate", headers=ACTOR)

    refused = post_event(client, sid, "command", "ls")
    assert refused.status_code == 409
    assert refused.get_json()["details"]["status"] == "terminated"
    for path in ("pause", "resume", "lock"):
        assert (
            client.post(f"/api/v1/sessions/{sid}/{path}", headers=ACTOR).status_code
            == 400
        )
    # playback still serves the recording
    assert client.get(f"/api/v1/sessions/{sid}/events").status_code == 200


# --- end + release-and-rotate cascade ------------------------------------------


def test_terminate_releases_checkout_and_rotates_once(client):
    item = onboard(client, "sess-terminate")
    session = start_session(client, item_id=item["id"], target="db.internal:5432")
    version_before = get_item(client, item["id"])["secret_version"]

    response = client.post(
        f"/api/v1/sessions/{session['id']}/terminate",
        json={"reason": "incident resolved"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    body = response.get_json()
    ended = body["session"]
    assert ended["status"] == "terminated"
    assert ended["end_reason"] == "terminated"
    assert ended["ended_at"] is not None and ended["duration_seconds"] >= 0

    cascade = body["cascade"]
    assert cascade["checkout_released"] is True
    assert cascade["rotated"] is True
    assert cascade["secret_version"] == version_before + 1
    assert cascade["session_ref"] == session["session_ref"]

    released = get_item(client, item["id"])
    assert released["status"] == "available"
    assert released["checked_out_by"] is None
    assert released["secret_version"] == version_before + 1

    rotated = [
        e
        for e in client.get("/api/v1/vault/events?action=rotated").get_json()["events"]
        if e["item_id"] == item["id"]
        and e["detail"].get("session_ref") == session["session_ref"]
    ]
    assert rotated, "ending a session must audit a session-end rotation"

    contents = [
        e["content"]
        for e in client.get(f"/api/v1/sessions/{session['id']}/events").get_json()[
            "events"
        ]
        if e["type"] == "status"
    ]
    assert "session terminated: incident resolved" in contents
    assert "checkout released; credential rotated" in contents

    # ending twice is refused
    again = client.post(
        f"/api/v1/sessions/{session['id']}/terminate", headers=ACTOR
    )
    assert again.status_code == 400


def test_complete_records_natural_end_for_a_bare_session(client):
    session = start_session(client, target="bastion.example:22")
    response = client.post(
        f"/api/v1/sessions/{session['id']}/complete",
        json={"reason": "work finished"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["session"]["status"] == "completed"
    assert body["session"]["end_reason"] == "completed"
    # nothing was held: honest cascade, no fake rotation
    assert body["cascade"]["rotated"] is False
    assert body["cascade"]["checkout_released"] is False
    assert client.post(
        f"/api/v1/sessions/{session['id']}/complete", headers=ACTOR
    ).status_code == 400


def test_terminate_closes_linked_grant_with_single_rotation(client, clock):
    item, grant = make_active_grant(client, "sess-link")
    session = start_session(client, jit_request_id=grant["id"])
    version_before = get_item(client, item["id"])["secret_version"]

    response = client.post(
        f"/api/v1/sessions/{session['id']}/terminate", headers=ACTOR
    )
    assert response.status_code == 200
    cascade = response.get_json()["cascade"]
    assert cascade["grant_closed"] is True
    assert cascade["rotated"] is True
    assert cascade["checkout_released"] is True
    assert cascade["secret_version"] == version_before + 1

    # exactly one rotation ran (session -> grant close -> rotate, once)
    released = get_item(client, item["id"])
    assert released["status"] == "available"
    assert released["secret_version"] == version_before + 1

    grant_row = client.get(f"/api/v1/jit/requests/{grant['id']}").get_json()
    assert grant_row["request"]["status"] == "closed"


def test_grant_expiry_ends_linked_session_without_double_rotation(
    client, app, clock
):
    item, grant = make_active_grant(client, "sess-expiry")
    session = start_session(client, jit_request_id=grant["id"])
    version_before = get_item(client, item["id"])["secret_version"]

    with app.app_context():
        row = db.session.get(JitRequest, grant["id"])
        row.expires_at = _Clock.FIXED - timedelta(minutes=1)
        db.session.commit()

    # any session read evaluates grant expiry, which ends the session with it
    listed = client.get("/api/v1/sessions").get_json()
    row = next(s for s in listed["items"] if s["id"] == session["id"])
    assert row["status"] == "terminated"
    assert row["end_reason"] == "grant_expired"
    assert row["ended_at"] is not None

    rotated = get_item(client, item["id"])
    assert rotated["status"] == "available"
    assert rotated["secret_version"] == version_before + 1  # once, not twice

    contents = [
        e["content"]
        for e in client.get(f"/api/v1/sessions/{session['id']}/events").get_json()[
            "events"
        ]
        if e["type"] == "status"
    ]
    assert any("access grant ended (expired)" in c for c in contents)


def test_session_ends_even_when_checkout_was_revoked_earlier(client):
    item = onboard(client, "sess-revoked")
    session = start_session(client, item_id=item["id"])
    revoke = client.post(
        f"/api/v1/vault/items/{item['id']}/revoke", headers=ACTOR
    )
    assert revoke.status_code == 200

    response = client.post(
        f"/api/v1/sessions/{session['id']}/terminate", headers=ACTOR
    )
    assert response.status_code == 200
    # nothing is held anymore: the session ends without inventing a rotation
    assert response.get_json()["cascade"]["rotated"] is False
    assert response.get_json()["session"]["status"] == "terminated"
    assert get_item(client, item["id"])["status"] == "available"


# --- stats / list / lookups ----------------------------------------------------


def test_stats_and_list_filters_reflect_real_rows(client):
    first = start_session(client, protocol="ssh", target="web-01.prod:22")
    second = start_session(client, protocol="rdp", target="dc-01.corp:389")
    client.post(f"/api/v1/sessions/{second['id']}/pause", headers=ACTOR)

    stats = client.get("/api/v1/sessions/stats").get_json()
    assert stats["total"] == 2
    assert stats["active"] == 1 and stats["paused"] == 1
    assert stats["ended"] == 0
    assert stats["by_status"]["active"] == 1
    # 2 started events + 1 pause marker
    assert stats["events_total"] == 3
    assert sum(stats["by_status"].values()) == stats["total"]

    only_paused = client.get("/api/v1/sessions?status=paused").get_json()
    assert [s["id"] for s in only_paused["items"]] == [second["id"]]
    only_ssh = client.get("/api/v1/sessions?protocol=ssh").get_json()
    assert [s["id"] for s in only_ssh["items"]] == [first["id"]]
    searched = client.get("/api/v1/sessions?q=web-01").get_json()
    assert [s["id"] for s in searched["items"]] == [first["id"]]
    paged = client.get("/api/v1/sessions?limit=1&offset=1").get_json()
    assert paged["total"] == 2 and len(paged["items"]) == 1

    assert client.get("/api/v1/sessions?status=bogus").status_code == 400
    assert client.get("/api/v1/sessions?protocol=bogus").status_code == 400


def test_unknown_sessions_and_event_filters_answer_404_400(client):
    assert client.get("/api/v1/sessions/999").status_code == 404
    assert client.get("/api/v1/sessions/999/events").status_code == 404
    assert (
        client.post(
            "/api/v1/sessions/999/events",
            json={"type": "command", "content": "ls"},
            headers=ACTOR,
        ).status_code
        == 404
    )
    session = start_session(client)
    assert (
        client.get(
            f"/api/v1/sessions/{session['id']}/events?type=bogus"
        ).status_code
        == 400
    )
    assert (
        client.get(
            f"/api/v1/sessions/{session['id']}/events?order=sideways"
        ).status_code
        == 400
    )
