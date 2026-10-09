"""Tests for the section-12 dynamic watermark (contextual session overlay).

The six-line overlay USER / SESSION / TARGET / TIME / TICKET / SOURCE is
assembled only from real session rows: the principal and custody ref from the
row, the clock of the latest recorded event (so TIME moves when the session
does), the ticket of the linked JIT grant, and the source address recorded at
start. Pause/resume/terminate change the payload's `state`, the watermark
control gates whether `text` is rendered at all, and the payload rides along
with GET /api/v1/sessions/{id} as an additive field - the list view and every
older detail key stay exactly as they were.

Run with:  python -m pytest backend/phase2_license_server/tests/test_watermark.py -q
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
import service as service_module  # noqa: E402
import models as models_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

GOOD_TICKET = "INC-1234"
SOURCE_IP = "10.20.1.10"
# the frozen clock the whole module runs against; tests that advance time
# move this value and every stamped row follows it.
BASE_TIME = datetime(2026, 10, 7, 12, 0, 0)


class _Clock(datetime):
    FIXED = BASE_TIME

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
    # reset the shared class attribute so a time-advancing test cannot leak
    # its value into the next one.
    _Clock.FIXED = BASE_TIME
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


def make_active_grant(client, name):
    """A low-risk (auto-approved) request, consumed: (item, active grant)."""
    item = onboard(client, name, access_tier="Tier-2")
    response = client.post(
        "/api/v1/jit/requests",
        json={
            "item_id": item["id"],
            "reason": "Watermark evidence window",
            "ticket": GOOD_TICKET,
            "minutes": 15,
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    request = response.get_json()["request"]
    assert request["status"] == "approved", request["risk"]
    granted = client.post(
        f"/api/v1/jit/requests/{request['id']}/consume", headers=ACTOR
    )
    assert granted.status_code == 200, granted.get_json()
    return item, granted.get_json()["request"]


def start_session(client, **payload):
    base = {"protocol": "ssh", "target": "web-01.prod:22"}
    base.update(payload)
    response = client.post("/api/v1/sessions", json=base, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["session"]


def watermark_of(client, session_id):
    response = client.get(f"/api/v1/sessions/{session_id}")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


# --- the payload --------------------------------------------------------------


def test_watermark_payload_comes_from_the_session_row(client, clock):
    session = start_session(
        client,
        device="laptop-7",
        source_ip=SOURCE_IP,
        watermark=True,
    )
    detail = watermark_of(client, session["id"])
    wm = detail["watermark"]

    # the six fields are this session's own row - nothing is invented
    assert wm["enabled"] is True
    assert wm["state"] == "active"
    assert wm["fields"] == {
        "user": session["actor"],
        "session": session["session_ref"],
        "target": "web-01.prod:22",
        "time": "07-Oct-2026 12:00",
        "ticket": None,  # no grant rides this session
        "source": SOURCE_IP,
    }
    # the rendered overlay is exactly the section-12 example's shape, with an
    # em dash where this session genuinely has no value.
    assert wm["text"] == (
        "USER: tester\n"
        f"SESSION: {session['session_ref']}\n"
        "TARGET: web-01.prod:22\n"
        "TIME: 07-Oct-2026 12:00\n"
        "TICKET: —\n"
        f"SOURCE: {SOURCE_IP}"
    )

    # per-event custody strings keep riding the recording while the control
    # is on (the 4c evidence chain this payload sits on top of).
    assert detail["events"], detail
    custody = [ev["watermark"] for ev in detail["events"]]
    assert all(
        value and value.startswith(session["session_ref"] + " | tester | ")
        for value in custody
    )


def test_watermark_time_tracks_the_latest_event_and_state(client, clock):
    session = start_session(client, source_ip=SOURCE_IP)
    assert watermark_of(client, session["id"])["watermark"]["fields"]["time"] == (
        "07-Oct-2026 12:00"
    )

    # pause half an hour later: the status event is stamped 12:30, so the
    # overlay's TIME and STATE both move with the session.
    _Clock.FIXED = datetime(2026, 10, 7, 12, 30, 0)
    paused = client.post(
        f"/api/v1/sessions/{session['id']}/pause", headers=ACTOR
    )
    assert paused.status_code == 200, paused.get_json()
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["state"] == "paused"
    assert wm["fields"]["time"] == "07-Oct-2026 12:30"
    assert "TIME: 07-Oct-2026 12:30" in wm["text"]

    # resume an hour on
    _Clock.FIXED = datetime(2026, 10, 7, 13, 30, 0)
    resumed = client.post(
        f"/api/v1/sessions/{session['id']}/resume", headers=ACTOR
    )
    assert resumed.status_code == 200, resumed.get_json()
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["state"] == "active"
    assert wm["fields"]["time"] == "07-Oct-2026 13:30"

    # terminate: the state closes for good and the clock freezes on the final
    # recorded event - re-reading later changes nothing.
    _Clock.FIXED = datetime(2026, 10, 7, 14, 5, 0)
    ended = client.post(
        f"/api/v1/sessions/{session['id']}/terminate",
        json={"reason": "watermark test complete"},
        headers=ACTOR,
    )
    assert ended.status_code == 200, ended.get_json()
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["state"] == "terminated"
    assert wm["fields"]["time"] == "07-Oct-2026 14:05"
    assert wm["text"] is not None  # the final overlay stays as evidence
    _Clock.FIXED = datetime(2026, 10, 7, 15, 0, 0)
    assert watermark_of(client, session["id"])["watermark"] == wm


def test_watermark_ticket_comes_from_the_linked_grant(client, clock):
    _item, grant = make_active_grant(client, "wm-grant-item")
    session = start_session(client, jit_request_id=grant["id"])
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["fields"]["ticket"] == GOOD_TICKET
    assert f"TICKET: {GOOD_TICKET}" in wm["text"]


def test_watermark_missing_source_renders_em_dash_not_a_guess(client, clock):
    session = start_session(client)  # no source_ip supplied
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["fields"]["source"] is None
    assert "SOURCE: —" in wm["text"]
    assert "TICKET: —" in wm["text"]
    # the text still shows the real time - only absent facts get the dash
    assert "TIME: 07-Oct-2026 12:00" in wm["text"]


def test_watermark_control_gates_the_rendered_text(client, clock):
    session = start_session(client, source_ip=SOURCE_IP, watermark=False)
    detail = watermark_of(client, session["id"])
    wm = detail["watermark"]
    # the data stays (it is the session's own row), the painting does not.
    assert wm["enabled"] is False
    assert wm["state"] == "active"
    assert wm["fields"]["source"] == SOURCE_IP
    assert wm["text"] is None
    # per-event custody strings are gated by the same control
    assert all(ev["watermark"] is None for ev in detail["events"])

    flipped = client.post(
        f"/api/v1/sessions/{session['id']}/controls",
        json={"watermark": True},
        headers=ACTOR,
    )
    assert flipped.status_code == 200, flipped.get_json()
    wm = watermark_of(client, session["id"])["watermark"]
    assert wm["enabled"] is True
    assert wm["text"].startswith("USER: tester\nSESSION: ")

    off = client.post(
        f"/api/v1/sessions/{session['id']}/controls",
        json={"watermark": False},
        headers=ACTOR,
    )
    assert off.status_code == 200, off.get_json()
    assert watermark_of(client, session["id"])["watermark"]["text"] is None


def test_watermark_is_additive_on_detail_only(client, clock):
    # every pre-4k key of the detail response is untouched
    session = start_session(client, source_ip=SOURCE_IP)
    detail = watermark_of(client, session["id"])
    assert {"session", "events", "event_count", "blocked_count"} <= set(detail)
    wm = detail["watermark"]
    assert set(wm) == {"enabled", "state", "fields", "text"}
    assert set(wm["fields"]) == {
        "user", "session", "target", "time", "ticket", "source",
    }

    # the list view stays lean - the payload rides the detail response only
    listing = client.get("/api/v1/sessions").get_json()
    row = next(r for r in listing["items"] if r["id"] == session["id"])
    assert "watermark" not in row

    # unknown ids keep their 404
    missing = client.get("/api/v1/sessions/424242")
    assert missing.status_code == 404
