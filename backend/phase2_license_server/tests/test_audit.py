"""Tests for the immutable audit ledger (architecture section 19).

Every module event trail (license, settings, vault, discovery, JIT, session
lifecycle, command control) fans into one append-only, hash-chained store:
`seq` links each record to the previous hash, SQLite triggers refuse UPDATE
and DELETE, a full walk (`/audit/verify`) reports the first break, and the
export endpoint hands a SIEM the same records as NDJSON.

The ledger never stores channel content (keystrokes stay in the session
recording) and never stores secrets (a reveal logs who/what/when, not the
plaintext).

Run with:  python -m pytest backend/phase2_license_server/tests/test_audit.py -q
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import audit  # noqa: E402
import models  # noqa: E402
from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from licensing_bridge import LicenseType, get_generator, sig  # noqa: E402
from models import (  # noqa: E402
    AUDIT_GENESIS_HASH,
    AuditEvent,
    CommandIncident,
    db,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}


# ---------------------------------------------------------------------------
# fixtures + API helpers (same shapes as the neighbouring suites)
# ---------------------------------------------------------------------------
@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
        secret_key="test-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
    )


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def install(client, **overrides):
    """Vendor-side install: sign with the shared engine, then import."""
    config = client.application.config["LICENSE_CONFIG"]
    fields = {"license_type": "subscription", "issued_to": "Acme Ltd"}
    fields.update(overrides)
    if isinstance(fields.get("license_type"), str):
        fields["license_type"] = LicenseType(fields["license_type"])
    algorithm = fields.pop("algorithm", sig.DEFAULT_ALGORITHM)
    file_format = fields.pop("format", sig.FORMAT_JSON)
    fields.setdefault("trial_days", config.default_trial_days)
    generator = get_generator(config)
    envelope = generator.build_license_file(
        generator.generate_license(**fields), algorithm, file_format
    )
    return client.post("/api/v1/licenses/import", json=envelope, headers=ADMIN)


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
    base = {"protocol": "ssh", "target": "web-01.prod:22"}
    base.update(payload)
    response = client.post("/api/v1/sessions", json=base, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["session"]


def post_event(client, session_id, event_type, content=""):
    return client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": event_type, "content": content},
        headers=ACTOR,
    )


def ledger_rows():
    return AuditEvent.query.order_by(AuditEvent.seq).all()


def stats(client):
    response = client.get("/api/v1/audit/stats")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def verify(client):
    response = client.get("/api/v1/audit/verify")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


# ---------------------------------------------------------------------------
# fan-in: every module trail reaches the one ledger
# ---------------------------------------------------------------------------
def test_every_module_trail_reaches_the_ledger(client):
    install(client)
    client.put("/api/v1/settings/zsp", json={"tier0_quorum_approvers": 3},
               headers=ACTOR)
    item = onboard(client, "ledger-item")
    client.post(
        "/api/v1/discovery/assets",
        json={"address": "10.9.9.9", "principal": "root"},
        headers=ACTOR,
    )
    client.post(
        "/api/v1/jit/requests",
        json={"item_id": item["id"], "reason": "Ledger coverage window",
              "ticket": "INC-1234", "minutes": 15},
        headers=ACTOR,
    )
    session = start_session(client)
    assert post_event(client, session["id"], "command",
                      "ls -la").status_code == 201
    assert client.post(
        "/api/v1/risk/evaluate",
        json={"subject": "risk-subject", "command": "whoami"},
        headers=ACTOR,
    ).status_code == 201
    assert client.post(
        "/api/v1/bypass/ingest",
        json={"origin": "auth.log", "target": "10.9.9.9",
              "content": "Accepted password for root from 10.10.5.7 port 22 ssh2"},
        headers=ACTOR,
    ).status_code == 201
    assert client.post(
        "/api/v1/break-glass/requests",
        json={"target": "10.9.9.9", "reason": "Ledger coverage window",
              "severity": "sev1"},
        headers=ACTOR,
    ).status_code == 201

    state = stats(client)
    assert state["total"] >= 8
    # one real record behind each of the ten sources, none fabricated
    assert all(count >= 1 for count in state["by_source"].values()), state

    # the feed filter that works for the old four works for all ten
    for source in audit.AUDIT_SOURCES:
        page = client.get("/api/v1/events",
                          query_string={"source": source}).get_json()
        assert page["total"] >= 1, source
        assert page["source"] == source
        assert all(row["source"] == source for row in page["events"])


def test_session_lifecycle_rows_use_the_session_source(client):
    session = start_session(client)
    feed = client.get("/api/v1/events",
                      query_string={"source": "session"}).get_json()
    assert feed["total"] == 1
    row = feed["events"][0]
    assert row["action"] == "status"
    assert row["subject"] == session["session_ref"]
    assert row["detail"]["content"] == "session started"
    assert row["id"].startswith("session:")
    assert row["seq"] >= 1 and len(row["event_hash"]) == 64


def test_channel_content_stays_in_the_recording_not_the_ledger(client):
    session = start_session(client)
    sid = session["id"]
    assert post_event(client, sid, "keystroke",
                      "SECRET_TYPOGRAPHY_STRING").status_code == 201
    assert post_event(client, sid, "screenshot",
                      "frame-0001.png").status_code == 201
    assert post_event(client, sid, "command", "whoami").status_code == 201

    recording = client.get(f"/api/v1/sessions/{sid}/events").get_json()["events"]
    kinds = {event["type"] for event in recording}
    assert {"status", "keystroke", "screenshot", "command"} <= kinds
    assert any(
        event["type"] == "keystroke"
        and event["content"] == "SECRET_TYPOGRAPHY_STRING"
        for event in recording
    )

    # the ledger keeps the actions (status + command), not the typed channel
    state = stats(client)
    assert state["by_source"]["session"] >= 1
    assert state["by_source"]["command"] >= 1
    with client.application.app_context():
        dump = json.dumps([row.detail for row in ledger_rows()])
    assert "SECRET_TYPOGRAPHY_STRING" not in dump
    assert "frame-0001.png" not in dump


def test_approval_resolution_is_chained_under_command_source(client):
    session = start_session(client)
    hold = post_event(client, session["id"], "command", "passwd service-account")
    hold_seq = hold.get_json()["event"]["seq"]
    approved = client.post(
        f"/api/v1/sessions/{session['id']}/events/{hold_seq}/approve",
        headers=ACTOR,
    )
    assert approved.status_code == 200, approved.get_json()
    resolution = approved.get_json()["resolution"]

    feed = client.get("/api/v1/events",
                      query_string={"source": "command"}).get_json()
    assert feed["total"] >= 2  # the hold and its resolution are both chained
    decision_rows = [
        row for row in feed["events"] if row["action"] == "approval"
    ]
    assert len(decision_rows) == 1
    assert decision_rows[0]["detail"]["decision"] == resolution["decision"]
    assert decision_rows[0]["detail"]["ref_seq"] == hold_seq
    assert any(row["action"] == "command" for row in feed["events"])
    assert verify(client)["intact"] is True


# ---------------------------------------------------------------------------
# the chain: genesis link, linkage, verify walk
# ---------------------------------------------------------------------------
def test_chain_links_from_genesis_and_verifies(client):
    install(client)
    client.put("/api/v1/settings/hsm", json={"key_rotation_hours": 12},
               headers=ACTOR)
    onboard(client, "chain-item")

    with client.application.app_context():
        rows = ledger_rows()
        assert rows, "ledger must hold the events the API just wrote"
        assert rows[0].seq == 1
        assert rows[0].prev_hash == AUDIT_GENESIS_HASH
        assert [row.seq for row in rows] == list(range(1, len(rows) + 1))
        for previous, current in zip(rows, rows[1:]):
            assert current.prev_hash == previous.event_hash
            assert current.seq == previous.seq + 1
        # every hash recomputes from the stored record
        for row in rows:
            assert row.event_hash == audit._row_hash(row)
        head_hash = rows[-1].event_hash

    verified = verify(client)
    assert verified["intact"] is True
    assert verified["broken_at"] is None and verified["reason"] is None
    assert verified["checked"] == verified["total"] >= 3
    assert verified["head_hash"] == head_hash


def test_empty_ledger_stays_honest(client):
    state = stats(client)
    assert state["total"] == 0 and state["last_seq"] == 0
    assert state["head_hash"] == ""
    assert state["oldest_at"] is None and state["newest_at"] is None
    assert set(state["by_source"]) == set(audit.AUDIT_SOURCES)
    assert all(count == 0 for count in state["by_source"].values())
    assert state["trigger_protection"] is True

    assert verify(client) == {
        "intact": True, "checked": 0, "total": 0, "last_seq": 0,
        "head_hash": "", "broken_at": None, "reason": None,
    }
    feed = client.get("/api/v1/events").get_json()
    assert feed["events"] == [] and feed["total"] == 0


def test_stats_report_real_ledger_state(client):
    install(client)
    onboard(client, "stats-item")
    state = stats(client)

    assert state["total"] == (
        state["by_source"]["license"] + state["by_source"]["vault"]
    )
    assert state["last_seq"] == state["total"]
    assert state["trigger_protection"] is True
    datetime.fromisoformat(state["oldest_at"])
    datetime.fromisoformat(state["newest_at"])
    with client.application.app_context():
        assert state["head_hash"] == ledger_rows()[-1].event_hash


# ---------------------------------------------------------------------------
# immutability: storage-layer triggers
# ---------------------------------------------------------------------------
def test_update_and_delete_are_refused_by_the_database(client):
    install(client)
    with client.application.app_context():
        first = ledger_rows()[0]
        original_actor = first.actor
        original_hash = audit._row_hash(first)

        with pytest.raises(DBAPIError) as update:
            db.session.execute(
                text("UPDATE audit_events SET actor='someone-else' WHERE seq = 1")
            )
            db.session.commit()
        db.session.rollback()
        assert "append-only" in str(update.value)

        with pytest.raises(DBAPIError) as delete:
            db.session.execute(text("DELETE FROM audit_events WHERE seq = 1"))
            db.session.commit()
        db.session.rollback()
        assert "append-only" in str(delete.value)

        row = ledger_rows()[0]
        assert row.actor == original_actor
        assert audit._row_hash(row) == original_hash
        assert audit.verify_chain()["intact"] is True


def test_altered_hash_is_reported_as_content_mismatch(client):
    install(client)
    with client.application.app_context():
        head = ledger_rows()[-1]
        forged_seq = head.seq + 1
        # a forged append: links to the real head, but its own hash is wrong
        db.session.execute(
            text(
                "INSERT INTO audit_events (seq, event_ref, source, action, "
                "actor, subject, detail, created_at, prev_hash, event_hash) "
                "VALUES (:seq, 'settings:forged', 'settings', 'updated', "
                "'intruder', 'zsp', '{}', :created_at, :prev, :hash)"
            ),
            {
                "seq": forged_seq,
                "created_at": datetime.now().isoformat(sep=" "),
                "prev": head.event_hash,
                "hash": "f" * 64,
            },
        )
        db.session.commit()

        verified = audit.verify_chain()
        assert verified["intact"] is False
        assert verified["broken_at"] == forged_seq
        assert verified["checked"] == forged_seq - 1
        assert "content hash mismatch" in verified["reason"]
        assert verified["head_hash"] == head.event_hash

    result = verify(client)
    assert result["intact"] is False and result["broken_at"] == forged_seq


def test_missing_record_is_a_gap_even_if_the_trigger_is_dropped(client):
    install(client)
    onboard(client, "gap-item")  # a second row so a gap is observable
    with client.application.app_context():
        assert audit.triggers_installed(db.engine) is True

        with db.engine.begin() as conn:
            conn.execute(text("DROP TRIGGER audit_events_no_delete"))
        assert audit.triggers_installed(db.engine) is False
        assert audit.chain_stats()["trigger_protection"] is False

        db.session.execute(text("DELETE FROM audit_events WHERE seq = 1"))
        db.session.commit()

        verified = audit.verify_chain()
        assert verified["intact"] is False
        assert verified["broken_at"] == 1
        assert verified["checked"] == 0
        assert "sequence gap" in verified["reason"]
        # tampering is detected and reported, never silently repaired
        assert audit.verify_chain()["intact"] is False

        db.session.commit()  # release the read transaction before DDL
        audit._install_triggers(db.engine)
        assert audit.triggers_installed(db.engine) is True
        assert audit.verify_chain()["intact"] is False  # gap still reported

    assert verify(client)["intact"] is False


# ---------------------------------------------------------------------------
# backfill: pre-existing history is chained on first boot
# ---------------------------------------------------------------------------
def test_backfill_chains_preexisting_history_once(app):
    with app.app_context():
        db.session.execute(
            text(
                "INSERT INTO license_events (id, license_key, action, detail, "
                "created_at) VALUES (1, 'legacy-key', 'imported', "
                "'{\"via\": \"raw\"}', :created_at)"
            ),
            {"created_at": (datetime.now() - timedelta(days=2)).isoformat(sep=" ")},
        )
        db.session.commit()
        assert AuditEvent.query.count() == 0  # raw SQL bypassed the listener

        assert audit.ensure_audit_chain() == 1
        rows = ledger_rows()
        assert len(rows) == 1
        assert rows[0].seq == 1
        assert rows[0].event_ref == "license:1"
        assert rows[0].prev_hash == AUDIT_GENESIS_HASH
        assert rows[0].detail == {"via": "raw"}
        # already-current ledger: nothing to add, nothing to renumber
        assert audit.ensure_audit_chain() == 0
        assert audit.verify_chain()["intact"] is True


# ---------------------------------------------------------------------------
# real seams: reveal and incident close are explicit ledger records
# ---------------------------------------------------------------------------
def test_reveal_is_audited_without_the_secret(client):
    item = onboard(client, "reveal-item", secret="hunter2-plain-text")
    response = client.get(f"/api/v1/vault/items/{item['id']}/secret",
                          headers=ADMIN)
    assert response.status_code == 200
    assert response.get_json()["secret"] == "hunter2-plain-text"

    events = client.get("/api/v1/vault/events").get_json()["events"]
    reveals = [event for event in events if event["action"] == "revealed"]
    assert len(reveals) == 1
    assert reveals[0]["actor"] == "admin"
    assert reveals[0]["detail"]["version"] == 1
    assert "hunter2-plain-text" not in json.dumps(reveals[0]["detail"])

    with client.application.app_context():
        refs = [row.event_ref for row in ledger_rows()]
        assert any(ref.startswith("vault:") for ref in refs)
        assert "hunter2-plain-text" not in json.dumps(
            [row.detail for row in ledger_rows()]
        )
    assert verify(client)["intact"] is True


def test_incident_escalation_and_close_are_chained(client):
    session = start_session(client, target="prod-db-01.example:5432")
    response = post_event(client, session["id"], "command",
                          "DROP DATABASE payments")
    assert response.status_code == 201, response.get_json()
    incident = response.get_json()["escalation"]["incident"]

    closed = client.post(
        f"/api/v1/command-control/incidents/{incident['id']}/close",
        json={"note": "forensics complete"},
        headers=ACTOR,
    )
    assert closed.status_code == 200, closed.get_json()

    with client.application.app_context():
        by_ref = {row.event_ref: row for row in ledger_rows()}
        assert f"incident:{incident['id']}" in by_ref
        assert f"incident-closed:{incident['id']}" in by_ref
        escalate = by_ref[f"incident:{incident['id']}"]
        assert escalate.action == "escalated"
        assert escalate.subject == incident["incident_ref"]
        assert escalate.detail["command"] == "DROP DATABASE payments"
        assert escalate.detail["status"] == "open"
        close = by_ref[f"incident-closed:{incident['id']}"]
        assert close.action == "closed"
        assert close.actor == "tester"
        assert close.detail["note"] == "forensics complete"
        assert close.detail["status"] == "closed"

    feed = client.get("/api/v1/events",
                      query_string={"source": "command"}).get_json()
    actions = {row["action"] for row in feed["events"]}
    assert {"escalated", "closed"} <= actions
    assert verify(client)["intact"] is True


# ---------------------------------------------------------------------------
# exports and feed shape
# ---------------------------------------------------------------------------
def test_ndjson_export_walks_the_chain_in_order(client):
    install(client)
    onboard(client, "export-item")
    client.put("/api/v1/settings/zsp", json={"tier0_quorum_approvers": 2},
               headers=ACTOR)

    response = client.get("/api/v1/audit/export")
    assert response.status_code == 200
    assert response.mimetype == "application/x-ndjson"
    assert "vy-pam-audit.ndjson" in response.headers["Content-Disposition"]

    lines = [line for line in response.get_data(as_text=True).splitlines() if line]
    records = [json.loads(line) for line in lines]
    required = {
        "id", "seq", "event_ref", "source", "action", "actor", "subject",
        "detail", "created_at", "prev_hash", "event_hash",
    }
    assert records and required == set(records[0])
    assert [record["seq"] for record in records] == list(
        range(1, len(records) + 1)
    )
    assert len(records) == stats(client)["total"]
    assert records[-1]["event_hash"] == stats(client)["head_hash"]
    for previous, current in zip(records, records[1:]):
        assert current["prev_hash"] == previous["event_hash"]


def test_feed_rows_keep_the_legacy_shape_and_add_chain_fields(client):
    onboard(client, "shape-item")
    feed = client.get("/api/v1/events",
                      query_string={"source": "vault"}).get_json()
    assert set(feed) == {"events", "total", "limit", "source"}

    row = feed["events"][0]
    legacy = {"id", "source", "action", "subject", "actor", "detail",
              "created_at"}
    assert legacy <= set(row)
    assert {"seq", "event_hash"} <= set(row)
    assert row["id"].startswith("vault:")
    assert row["seq"] >= 1
    assert len(row["event_hash"]) == 64
    # total counts the whole store, independent of the page limit
    limited = client.get("/api/v1/events",
                         query_string={"source": "vault", "limit": 1}).get_json()
    assert len(limited["events"]) == 1
    assert limited["total"] == feed["total"]


# ---------------------------------------------------------------------------
# honesty guards: overview, public reads, no-write-on-failure, drift
# ---------------------------------------------------------------------------
def test_overview_counts_the_ledger(client):
    install(client)
    onboard(client, "overview-item")
    overview = client.get("/api/v1/overview").get_json()
    assert overview["counters"]["total_events"] == stats(client)["total"]
    assert overview["counters"]["license_events"] == 1  # module table kept


def test_audit_reads_are_public(client):
    for path in ("/api/v1/audit/stats", "/api/v1/audit/verify",
                 "/api/v1/audit/export"):
        assert client.get(path).status_code == 200, path


def test_failed_write_leaves_the_ledger_untouched(client):
    before = stats(client)["total"]
    rejected = client.put("/api/v1/settings/zsp", json=[1, 2, 3],
                          headers=ADMIN)
    assert rejected.status_code == 400
    assert stats(client)["total"] == before


def test_drift_guard_every_event_model_is_mirrored(client):
    """New `*Event` / incident tables must join the ledger (or this fails)."""
    event_models = {
        cls for name, cls in vars(models).items()
        if name.endswith("Event")
        and isinstance(cls, type)
        and issubclass(cls, db.Model)
    }
    assert AuditEvent in event_models  # the ledger itself is a *Event table
    sources = event_models - {AuditEvent}
    assert sources <= set(audit.MAPPERS)  # no event model left unaudited
    assert CommandIncident in audit.MAPPERS
    assert set(audit.MAPPERS) <= sources | {CommandIncident}
    assert len(audit.MAPPERS) == len(sources) + 1
    # the ten sources the contract advertises match the mappers exactly
    mapped_sources = set(stats(client)["by_source"])
    assert mapped_sources == set(audit.AUDIT_SOURCES)
