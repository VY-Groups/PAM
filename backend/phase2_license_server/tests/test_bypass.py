"""Tests for PAM bypass detection (architecture module 10).

The detection loop is real end to end: a log bundle an operator supplies is
parsed into connection observations (OpenSSH `Accepted ...` lines or
structured JSON exports, everything else counted as malformed and never
invented), a correlation scan matches each observation against the managed
inventory and against recorded privileged sessions, and a managed target
with no covering session opens an incident carrying the architecture's
ACTION block - SOC alert on the `bypass` trail of the ledger, forced
credential rotation through the real module-5 pipeline, and block source
recorded honestly as `not_connected` until an enforcement connector exists.

Run with:  python -m pytest backend/phase2_license_server/tests/test_bypass.py -q
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

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}

MANAGED_HOST = "10.77.0.9"
OTHER_HOST = "198.51.100.7"   # never registered - out of scope
SSHD_LINE = (
    "Oct  8 06:40:12 prod-db sshd[2145]: "
    f"Accepted password for admin01 from 10.10.5.20 port 22 ssh2"
)


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
        ed25519_public_key_path=tmp_path / "license_ed25519_public_key.pem",
        secret_key="test-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
    )


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def register_asset(client, address=MANAGED_HOST):
    """Manual registration through the public API - lands managed (the
    operator onboarded its principal), so it is a PAM-protected target;
    registration ingests its admin credential into the vault in the same
    call (returns the full body: asset + vault_item)."""
    response = client.post(
        "/api/v1/discovery/assets",
        json={"address": address, "asset_type": "database", "principal": "root"},
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def onboard(client, name, *, target):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": target,
            "principal": "admin",
            "access_tier": "Tier-1",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def ingest(client, content, *, origin="auth.log", target=None, **extra):
    payload = {"origin": origin, "content": content}
    if target is not None:
        payload["target"] = target
    payload.update(extra)
    return client.post("/api/v1/bypass/ingest", json=payload, headers=ACTOR)


def ingest_ok(client, content, **kwargs):
    response = ingest(client, content, **kwargs)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["ingest"]


def scan(client):
    response = client.post("/api/v1/bypass/scans", headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["scan"]


def signals(client, **query):
    response = client.get("/api/v1/bypass/signals", query_string=query)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def incidents(client, **query):
    response = client.get("/api/v1/bypass/incidents", query_string=query)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def stats(client):
    response = client.get("/api/v1/bypass/stats")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def feed(client, source="bypass"):
    response = client.get("/api/v1/events", query_string={"source": source})
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def bypass_actions(client):
    return [row["action"] for row in feed(client)["events"]]


# ---------------------------------------------------------------------------
# ingest: real formats in, verbatim evidence out
# ---------------------------------------------------------------------------
def test_ingest_parses_sshd_lines_against_the_bundle_target(client):
    detail = ingest_ok(client, SSHD_LINE, origin="prod-db01-auth.log",
                       target=MANAGED_HOST)
    assert detail["stored"] == 1
    assert detail["parsed"] == 1
    assert detail["malformed"] == 0

    page = signals(client)
    assert page["total"] == 1
    signal = page["signals"][0]
    assert signal["user"] == "admin01"
    assert signal["source_ip"] == "10.10.5.20"
    assert signal["target"] == MANAGED_HOST
    assert signal["protocol"] == "ssh"
    assert signal["origin"] == "prod-db01-auth.log"
    assert signal["status"] == "observed"
    assert "Accepted password for admin01" in signal["raw"]  # verbatim
    assert signal["detail"]["at_source"] == "ingest_time"

    # ingestion is an action: it lands on the ninth ledger trail
    assert "ingested" in bypass_actions(client)


def test_ingest_parses_json_records_with_own_target_and_timestamp(client):
    lines = "\n".join(
        [
            '{"user": "svc-backup", "source_ip": "10.20.30.40", '
            f'"target": "{OTHER_HOST}", "protocol": "rdp", '
            '"at": "2026-10-07T22:15:00"}',
            '{"username": "dba", "source": "10.20.30.41", '
            f'"host": "{MANAGED_HOST}"}}',
        ]
    )
    detail = ingest_ok(client, lines, origin="edr-export.ndjson")
    assert detail["stored"] == 2
    assert detail["malformed"] == 0

    page = signals(client, q="svc-backup")
    assert page["total"] == 1
    first = page["signals"][0]
    assert first["protocol"] == "rdp"
    assert first["observed_at"].startswith("2026-10-07T22:15:00")
    assert first["detail"]["at_source"] == "line"

    # the second line carried no timestamp: ingest time, honestly labelled
    page = signals(client, q="dba")
    assert page["signals"][0]["detail"]["at_source"] == "ingest_time"


def test_ingest_requires_content_and_bounds_it(client):
    assert ingest(client, "", target=MANAGED_HOST).status_code == 400
    assert ingest(client, "Accepted x", origin="").status_code == 400  # no origin
    body = ingest(client, "x" * 200_001, origin="big.log", target=MANAGED_HOST)
    assert body.status_code == 400
    assert body.get_json()["details"]["max"] == 200_000
    assert signals(client)["total"] == 0  # nothing half-ingested


def test_ingest_counts_malformed_and_untargeted_lines(client):
    detail = ingest_ok(
        client,
        "\n".join(
            [
                "user nobody logged in",                 # not a connection record
                "{not json",                             # broken structured line
                "Accepted password for root from 1.2.3.4 port 22 ssh2",  # no target
            ]
        ),
        origin="mixed.log",
    )
    assert detail["stored"] == 0
    assert detail["malformed"] == 2
    assert detail["untargeted"] == 1
    assert signals(client)["total"] == 0  # never invented


def test_ingest_deduplicates_within_the_batch_and_across_calls(client):
    first = ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    assert first["stored"] == 1

    again = ingest_ok(client, SSHD_LINE + "\n" + SSHD_LINE,
                      origin="auth.log", target=MANAGED_HOST)
    assert again["stored"] == 0
    assert again["duplicates"] == 2  # in-batch repeat + across-call repeat

    assert signals(client)["total"] == 1


# ---------------------------------------------------------------------------
# correlation: managed inventory + recorded sessions decide the verdict
# ---------------------------------------------------------------------------
def test_scan_marks_unmanaged_targets_out_of_scope(client):
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=OTHER_HOST)
    result = scan(client)

    assert result == {
        "scanned": 1,
        "covered": 0,
        "out_of_scope": 1,
        "candidates": 0,
        "incidents": 0,
        "rotations_forced": 0,
    }
    signal = signals(client)["signals"][0]
    assert signal["status"] == "out_of_scope"
    assert "not a managed" in signal["detail"]["reason"]
    assert incidents(client)["total"] == 0
    assert "scanned" in bypass_actions(client)


def test_scan_with_no_signals_reports_honest_zero(client):
    assert scan(client)["scanned"] == 0
    page = feed(client)
    assert page["total"] >= 1  # the empty scan itself is recorded...
    assert bypass_actions(client)[0] == "scanned"  # ...as an action, not noise
    assert stats(client)["actions"]["scanned"] == 1


def test_scan_opens_incident_for_managed_target_without_session(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    result = scan(client)

    assert result["candidates"] == 1
    assert result["incidents"] == 1
    assert result["covered"] == 0
    assert result["rotations_forced"] == 1  # the target's credential rotated

    page = incidents(client)
    assert page["total"] == 1
    incident = page["incidents"][0]
    assert incident["incident_ref"].startswith("byp-")
    assert incident["status"] == "open"
    assert incident["user"] == "admin01"
    assert incident["source_ip"] == "10.10.5.20"
    assert incident["target"] == MANAGED_HOST
    assert incident["protocol"] == "ssh"

    # the ACTION block the architecture prescribes
    assert incident["actions"]["alert"]["status"] == "recorded"
    assert incident["actions"]["block_source"]["status"] == "not_connected"
    # registration = target + vault ingestion in one call, so this managed
    # target has a credential - section 10 forces its real rotation
    rotation = incident["actions"]["rotation"]
    assert rotation["status"] == "rotated"
    assert rotation["items"][0]["id"]  # the registered admin credential

    # the signal became the candidate and kept its evidence
    signal = signals(client)["signals"][0]
    assert signal["status"] == "candidate"
    assert signal["detail"]["asset_address"] == MANAGED_HOST

    # the detection is SOC evidence on the bypass trail
    assert "detected" in bypass_actions(client)


def test_scan_respects_a_covering_recorded_session(client):
    register_asset(client, MANAGED_HOST)
    session = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": f"{MANAGED_HOST}:22"},
        headers=ACTOR,  # X-Actor: tester
    )
    assert session.status_code == 201, session.get_json()

    # the same principal connecting to the same host *through* PAM
    ingest_ok(
        client,
        "Accepted password for tester from 10.10.5.9 port 22 ssh2",
        origin="auth.log",
        target=MANAGED_HOST,
    )
    result = scan(client)

    assert result["covered"] == 1
    assert result["incidents"] == 0
    signal = signals(client)["signals"][0]
    assert signal["status"] == "covered"
    assert signal["detail"]["session_ref"] == session.get_json()["session"]["session_ref"]
    assert incidents(client)["total"] == 0


def test_scan_forces_a_real_credential_rotation(client):
    register_asset(client, MANAGED_HOST)
    item = onboard(client, "prod-db-password", target=MANAGED_HOST)
    before = item["secret_version"]  # the onboarding mint

    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    result = scan(client)

    assert result["rotations_forced"] == 1
    incident = incidents(client)["incidents"][0]
    rotation = incident["actions"]["rotation"]
    assert rotation["status"] == "rotated"
    assert item["id"] in {entry["id"] for entry in rotation["items"]}

    refreshed = client.get(f"/api/v1/vault/items/{item['id']}",
                           headers=ACTOR).get_json()["item"]
    assert refreshed["secret_version"] == before + 1  # a new value was minted
    assert refreshed["last_rotated_at"] is not None  # the pipeline ran


def test_rotation_is_skipped_when_the_credential_is_checked_out(client):
    registered = register_asset(client, MANAGED_HOST)
    credential_id = registered["vault_item"]["id"]
    checkout = client.post(f"/api/v1/vault/items/{credential_id}/checkout",
                           json={}, headers=ACTOR)
    assert checkout.status_code == 200, checkout.get_json()

    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    result = scan(client)

    assert result["rotations_forced"] == 0  # nothing could rotate: honest
    rotation = incidents(client)["incidents"][0]["actions"]["rotation"]
    assert rotation["status"] == "skipped"
    assert rotation["skipped"][0]["id"] == credential_id
    assert rotation["skipped"][0]["reason"] == "checked_out"


def test_rescan_does_not_duplicate_incidents(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    scan(client)

    second = scan(client)
    assert second["scanned"] == 0  # only `observed` signals are correlated
    assert incidents(client)["total"] == 1


# ---------------------------------------------------------------------------
# reads, closure and stats
# ---------------------------------------------------------------------------
def test_signal_list_filters_by_status_and_search(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    ingest_ok(client, SSHD_LINE.replace("admin01", "root"),
              origin="auth.log", target=OTHER_HOST)
    scan(client)

    assert signals(client, status="candidate")["total"] == 1
    assert signals(client, status="out_of_scope")["total"] == 1
    assert signals(client, q="admin01")["total"] == 1
    assert signals(client, q="auth.log")["total"] == 2  # origin search
    assert signals(client, q="10.10.5.20")["total"] == 2  # source_ip search

    bad = client.get("/api/v1/bypass/signals", query_string={"status": "maybe"},
                     headers=ACTOR)
    assert bad.status_code == 400
    assert bad.get_json()["details"]["field"] == "status"


def test_incident_list_filters_and_pages(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    ingest_ok(client, SSHD_LINE.replace("admin01", "root"),
              origin="auth.log", target=MANAGED_HOST)
    scan(client)

    assert incidents(client)["total"] == 2
    assert incidents(client, status="open")["total"] == 2
    assert incidents(client, status="closed")["total"] == 0
    assert len(incidents(client, limit=1)["incidents"]) == 1
    assert incidents(client, offset=1)["total"] == 2

    bad = client.get("/api/v1/bypass/incidents", query_string={"status": "maybe"},
                     headers=ACTOR)
    assert bad.status_code == 400


def test_incident_detail_carries_the_evidence_line(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    scan(client)

    incident_id = incidents(client)["incidents"][0]["id"]
    response = client.get(f"/api/v1/bypass/incidents/{incident_id}")
    assert response.status_code == 200
    body = response.get_json()
    assert body["evidence"]["raw"].startswith("Oct  8 06:40:12")
    assert body["incident"]["signal_id"] == body["evidence"]["id"]

    missing = client.get("/api/v1/bypass/incidents/999999")
    assert missing.status_code == 404


def test_close_incident_records_note_actor_and_ledger(client):
    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    scan(client)
    incident_id = incidents(client)["incidents"][0]["id"]

    response = client.post(
        f"/api/v1/bypass/incidents/{incident_id}/close",
        json={"note": "Confirmed: legacy cron, credential already rotated"},
        headers=ACTOR,
    )
    assert response.status_code == 200, response.get_json()
    closed = response.get_json()["incident"]
    assert closed["status"] == "closed"
    assert closed["closed_by"] == "tester"
    assert closed["closed_at"]
    assert closed["close_note"].startswith("Confirmed")
    assert "closed" in bypass_actions(client)

    again = client.post(f"/api/v1/bypass/incidents/{incident_id}/close",
                        json={}, headers=ACTOR)
    assert again.status_code == 409
    assert incidents(client, status="closed")["total"] == 1


def test_stats_report_real_counts(client):
    assert stats(client)["signals"]["total"] == 0  # honest zeros up front

    register_asset(client, MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    ingest_ok(client, SSHD_LINE.replace("admin01", "root"),
              origin="other.log", target=OTHER_HOST)
    scan(client)

    state = stats(client)
    assert state["signals"]["total"] == 2
    assert state["signals"]["candidate"] == 1
    assert state["signals"]["out_of_scope"] == 1
    assert state["incidents"] == {"total": 1, "open": 1, "closed": 0}
    assert state["rotations_forced"] == 1  # the registration credential
    assert state["actions"]["ingested"] == 2
    assert state["actions"]["scanned"] == 1
    assert state["actions"]["detected"] == 1
    assert state["last_ingest_at"] is not None
    assert state["last_scan_at"] is not None


def test_admin_token_required_for_bypass_writes(client):
    assert client.post("/api/v1/bypass/ingest",
                       json={"origin": "x", "content": SSHD_LINE}).status_code == 401
    assert client.post("/api/v1/bypass/scans").status_code == 401
    assert client.post("/api/v1/bypass/incidents/1/close").status_code == 401
    # reads stay open like the other read endpoints
    assert client.get("/api/v1/bypass/stats").status_code == 200


def test_ledger_chain_verifies_after_the_bypass_flow(client):
    register_asset(client, MANAGED_HOST)
    onboard(client, "chain-password", target=MANAGED_HOST)
    ingest_ok(client, SSHD_LINE, origin="auth.log", target=MANAGED_HOST)
    scan(client)
    incident_id = incidents(client)["incidents"][0]["id"]
    client.post(f"/api/v1/bypass/incidents/{incident_id}/close",
                json={"note": "chain check"}, headers=ACTOR)

    verify = client.get("/api/v1/audit/verify").get_json()
    assert verify["intact"] is True, verify

    page = feed(client)
    assert {row["source"] for row in page["events"]} == {"bypass"}
    actions = set(bypass_actions(client))
    assert {"ingested", "scanned", "detected", "closed"} <= actions
    # the forced rotation is on its own trail, not smuggled into bypass
    vault = feed(client, source="vault")
    assert vault["total"] >= 1
