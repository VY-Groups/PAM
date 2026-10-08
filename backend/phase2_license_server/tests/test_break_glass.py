"""Tests for break glass (architecture section 17).

The emergency process is real end to end: an operator files a request with
a verbatim reason, severity and target; two *distinct* approvers must sign
before anything exists (the requester cannot approve their own emergency,
a second signature from the same approver does not count); the approved
request releases the emergency credential through a real vault checkout
and starts a session with `record=true` forced - recording is not an
operator preference here; closing ends the session (release-and-rotate
cascade), guarantees the released credential ends up rotated exactly once
through the real module-5 pipeline, and requires the post-incident review
note. MFA is recorded honestly as `not configured` until a factor exists
(section 20) - never a fake challenge. Every step lands on the tenth
ledger trail (`break-glass`), so the break-glass process itself is
auditable.

Run with:  python -m pytest backend/phase2_license_server/tests/test_break_glass.py -q
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

TARGET = "db-01.corp:5432"
NO_CREDENTIAL_TARGET = "ghost-01.corp"


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


def as_actor(name: str) -> dict:
    return {"X-Actor": name, "Authorization": "Bearer test-admin-token"}


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


def vault_item(client, item_id):
    response = client.get(f"/api/v1/vault/items/{item_id}")
    assert response.status_code == 200, response.get_json()
    return response.get_json()["item"]


def file_request(client, *, actor="alice", target=TARGET, **payload):
    body = {
        "reason": "Production database unreachable; DBA on call needs "
        "direct access to recover replication.",
        "target": target,
        "severity": "sev1",
        "protocol": "postgresql",
    }
    body.update(payload)
    response = client.post(
        "/api/v1/break-glass/requests", json=body, headers=as_actor(actor)
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["request"]


def approve(client, request_id, *, actor, note=None):
    payload = {} if note is None else {"note": note}
    return client.post(
        f"/api/v1/break-glass/requests/{request_id}/approve",
        json=payload,
        headers=as_actor(actor),
    )


def deny(client, request_id, *, actor, note=None):
    payload = {} if note is None else {"note": note}
    return client.post(
        f"/api/v1/break-glass/requests/{request_id}/deny",
        json=payload,
        headers=as_actor(actor),
    )


def dual_approve(client, request_id):
    first = approve(client, request_id, actor="bob", note="confirmed with on-call")
    assert first.status_code == 200, first.get_json()
    second = approve(client, request_id, actor="carol")
    assert second.status_code == 200, second.get_json()
    return second.get_json()["request"]


def open_request(client, request_id, *, actor="alice"):
    return client.post(
        f"/api/v1/break-glass/requests/{request_id}/open",
        json={},
        headers=as_actor(actor),
    )


def close_request(client, request_id, *, actor="alice", review=None):
    payload = {} if review is None else {"review": review}
    return client.post(
        f"/api/v1/break-glass/requests/{request_id}/close",
        json=payload,
        headers=as_actor(actor),
    )


def detail(client, request_id):
    response = client.get(f"/api/v1/break-glass/requests/{request_id}")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def feed(client, source="break-glass"):
    response = client.get("/api/v1/events", query_string={"source": source})
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def actions(client):
    return [row["action"] for row in feed(client)["events"]]


def stats(client):
    response = client.get("/api/v1/break-glass/stats")
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def open_emergency(client, *, target=TARGET, item_name=None):
    """The full pre-open path on real data: credential on file, request
    filed, two distinct approvals - returns (request, vault_item)."""
    item = onboard(
        client, item_name or "break-glass-db-cred", target=target
    )
    request = file_request(client, target=target)
    approved = dual_approve(client, request["id"])
    assert approved["status"] == "approved"
    return request, item


# ---------------------------------------------------------------------------
# filing: verbatim inputs, honest MFA state, ledger record
# ---------------------------------------------------------------------------
def test_create_requires_reason_and_target(client):
    no_reason = client.post(
        "/api/v1/break-glass/requests",
        json={"target": TARGET},
        headers=ACTOR,
    )
    assert no_reason.status_code == 400
    assert no_reason.get_json()["details"]["field"] == "reason"

    no_target = client.post(
        "/api/v1/break-glass/requests",
        json={"reason": "need in"},
        headers=ACTOR,
    )
    assert no_target.status_code == 400
    assert no_target.get_json()["details"]["field"] == "target"

    bad_severity = client.post(
        "/api/v1/break-glass/requests",
        json={"reason": "need in", "target": TARGET, "severity": "sev0"},
        headers=ACTOR,
    )
    assert bad_severity.status_code == 400
    assert bad_severity.get_json()["details"]["allowed"] == [
        "sev1",
        "sev2",
        "sev3",
    ]

    bad_protocol = client.post(
        "/api/v1/break-glass/requests",
        json={"reason": "need in", "target": TARGET, "protocol": "telnetish"},
        headers=ACTOR,
    )
    assert bad_protocol.status_code == 400
    assert bad_protocol.get_json()["details"]["field"] == "protocol"


def test_create_records_request_and_ledger_row(client):
    request = file_request(client, actor="alice")
    assert request["request_ref"].startswith("bg-")
    assert request["status"] == "pending"
    assert request["requested_by"] == "alice"
    assert request["severity"] == "sev1"
    assert request["protocol"] == "postgresql"
    assert request["approvals_required"] == 2
    assert request["approvals_signed"] == 0

    # filing is an action: it lands on the tenth ledger trail
    page = feed(client)
    assert page["total"] == 1
    row = page["events"][0]
    assert row["action"] == "requested"
    assert row["actor"] == "alice"
    assert row["subject"] == request["request_ref"]
    assert row["detail"]["reason"] == request["reason"]
    assert row["id"].startswith("break-glass:")


def test_mfa_is_recorded_honestly_never_faked(client):
    request = file_request(client, actor="alice")
    # section 20 does not exist yet: the request says so plainly
    assert request["mfa"] == "not configured"

    item = onboard(client, "mfa-cred", target=TARGET)
    dual_approve(client, request["id"])
    opened = open_request(client, request["id"])
    assert opened.status_code == 201, opened.get_json()
    assert opened.get_json()["request"]["mfa"] == "not configured"

    rows = {row["action"]: row for row in feed(client)["events"]}
    assert rows["requested"]["detail"]["mfa"] == "not configured"
    assert rows["opened"]["detail"]["mfa"] == "not configured"
    assert item["id"] == opened.get_json()["request"]["opened_item_id"]


# ---------------------------------------------------------------------------
# dual approval: two distinct approvers, self-approval refused
# ---------------------------------------------------------------------------
def test_dual_approval_flow_reaches_approved(client):
    request = file_request(client, actor="alice")

    first = approve(client, request["id"], actor="bob", note="paged CISO")
    assert first.status_code == 200, first.get_json()
    body = first.get_json()
    assert body["request"]["status"] == "pending"  # 1/2: nothing released yet
    assert body["request"]["approvals_signed"] == 1
    assert "Approval 1/2" in body["message"]

    second = approve(client, request["id"], actor="carol")
    assert second.status_code == 200, second.get_json()
    body = second.get_json()
    assert body["request"]["status"] == "approved"
    assert body["request"]["approvals_signed"] == 2
    assert "2/2" in body["message"]

    approvals = body["request"]["approvals"]
    assert [row["approver"] for row in approvals] == ["bob", "carol"]
    assert approvals[0]["note"] == "paged CISO"
    assert approvals[1]["note"] == ""

    # both signatures are on the ledger
    assert actions(client).count("approved") == 2


def test_requester_cannot_approve_own_emergency(client):
    request = file_request(client, actor="alice")
    response = approve(client, request["id"], actor="alice")
    assert response.status_code == 403
    assert "own emergency" in response.get_json()["error"]
    # nothing recorded
    assert detail(client, request["id"])["request"]["approvals_signed"] == 0


def test_second_approver_must_be_someone_else(client):
    request = file_request(client, actor="alice")
    first = approve(client, request["id"], actor="bob")
    assert first.status_code == 200

    again = approve(client, request["id"], actor="bob")
    assert again.status_code == 400
    assert again.get_json()["details"]["field"] == "approver"

    state = detail(client, request["id"])["request"]
    assert state["status"] == "pending"  # one valid signature only
    assert state["approvals_signed"] == 1


def test_approve_rejects_closed_states_and_unknown_ids(client):
    request = file_request(client, actor="alice")
    assert deny(client, request["id"], actor="carol").status_code == 200

    late = approve(client, request["id"], actor="bob")
    assert late.status_code == 400
    assert late.get_json()["details"]["status"] == "denied"

    missing = approve(client, 999999, actor="bob")
    assert missing.status_code == 404


def test_deny_records_who_when_and_note(client):
    request = file_request(client, actor="alice")
    response = deny(client, request["id"], actor="carol", note="use the DR runbook")
    assert response.status_code == 200, response.get_json()
    view = response.get_json()["request"]
    assert view["status"] == "denied"
    assert view["denied_by"] == "carol"
    assert view["deny_note"] == "use the DR runbook"
    assert view["denied_at"] is not None

    # denied requests never open
    opened = open_request(client, request["id"])
    assert opened.status_code == 400
    assert opened.get_json()["details"]["status"] == "denied"
    assert "denied" in actions(client)


# ---------------------------------------------------------------------------
# opening: real vault checkout, mandatory recording, risk still judging
# ---------------------------------------------------------------------------
def test_open_requires_dual_approval_first(client):
    request = file_request(client, actor="alice")
    response = open_request(client, request["id"])
    assert response.status_code == 400
    assert "two distinct approvals" in response.get_json()["error"]
    assert response.get_json()["details"]["status"] == "pending"

    approve(client, request["id"], actor="bob")  # 1/2 is still not enough
    one_of_two = open_request(client, request["id"])
    assert one_of_two.status_code == 400


def test_open_releases_credential_and_starts_recorded_session(client):
    request, item = open_emergency(client)
    opened = open_request(client, request["id"])
    assert opened.status_code == 201, opened.get_json()
    body = opened.get_json()

    # status machine: pending -> approved -> used
    assert body["request"]["status"] == "used"
    assert body["request"]["session_id"] == body["session"]["id"]
    assert body["request"]["opened_by"] == "alice"
    assert body["request"]["opened_item_id"] == item["id"]

    # recording is forced, not a preference
    assert body["session"]["controls"]["record"] is True
    assert body["session"]["status"] == "active"

    # the real vault checkout happened
    released = vault_item(client, item["id"])
    assert released["status"] == "checked_out"
    assert released["checked_out_by"] == "alice"

    # the section-7 gate judged the start and allowed it (evaluation kept)
    assert body["risk"]["result"] == "allowed"
    assert body["risk"]["band"] in ("low", "medium")
    assert body["risk"]["score"] <= 50

    # the opened record is the section-17 automatic alert on the trail
    row = feed(client)["events"][0]
    assert row["action"] == "opened"
    assert row["detail"]["record"] is True
    assert row["detail"]["session_ref"] == body["session"]["session_ref"]
    assert row["detail"]["mfa"] == "not configured"


def test_open_twice_reports_the_session_already_open(client):
    request, _ = open_emergency(client)
    assert open_request(client, request["id"]).status_code == 201

    second = open_request(client, request["id"])
    assert second.status_code == 400
    assert "already open" in second.get_json()["error"]


def test_open_without_credential_says_so_plainly(client):
    request = file_request(client, target=NO_CREDENTIAL_TARGET)
    dual_approve(client, request["id"])

    response = open_request(client, request["id"])
    assert response.status_code == 400
    assert (
        response.get_json()["error"]
        == "No vault credential is registered for this target"
    )
    # nothing was released: still approved, no session
    state = detail(client, request["id"])
    assert state["request"]["status"] == "approved"
    assert state["session"] is None


def test_open_conflicts_while_the_credential_is_checked_out(client):
    request, item = open_emergency(client)
    checkout = client.post(
        f"/api/v1/vault/items/{item['id']}/checkout",
        json={},
        headers=as_actor("someone-else"),
    )
    assert checkout.status_code == 200, checkout.get_json()

    response = open_request(client, request["id"])
    assert response.status_code == 409
    blocked = response.get_json()["details"]["credentials"]
    assert blocked[0]["id"] == item["id"]
    assert blocked[0]["status"] == "checked_out"


# ---------------------------------------------------------------------------
# closing: session ended, rotation guaranteed once, review required
# ---------------------------------------------------------------------------
def test_close_requires_the_post_incident_review_note(client):
    request, _ = open_emergency(client)
    assert open_request(client, request["id"]).status_code == 201

    missing = close_request(client, request["id"])
    assert missing.status_code == 400
    assert missing.get_json()["details"]["field"] == "review"

    blank = close_request(client, request["id"], review="   ")
    assert blank.status_code == 400


def test_close_only_allowed_from_an_open_emergency(client):
    request = file_request(client, actor="alice")

    from_pending = close_request(client, request["id"], review="nope")
    assert from_pending.status_code == 400
    assert from_pending.get_json()["details"]["status"] == "pending"

    dual_approve(client, request["id"])
    from_approved = close_request(client, request["id"], review="nope")
    assert from_approved.status_code == 400
    assert from_approved.get_json()["details"]["status"] == "approved"


def test_close_ends_session_rotates_once_and_files_review(client):
    request, item = open_emergency(client)
    opened = open_request(client, request["id"]).get_json()
    before = vault_item(client, item["id"])["secret_version"]

    closed = close_request(
        client,
        request["id"],
        actor="dave",
        review="Replication recovered from the DR node; emergency access "
        "was not needed after all. Credential rotated at close.",
    )
    assert closed.status_code == 200, closed.get_json()
    body = closed.get_json()

    # the session ended with the emergency (recorded as completed)
    assert body["session"]["status"] == "completed"
    assert body["request"]["status"] == "closed"
    assert body["request"]["closed_by"] == "dave"
    assert "Credential rotated at close" in body["request"]["review"]

    # exactly one rotation: the session-end cascade covered it
    assert body["rotation"]["status"] == "rotated"
    assert body["rotation"]["performed"] == "at session end"
    after = vault_item(client, item["id"])
    expected = (before if before is not None else 0) + 1
    assert after["secret_version"] == expected
    assert after["status"] == "available"

    # the process closed on the ledger with its review note
    row = feed(client)["events"][0]
    assert row["action"] == "closed"
    assert "DR node" in row["detail"]["review"]
    assert row["detail"]["session_status"] == "completed"


def test_close_after_early_session_end_does_not_rotate_twice(client):
    request, item = open_emergency(client)
    opened = open_request(client, request["id"]).get_json()
    session_id = opened["session"]["id"]
    before = vault_item(client, item["id"])["secret_version"]

    # operator ends the session first: the cascade rotates once, right there
    ended = client.post(
        f"/api/v1/sessions/{session_id}/terminate",
        json={"reason": "operator ended the emergency channel"},
        headers=as_actor("alice"),
    )
    assert ended.status_code == 200, ended.get_json()
    mid = vault_item(client, item["id"])["secret_version"]
    assert mid == (before if before is not None else 0) + 1

    # closing afterwards records the rotation that already happened
    closed = close_request(client, request["id"], review="session ended by ops")
    assert closed.status_code == 200, closed.get_json()
    body = closed.get_json()
    assert body["rotation"]["status"] == "rotated"
    assert body["rotation"]["performed"] == "at session end"
    assert body["rotation"]["secret_version"] == mid

    final = vault_item(client, item["id"])["secret_version"]
    assert final == mid  # still exactly one rotation


def test_close_forces_rotation_when_the_early_release_skipped_it(client):
    request, item = open_emergency(client)
    opened = open_request(client, request["id"]).get_json()
    session_id = opened["session"]["id"]
    before = vault_item(client, item["id"])["secret_version"]

    # release the checkout by hand: the session-end cascade then has nothing
    # to release-and-rotate, so the rotation is owed to the close step
    released = client.post(
        f"/api/v1/vault/items/{item['id']}/revoke",
        json={},
        headers=as_actor("alice"),
    )
    assert released.status_code == 200, released.get_json()
    ended = client.post(
        f"/api/v1/sessions/{session_id}/terminate",
        json={},
        headers=as_actor("alice"),
    )
    assert ended.status_code == 200, ended.get_json()
    assert vault_item(client, item["id"])["secret_version"] == before

    closed = close_request(client, request["id"], review="forced rotation on close")
    assert closed.status_code == 200, closed.get_json()
    rotation = closed.get_json()["rotation"]
    assert rotation["status"] == "rotated"
    rotated_ids = {entry["id"] for entry in rotation["items"]}
    assert item["id"] in rotated_ids

    after = vault_item(client, item["id"])["secret_version"]
    assert after == (before if before is not None else 0) + 1


# ---------------------------------------------------------------------------
# read paths: list, detail, stats, source hygiene
# ---------------------------------------------------------------------------
def test_list_filter_paging_and_validation(client):
    first = file_request(client, actor="alice")
    assert deny(client, first["id"], actor="carol").status_code == 200
    file_request(client, actor="alice", target="cache-01.corp")

    everything = client.get("/api/v1/break-glass/requests").get_json()
    assert everything["total"] == 2
    assert {row["status"] for row in everything["requests"]} == {
        "pending",
        "denied",
    }
    assert all("approvals" in row for row in everything["requests"])

    pending = client.get(
        "/api/v1/break-glass/requests", query_string={"status": "pending"}
    ).get_json()
    assert pending["total"] == 1
    assert pending["requests"][0]["status"] == "pending"

    limited = client.get(
        "/api/v1/break-glass/requests", query_string={"limit": 1}
    ).get_json()
    assert len(limited["requests"]) == 1
    assert limited["total"] == 2

    bad = client.get(
        "/api/v1/break-glass/requests", query_string={"status": "nope"}
    )
    assert bad.status_code == 400
    assert bad.get_json()["details"]["allowed"] == [
        "pending",
        "approved",
        "denied",
        "used",
        "closed",
    ]


def test_detail_carries_approvals_and_the_recorded_session(client):
    request, _ = open_emergency(client)

    before_open = detail(client, request["id"])
    assert before_open["request"]["approvals_signed"] == 2
    assert before_open["session"] is None

    opened = open_request(client, request["id"]).get_json()
    state = detail(client, request["id"])
    assert state["session"]["id"] == opened["session"]["id"]
    assert state["session"]["session_ref"].startswith("sess-")
    assert state["session"]["controls"]["record"] is True
    assert state["request"]["status"] == "used"

    missing = client.get("/api/v1/break-glass/requests/999999")
    assert missing.status_code == 404


def test_stats_reflect_the_real_counts(client):
    request, _ = open_emergency(client)
    assert open_request(client, request["id"]).status_code == 201

    state = stats(client)
    assert state["requests"] == {
        "total": 1,
        "pending": 0,
        "approved": 0,
        "denied": 0,
        "used": 1,
        "closed": 0,
    }
    assert state["approvals"] == {"recorded": 2, "outstanding": 0}
    assert state["open_emergencies"] == 1
    assert state["actions"] == {
        "requested": 1,
        "approved": 2,
        "denied": 0,
        "opened": 1,
        "closed": 0,
    }
    assert state["last_request_at"] is not None
    assert state["last_opened_at"] is not None
    assert state["last_closed_at"] is None

    # one pending request still owes both signatures
    pending = file_request(client, actor="alice")
    state = stats(client)
    assert state["requests"]["pending"] == 1
    assert state["approvals"]["outstanding"] == 2
    assert stats(client)["open_emergencies"] == 1
    assert detail(client, pending["id"])["request"]["approvals_signed"] == 0


def test_the_whole_process_walks_the_ledger_in_order(client):
    request, _ = open_emergency(client)
    assert open_request(client, request["id"]).status_code == 201
    assert close_request(
        client, request["id"], review="full-path verification"
    ).status_code == 200

    # newest first: closed, opened, approved, approved, requested
    walked = actions(client)
    assert walked == ["closed", "opened", "approved", "approved", "requested"]

    # every row belongs to this trail only, under its own id namespace
    rows = feed(client)["events"]
    assert all(row["source"] == "break-glass" for row in rows)
    assert all(row["id"].startswith("break-glass:") for row in rows)
    assert all(
        row["subject"] == request["request_ref"] for row in rows
    )
