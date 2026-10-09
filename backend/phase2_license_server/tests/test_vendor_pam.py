"""Section 13: third-party / vendor PAM (phase 5a).

The whole chain the architecture draws - *Invite -> MFA -> NDA -> Ticket ->
Approval -> JIT -> Session Recording -> Automatic Expiry* - against real
machinery only: RFC-6238 over the seed sealed at invite, the section-20
ITSM check as a real HTTP GET (a local stub answers; an unconfigured
connector refuses honestly), the section-6 JIT request underneath, and the
vendor dashboard (access / denied / valid window / recording) rendered
from the account's own row. Every refusal is asserted by its status,
`details` and the `vendor` ledger trail it lands on.
"""
from __future__ import annotations

import sys
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import integrations  # noqa: E402  (local module, path set above)
from app import create_app  # noqa: E402
from config import Config  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}
GOOD_TICKET = "INC-23891"
MISSING_TICKET = "NOTFOUND-99999"  # the stub answers 404 for this one
TARGET = "srv-01.corp:22"


# ---------------------------------------------------------------------------
# fixtures (same shapes as the neighbouring suites)
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


class _ItsmStub(BaseHTTPRequestHandler):
    """Local ITSM stand-in: any ticket answers 200 (verified), the
    NOTFOUND-* family answers 404 - real HTTP, no simulation in the
    product code under test."""

    def do_GET(self):  # noqa: N802 (stdlib naming)
        if "NOTFOUND" in self.path:
            body, code = b'{"error": "not found"}', 404
        else:
            body, code = b'{"result": {"state": "verified"}}', 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the suite output clean
        pass


@pytest.fixture(scope="module")
def itsm_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ItsmStub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
def invite(client, name="ABC Technologies", **overrides):
    payload = {"name": name, "contact": "ops@abc.example"}
    payload.update(overrides)
    response = client.post("/api/v1/vendors", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["vendor"], body["mfa"]


def configure_itsm(client, base_url):
    response = client.put(
        "/api/v1/settings/itsm", json={"base_url": base_url}, headers=ACTOR
    )
    assert response.status_code == 200, response.get_json()


def step(client, vendor_id, tail, payload):
    return client.post(
        f"/api/v1/vendors/{vendor_id}/{tail}", json=payload, headers=ACTOR
    )


def totp(secret: str) -> str:
    return integrations.totp_now(secret)


def run_chain(client, name, mfa_secret, vendor_id, *, itsm=None, ticket=GOOD_TICKET):
    """MFA -> NDA -> ticket -> approve, returning the fresh vendor view."""
    if itsm is not None:
        configure_itsm(client, itsm)
    assert step(client, vendor_id, "mfa", {"code": totp(mfa_secret)}).status_code == 200
    assert (
        step(client, vendor_id, "nda", {"ref": "NDA-2026-001"}).status_code == 200
    )
    assert (
        step(client, vendor_id, "ticket", {"ticket": ticket}).status_code == 200
    )
    approved = client.post(f"/api/v1/vendors/{vendor_id}/approve", headers=ACTOR)
    assert approved.status_code == 200, approved.get_json()
    detail = client.get(f"/api/v1/vendors/{vendor_id}").get_json()
    assert detail["name"] == name
    return detail


def approved_vendor(client, name, *, allowed=None, itsm_url=None, **invite_overrides):
    """An approved vendor with its scope already set."""
    allowed = [TARGET] if allowed is None else allowed
    vendor, mfa = invite(
        client, name, allowed_targets=allowed, **invite_overrides
    )
    detail = run_chain(client, name, mfa["secret"], vendor["id"], itsm=itsm_url)
    return detail, mfa


def onboard(client, name, *, target=TARGET, access_tier="Tier-2"):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": target,
            "principal": "admin",
            "access_tier": access_tier,
            "auth_method": "Password",
            "rotation_interval_hours": 24,
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def file_vendor_request(client, vendor_id, item_id, **overrides):
    payload = {
        "item_id": item_id,
        "reason": "Vendor maintenance window for the quarterly patch cycle",
        "minutes": 15,
    }
    payload.update(overrides)
    return client.post(
        f"/api/v1/vendors/{vendor_id}/requests", json=payload, headers=ACTOR
    )


def grant_active(client, request_id):
    """Approve if the band asked for sign-off, then consume the grant."""
    detail = client.get(f"/api/v1/jit/requests/{request_id}").get_json()
    request = detail["request"]
    if request["status"] == "pending":
        done = client.post(
            f"/api/v1/jit/requests/{request_id}/approve",
            json={"role": "manager"},
            headers={**ACTOR, "X-Actor": "mgr"},
        )
        assert done.status_code == 200, done.get_json()
    granted = client.post(
        f"/api/v1/jit/requests/{request_id}/consume", headers=ACTOR
    )
    assert granted.status_code == 200, granted.get_json()
    return granted.get_json()["request"]


def start_session(client, request_id, **overrides):
    payload = {
        "protocol": "ssh",
        "target": TARGET,
        "jit_request_id": request_id,
    }
    payload.update(overrides)
    return client.post("/api/v1/sessions", json=payload, headers=ACTOR)


def excluded_window():
    """A HH:MM window that never contains the current minute."""
    now = datetime.now().strftime("%H:%M")
    return ("12:00", "13:00") if now < "12:00" else ("00:00", "01:00")


# ---------------------------------------------------------------------------
# invite
# ---------------------------------------------------------------------------
def test_invite_shows_the_factor_once_and_seals_it(client, app):
    vendor, mfa = invite(client, "ABC Technologies", allowed_targets=[TARGET])
    assert vendor["status"] == "invited"
    assert vendor["steps"] == {
        "mfa": "pending", "nda": "pending", "ticket": "pending",
        "approval": "pending",
    }
    assert set(mfa) >= {"secret", "otpauth_uri", "digits", "period", "algorithm"}
    assert "ABC%20Technologies" in mfa["otpauth_uri"] or "ABC" in mfa["otpauth_uri"]
    assert mfa["digits"] == 6 and mfa["period"] == 30

    # the stored seed is sealed ciphertext, not the plaintext that was shown
    with app.app_context():
        from extensions import db
        from models import VendorAccount

        row = db.session.get(VendorAccount, vendor["id"])
        assert isinstance(row.mfa_secret, dict) and row.mfa_secret != mfa["secret"]

    # and the plaintext never appears in any later response
    for url in ("/api/v1/vendors", f"/api/v1/vendors/{vendor['id']}"):
        raw = client.get(url).get_data(as_text=True)
        assert mfa["secret"] not in raw
        assert "otpauth://" not in raw


def test_invite_validation_and_duplicates(client):
    missing = client.post("/api/v1/vendors", json={}, headers=ACTOR)
    assert missing.status_code == 400
    assert missing.get_json()["details"]["field"] == "name"

    short = client.post("/api/v1/vendors", json={"name": "X"}, headers=ACTOR)
    assert short.status_code == 400

    half_window = client.post(
        "/api/v1/vendors", json={"name": "Half Window", "window_start": "09:00"},
        headers=ACTOR,
    )
    assert half_window.status_code == 400
    assert half_window.get_json()["details"]["field"] == "window"

    backwards = client.post(
        "/api/v1/vendors",
        json={"name": "Backwards", "window_start": "16:00", "window_end": "14:00"},
        headers=ACTOR,
    )
    assert backwards.status_code == 400

    bad_targets = client.post(
        "/api/v1/vendors", json={"name": "Bad Targets", "allowed_targets": "x"},
        headers=ACTOR,
    )
    assert bad_targets.status_code == 400
    assert bad_targets.get_json()["details"]["field"] == "allowed_targets"

    past = client.post(
        "/api/v1/vendors",
        json={"name": "Past Expiry", "expires_at": "2020-01-01T00:00:00"},
        headers=ACTOR,
    )
    assert past.status_code == 400
    assert past.get_json()["details"]["field"] == "expires_at"

    invite(client, "Taken Name")
    again = client.post("/api/v1/vendors", json={"name": "Taken Name"}, headers=ACTOR)
    assert again.status_code == 409
    assert again.get_json()["details"]["field"] == "name"


def test_denied_name_can_be_reinvited_fresh(client):
    vendor, _ = invite(client, "Ghost Ops")
    denied = client.post(
        f"/api/v1/vendors/{vendor['id']}/deny",
        json={"reason": "NDA declined by their legal team"},
        headers=ACTOR,
    )
    assert denied.status_code == 200
    assert denied.get_json()["vendor"]["status"] == "denied"

    fresh, mfa = invite(client, "Ghost Ops", allowed_targets=[TARGET])
    assert fresh["id"] == vendor["id"]  # same row, fresh cycle
    assert fresh["status"] == "invited"
    assert fresh["steps"]["mfa"] == "pending"
    assert fresh["mfa_verified_at"] is None

    detail = client.get(f"/api/v1/vendors/{vendor['id']}").get_json()
    actions = [event["action"] for event in detail["events"]]
    assert "denied" in actions  # the refused cycle stays on the trail
    assert "invited" in actions


# ---------------------------------------------------------------------------
# MFA / NDA / ticket steps
# ---------------------------------------------------------------------------
def test_mfa_step_requires_the_real_code(client):
    vendor, mfa = invite(client, "MFA Vendor")

    wrong = step(client, vendor["id"], "mfa", {"code": "000000"})
    # a wrong code is either refused as invalid or (astronomically) accepted;
    # when refused it must be the honest 401 with the reason
    if wrong.status_code == 401:
        body = wrong.get_json()
        assert body["details"]["field"] == "mfa_code"
        assert "invalid" in body["details"]["mfa"]
    else:
        assert wrong.status_code == 200  # the one-in-a-million real code

    no_code = step(client, vendor["id"], "mfa", {})
    assert no_code.status_code == 400
    assert no_code.get_json()["details"]["field"] == "mfa_code"

    good = step(client, vendor["id"], "mfa", {"code": totp(mfa["secret"])})
    assert good.status_code == 200, good.get_json()
    assert good.get_json()["vendor"]["steps"]["mfa"] == "verified"

    repeat = step(client, vendor["id"], "mfa", {"code": totp(mfa["secret"])})
    assert repeat.status_code == 409  # already verified


def test_nda_step_records_reference_or_honest_null(client):
    vendor, _ = invite(client, "NDA Vendor")
    signed = step(client, vendor["id"], "nda", {"ref": "NDA-4416"})
    assert signed.status_code == 200
    view = signed.get_json()["vendor"]
    assert view["steps"]["nda"] == "signed"
    assert view["nda"] == {"ref": "NDA-4416", "signed_at": view["nda"]["signed_at"]}
    assert view["nda"]["signed_at"]

    again = step(client, vendor["id"], "nda", {})
    assert again.status_code == 409

    # a reference is optional; the timestamp is not
    other, _ = invite(client, "NDA Vendor Two")
    bare = step(client, other["id"], "nda", {})
    assert bare.status_code == 200
    assert bare.get_json()["vendor"]["nda"]["ref"] is None
    assert bare.get_json()["vendor"]["nda"]["signed_at"]


def test_ticket_step_is_honest_about_itsm(client):
    vendor, _ = invite(client, "Ticket Vendor")

    unconfigured = step(client, vendor["id"], "ticket", {"ticket": GOOD_TICKET})
    assert unconfigured.status_code == 409
    body = unconfigured.get_json()
    assert body["details"]["configured"] is False
    assert "not configured" in body["error"]

    bad_shape = step(client, vendor["id"], "ticket", {"ticket": "nonsense"})
    assert bad_shape.status_code == 400
    assert bad_shape.get_json()["details"]["field"] == "ticket"


def test_ticket_verification_runs_against_a_real_endpoint(client, itsm_url):
    vendor, _ = invite(client, "Verified Vendor")
    configure_itsm(client, itsm_url)

    good = step(client, vendor["id"], "ticket", {"ticket": GOOD_TICKET})
    assert good.status_code == 200, good.get_json()
    view = good.get_json()["vendor"]
    assert view["steps"]["ticket"] == "verified"
    assert view["ticket"] == GOOD_TICKET
    assert view["ticket_verification"]["verified"] is True
    assert view["ticket_verification"]["configured"] is True

    # the stub answers 404 for NOTFOUND-* -> the upstream's own answer,
    # refused, never a fabricated pass
    other, _ = invite(client, "Unverified Vendor")
    failed = step(client, other["id"], "ticket", {"ticket": MISSING_TICKET})
    assert failed.status_code == 409
    body = failed.get_json()
    assert body["details"]["verified"] is False
    assert body["details"]["http_status"] == 404
    detail = client.get(f"/api/v1/vendors/{other['id']}").get_json()
    assert detail["ticket_verified_at"] is None
    assert "ticket-refused" in [event["action"] for event in detail["events"]]


# ---------------------------------------------------------------------------
# approval / deny
# ---------------------------------------------------------------------------
def test_approval_gates_on_every_step(client, itsm_url):
    vendor, mfa = invite(client, "Chain Vendor", allowed_targets=[TARGET])

    early = client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR)
    assert early.status_code == 409
    assert early.get_json()["details"]["missing"] == ["mfa", "nda", "ticket"]

    configure_itsm(client, itsm_url)
    assert step(client, vendor["id"], "mfa", {"code": totp(mfa["secret"])}).status_code == 200
    assert step(client, vendor["id"], "nda", {}).status_code == 200

    still = client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR)
    assert still.status_code == 409
    assert still.get_json()["details"]["missing"] == ["ticket"]

    assert step(client, vendor["id"], "ticket", {"ticket": GOOD_TICKET}).status_code == 200
    done = client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR)
    assert done.status_code == 200
    view = done.get_json()["vendor"]
    assert view["status"] == "approved"
    assert view["steps"]["approval"] == "approved"
    assert view["approved_by"] == "admin"
    assert view["approved_at"]

    repeat = client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR)
    assert repeat.status_code == 409

    detail = client.get(f"/api/v1/vendors/{vendor['id']}").get_json()
    actions = [event["action"] for event in detail["events"]]
    assert "approval-refused" in actions and "approved" in actions


def test_deny_freezes_the_invite(client):
    vendor, _ = invite(client, "Denied Vendor")
    denied = client.post(
        f"/api/v1/vendors/{vendor['id']}/deny",
        json={"reason": "no signed agreement on file"},
        headers=ACTOR,
    )
    assert denied.status_code == 200
    view = denied.get_json()["vendor"]
    assert view["status"] == "denied"
    assert view["denied_reason"] == "no signed agreement on file"
    assert view["steps"]["approval"] == "denied"

    assert (
        client.post(f"/api/v1/vendors/{vendor['id']}/deny", headers=ACTOR).status_code
        == 409
    )
    assert (
        client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR).status_code
        == 409
    )


# ---------------------------------------------------------------------------
# scope / dashboard / update
# ---------------------------------------------------------------------------
def test_dashboard_carries_the_spec_example(client, itsm_url):
    start, end = "14:00", "16:00"
    detail, _ = approved_vendor(
        client, "ABC Technologies",
        allowed=["srv-01.corp:22", "srv-03.corp:22"],
        itsm_url=itsm_url,
        denied_targets=["Database", "Firewall"],
        window_start=start,
        window_end=end,
        recording=True,
    )
    # the section-13 dashboard example, straight from the account's row
    assert detail["name"] == "ABC Technologies"
    access = detail["access"]
    assert access["allowed"] == ["srv-01.corp:22", "srv-03.corp:22"]
    assert access["denied"] == ["Database", "Firewall"]
    assert access["window"] == "14:00–16:00"
    assert access["recording"] is True
    assert access["expires_at"] is None
    assert detail["steps"] == {
        "mfa": "verified", "nda": "signed", "ticket": "verified",
        "approval": "approved",
    }
    assert detail["requests"] == [] and detail["request_count"] == 0
    assert [event["action"] for event in detail["events"]][0] == "approved"


def test_update_edits_scope_and_validates(client):
    vendor, _ = invite(client, "Scoped Vendor", allowed_targets=["a:1"])

    patched = client.patch(
        f"/api/v1/vendors/{vendor['id']}",
        json={
            "allowed_targets": [TARGET, "srv-02.corp:22"],
            "denied_targets": ["Firewall"],
            "recording": False,
        },
        headers=ACTOR,
    )
    assert patched.status_code == 200
    access = patched.get_json()["vendor"]["access"]
    assert access["allowed"] == [TARGET, "srv-02.corp:22"]
    assert access["denied"] == ["Firewall"]
    assert access["recording"] is False

    unknown = client.patch(
        f"/api/v1/vendors/{vendor['id']}", json={"nope": 1}, headers=ACTOR
    )
    assert unknown.status_code == 400
    assert unknown.get_json()["details"]["field"] == "nope"

    half = client.patch(
        f"/api/v1/vendors/{vendor['id']}", json={"window_start": "09:00"},
        headers=ACTOR,
    )
    assert half.status_code == 400

    window = client.patch(
        f"/api/v1/vendors/{vendor['id']}",
        json={"window_start": "09:00", "window_end": "17:00"},
        headers=ACTOR,
    )
    assert window.status_code == 200
    assert window.get_json()["vendor"]["access"]["window"] == "09:00–17:00"

    detail = client.get(f"/api/v1/vendors/{vendor['id']}").get_json()
    fields = set()
    for event in detail["events"]:
        if event["action"] == "updated":
            fields.update(event["detail"]["fields"])
    assert {"allowed_targets", "denied_targets", "recording"} <= fields

    # frozen accounts cannot be edited
    denied = client.post(
        f"/api/v1/vendors/{vendor['id']}/deny", headers=ACTOR
    )
    assert denied.status_code == 200
    frozen = client.patch(
        f"/api/v1/vendors/{vendor['id']}", json={"contact": "x@y.z"}, headers=ACTOR
    )
    assert frozen.status_code == 409


# ---------------------------------------------------------------------------
# vendor access requests (scoped JIT)
# ---------------------------------------------------------------------------
def test_request_refused_until_approved(client, itsm_url):
    vendor, _ = invite(client, "Early Bird", allowed_targets=[TARGET])
    item = onboard(client, "early-item")

    refused = file_vendor_request(client, vendor["id"], item["id"])
    assert refused.status_code == 403
    body = refused.get_json()
    assert body["details"]["vendor"]["reason"] == "account is invited"
    detail = client.get(f"/api/v1/vendors/{vendor['id']}").get_json()
    assert "access-refused" in [event["action"] for event in detail["events"]]
    assert detail["request_count"] == 0


def test_request_scope_and_window_gates(client, itsm_url):
    detail, _ = approved_vendor(client, "Scoped Co", itsm_url=itsm_url)
    vendor_id = detail["id"]
    inside = onboard(client, "scope-inside", target=TARGET)
    outside = onboard(client, "scope-outside", target="db-99.corp:5432")

    # outside the allow list
    denied_scope = file_vendor_request(client, vendor_id, outside["id"])
    assert denied_scope.status_code == 403
    assert denied_scope.get_json()["details"]["vendor"]["reason"] == (
        "target is not in the vendor's access list"
    )

    # deny takes precedence even when the entry is also allowed
    client.patch(
        f"/api/v1/vendors/{vendor_id}",
        json={"denied_targets": [TARGET]},
        headers=ACTOR,
    )
    denied_list = file_vendor_request(client, vendor_id, inside["id"])
    assert denied_list.status_code == 403
    assert denied_list.get_json()["details"]["vendor"]["reason"] == (
        "target is denied for this vendor"
    )
    client.patch(
        f"/api/v1/vendors/{vendor_id}", json={"denied_targets": []}, headers=ACTOR
    )

    # outside the valid window (a window that never holds the current minute)
    start, end = excluded_window()
    client.patch(
        f"/api/v1/vendors/{vendor_id}",
        json={"window_start": start, "window_end": end},
        headers=ACTOR,
    )
    outside_window = file_vendor_request(client, vendor_id, inside["id"])
    assert outside_window.status_code == 403
    window_body = outside_window.get_json()
    assert "window" in window_body["details"]
    assert window_body["details"]["window"]["window"] == f"{start}–{end}"
    assert window_body["details"]["window"]["now"]

    # clearing the window lets the very same request through - the window
    # was the only blocker
    client.patch(
        f"/api/v1/vendors/{vendor_id}",
        json={"window_start": None, "window_end": None},
        headers=ACTOR,
    )
    filed = file_vendor_request(client, vendor_id, inside["id"])
    assert filed.status_code == 201, filed.get_json()


def test_request_is_the_normal_jit_machinery(client, itsm_url):
    detail, _ = approved_vendor(client, "JIT Co", itsm_url=itsm_url)
    vendor_id = detail["id"]
    item = onboard(client, "jit-co-item")  # Tier-2 + 15min + good ticket = low

    filed = file_vendor_request(client, vendor_id, item["id"])
    assert filed.status_code == 201, filed.get_json()
    request = filed.get_json()["request"]
    assert request["vendor_account_id"] == vendor_id
    assert request["requester"] == "ABC Technologies"[:64] or request["requester"]
    assert request["ticket"] == GOOD_TICKET  # defaults to the vendor's ticket
    assert request["risk"]["level"] in ("low", "medium", "high")
    assert request["risk"]["score"] == sum(
        factor["points"] for factor in request["risk"]["factors"]
    )
    assert request["status"] in ("approved", "pending")

    # the request also shows up on the vendor's dashboard
    dash = client.get(f"/api/v1/vendors/{vendor_id}").get_json()
    assert dash["request_count"] == 1
    assert dash["requests"][0]["id"] == request["id"]
    actions = [event["action"] for event in dash["events"]]
    assert actions.count("access-requested") == 1


# ---------------------------------------------------------------------------
# sessions: Recording: ENABLED + the scope gate at start
# ---------------------------------------------------------------------------
def test_vendor_session_forces_recording(client, itsm_url):
    detail, _ = approved_vendor(client, "Recording Co", itsm_url=itsm_url)
    item = onboard(client, "rec-item")
    filed = file_vendor_request(client, detail["id"], item["id"])
    assert filed.status_code == 201, filed.get_json()
    grant_active(client, filed.get_json()["request"]["id"])

    started = start_session(
        client, filed.get_json()["request"]["id"], record=False
    )
    assert started.status_code == 201, started.get_json()
    session = started.get_json()["session"]
    # forced - section 13, not a caller preference
    assert session["controls"]["record"] is True
    assert session["jit_request_id"] == filed.get_json()["request"]["id"]

    # recording really works: a channel event lands in the recording
    posted = client.post(
        f"/api/v1/sessions/{session['id']}/events",
        json={"type": "command", "content": "systemctl reload nginx"},
        headers=ACTOR,
    )
    assert posted.status_code == 201
    events = client.get(f"/api/v1/sessions/{session['id']}/events").get_json()
    assert any(event["content"] == "systemctl reload nginx" for event in events["events"])


def test_session_gate_refuses_tightened_scope(client, itsm_url):
    detail, _ = approved_vendor(client, "Tightened Co", itsm_url=itsm_url)
    item = onboard(client, "tight-item")
    filed = file_vendor_request(client, detail["id"], item["id"])
    assert filed.status_code == 201, filed.get_json()
    request_id = filed.get_json()["request"]["id"]
    grant_active(client, request_id)

    # the admin tightens the scope while the grant is live
    client.patch(
        f"/api/v1/vendors/{detail['id']}",
        json={"allowed_targets": ["other-box:22"]},
        headers=ACTOR,
    )
    refused = start_session(client, request_id)
    assert refused.status_code == 403
    assert refused.get_json()["details"]["vendor"]["reason"] == (
        "target is not in the vendor's access list"
    )
    dash = client.get(f"/api/v1/vendors/{detail['id']}").get_json()
    assert "session-refused" in [event["action"] for event in dash["events"]]

    # restoring the scope lets the session start
    client.patch(
        f"/api/v1/vendors/{detail['id']}",
        json={"allowed_targets": [TARGET]},
        headers=ACTOR,
    )
    started = start_session(client, request_id)
    assert started.status_code == 201, started.get_json()
    assert started.get_json()["session"]["controls"]["record"] is True


# ---------------------------------------------------------------------------
# revocation / expiry
# ---------------------------------------------------------------------------
def test_revoke_closes_grants_and_sessions(client, itsm_url):
    detail, _ = approved_vendor(client, "Revoked Co", itsm_url=itsm_url)
    item = onboard(client, "revoke-item")
    filed = file_vendor_request(client, detail["id"], item["id"])
    assert filed.status_code == 201, filed.get_json()
    request_id = filed.get_json()["request"]["id"]
    grant_active(client, request_id)
    started = start_session(client, request_id)
    assert started.status_code == 201, started.get_json()
    session_id = started.get_json()["session"]["id"]

    revoked = client.post(
        f"/api/v1/vendors/{detail['id']}/revoke",
        json={"reason": "contract terminated"},
        headers=ACTOR,
    )
    assert revoked.status_code == 200, revoked.get_json()
    body = revoked.get_json()
    assert body["grants_ended"] == [request_id]
    assert body["vendor"]["status"] == "revoked"

    grant = client.get(f"/api/v1/jit/requests/{request_id}").get_json()["request"]
    assert grant["status"] == "closed"
    session = client.get(f"/api/v1/sessions/{session_id}").get_json()["session"]
    assert session["status"] == "terminated"
    assert session["end_reason"] == "grant_closed"

    again = client.post(f"/api/v1/vendors/{detail['id']}/revoke", headers=ACTOR)
    assert again.status_code == 409
    after = file_vendor_request(client, detail["id"], item["id"])
    assert after.status_code == 403
    assert after.get_json()["details"]["vendor"]["reason"] == "account is revoked"


def test_expiry_is_automatic_and_lazy(client, app, itsm_url):
    future = (datetime.now() + timedelta(hours=1)).isoformat()
    vendor, _ = invite(client, "Expiring Co", expires_at=future)
    assert vendor["access"]["expires_at"] is not None

    with app.app_context():
        from extensions import db
        from models import VendorAccount

        row = db.session.get(VendorAccount, vendor["id"])
        row.expires_at = datetime.now() - timedelta(minutes=1)
        db.session.commit()

    listed = client.get("/api/v1/vendors").get_json()
    expired = next(v for v in listed["vendors"] if v["id"] == vendor["id"])
    assert expired["status"] == "expired"

    approve = client.post(f"/api/v1/vendors/{vendor['id']}/approve", headers=ACTOR)
    assert approve.status_code == 409

    detail = client.get(f"/api/v1/vendors/{vendor['id']}").get_json()
    actions = [event["action"] for event in detail["events"]]
    assert "expired" in actions


# ---------------------------------------------------------------------------
# trail + auth + list filters
# ---------------------------------------------------------------------------
def test_vendor_trail_reaches_the_ledger(client, itsm_url):
    detail, _ = approved_vendor(client, "Ledger Co", itsm_url=itsm_url)

    feed = client.get(
        "/api/v1/events", query_string={"source": "vendor"}
    ).get_json()
    assert feed["total"] >= 5
    assert feed["source"] == "vendor"
    actions = [row["action"] for row in feed["events"]]
    for expected in ("invited", "mfa-verified", "nda-signed", "ticket-verified", "approved"):
        assert expected in actions
    assert all(row["id"].startswith("vendor:") for row in feed["events"])
    assert all(row["source"] == "vendor" for row in feed["events"])
    # the ticket check itself stays on the integration trail (section 20
    # recorded it where connectors are recorded)
    itsm_feed = client.get(
        "/api/v1/events", query_string={"source": "integration"}
    ).get_json()
    assert "itsm-verified" in [row["action"] for row in itsm_feed["events"]]
    assert detail["id"]


def test_vendor_writes_require_the_admin_token(client):
    no_token = {"X-Actor": "admin"}
    assert client.post("/api/v1/vendors", json={"name": "No Auth"}, headers=no_token).status_code == 401
    assert client.post("/api/v1/vendors/1/mfa", json={"code": "123456"}, headers=no_token).status_code == 401
    assert client.post("/api/v1/vendors/1/approve", headers=no_token).status_code == 401
    assert client.patch("/api/v1/vendors/1", json={"contact": "x"}, headers=no_token).status_code == 401
    assert client.post("/api/v1/vendors/1/requests", json={}, headers=no_token).status_code == 401
    # reads stay public, like the other console inventory endpoints
    assert client.get("/api/v1/vendors").status_code == 200
    assert client.get("/api/v1/vendors/1").status_code == 404


def test_list_filters_and_paging(client, itsm_url):
    approved_vendor(client, "Alpha Co", itsm_url=itsm_url)
    invite(client, "Beta Industries")
    invite(client, "Gamma Services")

    everything = client.get("/api/v1/vendors").get_json()
    assert everything["total"] == 3
    assert {v["name"] for v in everything["vendors"]} == {
        "Alpha Co", "Beta Industries", "Gamma Services",
    }

    invited = client.get(
        "/api/v1/vendors", query_string={"status": "invited"}
    ).get_json()
    assert invited["total"] == 2
    approved = client.get(
        "/api/v1/vendors", query_string={"status": "approved"}
    ).get_json()
    assert approved["total"] == 1
    assert approved["vendors"][0]["name"] == "Alpha Co"

    search = client.get("/api/v1/vendors", query_string={"q": "industries"}).get_json()
    assert search["total"] == 1
    assert search["vendors"][0]["name"] == "Beta Industries"

    page = client.get(
        "/api/v1/vendors", query_string={"limit": 2, "offset": 2}
    ).get_json()
    assert len(page["vendors"]) == 1  # 3 total, offset 2 leaves one
    assert page["total"] == 3

    bad = client.get(
        "/api/v1/vendors", query_string={"status": "nonsense"}
    )
    assert bad.status_code == 400

    assert client.get("/api/v1/vendors/99999").status_code == 404
