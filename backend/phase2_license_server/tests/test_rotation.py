"""Tests for encrypted-at-rest secrets, versioning and the rotation engine.

Everything asserted here is real: secrets are sealed with AES-256-GCM and
the plaintext is checked absent from the database file, rotations mint new
versions validated by decrypt round-trip, cascade/skip/session-end behaviour
is read back from the API's own responses, and a quiet scheduler clock
produces no events.

Run with:  python -m pytest backend/phase2_license_server/tests/test_rotation.py -q
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from errors import APIError, ValidationFailed  # noqa: E402
from models import (  # noqa: E402
    VaultEvent,
    VaultItem,
    VaultSecretVersion,
    db,
)
import service as service_module  # noqa: E402
from rotation_scheduler import run_due  # noqa: E402
from secrets_store import (  # noqa: E402
    generate_secret,
    generated_secret_is_valid,
    seal,
    unseal,
)

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}


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


def onboard(client, name, **overrides):
    """Onboard a credential through the public API (the only way in)."""
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


def insert_item(app, name, *, status="available", secret_type="database",
                rotation_interval_hours=24, rotated_hours_ago=None,
                target="db.test.internal"):
    """Model-level insert for rows no API call produces (due/failed state,
    metadata-only legacy records)."""
    with app.app_context():
        item = VaultItem(
            name=name,
            secret_type=secret_type,
            description="test fixture",
            target=target,
            target_detail="",
            principal="admin",
            access_tier="Tier-1",
            auth_method="Password",
            rotation_interval_hours=rotation_interval_hours,
            last_rotated_at=(
                datetime.now() - timedelta(hours=rotated_hours_ago)
                if rotated_hours_ago is not None
                else datetime.now()
            ),
            status=status,
        )
        db.session.add(item)
        db.session.commit()
        return item.id


def reveal(client, item_id):
    return client.get(f"/api/v1/vault/items/{item_id}/secret", headers=ADMIN)


# ---------------------------------------------------------------------------
# at-rest encryption: masking, reveal, tamper resistance
# ---------------------------------------------------------------------------
def test_list_and_detail_never_expose_the_secret(client):
    value = "Op3rator-Supplied-Value-4411"
    item = onboard(client, "pg-primary", secret=value)

    page = client.get("/api/v1/vault/items").get_json()
    assert value not in json.dumps(page)
    row = page["items"][0]
    assert "secret" not in row
    assert row["secret_version"] == 1

    detail = client.get(f"/api/v1/vault/items/{item['id']}").get_json()
    assert value not in json.dumps(detail)
    assert "secret" not in detail["item"]


def test_no_plaintext_in_the_database_file(client, tmp_path):
    value = "Plaintext-Must-Not-Be-At-Rest-9977"
    onboard(client, "sql-secret", secret=value)

    raw = b""
    for suffix in ("", "-wal", "-shm"):
        path = tmp_path / f"licenses.db{suffix}"
        if path.exists():
            raw += path.read_bytes()
    # the sealed row is on disk, the plaintext is not
    assert b"vault_secret_versions" in raw
    assert value.encode("utf-8") not in raw


def test_reveal_requires_admin_token(client):
    item = onboard(client, "needs-auth")
    assert client.get(f"/api/v1/vault/items/{item['id']}/secret").status_code == 401


def test_reveal_unknown_item_is_404(client):
    response = client.get("/api/v1/vault/items/999/secret", headers=ADMIN)
    assert response.status_code == 404


def test_reveal_roundtrip_returns_the_stored_value(client):
    value = "Round-Trip-Value-8181"
    item = onboard(client, "rt-credential", secret=value)

    revealed = reveal(client, item["id"]).get_json()
    assert revealed["secret"] == value
    assert revealed["version"] == 1
    assert revealed["alg"] == "AES-256-GCM"
    assert revealed["source"] == "operator"
    assert revealed["item_id"] == item["id"]
    assert revealed["entropy_bits"] > 0


def test_metadata_only_record_reveals_404(app, client):
    item_id = insert_item(app, "legacy-metadata-row")
    response = reveal(client, item_id)
    assert response.status_code == 404
    assert "metadata-only" in response.get_json()["error"]


def test_aad_binds_each_ciphertext_to_its_row(app, client):
    item_a = onboard(client, "cred-a", secret="value-A-0001")
    item_b = onboard(client, "cred-b", secret="value-B-0002")
    with app.app_context():
        donor = VaultSecretVersion.query.filter_by(item_id=item_a["id"]).one()
        recipient = VaultSecretVersion.query.filter_by(item_id=item_b["id"]).one()
        # same bytes, wrong owner: AAD must reject the foreign ciphertext
        recipient.blob = dict(donor.blob)
        db.session.commit()

    response = reveal(client, item_b["id"])
    assert response.status_code == 500
    assert "integrity" in response.get_json()["error"]


def test_tampered_ciphertext_fails_its_integrity_check(app, client):
    item = onboard(client, "tamper-me", secret="original-value-1234")
    with app.app_context():
        row = VaultSecretVersion.query.filter_by(item_id=item["id"]).one()
        blob = dict(row.blob)
        raw = bytearray(base64.b64decode(blob["ct"]))
        raw[0] ^= 0xFF
        blob["ct"] = base64.b64encode(bytes(raw)).decode("ascii")
        row.blob = blob
        db.session.commit()

    response = reveal(client, item["id"])
    assert response.status_code == 500
    assert "integrity" in response.get_json()["error"]


def test_secret_store_roundtrip_and_format_checks(config):
    blob = seal("plain-value", 7, config)
    assert blob["v"] == 1
    assert blob["alg"] == "AES-256-GCM"
    assert unseal(blob, 7, config) == "plain-value"
    with pytest.raises(APIError):
        unseal(blob, 8, config)  # AAD belongs to item 7, not 8

    for kind in ("database", "domain_password", "service_account",
                 "api_token", "cloud_iam", "ssh_key"):
        value = generate_secret(kind)
        assert generated_secret_is_valid(kind, value), kind
    with pytest.raises(ValidationFailed):
        generate_secret("not-a-vault-type")


# ---------------------------------------------------------------------------
# versioning and the rotation pipeline
# ---------------------------------------------------------------------------
def test_rotate_mints_a_new_version_and_changes_the_value(client):
    first = onboard(client, "rotate-me", secret="v1-operator-value")
    before = reveal(client, first["id"]).get_json()
    assert before["version"] == 1

    response = client.post(
        f"/api/v1/vault/items/{first['id']}/rotate", headers=ACTOR
    )
    assert response.status_code == 200
    rotation = response.get_json()["rotation"]
    assert rotation["trigger"] == "manual"
    assert rotation["previous_status"] == "available"
    assert rotation["secret_version"] == 2
    assert rotation["validation"] == {
        "method": "local_roundtrip",
        "passed": True,
        "checks": ["decrypt", "plaintext_match", "type_format"],
    }
    assert rotation["dependents"] == {"considered": 0, "rotated": [], "skipped": []}
    assert rotation["duration_ms"] >= 0

    after = reveal(client, first["id"]).get_json()
    assert after["version"] == 2
    assert after["secret"] != before["secret"]
    assert after["source"] == "generated"

    with client.application.app_context():
        rows = (
            VaultSecretVersion.query.filter_by(item_id=first["id"])
            .order_by(VaultSecretVersion.version)
            .all()
        )
        assert [row.version for row in rows] == [1, 2]  # history retained
        item = VaultItem.query.filter_by(id=first["id"]).first()
        assert item.secret_version == 2
        assert item.status == "available"


def test_rotate_guards_checked_out_and_in_progress(app, client):
    checked = onboard(client, "checked-out-cred", target="t1")
    client.post(f"/api/v1/vault/items/{checked['id']}/checkout", headers=ACTOR)
    blocked = client.post(
        f"/api/v1/vault/items/{checked['id']}/rotate", headers=ACTOR
    )
    assert blocked.status_code == 400
    assert "Revoke the checkout" in blocked.get_json()["error"]

    spinning = insert_item(app, "mid-flight")
    with client.application.app_context():
        VaultItem.query.filter_by(id=spinning).first().status = "rotating"
        db.session.commit()
    busy = client.post(f"/api/v1/vault/items/{spinning}/rotate", headers=ACTOR)
    assert busy.status_code == 400
    assert "already in progress" in busy.get_json()["error"]


def test_failed_rotation_is_marked_failed_and_retriable(monkeypatch, client):
    item = onboard(client, "gonna-fail")

    # fault inside the pipeline (after mint/seal), i.e. the state-machine path
    monkeypatch.setattr(
        service_module, "generated_secret_is_valid", lambda kind, value: False
    )
    response = client.post(f"/api/v1/vault/items/{item['id']}/rotate", headers=ACTOR)
    assert response.status_code == 500
    assert "type_format" in response.get_json()["error"]

    failed = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert failed["status"] == "failed"
    events = client.get("/api/v1/vault/events?action=rotation_failed").get_json()
    assert events["total"] == 1
    assert "type_format" in events["events"][0]["detail"]["error"]

    # manual retry re-runs the real pipeline and recovers the item
    monkeypatch.undo()
    retry = client.post(f"/api/v1/vault/items/{item['id']}/rotate", headers=ACTOR)
    assert retry.status_code == 200
    assert retry.get_json()["rotation"]["previous_status"] == "failed"
    recovered = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert recovered["status"] == "available"


def test_mint_failure_leaves_item_state_untouched(monkeypatch, client):
    item = onboard(client, "safe-credential")

    def engine_down(secret_type):
        raise RuntimeError("entropy source unavailable")

    monkeypatch.setattr(service_module, "generate_secret", engine_down)
    response = client.post(f"/api/v1/vault/items/{item['id']}/rotate", headers=ACTOR)
    assert response.status_code == 500
    monkeypatch.undo()

    after = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert after["status"] == "available"  # failed before any state change
    assert after["secret_version"] == 1


def _is_password(value):
    return (
        len(value) == 24
        and any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
        and any(not c.isalnum() for c in value)
    )


def _is_token(value):
    return len(value) >= 32 and all(c.isalnum() or c in "-_" for c in value)


def _is_cloud_pair(value):
    parsed = json.loads(value)
    return (
        isinstance(parsed, dict)
        and bool(parsed.get("access_key_id"))
        and bool(parsed.get("secret_access_key"))
    )


def _is_ssh_pem(value):
    key = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
    return value.startswith("-----BEGIN PRIVATE KEY-----") and key is not None


def test_generated_secret_formats_match_their_types(client):
    checks = {
        "database": _is_password,
        "domain_password": _is_password,
        "service_account": _is_password,
        "api_token": _is_token,
        "cloud_iam": _is_cloud_pair,
        "ssh_key": _is_ssh_pem,
    }
    for index, (secret_type, check) in enumerate(checks.items(), start=1):
        item = onboard(
            client, f"gen-{secret_type}", secret_type=secret_type,
            target=f"gen-target-{index}",
        )
        value = reveal(client, item["id"]).get_json()["secret"]
        assert check(value), secret_type


def test_default_onboarding_generates_a_unique_real_value(client):
    one = onboard(client, "auto-one")
    two = onboard(client, "auto-two")
    first = reveal(client, one["id"]).get_json()
    second = reveal(client, two["id"]).get_json()
    assert first["source"] == "generated"
    assert len(first["secret"]) > 10
    assert first["secret"] != second["secret"]  # no static placeholder


def test_stats_report_real_encryption_coverage(app, client):
    onboard(client, "covered-one", secret="value-1")
    onboard(client, "covered-two", secret="value-2")
    insert_item(app, "metadata-only-row")
    stats = client.get("/api/v1/vault/stats").get_json()
    assert stats["secrets"] == {"managed": 2, "unmanaged": 1, "versions": 2}


def test_event_action_filter(client):
    item = onboard(client, "filter-cred")
    client.post(f"/api/v1/vault/items/{item['id']}/rotate", headers=ACTOR)

    rotated = client.get("/api/v1/vault/events?action=rotated").get_json()
    assert rotated["action"] == "rotated"
    assert rotated["total"] == 1
    assert {event["action"] for event in rotated["events"]} == {"rotated"}

    onboarding = client.get("/api/v1/vault/events?action=onboarded").get_json()
    assert {event["action"] for event in onboarding["events"]} == {"onboarded"}

    bad = client.get("/api/v1/vault/events?action=nope")
    assert bad.status_code == 400
    assert "allowed" in bad.get_json()["details"]


def test_onboard_event_records_secret_source(client):
    onboard(client, "src-generated")
    onboard(client, "src-operator", secret="operator-supplied")
    events = client.get("/api/v1/vault/events?action=onboarded").get_json()["events"]
    by_name = {event["item_name"]: event for event in events}
    assert by_name["src-generated"]["detail"]["secret_source"] == "generated"
    assert by_name["src-operator"]["detail"]["secret_source"] == "operator"


# ---------------------------------------------------------------------------
# run engine: due selection, retry semantics, scheduler
# ---------------------------------------------------------------------------
def test_rotation_run_selects_only_due_credentials(app, client):
    due_id = insert_item(app, "overdue-cred", rotated_hours_ago=48)
    fresh = onboard(client, "fresh-cred", target="fresh.internal")

    response = client.post("/api/v1/rotation/run", json={}, headers=ACTOR)
    assert response.status_code == 200
    summary = response.get_json()
    assert summary["trigger"] == "bulk"
    assert [entry["id"] for entry in summary["rotated"]] == [due_id]
    assert summary["skipped"] == []
    assert summary["failed"] == []
    assert summary["dependents_rotated"] == 0
    assert summary["due_remaining"] == 0
    assert summary["failed_remaining"] == 0

    rotated = client.get(f"/api/v1/vault/items/{due_id}").get_json()["item"]
    assert rotated["secret_version"] == 1  # was a metadata row, now managed
    untouched = client.get(f"/api/v1/vault/items/{fresh['id']}").get_json()["item"]
    assert untouched["secret_version"] == 1  # rotated nothing extra


def test_rotation_run_retries_failed_items(app, client):
    failed_id = insert_item(app, "broken-cred", status="failed")
    summary = client.post("/api/v1/rotation/run", json={}, headers=ACTOR).get_json()
    assert [entry["id"] for entry in summary["rotated"]] == [failed_id]
    assert summary["failed_remaining"] == 0
    recovered = client.get(f"/api/v1/vault/items/{failed_id}").get_json()["item"]
    assert recovered["status"] == "available"


def test_rotation_run_validates_its_payload(app, client):
    insert_item(app, "needs-valid-payload", rotated_hours_ago=48)
    assert client.post("/api/v1/rotation/run", json="nope", headers=ACTOR).status_code == 400
    assert client.post("/api/v1/rotation/run", json={"item_ids": []}, headers=ACTOR).status_code == 400
    assert client.post("/api/v1/rotation/run", json={"item_ids": ["x"]}, headers=ACTOR).status_code == 400
    missing = client.post("/api/v1/rotation/run", json={"item_ids": [4321]}, headers=ACTOR)
    assert missing.status_code == 400
    assert missing.get_json()["details"]["missing"] == [4321]
    assert client.post("/api/v1/rotation/run", json={"cascade": "yes"}, headers=ACTOR).status_code == 400
    # a rejected run changes nothing
    assert client.get("/api/v1/vault/items/1").get_json()["item"]["status"] == "available"


def test_scheduler_quiet_clock_creates_no_events(app, client):
    onboard(client, "not-due-yet", target="quiet.internal")
    events_before = client.get("/api/v1/vault/events?limit=200").get_json()["total"]

    with client.application.app_context():
        quiet = run_due(client.application)
    assert quiet["rotated"] == []
    assert quiet["due_remaining"] == 0

    events_after = client.get("/api/v1/vault/events?limit=200").get_json()["total"]
    assert events_after == events_before  # silence is not an event


def test_scheduler_rotates_only_due_credentials(app, client):
    due_id = insert_item(app, "clock-due", rotated_hours_ago=48)
    with client.application.app_context():
        tick = run_due(client.application)
    assert [entry["id"] for entry in tick["rotated"]] == [due_id]
    assert tick["trigger"] == "scheduled"

    rotated = client.get("/api/v1/vault/events?action=rotated").get_json()["events"]
    scheduled = [
        event for event in rotated if event["detail"].get("trigger") == "scheduled"
    ]
    assert scheduled and scheduled[0]["item_id"] == due_id


# ---------------------------------------------------------------------------
# dependents (same-target cascade)
# ---------------------------------------------------------------------------
def test_cascade_updates_same_target_dependents_only(app, client):
    primary = insert_item(app, "primary-cred", rotated_hours_ago=48)  # due
    sibling = insert_item(app, "sibling-cred")  # same target, not due
    outsider = insert_item(
        app, "outsider-cred", rotated_hours_ago=48, target="other.internal"
    )

    summary = client.post("/api/v1/rotation/run", json={}, headers=ACTOR).get_json()
    assert sorted(entry["id"] for entry in summary["rotated"]) == sorted(
        [primary, outsider]
    )
    assert summary["dependents_rotated"] == 1
    assert summary["dependents_skipped"] == []

    with client.application.app_context():
        assert VaultItem.query.filter_by(id=sibling).first().secret_version == 1
        assert VaultItem.query.filter_by(id=primary).first().secret_version == 1
    events = client.get("/api/v1/vault/events?action=rotated").get_json()["events"]
    assert {event["item_name"] for event in events} == {
        "primary-cred",
        "sibling-cred",
        "outsider-cred",
    }


def test_cascade_reports_checked_out_dependents_with_a_reason(app, client):
    insert_item(app, "primary-cred", rotated_hours_ago=48)
    held = insert_item(app, "held-dependency")
    client.post(f"/api/v1/vault/items/{held}/checkout", headers=ACTOR)

    summary = client.post("/api/v1/rotation/run", json={}, headers=ACTOR).get_json()
    assert summary["dependents_rotated"] == 0
    assert summary["dependents_skipped"] == [
        {"name": "held-dependency", "reason": "Revoke the checkout before rotating"}
    ]
    survivor = client.get(f"/api/v1/vault/items/{held}").get_json()["item"]
    assert survivor["status"] == "checked_out"  # the run did not steal the checkout


def test_manual_rotate_has_no_cascade(app, client):
    first = insert_item(app, "manual-one")
    second = insert_item(app, "manual-two")  # same target

    response = client.post(f"/api/v1/vault/items/{first}/rotate", headers=ACTOR)
    assert response.status_code == 200
    assert response.get_json()["rotation"]["dependents"] == {
        "considered": 0,
        "rotated": [],
        "skipped": [],
    }
    with client.application.app_context():
        assert VaultItem.query.filter_by(id=second).first().secret_version is None


# ---------------------------------------------------------------------------
# event-based trigger: checkout -> session end -> rotate
# ---------------------------------------------------------------------------
def test_session_end_releases_checkout_then_rotates_with_dependents(app, client):
    item = onboard(client, "session-cred", secret="session-v1")
    sibling = insert_item(app, "session-sibling", target="db.internal")
    checkout = client.post(
        f"/api/v1/vault/items/{item['id']}/checkout",
        json={"reason": "INC-1138"},
        headers=ACTOR,
    )
    assert checkout.status_code == 200

    response = client.post(
        "/api/v1/rotation/session-end",
        json={"item_id": item["id"], "session_id": "sess-77"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    rotation = response.get_json()["rotation"]
    assert rotation["trigger"] == "session_end"
    assert rotation["checkout_released"] is True
    assert rotation["session_ref"] == "sess-77"
    assert rotation["previous_status"] == "available"  # released before rotating
    assert rotation["dependents"]["rotated"] == ["session-sibling"]

    detail = client.get(f"/api/v1/vault/items/{item['id']}").get_json()["item"]
    assert detail["status"] == "available"
    assert detail["checked_out_by"] is None
    assert detail["secret_version"] == 2
    assert reveal(client, item["id"]).get_json()["secret"] != "session-v1"
    with client.application.app_context():
        assert VaultItem.query.filter_by(id=sibling).first().secret_version == 1

    events = client.get("/api/v1/vault/events?limit=10").get_json()["events"]
    actions = [event["action"] for event in events]
    assert "revoked" in actions and "rotated" in actions
    revoked = next(event for event in events if event["action"] == "revoked")
    assert revoked["detail"]["reason"] == "session ended"
    assert revoked["detail"]["session_ref"] == "sess-77"
    rotated = next(event for event in events if event["action"] == "rotated")
    assert rotated["detail"]["trigger"] == "session_end"


def test_session_end_payload_validation(app, client):
    assert client.post("/api/v1/rotation/session-end", json={}, headers=ACTOR).status_code == 400
    assert client.post(
        "/api/v1/rotation/session-end", json={"item_id": "x"}, headers=ACTOR
    ).status_code == 400
    assert client.post(
        "/api/v1/rotation/session-end", json={"item_id": 999}, headers=ACTOR
    ).status_code == 404
    assert client.post(
        "/api/v1/rotation/session-end",
        json={"item_id": 999, "session_id": " "},
        headers=ACTOR,
    ).status_code == 400  # payload checked before lookup


def test_rotation_endpoints_require_admin(client):
    assert client.post("/api/v1/rotation/run", json={}).status_code == 401
    assert client.post(
        "/api/v1/rotation/session-end", json={"item_id": 1}
    ).status_code == 401


# ---------------------------------------------------------------------------
# key custody
# ---------------------------------------------------------------------------
def test_missing_key_without_autogen_fails_503_and_state_stays_clean(tmp_path):
    config = make_config(
        tmp_path,
        vault_key_path=tmp_path / "absent.key",
        vault_autogenerate_key=False,
    )
    application = create_app(config)
    application.config["TESTING"] = True
    client = application.test_client()

    refused = client.post(
        "/api/v1/vault/items",
        json={
            "name": "cannot-seal",
            "secret_type": "database",
            "target": "db.internal",
            "principal": "admin",
        },
        headers=ACTOR,
    )
    assert refused.status_code == 503
    assert "Vault encryption key unavailable" in refused.get_json()["error"]
    assert client.get("/api/v1/vault/stats").get_json()["total"] == 0

    item_id = insert_item(application, "pre-key-row")
    rotate = client.post(f"/api/v1/vault/items/{item_id}/rotate", headers=ACTOR)
    assert rotate.status_code == 503
    with application.app_context():
        item = VaultItem.query.filter_by(id=item_id).first()
        assert item.status == "available"  # failed before any state change
        assert item.secret_version is None
        assert VaultEvent.query.count() == 0  # nothing to audit yet
