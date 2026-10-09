"""Tests for UEBA: behavior baselines and the anomaly response chain
(architecture module 11).

A principal's baseline is learned only from the product's own history rows -
risk evaluations, privileged sessions, posted command events and command
incidents inside the rolling window (never synthetic users) - and stored on
`behavior_baselines`. Evaluations then diff the request against that stored
profile: every deviation is a named reason on the `behavior` component
("unusual time", "unusual device", "unusual IP", "unusual target",
"unusual command", "unusual privilege"), worth RISK_ANOMALY_POINTS each.

A critical deviation at session start runs the architecture's response
chain for real: the start is refused (block), the principal's other active
sessions end through the release-and-rotate cascade (rotate), the incident
row is committed as evidence on the `risk` trail (SOC alert via the ledger
- reaching SIEM when section 20 is configured), and the refusal carries the
whole incident back to the caller. Console evaluations stay advisory: they
score with the same reasons but never run the chain.

Run with:  python -m pytest backend/phase2_license_server/tests/test_ueba.py -q
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
from models import (  # noqa: E402
    BASE_RISK,
    DiscoveredAsset,
    PrivilegedSession,
    RiskEvent,
    SessionEvent,
    db,
)
import models as models_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
YASH = {"X-Actor": "yash", "Authorization": "Bearer test-admin-token"}

PROD_ADDRESS = "db-prod-01"          # the "production DB" from section 11
NIGHT = datetime(2026, 10, 7, 2, 37, 0)   # 02:37 - the spec's example hour
DAY = datetime(2026, 10, 7, 14, 0, 0)     # the principal's learned hour


class _Clock(datetime):
    """Mutable frozen clock: the fixture resets it to DAY before each test
    and tests step it to NIGHT to deviate from the learned profile."""

    FIXED = DAY

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
    _Clock.FIXED = DAY
    monkeypatch.setattr(service_module, "datetime", _Clock)
    monkeypatch.setattr(models_module, "datetime", _Clock)
    return _Clock


def insert_prod_asset(app) -> int:
    """A discovered, still-unmanaged production database - the section-11
    example's target (CRITICAL asset, unmanaged exposure)."""
    with app.app_context():
        asset = DiscoveredAsset(
            address=PROD_ADDRESS,
            asset_type="database",
            risk=BASE_RISK.get("database", "LOW"),
            pam_status="unmanaged",
        )
        db.session.add(asset)
        db.session.commit()
        return asset.id


def start_session(client, **payload):
    base = {
        "protocol": "ssh",
        "target": "web-01.example:22",
        "device": "corp-laptop",
        "source_ip": "10.1.2.3",
    }
    base.update(payload)
    return client.post("/api/v1/sessions", json=base, headers=YASH)


def post_command(client, session_id, command):
    response = client.post(
        f"/api/v1/sessions/{session_id}/events",
        json={"type": "command", "content": command},
        headers=YASH,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def pin_history_clock(app, when=DAY):
    """Pin every history row to the learned instant.

    Column defaults bind `datetime.now` at import, so API-created rows
    carry the real wall clock while scoring runs on the frozen fixture -
    the baseline's hour dimension would then depend on when the suite ran.
    The rows are untouched otherwise (same real entities, same events);
    only their timestamps move to the instant the test means to teach."""
    with app.app_context():
        for row in RiskEvent.query.filter_by(subject="yash"):
            row.created_at = when
        for row in PrivilegedSession.query.filter_by(actor="yash"):
            row.started_at = when
        for row in SessionEvent.query.filter_by(actor="yash"):
            row.created_at = when
        db.session.commit()


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
    response = client.post("/api/v1/vault/items", json=payload, headers=YASH)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def train(client, **body):
    return client.post("/api/v1/risk/baselines/train", json=body, headers=YASH)


def baseline_of(client, subject="yash"):
    response = client.get("/api/v1/risk/baselines")
    assert response.status_code == 200, response.get_json()
    for row in response.get_json()["baselines"]:
        if row["subject"] == subject:
            return row
    return None


def eval_of(client, payload):
    response = client.post("/api/v1/risk/evaluate", json=payload, headers=YASH)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["evaluation"]


def component(evaluation, name):
    for item in evaluation["components"]:
        if item["component"] == name:
            return item
    raise AssertionError(f"missing component: {evaluation['components']}")


def build_history(client):
    """The principal's normal day: one session on the known host with the
    known device/IP, two ordinary commands, one checked-out session."""
    plain = start_session(client)
    assert plain.status_code == 201, plain.get_json()
    session = plain.get_json()["session"]
    post_command(client, session["id"], "ls -la /var/log")
    post_command(
        client, session["id"], "systemctl status nginx"
    )
    return session


# ---------------------------------------------------------------------------
# baselines: learned from real rows, never invented
# ---------------------------------------------------------------------------


def test_baselines_start_empty_and_train_requires_an_admin(client, clock):
    # public read, no rows yet
    listing = client.get("/api/v1/risk/baselines")
    assert listing.status_code == 200
    assert listing.get_json() == {
        "total": 0,
        "window_days": service_module.UEBA_WINDOW_DAYS,
        "baselines": [],
    }
    # training is an operator action
    assert (
        client.post("/api/v1/risk/baselines/train", json={}).status_code == 401
    )
    # training with no history anywhere stays honest: nothing to learn
    done = train(client)
    assert done.status_code == 200
    assert done.get_json()["trained"] == 0
    assert done.get_json()["baselines"] == []


def test_training_learns_only_from_real_history(app, client, clock):
    build_history(client)
    pin_history_clock(app)

    done = train(client)
    assert done.status_code == 200, done.get_json()
    assert done.get_json()["trained"] == 1

    row = baseline_of(client)
    assert row is not None
    assert row["subject"] == "yash"
    # 1 risk evaluation + 1 privileged session + 2 command events
    assert row["samples"] == 4
    assert row["evaluations"] == 1
    assert row["sessions"] == 1
    assert row["incidents"] == 0
    # every dimension comes from those rows, nothing else
    assert row["hours"] == [14]
    assert row["devices"] == ["corp-laptop"]
    assert row["source_ips"] == ["10.1.2.3"]
    assert row["targets"] == ["web-01.example"]
    assert row["protocols"] == ["ssh"]
    assert row["command_verbs"] == ["ls", "systemctl"]
    assert row["privilege_verbs"] == []
    assert row["sessions_per_day"] == 1.0
    assert row["window_days"] == service_module.UEBA_WINDOW_DAYS
    assert row["trained_by"] == "yash"


def test_train_validates_and_targets_a_named_subject(app, client, clock):
    # shape is validated for real
    rejected = train(client, subject="")
    assert rejected.status_code == 400
    assert rejected.get_json()["details"]["field"] == "subject"
    assert train(client, subject=123).status_code == 400

    build_history(client)
    pin_history_clock(app)
    # a named subject trains just that principal
    done = train(client, subject="yash")
    assert done.get_json()["trained"] == 1
    assert [row["subject"] for row in done.get_json()["baselines"]] == ["yash"]
    # a principal the product has never seen gets no baseline at all
    ghost = train(client, subject="ghost")
    assert ghost.status_code == 200
    assert ghost.get_json()["trained"] == 0


def test_an_in_profile_request_scores_no_deviation(app, client, clock):
    build_history(client)
    pin_history_clock(app)
    assert train(client).status_code == 200

    evaluation = eval_of(
        client,
        {
            "subject": "yash",
            "target": "web-01.example:22",
            "device": "corp-laptop",
            "source_ip": "10.1.2.3",
            "command": "ls /var/log",
        },
    )
    behavior = component(evaluation, "behavior")
    assert behavior["points"] == 0
    assert "reasons" not in behavior
    assert "baseline deviation" not in behavior["detail"]


def test_deviations_are_named_and_scored(app, client, clock):
    build_history(client)
    pin_history_clock(app)
    assert train(client).status_code == 200

    _Clock.FIXED = NIGHT  # 02:37 - outside every learned dimension
    evaluation = eval_of(
        client,
        {
            "subject": "yash",
            "target": "db-prod-01:5432",
            "device": "phone-unknown",
            "source_ip": "8.8.8.8",
            "command": "sudo rm -rf /",
        },
    )
    behavior = component(evaluation, "behavior")
    # the spec's "Reasons:" list, in the spec's order, five points each
    assert behavior["reasons"] == [
        "unusual time",
        "unusual device",
        "unusual IP",
        "unusual target",
        "unusual command",
        "unusual privilege",
    ]
    assert behavior["points"] == 6 * service_module.RISK_ANOMALY_POINTS
    assert "+ unusual privilege" in behavior["detail"]
    # the rest of the score still traces to measured inputs
    assert component(evaluation, "time")["points"] == 10  # 02:37 off-hours
    assert component(evaluation, "device")["points"] == 15  # unknown device
    assert component(evaluation, "location")["points"] == 5  # public source
    # 15 + 10 + 5 + 30 (behavior) + 10 (blocked command) = 70 -> HIGH
    assert evaluation["score"] == 70
    assert evaluation["band"] == "high"
    assert evaluation["result"] == "advisory"  # console evaluations advise


def test_truncated_dimensions_stand_down():
    """Past the distinct-value cap a dimension stops claiming deviation."""
    profile = {
        "hours": [3],
        "devices": ["laptop-a"],
        "devices_truncated": True,
    }
    reasons = service_module._behavior_deviations(
        profile,
        now=datetime(2026, 10, 7, 12, 0, 0),
        device="totally-new-device",
        source_ip="",
        target_host="",
        command="",
    )
    # hour 12 is not in [3] -> unusual time; the truncated device list makes
    # no claim about "totally-new-device"
    assert reasons == ["unusual time"]


# ---------------------------------------------------------------------------
# the response chain (section 11: block -> rotate -> alert -> incident)
# ---------------------------------------------------------------------------


def test_critical_deviation_blocks_the_session_and_runs_the_chain(
    app, client, clock
):
    insert_prod_asset(app)
    plain = start_session(client)
    assert plain.status_code == 201, plain.get_json()
    plain_session = plain.get_json()["session"]
    post_command(client, plain_session["id"], "ls -la /var/log")

    # a second, live session holding a checked-out credential
    item = onboard(client, "ueba-db", target="web-01.example:22")
    checked = start_session(client, item_id=item["id"])
    assert checked.status_code == 201, checked.get_json()
    checkout_session = checked.get_json()["session"]
    # a credential on the production target too: the chain's ROTATE step
    # seeks the credential the refused request would have checked out
    prod_item = onboard(client, "ueba-prod-db", target=f"{PROD_ADDRESS}:5432")
    pin_history_clock(app)
    assert train(client).status_code == 200

    _Clock.FIXED = NIGHT  # 02:37 from a new device/IP against the prod DB
    refused = start_session(
        client, target=f"{PROD_ADDRESS}:5432", device="phone-unknown",
        source_ip="8.8.8.8",
    )
    assert refused.status_code == 403, refused.get_json()
    details = refused.get_json()["details"]
    assert details["risk"]["band"] == "critical"
    assert details["risk"]["result"] == "refused"

    anomaly = details["anomaly"]
    assert anomaly["reasons"] == [
        "unusual time",
        "unusual device",
        "unusual IP",
        "unusual target",
    ]
    assert anomaly["incident_ref"].startswith("anom-")
    actions = anomaly["actions"]
    # BLOCK: the start itself (no session row exists for the refusal)
    assert actions["blocked"] is True
    # ROTATE: both standing sessions ended through the real cascade, and the
    # checked-out credential was rotated with it
    assert sorted(actions["sessions_ended"]) == sorted(
        [plain_session["session_ref"], checkout_session["session_ref"]]
    )
    assert len(actions["rotations"]) == 2
    cascade = [
        entry
        for entry in actions["rotations"]
        if entry["via"].startswith("session ")
    ]
    forced = [
        entry
        for entry in actions["rotations"]
        if entry["via"].startswith("target ")
    ]
    assert len(cascade) == 1
    assert cascade[0]["item_id"] == item["id"]
    assert cascade[0]["secret_version"] == 2
    # the credential the refused request sought: the target's own item,
    # rotated through the module-5 pipeline and recorded on the incident
    assert len(forced) == 1
    assert forced[0]["item_id"] == prod_item["id"]
    assert forced[0]["secret_version"] == 2
    assert forced[0]["via"] == f"target {PROD_ADDRESS}"
    assert actions["notes"] == []

    # the sessions really ended ...
    for session in (plain_session, checkout_session):
        detail = client.get(f"/api/v1/sessions/{session['id']}")
        assert detail.get_json()["session"]["status"] == "terminated"
    # ... and the credential really rotated (module-5 pipeline, versioned)
    rotated = client.get(f"/api/v1/vault/items/{item['id']}").get_json()[
        "item"
    ]
    assert rotated["secret_version"] == 2
    assert rotated["status"] == "available"
    assert rotated["checked_out_by"] is None
    prod_rotated = client.get(
        f"/api/v1/vault/items/{prod_item['id']}"
    ).get_json()["item"]
    assert prod_rotated["secret_version"] == 2
    assert prod_rotated["status"] == "available"

    # INCIDENT: the row is queryable with its evidence intact
    listing = client.get("/api/v1/risk/anomalies?subject=yash")
    assert listing.status_code == 200
    page = listing.get_json()
    assert page["total"] == 1
    incident = page["anomalies"][0]
    assert incident["incident_ref"] == anomaly["incident_ref"]
    assert incident["evaluation_id"] == details["risk"]["id"]
    assert incident["reasons"] == anomaly["reasons"]
    assert incident["band"] == "critical"
    assert incident["score"] == details["risk"]["score"]
    assert incident["actions"]["sessions_ended"] == actions["sessions_ended"]

    # SOC ALERT / PRESERVE EVIDENCE: the incident fans into the ledger's
    # risk trail next to the evaluation, and the chain still verifies
    events = client.get("/api/v1/events?source=risk&limit=200").get_json()
    anomaly_rows = [
        row for row in events["events"] if row["action"] == "anomaly-incident"
    ]
    assert len(anomaly_rows) == 1
    assert anomaly_rows[0]["id"].startswith("anom:")
    assert anomaly_rows[0]["subject"] == "yash"
    verify = client.get("/api/v1/audit/verify").get_json()
    assert verify["intact"] is True, verify

    # a second critical target with no credential on file: the chain still
    # runs (block + incident), and the empty rotation is reported on the
    # incident as evidence - never silent success
    with app.app_context():
        db.session.add(
            DiscoveredAsset(
                address="db-prod-02",
                asset_type="database",
                risk=BASE_RISK.get("database", "LOW"),
                pam_status="unmanaged",
            )
        )
        db.session.commit()
    second = start_session(
        client, target="db-prod-02:5432", device="phone-unknown",
        source_ip="8.8.8.8",
    )
    assert second.status_code == 403, second.get_json()
    second_details = second.get_json()["details"]
    assert second_details["risk"]["band"] == "critical"
    second_actions = second_details["anomaly"]["actions"]
    assert second_actions["blocked"] is True
    assert second_actions["sessions_ended"] == []
    assert second_actions["rotations"] == []
    assert second_actions["notes"] == [
        "credential on db-prod-02 not rotated: no credential on file"
    ]
    page = client.get("/api/v1/risk/anomalies?subject=yash").get_json()
    assert page["total"] == 2
    verify = client.get("/api/v1/audit/verify").get_json()
    assert verify["intact"] is True, verify


def test_advisory_critical_never_runs_the_chain(app, client, clock):
    insert_prod_asset(app)
    live = build_history(client)
    pin_history_clock(app)
    assert train(client).status_code == 200

    _Clock.FIXED = NIGHT
    evaluation = eval_of(
        client,
        {
            "subject": "yash",
            "target": f"{PROD_ADDRESS}:5432",
            "device": "phone-unknown",
            "source_ip": "8.8.8.8",
            "ticket": "fix-now",
            "command": "sudo rm -rf /",
        },
    )
    # all six dimensions deviate: measured sum 105 - the score clamps at 100
    # and says so
    assert component(evaluation, "behavior")["points"] == 30
    assert evaluation["band"] == "critical"
    assert evaluation["score"] == 100
    assert "measured sum 105; score clamps at 100" in component(
        evaluation, "behavior"
    )["detail"]
    # a console evaluation only advises: no incident, no cascade
    assert evaluation["result"] == "advisory"
    assert client.get("/api/v1/risk/anomalies").get_json()["total"] == 0
    still = client.get(f"/api/v1/sessions/{live['id']}")
    assert still.get_json()["session"]["status"] == "active"


def test_anomaly_list_filters_and_validates(client, clock):
    # filters and pagination shapes are enforced for real
    bad_limit = client.get("/api/v1/risk/anomalies?limit=0")
    assert bad_limit.status_code == 400
    assert bad_limit.get_json()["details"]["field"] == "limit"
    empty = client.get("/api/v1/risk/anomalies?subject=nobody")
    assert empty.status_code == 200
    assert empty.get_json() == {"total": 0, "anomalies": []}
