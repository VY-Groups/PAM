"""Section 15: DevSecOps PAM (phase 5c).

The CI/CD credential broker: a pipeline identity (Jenkins/GitLab/GitHub/
Azure DevOps/Terraform/Ansible/ArgoCD) authenticates with an API token
issued once and stored as a sha256 hash, and requests short-lived
credentials from the vault instead of holding a static secret of its own.
The policy decides - `auto` releases on request, `manual` queues for an
admin approval - and every released credential is checked out under the
pipeline, expires like a JIT grant and rotates through the section-5
pipeline when it ends. Refusals are honest: wrong token, revoked or
expired identity, target outside scope, TTL above the policy cap.
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

# Wednesday 2026-10-07 noon - a fixed base the expiry tests move past.
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
def onboard(client, name, *, target="db.prod:5432", secret="broker-vault-value-77aa"):
    payload = {
        "name": name,
        "secret_type": "database",
        "target": target,
        "principal": "deploy",
        "access_tier": "Tier-2",
        "auth_method": "Password",
        "rotation_interval_hours": 24,
        "secret": secret,
    }
    response = client.post("/api/v1/vault/items", json=payload, headers=ACTOR)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def add_policy(client, name="jenkins-deploy-prod", **overrides):
    payload = {"name": name, "ci_system": "jenkins"}
    payload.update(overrides)
    response = client.post(
        "/api/v1/broker/policies", json=payload, headers=ACTOR
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["policy"], body["token"]


def pipeline(token):
    return {"Authorization": f"Bearer {token}"}


def ask(client, token, item_id, **overrides):
    payload = {
        "item_id": item_id,
        "reason": "Nightly schema migration run",
        "ticket": "DEP-4471",
        "minutes": 15,
    }
    payload.update(overrides)
    return client.post(
        "/api/v1/broker/credentials", json=payload, headers=pipeline(token)
    )


def vault_view(client, item_id):
    return client.get(f"/api/v1/vault/items/{item_id}").get_json()["item"]


# ---------------------------------------------------------------------------
# policy lifecycle
# ---------------------------------------------------------------------------
def test_policy_create_returns_token_once_and_stores_hash(client):
    policy, token = add_policy(client, "jenkins-deploy-prod")
    assert policy["id"] >= 1
    assert policy["status"] == "active"
    assert policy["approval_mode"] == "manual"
    assert policy["max_ttl_minutes"] == 30
    assert token.startswith(f"vypam-ci1.{policy['id']}.")
    assert len(token.split(".")[2]) >= 32
    # stored as a hash prefix only - the list never carries the token
    assert policy["token_hash"].startswith("sha256:")
    listed = client.get("/api/v1/broker/policies", headers=ADMIN).get_json()
    assert listed["total"] == 1
    # the list never carries the token - only its hash prefix
    assert token not in json.dumps(listed)
    assert token.split(".")[2] not in json.dumps(listed)


def test_policy_create_validates_inputs(client):
    response = client.post("/api/v1/broker/policies", json={}, headers=ACTOR)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "name"

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "p1", "ci_system": "bamboo"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "ci_system"

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "p1", "approval_mode": "whenever"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "approval_mode"

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "p1", "max_ttl_minutes": 0},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"] == {
        "field": "max_ttl_minutes",
        "min": 1,
        "max": 480,
    }

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "p1", "allowed_targets": "db.prod:5432"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "allowed_targets"

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "p1", "expires_at": "2020-01-01T00:00:00"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "expires_at"


def test_policy_duplicate_name_conflicts(client):
    add_policy(client, "jenkins-deploy-prod")
    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "jenkins-deploy-prod", "ci_system": "gitlab"},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]


def test_policy_list_filters(client):
    add_policy(client, "jenkins-a", ci_system="jenkins")
    add_policy(client, "terraform-a", ci_system="terraform")
    rows = client.get(
        "/api/v1/broker/policies?ci_system=terraform", headers=ADMIN
    ).get_json()
    assert rows["total"] == 1
    assert rows["policies"][0]["name"] == "terraform-a"
    rows = client.get("/api/v1/broker/policies?status=active", headers=ADMIN).get_json()
    assert rows["total"] == 2
    rows = client.get("/api/v1/broker/policies?q=jenkins", headers=ADMIN).get_json()
    assert rows["total"] == 1
    response = client.get("/api/v1/broker/policies?ci_system=bamboo", headers=ADMIN)
    assert response.status_code == 400


def test_policy_patch_edits_knobs_and_freezes_after_revoke(client):
    policy, _ = add_policy(client, "jenkins-deploy-prod")
    response = client.patch(
        f"/api/v1/broker/policies/{policy['id']}",
        json={
            "approval_mode": "auto",
            "max_ttl_minutes": 10,
            "allowed_targets": ["db.prod:5432"],
        },
        headers=ACTOR,
    )
    assert response.status_code == 200
    view = response.get_json()["policy"]
    assert view["approval_mode"] == "auto"
    assert view["max_ttl_minutes"] == 10
    assert view["allowed_targets"] == ["db.prod:5432"]

    # the identity itself is never editable, and an empty patch is refused
    response = client.patch(
        f"/api/v1/broker/policies/{policy['id']}",
        json={"name": "renamed"},
        headers=ACTOR,
    )
    assert response.status_code == 400
    response = client.patch(
        f"/api/v1/broker/policies/{policy['id']}", json={}, headers=ACTOR
    )
    assert response.status_code == 400

    client.delete(f"/api/v1/broker/policies/{policy['id']}", headers=ACTOR)
    response = client.patch(
        f"/api/v1/broker/policies/{policy['id']}",
        json={"approval_mode": "manual"},
        headers=ACTOR,
    )
    assert response.status_code == 409
    assert "frozen" in response.get_json()["error"]


def test_revoke_closes_open_credentials_rotates_and_blocks_token(client):
    item = onboard(client, "db-deploy-credential")
    policy, token = add_policy(client, "jenkins-retire-me", approval_mode="auto")
    body = ask(client, token, item["id"]).get_json()
    assert body["credential"]["status"] == "released"
    cred_id = body["credential"]["id"]

    response = client.delete(
        f"/api/v1/broker/policies/{policy['id']}",
        json={"reason": "pipeline retired"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["credentials_closed"] == 1
    assert body["policy"]["status"] == "revoked"
    assert body["policy"]["revoked_reason"] == "pipeline retired"

    # the released grant ended through the real rotation path
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["checked_out_by"] is None
    assert vault["last_rotated_at"] is not None

    # the credential row is closed, and the token no longer authenticates
    row = client.get(f"/api/v1/broker/credentials/{cred_id}", headers=ADMIN)
    assert row.status_code == 200
    assert row.get_json()["credential"]["status"] == "closed"
    response = ask(client, token, item["id"])
    assert response.status_code == 401
    assert "revoked" in response.get_json()["error"]

    # a second revoke is a 409
    response = client.delete(
        f"/api/v1/broker/policies/{policy['id']}", headers=ACTOR
    )
    assert response.status_code == 409


def test_policy_expiry_closes_grants_and_refuses_the_token(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    item = onboard(client, "db-expiring-credential")
    policy, token = add_policy(
        client,
        "expiring-pipeline",
        approval_mode="auto",
        expires_at=(NOON + timedelta(hours=1)).isoformat(),
    )
    body = ask(client, token, item["id"]).get_json()
    assert body["credential"]["status"] == "released"

    _clock_at(monkeypatch, NOON + timedelta(hours=2))
    rows = client.get("/api/v1/broker/policies", headers=ADMIN).get_json()["policies"]
    row = next(p for p in rows if p["id"] == policy["id"])
    assert row["status"] == "expired"
    credential = client.get(
        "/api/v1/broker/credentials/1", headers=ADMIN
    ).get_json()["credential"]
    assert credential["status"] == "closed"
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["last_rotated_at"] is not None

    response = ask(client, token, item["id"])
    assert response.status_code == 401
    assert "expired" in response.get_json()["error"]


# ---------------------------------------------------------------------------
# pipeline authentication (the API token is the only way in)
# ---------------------------------------------------------------------------
def test_pipeline_auth_is_real(client):
    item = onboard(client, "db-auth-credential")
    _, token = add_policy(client, "jenkins-auth-probe")

    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "no token presented", "ticket": "DEP-1"},
    )
    assert response.status_code == 401
    assert "token" in response.get_json()["error"].lower()

    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "garbage token", "ticket": "DEP-1"},
        headers={"Authorization": "Bearer nonsense"},
    )
    # a plain bearer token is the admin credential shape, not a pipeline
    # token - it authenticates nothing here
    assert response.status_code == 401
    assert "Broker API token required" in response.get_json()["error"]

    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "garbage token", "ticket": "DEP-1"},
        headers={"X-Broker-Token": "nonsense"},
    )
    assert response.status_code == 401
    assert "Not a broker API token" in response.get_json()["error"]

    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "unknown id", "ticket": "DEP-1"},
        headers=pipeline("vypam-ci1.9999.secret"),
    )
    assert response.status_code == 401
    assert "Unknown" in response.get_json()["error"]

    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "non numeric id", "ticket": "DEP-1"},
        headers=pipeline("vypam-ci1.abc.secret"),
    )
    assert response.status_code == 401

    good_id = token.split(".")[1]
    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "wrong secret", "ticket": "DEP-1"},
        headers=pipeline(f"vypam-ci1.{good_id}.wrong-secret"),
    )
    assert response.status_code == 401
    assert "Invalid" in response.get_json()["error"]

    # the admin token is not a pipeline credential
    response = client.post(
        "/api/v1/broker/credentials",
        json={"item_id": item["id"], "reason": "admin bearer", "ticket": "DEP-1"},
        headers=ADMIN,
    )
    assert response.status_code == 401


def test_valid_token_records_use(client):
    item = onboard(client, "db-use-credential")
    policy, token = add_policy(client, "jenkins-use-counter")
    assert ask(client, token, item["id"]).status_code == 201
    view = client.get(f"/api/v1/broker/policies/{policy['id']}", headers=ADMIN).get_json()["policy"]
    assert view["use_count"] == 1
    assert view["last_used_at"] is not None


def test_open_dev_mode_waives_admin_but_never_the_pipeline_token(tmp_path):
    application = create_app(_config(tmp_path, admin_token=None))
    application.config["TESTING"] = True
    client = application.test_client()
    dev = {"X-Actor": "dev"}

    response = client.post(
        "/api/v1/broker/policies",
        json={"name": "dev-pipeline", "ci_system": "gitlab"},
        headers=dev,
    )
    assert response.status_code == 201
    token = response.get_json()["token"]

    item = onboard(client, "dev-credential")
    # without the pipeline token the request is still refused
    response = client.post(
        "/api/v1/broker/credentials",
        json={
            "item_id": item["id"],
            "reason": "dev deploy without token",
            "ticket": "DEV-1001",
        },
    )
    assert response.status_code == 401
    # with it - the machine identity is the point - the request is served
    response = client.post(
        "/api/v1/broker/credentials",
        json={
            "item_id": item["id"],
            "reason": "dev deploy with token",
            "ticket": "DEV-1002",
        },
        headers=pipeline(token),
    )
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# manual policy: request -> approval -> release (once)
# ---------------------------------------------------------------------------
def test_manual_policy_approve_release_once(client):
    item = onboard(client, "db-deploy-credential", secret="broker-vault-value-77aa")
    policy, token = add_policy(client, "gitlab-deploy-prod")
    response = ask(
        client,
        token,
        item["id"],
        minutes=20,
        build_ref="https://ci.example/build/912",
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["credential"]["status"] == "pending"
    assert body["credential"]["secret_released"] is False
    assert "secret" not in body
    cred_id = body["credential"]["id"]

    # the approval gate
    response = client.post(
        f"/api/v1/broker/credentials/{cred_id}/approve",
        json={"reason": "change window is open"},
        headers=ACTOR,
    )
    assert response.status_code == 200
    assert response.get_json()["credential"]["approved_by"] == "admin"

    # the pipeline releases it with its own token
    response = client.post(
        f"/api/v1/broker/credentials/{cred_id}/release", headers=pipeline(token)
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["secret"]["value"] == "broker-vault-value-77aa"
    assert body["secret"]["item_name"] == "db-deploy-credential"
    assert body["secret"]["principal"] == "deploy"
    assert body["secret"]["version"] == 1
    assert body["secret"]["expires_at"] == body["credential"]["expires_at"]
    credential = body["credential"]
    assert credential["status"] == "released"
    assert credential["secret_released"] is True
    assert credential["released_version"] == 1
    assert credential["session_ref"] == f"broker-{cred_id}"

    # checked out under the pipeline for the window
    vault = vault_view(client, item["id"])
    assert vault["status"] == "checked_out"
    assert vault["checked_out_by"] == "gitlab-deploy-prod"

    # exactly once: a second release is refused with the state
    response = client.post(
        f"/api/v1/broker/credentials/{cred_id}/release", headers=pipeline(token)
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "released"

    # later reads carry the flag, never the value
    detail = client.get(f"/api/v1/broker/credentials/{cred_id}", headers=ADMIN).get_json()
    assert detail["credential"]["secret_released"] is True
    assert "broker-vault-value-77aa" not in json.dumps(detail)


def test_release_state_guards_and_ownership(client):
    item_a = onboard(client, "db-a", target="db.prod:5432")
    item_b = onboard(client, "db-b", target="db.prod:6432")
    policy_a, token_a = add_policy(client, "jenkins-pipeline-a")
    policy_b, token_b = add_policy(client, "jenkins-pipeline-b", approval_mode="auto")

    # pending cannot be released
    pending = ask(client, token_a, item_a["id"]).get_json()["credential"]
    response = client.post(
        f"/api/v1/broker/credentials/{pending['id']}/release",
        headers=pipeline(token_a),
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "pending"

    # denied cannot be released
    client.post(
        f"/api/v1/broker/credentials/{pending['id']}/deny",
        json={"reason": "not during the freeze window"},
        headers=ACTOR,
    )
    response = client.post(
        f"/api/v1/broker/credentials/{pending['id']}/release",
        headers=pipeline(token_a),
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["status"] == "denied"

    # another pipeline's credential is not observable with this token
    released = ask(client, token_b, item_b["id"]).get_json()["credential"]
    response = client.post(
        f"/api/v1/broker/credentials/{released['id']}/release",
        headers=pipeline(token_a),
    )
    assert response.status_code == 404
    response = client.post(
        f"/api/v1/broker/credentials/{released['id']}/close",
        headers=pipeline(token_a),
    )
    assert response.status_code == 404
    # ...but an admin sees and closes any
    response = client.post(
        f"/api/v1/broker/credentials/{released['id']}/close", headers=ACTOR
    )
    assert response.status_code == 200
    assert response.get_json()["credential"]["status"] == "closed"


def test_approve_deny_state_guards(client):
    item = onboard(client, "db-guards")
    policy, token = add_policy(client, "jenkins-guards")
    cred = ask(client, token, item["id"]).get_json()["credential"]

    response = client.post(
        f"/api/v1/broker/credentials/{cred['id']}/approve",
        json={"reason": ""},
        headers=ACTOR,
    )
    assert response.status_code == 400

    assert (
        client.post(
            f"/api/v1/broker/credentials/{cred['id']}/approve", headers=ACTOR
        ).status_code
        == 200
    )
    # approved: neither approve nor deny applies again
    for action in ("approve", "deny"):
        response = client.post(
            f"/api/v1/broker/credentials/{cred['id']}/{action}", headers=ACTOR
        )
        assert response.status_code == 400
        assert response.get_json()["details"]["status"] == "approved"

    response = client.post(
        "/api/v1/broker/credentials/9999/approve", headers=ACTOR
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# policy scope and TTL cap
# ---------------------------------------------------------------------------
def test_target_outside_allowed_targets_is_refused_403(client):
    onboard(client, "db-main", target="db.prod:5432")
    other = onboard(client, "cache-main", target="cache.prod:6379")
    policy, token = add_policy(
        client, "scoped-pipeline", allowed_targets=["db.prod:5432"]
    )
    response = ask(client, token, other["id"])
    assert response.status_code == 403
    assert response.get_json()["details"]["allowed"] == ["db.prod:5432"]

    # the refusal is evidence on the trail, and nothing was created
    events = client.get(f"/api/v1/broker/policies/{policy['id']}", headers=ADMIN).get_json()["events"]
    assert any(e["action"] == "refused" for e in events)
    assert client.get("/api/v1/broker/credentials", headers=ADMIN).get_json()["total"] == 0


def test_minutes_above_policy_cap_is_refused(client):
    item = onboard(client, "db-capped")
    policy, token = add_policy(client, "jenkins-capped", max_ttl_minutes=10)
    response = ask(client, token, item["id"], minutes=15)
    assert response.status_code == 400
    assert response.get_json()["details"] == {"field": "minutes", "cap": 10}
    # inside the cap is served
    assert ask(client, token, item["id"], minutes=10).status_code == 201
    # and the hard ceiling still applies
    response = ask(client, token, item["id"], minutes=0)
    assert response.status_code == 400
    assert response.get_json()["details"]["field"] == "minutes"


# ---------------------------------------------------------------------------
# auto policy: one call releases, conflicts stay honest
# ---------------------------------------------------------------------------
def test_auto_policy_releases_in_one_call(client):
    item = onboard(client, "db-auto", secret="broker-auto-value-88bb")
    _, token = add_policy(client, "github-actions-prod", approval_mode="auto")
    response = ask(client, token, item["id"], minutes=30)
    assert response.status_code == 201
    body = response.get_json()
    assert body["credential"]["status"] == "released"
    assert body["secret"]["value"] == "broker-auto-value-88bb"
    assert body["credential"]["approved_by"] == "broker-policy"
    # the admin list shows the flag, never the value
    listed = client.get("/api/v1/broker/credentials", headers=ADMIN).get_json()
    assert listed["credentials"][0]["secret_released"] is True
    assert "broker-auto-value-88bb" not in json.dumps(listed)


def test_auto_release_conflict_is_honest_and_keeps_the_request(client):
    item = onboard(client, "db-contended")
    _, token = add_policy(client, "argocd-prod", approval_mode="auto")
    checkout = client.post(
        f"/api/v1/vault/items/{item['id']}/checkout", headers=ACTOR
    )
    assert checkout.status_code == 200

    response = ask(client, token, item["id"])
    assert response.status_code == 400
    assert "already checked out" in response.get_json()["error"]

    # the request itself survived as evidence, waiting for a retry
    rows = client.get("/api/v1/broker/credentials", headers=ADMIN).get_json()["credentials"]
    assert rows[0]["status"] == "approved"
    assert rows[0]["secret_released"] is False


# ---------------------------------------------------------------------------
# close and real-clock expiry (both rotate like a JIT grant)
# ---------------------------------------------------------------------------
def test_pipeline_close_ends_the_grant_and_rotates(client):
    item = onboard(client, "db-closed-early")
    _, token = add_policy(client, "jenkins-close-fast", approval_mode="auto")
    cred = ask(client, token, item["id"]).get_json()["credential"]
    response = client.post(
        f"/api/v1/broker/credentials/{cred['id']}/close", headers=pipeline(token)
    )
    assert response.status_code == 200
    assert response.get_json()["credential"]["status"] == "closed"
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["checked_out_by"] is None
    assert vault["last_rotated_at"] is not None


def test_close_requires_token_or_admin(client):
    item = onboard(client, "db-close-auth")
    _, token = add_policy(client, "jenkins-close-auth")
    cred = ask(client, token, item["id"]).get_json()["credential"]
    response = client.post(f"/api/v1/broker/credentials/{cred['id']}/close")
    assert response.status_code == 401
    response = client.post(
        f"/api/v1/broker/credentials/{cred['id']}/close", headers=ADMIN
    )
    assert response.status_code == 200
    assert response.get_json()["credential"]["status"] == "closed"


def test_pending_close_needs_no_rotation(client):
    item = onboard(client, "db-aborted")
    _, token = add_policy(client, "jenkins-abort")
    cred = ask(client, token, item["id"]).get_json()["credential"]
    before = vault_view(client, item["id"])
    response = client.post(
        f"/api/v1/broker/credentials/{cred['id']}/close", headers=ACTOR
    )
    assert response.status_code == 200
    assert response.get_json()["credential"]["status"] == "closed"
    # nothing was released, so nothing rotated
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["secret_version"] == before["secret_version"]
    assert vault["last_rotated_at"] == before["last_rotated_at"]
    # and a closed credential cannot be closed again
    response = client.post(
        f"/api/v1/broker/credentials/{cred['id']}/close", headers=ACTOR
    )
    assert response.status_code == 400


def test_released_credential_expires_and_rotates(client, monkeypatch):
    _clock_at(monkeypatch, NOON)
    item = onboard(client, "db-expiring-grant")
    _, token = add_policy(client, "jenkins-expiry", approval_mode="auto")
    body = ask(client, token, item["id"], minutes=15).get_json()
    assert body["secret"]["expires_at"].startswith("2026-10-07T12:15")

    _clock_at(monkeypatch, NOON + timedelta(minutes=16))
    rows = client.get("/api/v1/broker/credentials", headers=ADMIN).get_json()["credentials"]
    row = next(r for r in rows if r["id"] == body["credential"]["id"])
    assert row["status"] == "expired"
    vault = vault_view(client, item["id"])
    assert vault["status"] == "available"
    assert vault["checked_out_by"] is None
    assert vault["last_rotated_at"] is not None
    assert vault["secret_version"] >= 2


# ---------------------------------------------------------------------------
# trail, ledger and aggregates
# ---------------------------------------------------------------------------
def test_trail_and_stats_reflect_real_rows(client):
    item = onboard(client, "db-stats")
    policy, token = add_policy(client, "jenkins-stats", approval_mode="auto")
    cred = ask(client, token, item["id"]).get_json()["credential"]
    client.post(
        f"/api/v1/broker/credentials/{cred['id']}/close", headers=pipeline(token)
    )

    stats = client.get("/api/v1/broker/stats").get_json()
    assert stats["policies"]["total"] == 1
    assert stats["policies"]["by_status"]["active"] == 1
    assert stats["policies"]["by_ci_system"] == {"jenkins": 1}
    assert stats["credentials"]["total"] == 1
    assert stats["credentials"]["by_status"]["closed"] == 1
    assert stats["credentials"]["open"] == 0
    assert stats["events"] >= 5  # created, requested, approved, released, closed

    detail = client.get(f"/api/v1/broker/policies/{policy['id']}", headers=ADMIN).get_json()
    assert detail["open_credentials"] == 0
    actions = [e["action"] for e in detail["events"]]
    assert actions[0] == "closed"  # newest first
    released = next(e for e in detail["events"] if e["action"] == "released")
    assert released["actor"] == "jenkins-stats"  # the pipeline is the actor
    assert "value" not in released["detail"]


def test_broker_trail_reaches_the_ledger_as_the_fourteenth_source(client):
    item = onboard(client, "db-ledger")
    _, token = add_policy(client, "jenkins-ledger", approval_mode="auto")
    ask(client, token, item["id"])

    assert len(audit_module.AUDIT_SOURCES) == 14
    assert audit_module.AUDIT_SOURCES[-1] == "broker"
    events = client.get("/api/v1/events?source=broker&limit=50").get_json()["events"]
    assert events and all(e["source"] == "broker" for e in events)
    assert all(e["id"].startswith("broker:") for e in events)
    actions = {e["action"] for e in events}
    assert {"policy-created", "requested", "approved", "released"} <= actions
    # the ledger verify endpoint still walks a clean chain
    assert client.get("/api/v1/audit/verify").get_json()["intact"] is True


def test_credential_and_policy_filters(client):
    item = onboard(client, "db-filters")
    policy_a, token_a = add_policy(client, "jenkins-filter-a")
    add_policy(client, "jenkins-filter-b", approval_mode="auto")
    pending = ask(client, token_a, item["id"]).get_json()["credential"]
    ask(client, token_a, item["id"], ticket="DEP-4472")

    rows = client.get(
        "/api/v1/broker/credentials?status=pending", headers=ADMIN
    ).get_json()
    assert rows["total"] == 2
    rows = client.get(
        f"/api/v1/broker/credentials?policy_id={policy_a['id']}", headers=ADMIN
    ).get_json()
    assert rows["total"] == 2
    rows = client.get(
        f"/api/v1/broker/credentials?status=denied&policy_id={policy_a['id']}",
        headers=ADMIN,
    ).get_json()
    assert rows["total"] == 0
    response = client.get("/api/v1/broker/credentials?status=maybe", headers=ADMIN)
    assert response.status_code == 400
    response = client.get("/api/v1/broker/credentials?policy_id=abc", headers=ADMIN)
    assert response.status_code == 400
    detail = client.get(
        f"/api/v1/broker/credentials/{pending['id']}", headers=ADMIN
    ).get_json()
    assert detail["policy"]["id"] == policy_a["id"]
    assert [e["action"] for e in detail["events"]] == ["requested"]
