"""Phase 6b - RBAC / ABAC (architecture section 10) coverage.

The five built-in roles are seeded once and their policy over the admin
operations is computed, not copied: a bound token reaches exactly its
role's operations, a directory identity without a binding is refused
instead of silently holding the admin token, the binding's attribute
rules gate vault items and session targets, and revocation is immediate.
Every assertion runs against the real Flask app in token mode (open/dev
mode stays open and says so).
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
import service as service_module  # noqa: E402
from models import RBAC_ROLES, RBAC_TOKEN_PREFIX  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}


def _config(tmp_path: Path, admin_token="test-admin-token") -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-rbac-secret",
        admin_token=admin_token,
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-rbac",
        node_site="dc",
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


def bind(client, principal, role, *, kind="local", scope=None):
    payload = {"principal": principal, "role": role, "kind": kind}
    if scope is not None:
        payload["scope"] = scope
    response = client.post("/api/v1/role-bindings", json=payload, headers=ADMIN)
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    return body["binding"], body.get("token")


def operator_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# the roles and the computed policy
# ---------------------------------------------------------------------------
def test_five_roles_seeded_once_with_operation_counts(client, app):
    response = client.get("/api/v1/roles", headers=ADMIN)
    assert response.status_code == 200
    roles = response.get_json()["roles"]
    assert [row["name"] for row in roles] == sorted(RBAC_ROLES)
    by_name = {row["name"]: row for row in roles}
    assert by_name["admin"]["operations"] == len(service_module.ADMIN_OPERATIONS)
    for name in RBAC_ROLES:
        assert by_name[name]["operations"] == len(
            service_module.operations_for_role(name)
        )
    assert by_name["admin"]["description"]
    # idempotent: seeding again creates nothing
    with app.app_context():
        assert service_module.ensure_rbac_seed() == 0


def test_policy_shape_approver_never_operator(client):
    """Separation of duties: the approver's decision set and the operator's
    action set do not overlap, the reveal is never an auditor read, and the
    evidence exports are the auditor's, not the read-only auditor's."""
    approver = set(service_module.operations_for_role("approver"))
    operator = set(service_module.operations_for_role("operator"))
    assert approver and operator and not (approver & operator)
    assert "get /api/v1/vault/items/{item_id}/secret" in operator
    assert "get /api/v1/vault/items/{item_id}/secret" not in approver
    for export in (
        "get /api/v1/licenses/{license_key}/file",
        "get /api/v1/cluster/export/vault",
        "get /api/v1/cluster/export/sessions",
    ):
        assert export in service_module.operations_for_role("auditor")
        assert export not in service_module.operations_for_role("auditor-read-only")


def test_admin_only_operations_default_to_admin(client):
    for key in (
        ("put", "/api/v1/settings/{group}"),
        ("post", "/api/v1/licenses/import"),
        ("post", "/api/v1/role-bindings"),
    ):
        assert service_module.ROLE_OPERATIONS.get(key) is None or "admin" not in (
            service_module.ROLE_OPERATIONS.get(key) or set()
        )
        assert not service_module.role_allows("operator", *key)
        assert not service_module.role_allows("auditor", *key)


# ---------------------------------------------------------------------------
# authentication states
# ---------------------------------------------------------------------------
def test_unauthenticated_is_401_with_the_verbatim_message(client):
    response = client.get("/api/v1/roles")
    assert response.status_code == 401
    assert (
        response.get_json()["error"]
        == "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
    )


def test_admin_token_keeps_every_operation(client):
    assert client.get("/api/v1/roles", headers=ADMIN).status_code == 200
    response = client.post(
        "/api/v1/cluster/monitor/tick", json={}, headers=ADMIN
    )
    assert response.status_code == 200
    assert client.put(
        "/api/v1/settings/ldap", json={"bind_password": "x"}, headers=ADMIN
    ).status_code in (200, 400)


def test_open_mode_stays_open_and_says_so(tmp_path):
    application = create_app(_config(tmp_path, admin_token=None))
    application.config["TESTING"] = True
    client = application.test_client()
    # no credentials anywhere: every admin route allowed, whoami reports open
    assert client.get("/api/v1/roles").status_code == 200
    who = client.get("/api/v1/auth/whoami").get_json()
    assert who["mode"] == "open"
    assert who["role"] == "admin"
    assert who["operations"] == "all"
    assert who["operations_count"] == len(service_module.ADMIN_OPERATIONS)


def test_whoami_admin_token(client):
    who = client.get("/api/v1/auth/whoami", headers=ADMIN).get_json()
    assert who["mode"] == "token"
    assert who["principal"] == "admin-token"
    assert who["role"] == "admin"
    assert who["operations_count"] == len(service_module.ADMIN_OPERATIONS)


def test_whoami_bound_token_reports_role_and_operations(client):
    _, token = bind(client, "svc-backup", "auditor-read-only")
    who = client.get("/api/v1/auth/whoami", headers=operator_headers(token)).get_json()
    assert who["principal"] == "svc-backup"
    assert who["role"] == "auditor-read-only"
    assert who["kind"] == "local"
    assert "get /api/v1/cluster" in who["operations"]
    assert "post /api/v1/cluster/monitor/tick" not in who["operations"]


# ---------------------------------------------------------------------------
# enforcement per role
# ---------------------------------------------------------------------------
def test_operator_allowed_operation_passes(client):
    _, token = bind(client, "op-carla", "operator")
    response = client.post(
        "/api/v1/cluster/monitor/tick", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 200


def test_operator_forbidden_operation_is_403_with_details(client):
    _, token = bind(client, "op-carla", "operator")
    response = client.get("/api/v1/roles", headers=operator_headers(token))
    assert response.status_code == 403
    body = response.get_json()
    assert body["error"] == "Role 'operator' may not call GET /api/v1/roles"
    assert body["details"] == {
        "role": "operator",
        "operation": "get /api/v1/roles",
    }
    # and a settings write stays admin-only
    response = client.put(
        "/api/v1/settings/ldap", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 403


def test_approver_decides_but_does_not_act(client):
    _, token = bind(client, "apr-dan", "approver")
    # role passes, entity missing: 404 - not 401/403
    response = client.post(
        "/api/v1/jit/requests/999999/approve", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 404
    # an action operation stays out of the approver's role
    response = client.post(
        "/api/v1/vault/items/1/checkout", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 403
    assert response.get_json()["details"]["role"] == "approver"


def test_operator_cannot_approve_separation_of_duties(client):
    _, token = bind(client, "op-carla", "operator")
    response = client.post(
        "/api/v1/jit/requests/1/approve", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 403


def test_auditor_exports_but_read_only_does_not(client):
    auditor, auditor_token = bind(client, "aud-eva", "auditor")
    pro_token = bind(client, "aud-ron", "auditor-read-only")[1]
    response = client.get(
        "/api/v1/licenses/NO-SUCH-KEY/file", headers=operator_headers(auditor_token)
    )
    assert response.status_code == 404  # role passed; the entity is missing
    response = client.get(
        "/api/v1/licenses/NO-SUCH-KEY/file", headers=operator_headers(pro_token)
    )
    assert response.status_code == 403
    assert response.get_json()["details"]["role"] == "auditor-read-only"


def test_secret_reveal_is_never_an_auditor_read(client):
    _, auditor_token = bind(client, "aud-eva", "auditor")
    _, pro_token = bind(client, "aud-ron", "auditor-read-only")
    for token in (auditor_token, pro_token):
        response = client.get(
            "/api/v1/vault/items/1/secret", headers=operator_headers(token)
        )
        assert response.status_code == 403
    _, operator_token = bind(client, "op-carla", "operator")
    response = client.get(
        "/api/v1/vault/items/1/secret", headers=operator_headers(operator_token)
    )
    assert response.status_code == 404  # role + scope passed; no such item


def test_management_endpoints_stay_admin_only(client):
    _, token = bind(client, "op-carla", "operator")
    assert client.get("/api/v1/role-bindings", headers=operator_headers(token)).status_code == 403
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": "sneaky", "role": "admin"},
        headers=operator_headers(token),
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# the binding lifecycle and its credential
# ---------------------------------------------------------------------------
def test_local_binding_token_is_shown_once_and_hashed_at_rest(client, config, app):
    binding, token = bind(client, "svc-nightly", "auditor")
    assert token.startswith(f"{RBAC_TOKEN_PREFIX}.{binding['id']}.")
    listed = client.get("/api/v1/role-bindings", headers=ADMIN).get_json()["bindings"]
    row = [entry for entry in listed if entry["id"] == binding["id"]][0]
    assert row["has_token"] is True
    assert "token_sha256" not in row
    assert row["token_prefix"].startswith(f"{RBAC_TOKEN_PREFIX}.{binding['id']}.")
    # the plaintext never round-trips through any response
    assert token not in json.dumps(listed)
    # and the database stores only the sha256
    with app.app_context():
        db_path = config.database_uri.replace("sqlite:///", "")
        connection = sqlite3.connect(db_path)
        stored = connection.execute(
            "SELECT token_sha256 FROM role_bindings WHERE id = ?", (binding["id"],)
        ).fetchone()[0]
        connection.close()
    assert stored and stored != token
    assert len(stored) == 64


def test_tampered_or_unknown_token_is_401(client):
    _, token = bind(client, "svc-nightly", "auditor")
    good_id = token.split(".")[1]
    for bad in (
        token[:-2] + "xy",  # tampered secret
        f"{RBAC_TOKEN_PREFIX}.{good_id}.not-the-secret",
        f"{RBAC_TOKEN_PREFIX}.999999.secrets",
        "vypam-rbac1.junk",
        "vypam-agt1.1.whatever",
    ):
        response = client.get(
            "/api/v1/roles", headers={"Authorization": f"Bearer {bad}"}
        )
        assert response.status_code == 401, bad


def test_duplicate_active_principal_is_409_revoked_can_be_bound_again(client):
    bind(client, "op-carla", "operator")
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": "op-carla", "role": "auditor"},
        headers=ADMIN,
    )
    assert response.status_code == 409
    binding_id = client.get("/api/v1/role-bindings", headers=ADMIN).get_json()[
        "bindings"
    ][0]["id"]
    assert (
        client.delete(f"/api/v1/role-bindings/{binding_id}", headers=ADMIN).status_code
        == 200
    )
    # the revoked row keeps the name as evidence; a fresh binding may reuse it
    again, token = bind(client, "op-carla", "auditor")
    assert again["id"] != binding_id
    assert token
    all_rows = client.get(
        "/api/v1/role-bindings?include_revoked=1", headers=ADMIN
    ).get_json()["bindings"]
    assert len(all_rows) == 2
    assert sum(1 for row in all_rows if row["revoked_at"]) == 1


def test_role_and_kind_validation(client):
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": "x", "role": "superuser"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert set(response.get_json()["details"]["allowed"]) == set(RBAC_ROLES)
    response = client.post(
        "/api/v1/role-bindings",
        json={"principal": "x", "role": "operator", "kind": "magic"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    assert response.get_json()["details"]["allowed"] == ["local", "ldap"]


def test_scope_validation(client):
    cases = [
        {"targets": "web-*"},  # not a list
        {"targets": [""]},  # empty pattern
        {"targets": ["a"] * 21},  # too many
        {"vault_items": ["3"]},  # ids are integers
        {"vault_items": [0]},  # ids start at 1
        {"everything": True},  # unknown key refused, not ignored
    ]
    for scope in cases:
        response = client.post(
            "/api/v1/role-bindings",
            json={"principal": f"scope-{abs(hash(str(scope)))}", "role": "operator", "scope": scope},
            headers=ADMIN,
        )
        assert response.status_code == 400, scope


def test_revoke_is_immediate_and_idempotent_conflict(client):
    binding, token = bind(client, "op-x", "operator")
    assert (
        client.post(
            "/api/v1/cluster/monitor/tick", json={}, headers=operator_headers(token)
        ).status_code
        == 200
    )
    revoked = client.delete(
        f"/api/v1/role-bindings/{binding['id']}", headers=ADMIN
    ).get_json()["binding"]
    assert revoked["revoked_at"]
    # the token dies with the binding
    response = client.post(
        "/api/v1/cluster/monitor/tick", json={}, headers=operator_headers(token)
    )
    assert response.status_code == 401
    # active list excludes it, evidence list keeps it, second revoke conflicts
    active = client.get("/api/v1/role-bindings", headers=ADMIN).get_json()["bindings"]
    assert all(row["id"] != binding["id"] for row in active)
    assert (
        client.delete(f"/api/v1/role-bindings/{binding['id']}", headers=ADMIN).status_code
        == 409
    )
    assert (
        client.delete("/api/v1/role-bindings/999999", headers=ADMIN).status_code == 404
    )


def test_last_used_is_recorded_when_a_token_authenticates(client):
    binding, token = bind(client, "svc-nightly", "auditor")
    client.get("/api/v1/auth/whoami", headers=operator_headers(token))
    listed = client.get("/api/v1/role-bindings", headers=ADMIN).get_json()["bindings"]
    row = [entry for entry in listed if entry["id"] == binding["id"]][0]
    assert row["last_used_at"]


# ---------------------------------------------------------------------------
# ABAC - attribute rules on vault items and targets
# ---------------------------------------------------------------------------
def _onboard_vault_item(client, name, target="db.prod:5432"):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": target,
            "principal": "dba",
            "access_tier": "Tier-2",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
            "secret": "rbac-scope-value",
        },
        headers=ACTOR,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["item"]


def test_scope_gates_vault_items(client):
    item_a = _onboard_vault_item(client, "scope-item-a")
    item_b = _onboard_vault_item(client, "scope-item-b")
    _, token = bind(
        client, "op-scoped", "operator", scope={"vault_items": [item_a["id"]]}
    )
    headers = operator_headers(token)
    response = client.post(
        f"/api/v1/vault/items/{item_b['id']}/checkout", json={}, headers=headers
    )
    assert response.status_code == 403
    assert response.get_json()["details"]["item_id"] == item_b["id"]
    # the in-scope item passes the scope gate (any further failure is the
    # service's own entity/state validation, never 403)
    response = client.post(
        f"/api/v1/vault/items/{item_a['id']}/checkout", json={}, headers=headers
    )
    assert response.status_code != 403, response.get_json()


def test_scope_gates_session_targets(client):
    _, token = bind(
        client, "op-web", "operator", scope={"targets": ["web-*", "bastion-1"]}
    )
    headers = operator_headers(token)
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "db-prod-1:22"},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.get_json()["details"]["target"] == "db-prod-1:22"
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "web-01.prod:22"},
        headers=headers,
    )
    assert response.status_code != 403, response.get_json()
    # fnmatch semantics: exact names are patterns too
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "bastion-1"},
        headers=headers,
    )
    assert response.status_code != 403, response.get_json()


def test_unscoped_binding_is_unrestricted_within_the_role(client):
    _, token = bind(client, "op-any", "operator")
    response = client.post(
        "/api/v1/sessions",
        json={"protocol": "ssh", "target": "anything.at.all:22"},
        headers=operator_headers(token),
    )
    assert response.status_code != 403


# ---------------------------------------------------------------------------
# LDAP tickets - the directory authenticates, the binding decides
# ---------------------------------------------------------------------------
def test_ldap_ticket_without_a_binding_is_refused(client, config):
    ticket = service_module.mint_ldap_ticket("jdoe", 300, config)
    response = client.get("/api/v1/roles", headers={"Authorization": f"Bearer {ticket}"})
    assert response.status_code == 403
    assert response.get_json()["error"] == (
        "Directory identity 'jdoe' has no role binding - an admin must grant "
        "one (POST /api/v1/role-bindings)"
    )
    # whoami refuses the same way
    response = client.get(
        "/api/v1/auth/whoami", headers={"Authorization": f"Bearer {ticket}"}
    )
    assert response.status_code == 403


def test_ldap_ticket_with_a_binding_gets_that_role(client, config):
    bind(client, "jdoe", "auditor-read-only", kind="ldap")
    ticket = service_module.mint_ldap_ticket("jdoe", 300, config)
    headers = {"Authorization": f"Bearer {ticket}"}
    # a read the role allows
    assert client.get("/api/v1/cluster", headers=headers).status_code == 200
    # an operation the role does not
    response = client.post("/api/v1/cluster/monitor/tick", json={}, headers=headers)
    assert response.status_code == 403
    # another directory user still has no binding
    other = service_module.mint_ldap_ticket("mallory", 300, config)
    response = client.get(
        "/api/v1/cluster", headers={"Authorization": f"Bearer {other}"}
    )
    assert response.status_code == 403


def test_revoked_ldap_binding_stops_counting(client, config):
    binding, _ = bind(client, "jdoe", "auditor", kind="ldap")
    client.delete(f"/api/v1/role-bindings/{binding['id']}", headers=ADMIN)
    ticket = service_module.mint_ldap_ticket("jdoe", 300, config)
    response = client.get(
        "/api/v1/cluster", headers={"Authorization": f"Bearer {ticket}"}
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# audit trail (seventeenth source `rbac`)
# ---------------------------------------------------------------------------
def test_binding_actions_reach_the_ledger_without_the_token(client):
    bind(client, "svc-nightly", "auditor")
    response = client.get("/api/v1/audit/export")
    assert response.status_code == 200
    rows = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
    rbac_rows = [row for row in rows if row["source"] == "rbac"]
    assert rbac_rows, "binding creation must reach the ledger under source rbac"
    created = rbac_rows[-1]
    assert created["action"] == "rbac.binding.created"
    assert created["subject"] == "svc-nightly"
    assert created["actor"] == "admin"
    assert created["detail"]["role"] == "auditor"
    assert "event_ref" in created and created["event_ref"].startswith("rbac:")
    # the minted token never enters the ledger
    assert "token" not in json.dumps(created["detail"]).lower()


def test_seeding_writes_no_trail_row(client):
    """The role registry is configuration: seeding produces no action."""
    response = client.get("/api/v1/audit/export")
    rows = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
    assert all(row["source"] != "rbac" for row in rows)


def test_bound_principal_acts_as_itself_on_the_trail(client):
    _onboard_vault_item(client, "actor-item")
    item = client.get("/api/v1/vault/items").get_json()["items"][0]
    _, token = bind(client, "op-carla", "operator")
    client.post(
        f"/api/v1/vault/items/{item['id']}/checkout",
        json={},
        headers={
            **operator_headers(token),
            "X-Actor": "spoofed-name",
        },
    )
    events = client.get("/api/v1/vault/events").get_json()["events"]
    checkout = [row for row in events if row["action"] == "checked_out"][-1]
    assert checkout["actor"] == "op-carla"
