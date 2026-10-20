"""Phase 7 - SCIM 2.0 lifecycle sync (Addendum C): the identity provider's
real joiner-mover-leaver surface behind its own bearer token (minted once,
sha256 at rest, rotated by an admin). Users are provider-managed rows:
password login is refused honestly, privilege still only ever comes from a
role binding, deactivation is immediate, the row stays as evidence, and
local users are invisible and unaddressable to SCIM. Error bodies follow
RFC 7644 3.12.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri  # noqa: E402
from models import AuthEvent  # noqa: E402
import identity  # noqa: E402
import service  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-scim-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-scim",
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


@pytest.fixture(autouse=True)
def _limiter(app):
    identity.reset_windows_for_tests()
    with app.app_context():
        service.update_settings("auth", {"progressive_delay": False}, actor="test")
    yield
    identity.reset_windows_for_tests()


@pytest.fixture
def token(client):
    """A freshly rotated SCIM bearer token (shown once)."""
    response = client.post("/api/v1/settings/scim/rotate", headers=ADMIN)
    assert response.status_code == 200, response.get_json()
    return response.get_json()["token"]


def scim_headers(token):
    return {"Authorization": f"Bearer {token}"}


def scim_create(client, token, user_name="dana", **extra):
    payload = {
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "name": {"givenName": "Dana", "familyName": "Scully"},
        "emails": [{"value": f"{user_name}@idp.test", "primary": True, "type": "work"}],
        "active": True,
    }
    payload.update(extra)
    return client.post("/api/v1/scim/v2/Users", json=payload, headers=scim_headers(token))


def create_local_user(client, username="lee", password=GOOD_PASSWORD, **fields):
    response = client.post(
        "/api/v1/users",
        json={"username": username, "password": password, **fields},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def action_count(app, action, subject=""):
    with app.app_context():
        query = AuthEvent.query.filter(AuthEvent.action == action)
        if subject:
            query = query.filter(AuthEvent.subject == subject)
        return query.count()


# ---------------------------------------------------------------------------
# the token
# ---------------------------------------------------------------------------


def test_scim_endpoints_accept_only_the_scim_token(client, app, token):
    anonymous = client.get("/api/v1/scim/v2/Users")
    assert anonymous.status_code == 401
    assert anonymous.get_json()["error"] == "SCIM bearer token required"

    forged = client.get("/api/v1/scim/v2/Users", headers=scim_headers("vypam-scim1.wrong"))
    assert forged.status_code == 401

    # the admin token is a different credential entirely - SCIM stays walled
    as_admin = client.get("/api/v1/scim/v2/Users", headers=ADMIN)
    assert as_admin.status_code == 401

    # and the scim token grants nothing on the admin surface
    scim_on_admin = client.get("/api/v1/users", headers=scim_headers(token))
    assert scim_on_admin.status_code == 401


def test_rotation_shows_the_token_once_and_stores_only_its_sha256(client, app):
    rotated = client.post("/api/v1/settings/scim/rotate", headers=ADMIN)
    assert rotated.status_code == 200, rotated.get_json()
    token = rotated.get_json()["token"]
    assert token.startswith("vypam-scim1.")

    settings = client.get("/api/v1/settings", headers=ADMIN).get_json()["settings"]["scim"]
    assert token not in str(settings)
    stored = settings["values"]["token_sha256"]
    assert stored == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert client.get("/api/v1/scim/v2/Users", headers=scim_headers(token)).status_code == 200

    # rotation invalidates the old credential
    second = client.post("/api/v1/settings/scim/rotate", headers=ADMIN).get_json()
    assert second["token"] != token
    assert client.get("/api/v1/scim/v2/Users", headers=scim_headers(token)).status_code == 401
    assert client.get(
        "/api/v1/scim/v2/Users", headers=scim_headers(second["token"])
    ).status_code == 200
    assert action_count(app, "auth.scim.token-rotated") == 2


# ---------------------------------------------------------------------------
# Users lifecycle
# ---------------------------------------------------------------------------


def test_user_lifecycle_create_read_list_replace(client, app, token):
    created = scim_create(client, token)
    assert created.status_code == 201, created.get_json()
    body = created.get_json()
    assert body["schemas"] == [USER_SCHEMA]
    assert body["userName"] == "dana"
    assert body["active"] is True
    assert body["name"]["givenName"] == "Dana"
    assert body["meta"]["location"].endswith(f"/Users/{body['id']}")
    scim_id = body["id"]

    fetched = client.get(f"/api/v1/scim/v2/Users/{scim_id}", headers=scim_headers(token))
    assert fetched.status_code == 200
    assert fetched.get_json()["userName"] == "dana"

    listed = client.get("/api/v1/scim/v2/Users", headers=scim_headers(token)).get_json()
    assert listed["totalResults"] == 1
    assert listed["Resources"][0]["id"] == scim_id
    filtered = client.get(
        '/api/v1/scim/v2/Users?filter=userName eq "dana"', headers=scim_headers(token)
    ).get_json()
    assert filtered["totalResults"] == 1
    empty = client.get(
        '/api/v1/scim/v2/Users?filter=userName eq "ghost"', headers=scim_headers(token)
    ).get_json()
    assert empty["totalResults"] == 0

    replaced = client.put(
        f"/api/v1/scim/v2/Users/{scim_id}",
        json={
            "userName": "dana",
            "displayName": "Dana Scully",
            "emails": [{"value": "dana.scully@idp.test", "primary": True}],
        },
        headers=scim_headers(token),
    )
    assert replaced.status_code == 200, replaced.get_json()
    assert replaced.get_json()["displayName"] == "Dana Scully"
    assert replaced.get_json()["emails"][0]["value"] == "dana.scully@idp.test"
    assert action_count(app, "auth.scim.user-created", subject="dana") == 1
    assert action_count(app, "auth.scim.user-updated", subject="dana") == 1


def test_scim_validates_and_conflicts_honestly(client, app, token):
    missing = client.post("/api/v1/scim/v2/Users", json={}, headers=scim_headers(token))
    assert missing.status_code == 400
    assert missing.get_json()["details"]["status"] == "400"
    assert missing.get_json()["details"]["detail"] == "userName is required"

    assert scim_create(client, token).status_code == 201
    duplicate = scim_create(client, token)
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.get_json()["error"]

    create_local_user(client, "walt")
    clashes = scim_create(client, token, "walt")
    assert clashes.status_code == 409  # usernames are unique across sources

    missing_id = client.get("/api/v1/scim/v2/Users/9999", headers=scim_headers(token))
    assert missing_id.status_code == 404
    error = missing_id.get_json()
    assert error["details"]["schemas"] == [ERROR_SCHEMA]
    assert error["details"]["status"] == "404"

    bad_filter = client.get(
        "/api/v1/scim/v2/Users?filter=name sw \"x\"", headers=scim_headers(token)
    )
    assert bad_filter.status_code == 400
    assert "Unsupported filter" in bad_filter.get_json()["error"]


def test_local_users_are_invisible_and_unaddressable_to_scim(client, app, token):
    local = create_local_user(client, "lee")
    scim_id = str(local["user"]["id"])

    listed = client.get("/api/v1/scim/v2/Users", headers=scim_headers(token)).get_json()
    assert listed["totalResults"] == 0

    addressed = client.get(f"/api/v1/scim/v2/Users/{scim_id}", headers=scim_headers(token))
    assert addressed.status_code == 404
    patched = client.patch(
        f"/api/v1/scim/v2/Users/{scim_id}",
        json={"Operations": [{"op": "replace", "value": {"active": False}}]},
        headers=scim_headers(token),
    )
    assert patched.status_code == 404


# ---------------------------------------------------------------------------
# provider-managed credentials
# ---------------------------------------------------------------------------


def test_scim_users_refuse_password_login_and_admin_resets(client, app, token):
    created = scim_create(client, token, "maria").get_json()
    scim_id = created["id"]

    refused = client.post(
        "/api/v1/auth/login", json={"username": "maria", "password": GOOD_PASSWORD}
    )
    # the answer is the uniform 401 - a provider-managed account is never an
    # existence oracle; the ledger records the true reason instead
    assert refused.status_code == 401
    assert refused.get_json()["error"] == "Invalid username or password"

    # a wrong password gives the same 401 with the same recorded reason
    also_refused = client.post(
        "/api/v1/auth/login", json={"username": "maria", "password": "wrong-password"}
    )
    assert also_refused.status_code == 401
    assert action_count(app, "auth.login.failed", subject="maria") == 2

    reset = client.post(f"/api/v1/users/{scim_id}/password-reset", headers=ADMIN)
    assert reset.status_code == 403
    assert "identity provider" in reset.get_json()["error"]


def test_patch_offboard_and_delete_leave_the_row_as_evidence(client, app, token):
    scim_id = scim_create(client, token, "nina").get_json()["id"]

    patched = client.patch(
        f"/api/v1/scim/v2/Users/{scim_id}",
        json={"Operations": [{"op": "replace", "value": {"active": False}}]},
        headers=scim_headers(token),
    )
    assert patched.status_code == 200, patched.get_json()
    assert patched.get_json()["active"] is False

    fetched = client.get(f"/api/v1/scim/v2/Users/{scim_id}", headers=scim_headers(token))
    assert fetched.status_code == 200  # the row stays - evidence, not a delete
    assert fetched.get_json()["active"] is False
    assert action_count(app, "auth.scim.user-patched", subject="nina") == 1

    # an offboarded account cannot sign in (inactive, generic 401 like
    # any other inactive account)
    login_attempt = client.post(
        "/api/v1/auth/login", json={"username": "nina", "password": GOOD_PASSWORD}
    )
    assert login_attempt.status_code == 401

    deleted = client.delete(f"/api/v1/scim/v2/Users/{scim_id}", headers=scim_headers(token))
    assert deleted.status_code == 204
    still_there = client.get(f"/api/v1/scim/v2/Users/{scim_id}", headers=scim_headers(token))
    assert still_there.status_code == 200
    assert still_there.get_json()["active"] is False
    assert action_count(app, "auth.scim.user-deactivated", subject="nina") == 1


def test_patch_only_supports_replace_operations(client, app, token):
    scim_id = scim_create(client, token, "ozzy").get_json()["id"]

    empty = client.patch(f"/api/v1/scim/v2/Users/{scim_id}", json={}, headers=scim_headers(token))
    assert empty.status_code == 400
    assert "at least one operation" in empty.get_json()["error"]

    unsupported = client.patch(
        f"/api/v1/scim/v2/Users/{scim_id}",
        json={"Operations": [{"op": "add", "value": {"active": True}}]},
        headers=scim_headers(token),
    )
    assert unsupported.status_code == 400
    assert "Only 'replace' operations" in unsupported.get_json()["error"]

    # a combined replace (active + displayName + emails) lands in one PATCH
    combined = client.patch(
        f"/api/v1/scim/v2/Users/{scim_id}",
        json={
            "Operations": [
                {
                    "op": "replace",
                    "value": {
                        "displayName": "Ozzy W.",
                        "emails": [{"value": "ozzy@idp.test"}],
                    },
                }
            ]
        },
        headers=scim_headers(token),
    )
    assert combined.status_code == 200
    assert combined.get_json()["displayName"] == "Ozzy W."
    assert combined.get_json()["emails"][0]["value"] == "ozzy@idp.test"


# ---------------------------------------------------------------------------
# Groups (membership the provider owns)
# ---------------------------------------------------------------------------


def test_group_lifecycle_resolves_member_ids_to_users(client, app, token):
    scim_id = scim_create(client, token, "kate").get_json()["id"]

    created = client.post(
        "/api/v1/scim/v2/Groups",
        json={"displayName": "Analysts", "members": [{"value": scim_id}]},
        headers=scim_headers(token),
    )
    assert created.status_code == 201, created.get_json()
    group = created.get_json()
    assert group["displayName"] == "Analysts"
    assert group["members"] == [{"value": scim_id, "display": "kate"}]
    assert group["id"].startswith("grp-")

    listed = client.get("/api/v1/scim/v2/Groups", headers=scim_headers(token)).get_json()
    assert listed["totalResults"] == 1

    replaced = client.put(
        f"/api/v1/scim/v2/Groups/{group['id']}",
        json={"displayName": "Senior Analysts", "members": []},
        headers=scim_headers(token),
    )
    assert replaced.status_code == 200
    assert replaced.get_json()["displayName"] == "Senior Analysts"
    assert replaced.get_json()["members"] == []

    fetched = client.get(f"/api/v1/scim/v2/Groups/{group['id']}", headers=scim_headers(token))
    assert fetched.get_json()["displayName"] == "Senior Analysts"
    assert action_count(app, "auth.scim.group-created", subject="Analysts") == 1
    assert action_count(app, "auth.scim.group-updated", subject="Senior Analysts") == 1

    missing = client.get("/api/v1/scim/v2/Groups/grp-nope", headers=scim_headers(token))
    assert missing.status_code == 404
    assert missing.get_json()["details"]["status"] == "404"

    nameless = client.post(
        "/api/v1/scim/v2/Groups", json={"members": []}, headers=scim_headers(token)
    )
    assert nameless.status_code == 400
    assert nameless.get_json()["details"]["detail"] == "displayName is required"
