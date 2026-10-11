"""The API contract (apis/openapi.yaml) stays in sync with the live routes.

Run with:  python -m pytest backend/phase2_license_server/tests -q
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, Set

import pytest
import yaml

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
import service  # noqa: E402

SPEC_PATH = REPO_ROOT / "apis" / "openapi.yaml"
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

# The admin operations, as the runtime enforces them (the service is the
# single source: the role policy and the route guards derive from this
# list, and this test asserts the document declares exactly it).
ADMIN_OPERATIONS = service.ADMIN_OPERATIONS


def _make_config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'contract.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
        secret_key="test-secret",
        admin_token="contract-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
    )


@pytest.fixture(scope="module")
def spec() -> dict:
    assert SPEC_PATH.is_file(), f"missing API contract at {SPEC_PATH}"
    loaded = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    return create_app(_make_config(tmp_path_factory.mktemp("contract")))


def _documented(spec: dict) -> Dict[str, Set[str]]:
    return {
        path: {method for method in item if method in HTTP_METHODS}
        for path, item in spec["paths"].items()
    }


def _app_routes(app) -> Dict[str, Set[str]]:
    """Flask rule -> HTTP methods, with <converter:name> rewritten to {name}."""
    routes: Dict[str, Set[str]] = {}
    for rule in app.url_map.iter_rules():
        path = re.sub(r"<[^:>]+:([^>]+)>", r"{\1}", rule.rule)
        path = re.sub(r"<([^>]+)>", r"{\1}", path)
        routes.setdefault(path, set()).update(
            method.lower() for method in rule.methods - {"HEAD", "OPTIONS"}
        )
    return routes


def test_contract_is_valid_openapi(spec):
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] and spec["info"]["version"]
    assert {"bearerAuth", "adminTokenHeader"} <= set(spec["components"]["securitySchemes"])

    # every $ref in the document resolves
    raw = SPEC_PATH.read_text(encoding="utf-8")
    for ref in re.findall(r'\$ref: "#/([^"]+)"', raw):
        node = spec
        for part in ref.split("/"):
            assert isinstance(node, dict) and part in node, f"dangling $ref: {ref}"
            node = node[part]


def test_every_documented_operation_exists_in_the_app(spec, app):
    routes = _app_routes(app)
    for path, methods in _documented(spec).items():
        assert path in routes, f"documented path is not served: {path}"
        for method in methods:
            assert method in routes[path], f"{method.upper()} {path} is not served"


def test_every_api_route_is_documented(spec, app):
    documented = _documented(spec)
    for path, methods in _app_routes(app).items():
        if path == "/health" or path == "/api/v1" or path.startswith("/api/v1/"):
            assert path in documented, f"undocumented route: {path}"
            missing = methods - documented[path]
            assert not missing, f"undocumented on {path}: {sorted(missing)}"


def test_admin_operations_declare_admin_token_security(spec):
    for method, path in ADMIN_OPERATIONS:
        operation = spec["paths"][path][method]
        schemes = operation.get("security", [])
        assert any("bearerAuth" in entry for entry in schemes), f"{method} {path}"
        assert any("adminTokenHeader" in entry for entry in schemes), f"{method} {path}"


def test_documented_admin_operation_set_matches_the_runtime(spec):
    """The operations carrying the admin credential in the document are
    exactly the ones the runtime guards - plus /auth/whoami, which accepts
    the admin token as one of several self-service credentials."""
    documented = {
        (method, path)
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in HTTP_METHODS
        and any("adminTokenHeader" in entry for entry in operation.get("security", []))
    }
    assert documented == set(ADMIN_OPERATIONS) | {("get", "/api/v1/auth/whoami")}


def test_admin_operations_declare_their_role_requirements(spec):
    """Each admin operation's rbacToken/ldapTicket scopes list exactly the
    non-admin roles the shipped policy grants it; admin-only operations
    carry no role entry."""
    for method, path in ADMIN_OPERATIONS:
        operation = spec["paths"][path][method]
        schemes = operation.get("security", [])
        expected = sorted(service.ROLE_OPERATIONS.get((method, path), set()))
        for scheme in ("rbacToken", "ldapTicket"):
            roles = sorted(
                role
                for entry in schemes
                if scheme in entry
                for role in (entry[scheme] or [])
            )
            assert roles == expected, f"{scheme} on {method} {path}: {roles} != {expected}"


def test_rbac_security_schemes_are_documented(spec):
    schemes = spec["components"]["securitySchemes"]
    assert schemes["rbacToken"]["type"] == "http"
    assert "vypam-rbac1" in schemes["rbacToken"]["description"]
    assert schemes["ldapTicket"]["type"] == "http"
    assert "/api/v1/auth/ldap" in schemes["ldapTicket"]["description"]


def test_whoami_documents_every_credential(spec):
    operation = spec["paths"]["/api/v1/auth/whoami"]["get"]
    schemes = operation.get("security", [])
    for scheme in ("bearerAuth", "adminTokenHeader", "rbacToken", "ldapTicket"):
        assert any(scheme in entry for entry in schemes), scheme


def test_settings_group_enum_matches_service_schema(spec):
    """The documented {group} enum mirrors service.SETTINGS_GROUPS exactly."""
    group_param = spec["paths"]["/api/v1/settings/{group}"]["put"]["parameters"][0]
    assert group_param["name"] == "group"
    assert group_param["in"] == "path"
    assert set(group_param["schema"]["enum"]) == set(service.SETTINGS_GROUPS)
