"""The MASTER's own contract (pam_master/openapi.yaml) stays in sync with the
live routes and the *real* response shapes, both directions:

* every documented operation is served; every served route is documented;
* live responses match the documented required properties exactly;
* documented enums/ranges equal the code constants they claim to mirror;
* phase-2d shipped-surface invariant: no private-key material in any
  git-tracked file (tracked = what the repo ships).

Run with:  python -m pytest pam_master -q
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Set

import pytest
import yaml

from pam_master import errors, issuance, registry
from pam_master.licensing import MODULE_IDS, LicenseType, sig

PAM_MASTER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PAM_MASTER_DIR.parent
SPEC_PATH = PAM_MASTER_DIR / "openapi.yaml"
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


@pytest.fixture(scope="module")
def spec() -> dict:
    assert SPEC_PATH.is_file(), f"missing API contract at {SPEC_PATH}"
    loaded = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _documented(spec: dict) -> dict:
    return {
        path: {method for method in item if method in HTTP_METHODS}
        for path, item in spec["paths"].items()
    }


def _app_routes(app) -> dict:
    """Flask rule -> HTTP methods, with <converter:name> rewritten to {name}."""
    routes: dict = {}
    for rule in app.url_map.iter_rules():
        path = re.sub(r"<[^:>]+:([^>]+)>", r"{\1}", rule.rule)
        path = re.sub(r"<([^>]+)>", r"{\1}", path)
        routes.setdefault(path, set()).update(
            method.lower() for method in rule.methods - {"HEAD", "OPTIONS"}
        )
    return routes


def _schema(spec: dict, name: str) -> dict:
    return spec["components"]["schemas"][name]


def _required(spec: dict, name: str) -> Set[str]:
    return set(_schema(spec, name)["required"])


def _assert_shape(actual, spec: dict, name: str, where: str = "") -> None:
    """Live keys must equal the schema's required set (the contract for
    these always-present response objects)."""
    label = f"{name}{where}"
    assert set(actual) == _required(spec, name), (
        f"{label}: actual keys {sorted(actual)} != documented required "
        f"{sorted(_required(spec, name))}"
    )


# ------------------------------------------------------------ spec validity --
def test_contract_is_valid_openapi(spec):
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] and spec["info"]["version"]

    # every $ref in the document resolves
    raw = SPEC_PATH.read_text(encoding="utf-8")
    for ref in re.findall(r'\$ref: "#/([^"]+)"', raw):
        node = spec
        for part in ref.split("/"):
            assert isinstance(node, dict) and part in node, (
                f"dangling $ref: {ref}"
            )
            node = node[part]

    # required lists only name declared properties
    for name, schema in spec["components"]["schemas"].items():
        for field in schema.get("required", []):
            assert field in schema.get("properties", {}), f"{name}.{field}"


# ---------------------------------------------------------- both directions --
def test_every_documented_operation_exists_in_the_app(spec, app):
    routes = _app_routes(app)
    for path, methods in _documented(spec).items():
        assert path in routes, f"documented path is not served: {path}"
        for method in methods:
            assert method in routes[path], f"{method.upper()} {path} not served"


def test_every_master_route_is_documented(spec, app):
    documented = _documented(spec)
    for path, methods in _app_routes(app).items():
        if path in ("/", "/health") or path.startswith("/api/v1/"):
            assert path in documented, f"undocumented route: {path}"
            missing = methods - documented[path]
            assert not missing, f"undocumented on {path}: {sorted(missing)}"


# ------------------------------------------------- enums mirror code truth --
def test_documented_enums_match_code_constants(spec):
    issue_request = _schema(spec, "LicenseIssueRequest")
    assert set(issue_request["properties"]["license_type"]["enum"]) == {
        t.value for t in LicenseType
    }
    assert set(issue_request["properties"]["modules"]["items"]["enum"]) == set(
        MODULE_IDS
    )
    assert (
        issue_request["properties"]["algorithm"]["enum"]
        == list(sig.SUPPORTED_ALGORITHMS)
    )

    validity = issue_request["properties"]["validity_days"]
    assert validity["minimum"] == issuance.MIN_VALIDITY_DAYS
    assert validity["maximum"] == issuance.MAX_VALIDITY_DAYS
    assert (
        issue_request["properties"]["environment"]["pattern"]
        == issuance.ENVIRONMENT_RE.pattern
    )

    error_types = {errors.RegistryApiError.error_type} | {
        cls.error_type for cls in errors.RegistryApiError.__subclasses__()
    }
    assert (
        set(_schema(spec, "Error")["properties"]["error"]["properties"]["type"]["enum"])
        == error_types
    )

    assert (
        set(
            _schema(spec, "IssuanceHistoryAction")["properties"]["action"][
                "enum"
            ]
        )
        == set(registry.ISSUANCE_ACTIONS)
    )
    assert (
        set(_schema(spec, "AuditEvent")["properties"]["action"]["enum"])
        == set(issuance.AUDIT_ACTIONS)
    )
    assert set(_schema(spec, "License")["properties"]["status"]["enum"]) == {
        issuance.STATUS_ACTIVE,
        issuance.STATUS_SUPERSEDED,
    }

    limit = spec["components"]["parameters"]["limit"]["schema"]
    assert limit["maximum"] == registry.MAX_LIMIT
    assert limit["default"] == registry.DEFAULT_LIMIT


# ------------------------------------------------------ live response shapes --
def test_live_response_shapes_match_schemas(spec, client):
    # index
    index = client.get("/").get_json()
    _assert_shape(index, spec, "Index")
    endpoints_schema = spec["components"]["schemas"]["Index"]["properties"][
        "endpoints"
    ]
    assert set(index["endpoints"]) == set(endpoints_schema["required"])

    # health (all three blocks)
    health = client.get("/health").get_json()
    _assert_shape(health, spec, "Health")
    _assert_shape(health["database"], spec, "DatabaseStatus")
    _assert_shape(health["signing"], spec, "SigningStatus")
    _assert_shape(health["registry"], spec, "RegistryStatus")

    # customers: create -> list -> get
    body = {
        "name": "Contract Corp",
        "region": "eu-central",
        "contact_email": "contract@example.test",
    }
    created = client.post("/api/v1/customers", json=body)
    assert created.status_code == 201
    customer = created.get_json()
    _assert_shape(customer, spec, "Customer")
    public_id = customer["public_id"]

    listing = client.get("/api/v1/customers").get_json()
    _assert_shape(listing, spec, "CustomerList")
    _assert_shape(listing["customers"][0], spec, "Customer")

    # issuance: issue -> list -> history -> audit
    issued = client.post(
        f"/api/v1/customers/{public_id}/licenses",
        json={"license_type": "subscription", "validity_days": 90},
    )
    assert issued.status_code == 201
    license_record = issued.get_json()
    _assert_shape(license_record, spec, "License")

    license_list = client.get("/api/v1/licenses").get_json()
    _assert_shape(license_list, spec, "LicenseList")
    _assert_shape(license_list["licenses"][0], spec, "License")

    history = client.get(
        f"/api/v1/customers/{public_id}/issuance-history"
    ).get_json()
    _assert_shape(history, spec, "IssuanceHistory")
    _assert_shape(history["actions"][0], spec, "IssuanceHistoryAction")

    audit = client.get("/api/v1/audit").get_json()
    _assert_shape(audit, spec, "AuditTrail")
    _assert_shape(audit["events"][0], spec, "AuditEvent")

    # options
    options = client.get("/api/v1/license-options").get_json()
    _assert_shape(options, spec, "LicenseOptions")
    _assert_shape(options["license_types"][0], spec, "LicenseTypeOption")
    _assert_shape(options["modules"][0], spec, "Module")

    # error envelope
    bad = client.post("/api/v1/customers", json={})
    assert bad.status_code == 400
    error_body = bad.get_json()
    _assert_shape(error_body, spec, "Error")
    error_schema = spec["components"]["schemas"]["Error"]["properties"][
        "error"
    ]
    assert set(error_body["error"]) == set(error_schema["required"])


# ------------------------------------------------ shipped-surface invariant --
@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_no_private_key_material_in_tracked_files():
    """Tracked files are what the repository ships: none may contain a
    private key block (signing keys and the registry key are git-ignored
    by design)."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    offenders = []
    for relative in result.stdout.splitlines():
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if PRIVATE_KEY_MARKER.search(text):
            offenders.append(relative)
    assert offenders == [], (
        f"private key material in shipped (tracked) files: {offenders}"
    )
