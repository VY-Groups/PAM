"""Tests for the Platform Settings API and the wired-up design suite.

Run with:  python -m pytest backend/phase2_license_server/tests -q
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_DIR.parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app as app_module  # noqa: E402
from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
UI_ROOT = REPO_ROOT / "frontend"
SCREENS_DIR = UI_ROOT / "screens"

# The canonical sidebar every screen carries, in order (spec screens' order).
CANONICAL_NAV = [
    ("pam-command-center-threat-dashboard", "pam_command_center_threat_dashboard"),
    ("credential-vault-secrets-inventory", "credential_vault_secrets_inventory"),
    ("jit-access-ephemeral-approvals", "jit_access_ephemeral_approvals"),
    ("live-session-recording-inspection-hub", "live_session_recording_inspection_hub"),
    ("target-infrastructure-connectors", "target_infrastructure_connectors"),
    ("policy-zero-trust-rules-engine", "policy_zero_trust_rules_engine"),
    ("compliance-soc-2-audit-center", "compliance_soc_2_audit_center"),
    ("license-entitlement-center", "license_entitlement_center"),
    ("break-glass-emergency-protocol", "break_glass_emergency_protocol"),
    ("vendor-access-third-party-lifecycle", "vendor_access_third_party_lifecycle"),
    # The settings slot stays in every sidebar (CANONICAL_NAV truth) but its
    # href is the server route /settings since the 11.5 flip (ADR-0015): the
    # legacy page it pointed at is deleted.
    ("platform-settings-center", "platform_settings_center"),
]
# Which sidebar item marks "you are here" on each screen (the two spec screens
# point at themselves instead of the live screen they spec'd). The deleted
# platform_settings_center page (11.5 flip) is not a WIRED_SCREEN anymore.
OWN_INDEX = {
    "pam_command_center_threat_dashboard": 0,
    "credential_vault_secrets_inventory": 1,
    "jit_access_ephemeral_approvals": 2,
    "live_session_recording_inspection_hub": 3,
    "target_infrastructure_connectors": 4,
    "policy_zero_trust_rules_engine": 5,
    "compliance_soc_2_audit_center": 6,
    "license_entitlement_center": 7,
    "break_glass_emergency_protocol": 8,
    "vendor_access_third_party_lifecycle": 9,
    "enterprise_licensing_tier_entitlements_node_quotas": 7,
    "platform_settings_idp_hsm_configuration": 10,
}
WIRED_SCREENS = sorted(OWN_INDEX)


def _make_config(tmp_path: Path, admin_token) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path, 'settings.db'),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public.pem",
        secret_key="test-secret",
        admin_token=admin_token,
        autogenerate_keys=False,
        default_trial_days=30,
    )


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return _make_config(tmp_path, "test-admin-token")


@pytest.fixture
def client(config: Config):
    app = create_app(config)
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def open_client(tmp_path: Path):
    """Same app but with no admin token: open/dev mode."""
    app = create_app(_make_config(tmp_path, None))
    app.config["TESTING"] = True
    return app.test_client()


# ---------------------------------------------------------------------------
# settings: read
# ---------------------------------------------------------------------------
def test_settings_returns_spec_defaults_and_schema(client):
    response = client.get("/api/v1/settings", headers=ADMIN)
    assert response.status_code == 200
    data = response.get_json()

    assert set(data["settings"]) == {
        "sso", "hsm", "zsp", "worm", "mfa", "itsm", "siem", "ldap",
        "auth", "smtp", "sms", "radius", "scim", "webauthn",
        "gateway",  # phase 8a
    }
    assert set(data["schema"]) == {
        "sso", "hsm", "zsp", "worm", "mfa", "itsm", "siem", "ldap",
        "auth", "smtp", "sms", "radius", "scim", "webauthn",
        "gateway",  # phase 8a
    }

    sso = data["settings"]["sso"]
    hsm = data["settings"]["hsm"]
    zsp = data["settings"]["zsp"]
    worm = data["settings"]["worm"]

    # never saved yet -> built-in defaults, flagged accordingly
    for group in (sso, hsm, zsp, worm):
        assert group["stored"] is False
        assert group["updated_at"] is None
        assert group["updated_by"] is None

    assert sso["values"]["primary_provider"] == "okta"
    assert sso["values"]["secondary_provider"] == "entra"
    assert sso["values"]["session_ttl_minutes"] == 480
    assert sso["values"]["enforce_sso"] is True

    assert hsm["values"]["provider"] == "aws-cloudhsm"
    assert hsm["values"]["key_rotation_hours"] == 24
    assert hsm["values"]["seal_delay_seconds"] == 18
    assert hsm["values"]["fips_profile"] == "fips-140-2-level-4"
    # a reference, never a secret
    assert hsm["values"]["pin_reference"] == "vault://kv/pam/hsm"

    assert zsp["values"] == {
        "default_jit_ttl_minutes": 60,
        "max_ttl_extension_minutes": 120,
        "tier0_quorum_approvers": 2,
        "session_inactivity_timeout_minutes": 15,
    }

    assert worm["values"]["destination"] == "s3-object-lock"
    assert worm["values"]["object_lock_mode"] == "COMPLIANCE"
    assert worm["values"]["immutability_enabled"] is True
    # spec screen: "7 Years Retention (2,555 Days)" over that exact bucket
    assert worm["values"]["retention_days"] == 2555
    assert worm["values"]["bucket"] == "aegispam-immutable-worm-audit-prod-01"
    assert hsm["values"]["cluster_id"] == "hsm-cluster-k10-east"
    assert hsm["values"]["kms_endpoint"] == "https://hsm-cluster-k10-east.prod.aegis.internal:443"

    # schema is renderable: enums expose choices, ints expose ranges
    assert "okta" in data["schema"]["sso"]["primary_provider"]["choices"]
    assert data["schema"]["zsp"]["tier0_quorum_approvers"] == {
        "type": "int", "min": 1, "max": 10, "default": 2,
    }
    assert data["schema"]["worm"]["bucket"]["type"] == "slug"


def test_settings_screen_served_at_settings(client):
    """ADR-0015 11.5 (the strangler flip): the legacy URL keeps working -
    it 302s to the React screen Flask now serves under /app/. The screen
    itself is not asserted here on purpose: the serving contract (shell +
    SPA fallback + honest JSON 404 without a build) is pinned by the
    /app/ tests below, which do not depend on `pnpm build` having run."""
    response = client.get("/settings")
    assert response.status_code == 302
    assert response.headers["Location"] == "/app/settings"


# ---------------------------------------------------------------------------
# settings: write
# ---------------------------------------------------------------------------
def test_settings_write_requires_admin_token(client):
    response = client.put("/api/v1/settings/zsp", json={"tier0_quorum_approvers": 4})
    assert response.status_code == 401
    assert "error" in response.get_json()


def test_settings_write_allowed_in_open_mode(open_client):
    response = open_client.put(
        "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 4}
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-Mode"] == "open"


def test_settings_update_persists_and_is_read_back(client):
    response = client.put(
        "/api/v1/settings/zsp",
        json={"tier0_quorum_approvers": 4, "default_jit_ttl_minutes": 30},
        headers=ADMIN,
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["message"] == "Settings stored"
    assert body["changed_fields"] == ["default_jit_ttl_minutes", "tier0_quorum_approvers"]
    assert body["values"]["tier0_quorum_approvers"] == 4
    assert body["values"]["session_inactivity_timeout_minutes"] == 15  # untouched
    assert body["updated_by"] == "admin"

    read_back = client.get("/api/v1/settings", headers=ADMIN).get_json()["settings"]["zsp"]
    assert read_back["stored"] is True
    assert read_back["values"]["tier0_quorum_approvers"] == 4
    assert read_back["values"]["default_jit_ttl_minutes"] == 30
    assert read_back["updated_at"] is not None


def test_settings_actor_header_is_recorded(client):
    client.put(
        "/api/v1/settings/hsm",
        json={"key_rotation_hours": 12},
        headers={**ADMIN, "X-Actor": "alice"},
    )
    audit = client.get("/api/v1/settings/audit", headers=ADMIN).get_json()
    assert audit["events"][0]["actor"] == "alice"
    assert audit["events"][0]["group"] == "hsm"


def test_settings_no_changes_does_not_write_an_event(client):
    client.put("/api/v1/settings/worm", json={"retention_days": 2555}, headers=ADMIN)
    assert client.get("/api/v1/settings/audit", headers=ADMIN).get_json()["total"] == 0

    response = client.put(
        "/api/v1/settings/worm", json={"retention_days": 2555}, headers=ADMIN
    )
    assert response.status_code == 200
    assert response.get_json()["message"] == "No changes"
    assert response.get_json()["changed_fields"] == []
    assert client.get("/api/v1/settings/audit", headers=ADMIN).get_json()["total"] == 0


def test_settings_update_rejects_unknown_group(client):
    response = client.put("/api/v1/settings/telemetry", json={"x": 1}, headers=ADMIN)
    assert response.status_code == 404
    assert "error" in response.get_json()


def test_settings_update_rejects_unknown_fields(client):
    response = client.put(
        "/api/v1/settings/sso",
        json={"primary_provider": "okta", "api_key": "nope"},
        headers=ADMIN,
    )
    assert response.status_code == 400
    details = response.get_json()["details"]
    assert details["fields"] == ["api_key"]
    assert "primary_provider" in details["allowed"]


@pytest.mark.parametrize(
    "group,payload,expected_fragment",
    [
        # out of range
        ("zsp", {"tier0_quorum_approvers": 99}, "must be <= 10"),
        ("zsp", {"default_jit_ttl_minutes": 0}, "must be >= 1"),
        ("hsm", {"key_rotation_hours": 0}, "must be >= 1"),
        # wrong types
        ("zsp", {"tier0_quorum_approvers": "many"}, "must be an integer"),
        ("zsp", {"tier0_quorum_approvers": True}, "must be an integer"),
        ("sso", {"enforce_sso": "yes"}, "must be true or false"),
        ("sso", {"session_ttl_minutes": "480"}, "must be an integer"),
        # value formats
        ("sso", {"primary_metadata_url": "http://insecure.example/x"}, "must be an https URL"),
        ("worm", {"bucket": "Bad_Bucket"}, "DNS-style name"),
        ("worm", {"object_lock_mode": "COMPLIANT"}, "must be one of"),
        ("hsm", {"fips_profile": "fips-999-level-1"}, "must be one of"),
        ("hsm", {"cluster_id": ""}, "is required"),
    ],
)
def test_settings_update_rejects_bad_values(client, group, payload, expected_fragment):
    response = client.put(f"/api/v1/settings/{group}", json=payload, headers=ADMIN)
    assert response.status_code == 400, response.get_data(as_text=True)
    body = response.get_json()
    assert expected_fragment in body["error"]
    assert body["details"]["field"].startswith(group + ".")


def test_settings_update_rejects_empty_and_non_object_payloads(client):
    empty = client.put("/api/v1/settings/zsp", json={}, headers=ADMIN)
    assert empty.status_code == 400
    assert "at least one" in empty.get_json()["error"]

    not_object = client.put("/api/v1/settings/zsp", json=[1, 2], headers=ADMIN)
    assert not_object.status_code == 400


def test_settings_each_group_writes_independently(client):
    writes = [
        ("sso", {"primary_provider": "entra", "session_ttl_minutes": 60}),
        ("hsm", {"provider": "hashicorp-vault", "key_rotation_hours": 12}),
        ("zsp", {"session_inactivity_timeout_minutes": 5}),
        ("worm", {"object_lock_mode": "GOVERNANCE", "retention_days": 730}),
    ]
    for group, payload in writes:
        assert client.put(
            f"/api/v1/settings/{group}", json=payload, headers=ADMIN
        ).status_code == 200

    settings = client.get("/api/v1/settings", headers=ADMIN).get_json()["settings"]
    assert settings["sso"]["values"]["primary_provider"] == "entra"
    assert settings["sso"]["values"]["enforce_sso"] is True  # untouched default
    assert settings["hsm"]["values"]["provider"] == "hashicorp-vault"
    assert settings["zsp"]["values"]["session_inactivity_timeout_minutes"] == 5
    assert settings["worm"]["values"]["object_lock_mode"] == "GOVERNANCE"
    assert settings["worm"]["values"]["immutability_enabled"] is True

    audit = client.get("/api/v1/settings/audit", headers=ADMIN).get_json()
    assert audit["total"] == 4
    assert [event["group"] for event in audit["events"]] == [
        "worm", "zsp", "hsm", "sso",   # newest first
    ]
    assert audit["events"][0]["changes"] == {
        "object_lock_mode": {"old": "COMPLIANCE", "new": "GOVERNANCE"},
        "retention_days": {"old": 2555, "new": 730},
    }


def test_settings_audit_respects_limit(client):
    for approvers in (4, 5, 6):
        client.put(
            "/api/v1/settings/zsp",
            json={"tier0_quorum_approvers": approvers},
            headers=ADMIN,
        )
    audit = client.get("/api/v1/settings/audit?limit=2", headers=ADMIN).get_json()
    assert audit["total"] == 3
    assert audit["limit"] == 2
    assert len(audit["events"]) == 2
    assert audit["events"][0]["changes"]["tier0_quorum_approvers"]["new"] == 6


def test_settings_audit_limit_must_be_an_integer(client):
    response = client.get("/api/v1/settings/audit?limit=abc", headers=ADMIN)
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# suite navigation: every screen carries the canonical, working sidebar
# ---------------------------------------------------------------------------
def _nav_block(html: str) -> str:
    match = re.search(r"<nav[^>]*>.*?</nav>", html, re.S)
    assert match, "screen has no <nav>"
    return match.group(0)


def test_every_screen_has_the_canonical_nav():
    for folder in WIRED_SCREENS:
        path = SCREENS_DIR / folder / "code.html"
        assert path.is_file(), f"{folder}/code.html missing"
        nav = _nav_block(path.read_text(encoding="utf-8"))

        slugs = re.findall(r'data-path="([^"]+)"', nav)
        assert slugs == [slug for slug, _ in CANONICAL_NAV], folder

        hrefs = re.findall(r'data-path="[^"]+"[^>]*href="([^"]+)"', nav)
        own = OWN_INDEX[folder]
        expected = [
            # 11.5 flip (ADR-0015): the settings slot links the server route
            # /settings (which redirects to the React page) on every screen
            # except a spec screen whose own slot IS the settings slot.
            "/settings" if index == 10 and index != own
            else f"../{folder}/code.html" if index == own
            else f"../{target}/code.html"
            for index, (_, target) in enumerate(CANONICAL_NAV)
        ]
        assert hrefs == expected, folder

        active = re.findall(r'<a[^>]*aria-current="page"[^>]*data-path="([^"]+)"', nav)
        assert active == [CANONICAL_NAV[own][0]], folder

        # every target the sidebar names must exist on disk - server routes
        # (absolute hrefs like /settings) are asserted through the app in
        # test_server_serves_the_suite instead
        for href in hrefs:
            if href.startswith("/"):
                continue
            assert (SCREENS_DIR / folder / href).resolve().is_file(), f"{folder} -> {href}"


def test_no_screen_has_dead_sidebar_links():
    for folder in WIRED_SCREENS:
        html = (SCREENS_DIR / folder / "code.html").read_text(encoding="utf-8")
        dead = re.findall(r'<a\s[^>]*data-path="[^"]+"[^>]*href="#"', html)
        assert not dead, f"{folder} still has {len(dead)} dead sidebar links"


def test_launcher_links_every_screen():
    index = UI_ROOT / "index.html"
    assert index.is_file(), "frontend launcher index.html missing"
    html = index.read_text(encoding="utf-8")
    for folder in WIRED_SCREENS:
        assert f"screens/{folder}/code.html" in html, folder
        assert f"screens/{folder}/screen.png" in html, folder
    # 11.5 flip (ADR-0015): the launcher's settings card points at the
    # server route that now serves the React page, not the deleted file.
    assert 'data-kind="live" href="/settings"' in html
    assert "screens/platform_settings_center/code.html" not in html


# ---------------------------------------------------------------------------
# the server serves the suite without shadowing the API
# ---------------------------------------------------------------------------
def test_server_serves_the_suite(client):
    assert client.get("/index.html").status_code == 200
    for folder in WIRED_SCREENS:
        response = client.get(f"/screens/{folder}/code.html")
        assert response.status_code == 200, folder
        assert response.content_type.startswith("text/html"), folder

    # the live screens keep their own routes; /settings is the 11.5 flip:
    # the old URL lands on the React page under /app/
    for path in ("/", "/license"):
        assert client.get(path).status_code == 200, path
    settings = client.get("/settings")
    assert settings.status_code == 302
    assert settings.headers["Location"] == "/app/settings"


def test_root_mirror_serves_every_screen(client):
    """P0 fix (ADR-0020): the entry screen at / links ../<folder>/code.html,
    which the browser clamps to /<folder>/code.html - those root-relative
    URLs must answer 200 like the canonical /screens/... ones."""
    for folder in WIRED_SCREENS:
        response = client.get(f"/{folder}/code.html")
        assert response.status_code == 200, folder
        assert response.content_type.startswith("text/html"), folder


def test_root_mirror_refuses_api_health_and_unknown(client):
    """The mirror never shadows the API/health namespaces (same refusal as
    suite_files) and unknown folders stay honest 404s, not listings. Real
    /api/v1/... routes keep their own registered answers."""
    assert client.get("/api/v1/licenses").status_code != 404  # registered route
    for path in ("/api/anything", "/health/live", "/no_such_screen/code.html"):
        assert client.get(path).status_code == 404, path


# ---------------------------------------------------------------------------
# the built React console under /app/ (ADR-0012 serving contract)
# ---------------------------------------------------------------------------
def test_settings_redirect_without_a_build_is_honest(client, tmp_path, monkeypatch):
    """The redirect never depends on the bundle: /settings always answers
    302, and /app/ without a build is an honest JSON 404 - never a stub."""
    assert client.get("/settings").status_code == 302
    monkeypatch.setattr(app_module, "CONSOLE_DIST", tmp_path / "no-dist")
    missing = client.get("/app/")
    assert missing.status_code == 404
    assert "console build not found" in missing.get_json()["error"]


def test_console_serves_shell_assets_and_spa_fallback(client, tmp_path, monkeypatch):
    """ADR-0012: Flask serves frontend/app/dist under /app/ - the shell at
    /app/, real files as-is, and the shell as the SPA fallback so client
    routes deep-link (basename /app, ADR-0005)."""
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<div id=\"root\">console</div>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('ok')", encoding="utf-8")
    monkeypatch.setattr(app_module, "CONSOLE_DIST", dist)

    for path in ("/app", "/app/", "/app/settings", "/app/vault/deep"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert b"console" in response.data, path

    asset = client.get("/app/assets/app.js")
    assert asset.status_code == 200
    assert asset.content_type.startswith(("text/javascript", "application/javascript"))

    # the traversal attempt is refused, not served
    assert client.get("/app/../../etc/passwd").status_code in (308, 404)


def test_server_serves_previews_and_design_doc(client):
    for folder in WIRED_SCREENS:
        response = client.get(f"/screens/{folder}/screen.png")
        assert response.status_code == 200, folder
        assert response.content_type.startswith("image/"), folder

    design = client.get("/screens/zero_trust_sentinel/DESIGN.md")
    assert design.status_code == 200


def test_static_serving_does_not_shadow_the_api(client):
    # a real API route still answers...
    assert client.get("/api/v1/settings", headers=ADMIN).status_code == 200
    assert client.get("/health").status_code == 200
    # ...and a missing one is a JSON 404, not a file lookup
    response = client.get("/api/v1/no-such-route")
    assert response.status_code == 404
    assert response.is_json
    assert "error" in response.get_json()
    assert client.get("/health/nope").status_code == 404


def test_static_serving_refuses_paths_outside_the_suite(client):
    for path in ("/../config.py", "/no-such-folder/no-such-file.html"):
        response = client.get(path)
        assert response.status_code in (400, 404), path
