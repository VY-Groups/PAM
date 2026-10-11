"""Phase 6c - HSM/KMS master-key custody (architecture section 20).

The provider surface runs for real against an in-memory Vault-transit
stub that speaks the exact HTTP the hashicorp-vault provider speaks
(health, encrypt, decrypt, token header) - so the wrap/unwrap round trip,
the enforced no-file-fallback rule, the seal -> 503 -> unseal cycle, the
watchdog seal and the honest status/posture all execute the production
code paths. Key material never appears in a wrap file, an event detail or
a response; the wrap blob is the provider's opaque ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from extensions import db  # noqa: E402
from models import HsmKeyEvent  # noqa: E402
import hsm as hsm_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ENDPOINT = "https://vault.example.test"


def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-hsm-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-hsm",
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
def _reset_hsm_state():
    """Seal state, the cached key and the health history are process-global:
    every test starts from a clean, unsealed vault."""
    yield
    hsm_module._SEALED = False
    hsm_module._SEAL_REASON = ""
    hsm_module._UNWRAPPED_KEY = None
    hsm_module._LAST_HEALTH = {}
    hsm_module._HEALTH_FAILING_SINCE = None
    hsm_module._AZURE_TOKEN.clear()
    os.environ.pop("PAM_HSM_VAULT_TOKEN", None)


class _VaultStub:
    """An in-memory Vault transit engine: ciphertexts are opaque ids, so a
    wrap file written through it provably contains no key material."""

    def __init__(self, token: str = "stub-token"):
        self.token = token
        self.ciphertexts = {}
        self.health_status = 200
        self.fail_decrypt = False
        self.dead = False

    def request(self, url, *, method="GET", headers=None, body=None):
        assert headers and headers.get("X-Vault-Token") == self.token, (
            "the provider must send its token on every call"
        )
        if self.dead:
            raise hsm_module.ServiceUnavailable(
                "HSM provider endpoint unreachable: connection refused",
                {"url": url.split("?")[0], "provider_reachable": False},
            )
        if url.endswith("/v1/sys/health"):
            return self.health_status, b""
        raise AssertionError(f"unexpected vault request {method} {url}")

    def json(self, url, *, method="POST", headers=None, payload=None):
        assert headers and headers.get("X-Vault-Token") == self.token
        if self.dead:
            raise hsm_module.ServiceUnavailable(
                "HSM provider endpoint unreachable: connection refused",
                {"url": url.split("?")[0], "provider_reachable": False},
            )
        if "/v1/transit/encrypt/" in url:
            cid = f"vault:v1:opaque{len(self.ciphertexts)}"
            self.ciphertexts[cid] = payload["plaintext"]
            return 200, {"ciphertext": cid}
        if "/v1/transit/decrypt/" in url:
            if self.fail_decrypt:
                return 500, {"errors": ["transit key is disabled"]}
            plaintext = self.ciphertexts.get(payload["ciphertext"])
            if plaintext is None:
                return 400, {"errors": ["ciphertext unknown"]}
            return 200, {"plaintext": plaintext}
        raise AssertionError(f"unexpected vault request {method} {url}")


@pytest.fixture
def vault(monkeypatch):
    stub = _VaultStub()
    monkeypatch.setenv("PAM_HSM_VAULT_TOKEN", stub.token)
    monkeypatch.setattr(hsm_module, "_http_request", stub.request)
    monkeypatch.setattr(hsm_module, "_http_json", stub.json)
    return stub


def configure_hsm(client, **fields):
    response = client.put("/api/v1/settings/hsm", json=fields, headers=ADMIN)
    assert response.status_code in (200, 201), response.get_data(as_text=True)
    return response


def onboard(client, name, secret="hunter2-generated-value"):
    response = client.post(
        "/api/v1/vault/items",
        json={
            "name": name,
            "secret_type": "database",
            "target": "db.internal",
            "principal": "admin",
            "access_tier": "Tier-1",
            "auth_method": "Password",
            "rotation_interval_hours": 24,
            "secret": secret,
        },
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    return response.get_json()["item"]


def reveal(client, item_id):
    return client.get(f"/api/v1/vault/items/{item_id}/secret", headers=ADMIN)


# ---------------------------------------------------------------------------
# status + settings validation
# ---------------------------------------------------------------------------
def test_status_reports_advisory_file_custody(client):
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["mode"] == "advisory"
    assert status["sealed"] is False
    assert status["key_in_use"] == "file"
    assert "wrapped" in status["wrap_error"].lower()


def test_enforcement_setting_is_validated(client):
    bad = client.put(
        "/api/v1/settings/hsm", json={"enforcement": "kms"}, headers=ADMIN
    )
    assert bad.status_code == 400
    assert "advisory" in bad.get_json()["error"]
    configure_hsm(client, enforcement="enforced")
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["mode"] == "enforced"


def test_kms_endpoint_loopback_http_allowed_remote_http_refused(client):
    bad = client.put(
        "/api/v1/settings/hsm",
        json={"kms_endpoint": "http://vault.example.test"},
        headers=ADMIN,
    )
    assert bad.status_code == 400
    configure_hsm(client, kms_endpoint="http://127.0.0.1:8200")
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["mode"] == "advisory"


# ---------------------------------------------------------------------------
# seal / unseal cycle (advisory)
# ---------------------------------------------------------------------------
def test_seal_blocks_vault_until_unseal(client):
    item = onboard(client, "sealed-credential")
    assert reveal(client, item["id"]).status_code == 200

    sealed = client.post(
        "/api/v1/hsm/seal", json={"reason": "maintenance window"}, headers=ADMIN
    ).get_json()
    assert sealed["sealed"] is True and sealed["reason"] == "maintenance window"

    blocked = reveal(client, item["id"])
    assert blocked.status_code == 503
    assert "sealed" in blocked.get_json()["error"].lower()

    unsealed = client.post("/api/v1/hsm/unseal", headers=ADMIN).get_json()
    assert unsealed["sealed"] is False
    assert reveal(client, item["id"]).status_code == 200

    export = client.get("/api/v1/audit/export", headers=ADMIN)
    entries = [json.loads(line) for line in export.get_data(as_text=True).splitlines() if line]
    hsm_actions = [e["action"] for e in entries if e["source"] == "hsm"]
    assert "hsm.sealed" in hsm_actions and "hsm.unsealed" in hsm_actions


def test_seal_reason_length_is_validated(client):
    refused = client.post(
        "/api/v1/hsm/seal", json={"reason": "x" * 201}, headers=ADMIN
    )
    assert refused.status_code == 400
    assert "200" in refused.get_json()["error"]


# ---------------------------------------------------------------------------
# hashicorp-vault: wrap -> enforced unwrap -> seal/unseal -> dead provider
# ---------------------------------------------------------------------------
def test_vault_provider_wrap_enforced_unwrap_and_seal_cycle(client, vault, app, config):
    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        master_key_label="pam-root",
        enforcement="advisory",
    )
    item = onboard(client, "enforced-credential", secret="value-encrypted-under-file-key")

    rotated = client.post("/api/v1/hsm/keys/rotate", headers=ADMIN).get_json()
    assert rotated["provider"] == "hashicorp-vault"
    assert rotated["key_changed"] is False and "re-wrapped" in rotated["detail"]

    wrap_path = Path(str(config.vault_key_path) + ".wrap")
    assert wrap_path.is_file()
    wrap_text = wrap_path.read_text(encoding="utf-8")
    record = json.loads(wrap_text)
    assert record["provider"] == "hashicorp-vault" and record["key_label"] == "pam-root"
    # the wrap blob is the provider's opaque ciphertext - the key never lands on disk
    raw_key = Path(config.vault_key_path).read_bytes()
    assert base64.b64encode(raw_key).decode("ascii") not in wrap_text

    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["wrapped_key"]["provider"] == "hashicorp-vault"
    assert status["rotation_due"] is False and status["key_in_use"] == "file"

    # custody moves to the provider: the SAME key unwraps, old ciphertexts still open
    configure_hsm(client, enforcement="enforced")
    revealed = reveal(client, item["id"])
    assert revealed.status_code == 200
    assert revealed.get_json()["secret"] == "value-encrypted-under-file-key"

    with app.app_context():
        actions = [row.action for row in HsmKeyEvent.query.all()]
        assert "hsm.key.unwrapped" in actions
        for row in HsmKeyEvent.query.all():
            blob = json.dumps(row.detail)
            assert base64.b64encode(raw_key).decode("ascii") not in blob
            assert "plaintext" not in blob

    # sealed: enforced mode never falls back to the file sitting on disk
    client.post("/api/v1/hsm/seal", json={"reason": "key rotation"}, headers=ADMIN)
    blocked = reveal(client, item["id"])
    assert blocked.status_code == 503
    assert "sealed" in blocked.get_json()["error"].lower()

    # provider alive: unseal unwraps again and the vault opens
    assert client.post("/api/v1/hsm/unseal", headers=ADMIN).status_code == 200
    assert reveal(client, item["id"]).status_code == 200

    # dead provider: unseal refuses honestly and the vault STAYS sealed
    vault.dead = True
    client.post("/api/v1/hsm/seal", json={"reason": "drill"}, headers=ADMIN)
    refused = client.post("/api/v1/hsm/unseal", headers=ADMIN)
    assert refused.status_code == 503
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["sealed"] is True
    assert "unwrap" in status["seal_reason"]
    assert reveal(client, item["id"]).status_code == 503

    vault.dead = False
    assert client.post("/api/v1/hsm/unseal", headers=ADMIN).status_code == 200
    assert reveal(client, item["id"]).status_code == 200


def test_rotation_due_follows_the_clock(client, vault, config):
    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        master_key_label="pam-root",
        key_rotation_hours=24,
    )
    client.post("/api/v1/hsm/keys/rotate", headers=ADMIN)
    assert client.get("/api/v1/hsm/status", headers=ADMIN).get_json()["rotation_due"] is False
    # age the wrap record past the window: the flag follows the real clock
    wrap_path = Path(str(config.vault_key_path) + ".wrap")
    record = json.loads(wrap_path.read_text(encoding="utf-8"))
    record["wrapped_at"] = "2020-01-01T00:00:00"
    wrap_path.write_text(json.dumps(record), encoding="utf-8")
    assert client.get("/api/v1/hsm/status", headers=ADMIN).get_json()["rotation_due"] is True


def test_vault_token_missing_is_an_honest_503(client, monkeypatch):
    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        master_key_label="pam-root",
    )
    monkeypatch.setenv("PAM_HSM_VAULT_TOKEN", "")
    refused = client.post("/api/v1/hsm/keys/rotate", headers=ADMIN)
    assert refused.status_code == 503
    assert "PAM_HSM_VAULT_TOKEN" in refused.get_json()["details"]["env"]


# ---------------------------------------------------------------------------
# watchdog: enforced + unreachable past the delay seals on the monitor tick
# ---------------------------------------------------------------------------
def test_watchdog_seals_when_enforced_provider_stays_down(client, vault):
    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        master_key_label="pam-root",
        enforcement="enforced",
        seal_delay_seconds=0,
    )
    vault.health_status = 503  # vault sealed / provider answering unhealthy

    tick = client.post("/api/v1/cluster/monitor/tick", headers=ADMIN).get_json()
    assert tick["hsm"]["sealed"] is True
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["sealed"] is True and "watchdog" in status["seal_reason"]

    with app_context_for(client):
        rows = [row for row in HsmKeyEvent.query.all() if row.action == "hsm.sealed"]
        assert rows and rows[-1].actor == "hsm-watchdog"


def test_watchdog_never_seals_in_advisory_mode(client, vault):
    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        seal_delay_seconds=0,
    )
    vault.health_status = 503
    tick = client.post("/api/v1/cluster/monitor/tick", headers=ADMIN).get_json()
    assert "hsm" not in tick
    status = client.get("/api/v1/hsm/status", headers=ADMIN).get_json()
    assert status["sealed"] is False


def app_context_for(client):
    """The test client's app, for direct model reads inside a test."""
    return client.application.app_context()


# ---------------------------------------------------------------------------
# honest provider absences (no optional dependency, no credentials)
# ---------------------------------------------------------------------------
def test_pkcs11_absent_reports_it_and_watchdog_seals(client):
    configure_hsm(
        client,
        provider="local-pkcs11",
        enforcement="enforced",
        seal_delay_seconds=0,
    )
    tick = client.post("/api/v1/cluster/monitor/tick", headers=ADMIN).get_json()
    assert tick["hsm"]["sealed"] is True
    assert "PyKCS11" in tick["hsm"]["detail"]


def test_missing_cloud_credentials_are_named(client, monkeypatch):
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    configure_hsm(client, provider="aws-cloudhsm", enforcement="enforced")
    with app_context_for(client):
        health = hsm_module.health()
    assert health["reachable"] is False and "AWS credentials" in health["detail"]

    configure_hsm(client, provider="azure-dedicated-hsm")
    with app_context_for(client):
        health = hsm_module.health()
    assert health["reachable"] is False and "Azure credentials" in health["detail"]


def test_unknown_provider_is_refused_by_the_schema(client):
    refused = client.put(
        "/api/v1/settings/hsm", json={"provider": "yubikey-neo"}, headers=ADMIN
    )
    assert refused.status_code == 400
    assert "provider" in refused.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# posture honesty: the control counts what is really in force
# ---------------------------------------------------------------------------
def test_posture_counts_real_custody(client, vault):
    overview = client.get("/api/v1/overview", headers=ADMIN).get_json()
    control = next(c for c in overview["posture"]["controls"] if c["id"] == "hsm_backed")
    assert control["passed"] is False
    assert "advisory" in control["evidence"]

    configure_hsm(
        client,
        provider="hashicorp-vault",
        kms_endpoint=ENDPOINT,
        master_key_label="pam-root",
        seal_delay_seconds=60,
    )
    # wrap the file key while advisory, THEN move custody to the provider
    client.post("/api/v1/hsm/keys/rotate", headers=ADMIN)
    configure_hsm(client, enforcement="enforced")
    with app_context_for(client):
        hsm_module.health()  # a real probe: reachable through the stub
    overview = client.get("/api/v1/overview", headers=ADMIN).get_json()
    control = next(c for c in overview["posture"]["controls"] if c["id"] == "hsm_backed")
    assert control["passed"] is True
    assert "enforced" in control["evidence"] and "reachable" in control["evidence"]

    client.post("/api/v1/hsm/seal", json={"reason": "posture drill"}, headers=ADMIN)
    overview = client.get("/api/v1/overview", headers=ADMIN).get_json()
    control = next(c for c in overview["posture"]["controls"] if c["id"] == "hsm_backed")
    assert control["passed"] is False
    assert "sealed" in control["evidence"]
