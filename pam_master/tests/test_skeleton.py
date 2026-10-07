"""Phase 2a skeleton tests: honest health, key custody rules, engine wiring.

No fabricated values anywhere: health assertions compare against the real
state of the temp database and temp keys the fixtures just created.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from pam_master import Config, ConfigError, create_app, licensing
from pam_master.keygen import run as keygen_run
from pam_master.keys import (
    KeyCustodyError,
    generate_ed25519_key,
    generate_rsa_key,
)


# ------------------------------------------------------------------ index --
def test_index_is_descriptive_only(client):
    response = client.get("/")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["service"] == "vy-pam-master"
    assert "never shipped" in payload["role"]
    assert payload["endpoints"] == {
        "health": "/health",
        "customers": "/api/v1/customers",
        "licenses": "/api/v1/licenses",
        "license-options": "/api/v1/license-options",
        "audit": "/api/v1/audit",
    }


# ----------------------------------------------------------------- health --
def test_health_reports_real_state(client):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["service"] == "vy-pam-master"

    # Real database state: the probe created a fresh sqlite file, 0 tables.
    database = payload["database"]
    assert database["scheme"] == "sqlite"
    assert database["reachable"] is True
    assert database["tables"] == 0

    # Real key custody state: the fixture generated all three keys.
    signing = payload["signing"]
    assert signing["algorithms"] == list(licensing.sig.SUPPORTED_ALGORITHMS)
    assert signing["rsa_key"] == "present"
    assert signing["ed25519_key"] == "present"
    assert signing["ready"] is True
    assert payload["registry"]["pii_key"] == "present"
    assert payload["registry"]["ready"] is True

    # Presence only — key material never appears in any response.
    body = response.get_data(as_text=True)
    assert "BEGIN" not in body
    assert "PRIVATE" not in body


def test_health_reports_missing_keys_honestly(tmp_path):
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "absent_rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(tmp_path / "absent_ed.pem"),
        }
    )
    payload = create_app(config).test_client().get("/health").get_json()
    # The process is alive; the signing path is not ready — reported as such.
    assert payload["status"] == "ok"
    assert payload["signing"]["rsa_key"] == "missing"
    assert payload["signing"]["ed25519_key"] == "missing"
    assert payload["signing"]["ready"] is False
    # Probing presence must never create anything.
    assert not (tmp_path / "absent_rsa.pem").exists()
    assert not (tmp_path / "absent_ed.pem").exists()


# ----------------------------------------------------------------- config --
def test_config_defaults_match_documented_custody_layout():
    config = Config.from_env({})
    assert config.port == 5400
    assert config.host == "127.0.0.1"
    assert config.database_path == (
        licensing.REPO_ROOT / "pam_master" / "master.db"
    )
    assert config.rsa_private_key_path == (
        licensing.REPO_ROOT / "license_private_key.pem"
    )
    assert config.ed25519_private_key_path == (
        licensing.REPO_ROOT / "license_ed25519_private.pem"
    )
    assert config.customer_key_b64 is None
    assert config.customer_key_path == (
        licensing.REPO_ROOT / "pam_master" / "customer_registry.key"
    )


def test_config_honors_env_overrides(tmp_path):
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'vendor.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(tmp_path / "ed.pem"),
            "MASTER_CUSTOMER_KEY_PATH": str(tmp_path / "pii.key"),
            "MASTER_CUSTOMER_KEY_B64": "aGVsbG8td29ybGQ=",
            "MASTER_SERVER_PORT": "6001",
            "MASTER_BIND": "0.0.0.0",
        }
    )
    assert config.database_path == tmp_path / "vendor.db"
    assert config.rsa_private_key_path == tmp_path / "rsa.pem"
    assert config.ed25519_private_key_path == tmp_path / "ed.pem"
    assert config.customer_key_path == tmp_path / "pii.key"
    assert config.customer_key_b64 == "aGVsbG8td29ybGQ="
    assert config.port == 6001
    assert config.host == "0.0.0.0"


def test_config_rejects_invalid_values():
    with pytest.raises(ConfigError):
        Config.from_env({"MASTER_SERVER_PORT": "not-a-port"})
    with pytest.raises(ConfigError):
        Config.from_env({"MASTER_SERVER_PORT": "70000"})
    with pytest.raises(ConfigError):
        Config.from_env({"MASTER_DATABASE_URI": "postgres://vendor/master"})
    with pytest.raises(ConfigError):
        Config.from_env({"MASTER_DATABASE_URI": "sqlite:///"})


# ---------------------------------------------------------------- custody --
def test_custody_refuses_missing_keys_without_creating_them(tmp_path):
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(tmp_path / "keys" / "rsa.pem"),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(
                tmp_path / "keys" / "ed.pem"
            ),
        }
    )
    with pytest.raises(KeyCustodyError) as excinfo:
        licensing.get_generator(config)
    assert "keygen" in str(excinfo.value)
    # The engine's load-or-create path must never have run: not even the
    # key directory may exist afterwards.
    assert not (tmp_path / "keys").exists()


def test_key_generation_refuses_overwrite(tmp_path):
    rsa_path = tmp_path / "license_private_key.pem"
    generate_rsa_key(rsa_path)
    original = rsa_path.read_bytes()
    with pytest.raises(KeyCustodyError):
        generate_rsa_key(rsa_path)
    assert rsa_path.read_bytes() == original

    ed_path = tmp_path / "license_ed25519_private.pem"
    generate_ed25519_key(ed_path)
    ed_original = ed_path.read_bytes()
    with pytest.raises(KeyCustodyError):
        generate_ed25519_key(ed_path)
    assert ed_path.read_bytes() == ed_original


def test_keygen_creates_all_keys_then_keeps_them(tmp_path):
    config = Config.from_env(
        {
            "MASTER_DATABASE_URI": f"sqlite:///{tmp_path / 'master.db'}",
            "MASTER_RSA_PRIVATE_KEY_PATH": str(
                tmp_path / "license_private_key.pem"
            ),
            "MASTER_ED25519_PRIVATE_KEY_PATH": str(
                tmp_path / "license_ed25519_private.pem"
            ),
            "MASTER_CUSTOMER_KEY_PATH": str(
                tmp_path / "customer_registry.key"
            ),
        }
    )
    lines = keygen_run(config)
    assert sum("created" in line for line in lines) == 3
    assert (tmp_path / "license_private_key.pem").is_file()
    assert (tmp_path / "license_ed25519_private.pem").is_file()
    assert (tmp_path / "customer_registry.key").is_file()
    # Public counterparts follow the engine's naming convention so
    # LicenseValidator on the shipped side finds them.
    assert (tmp_path / "license_public_key.pem").is_file()
    assert (tmp_path / "license_ed25519_public.pem").is_file()
    # The registry key is symmetric — no public counterpart.
    assert not (tmp_path / "customer_registry_public.key").exists()

    rsa_bytes = (tmp_path / "license_private_key.pem").read_bytes()
    registry_bytes = (tmp_path / "customer_registry.key").read_bytes()
    second = keygen_run(config)
    assert all("kept" in line for line in second)
    assert (tmp_path / "license_private_key.pem").read_bytes() == rsa_bytes
    assert (
        (tmp_path / "customer_registry.key").read_bytes()
        == registry_bytes
    )


# ---------------------------------------------------------- engine wiring --
@pytest.mark.parametrize("algorithm", licensing.sig.SUPPORTED_ALGORITHMS)
def test_sign_verify_roundtrip_through_shared_engine(config, algorithm):
    generator = licensing.get_generator(config)
    claims = {
        "license_id": "TEST-0001",
        "customer": "fixture-customer",
        "issuer": "pam-master-skeleton",
    }
    envelope = licensing.sig.build_json_envelope(
        generator.private_key_for(algorithm), claims, algorithm
    )
    public_key = serialization.load_pem_public_key(
        generator.get_public_key_pem(algorithm)
    )
    assert licensing.sig.verify_envelope(public_key, envelope)

    # A tampered claim must fail verification.
    tampered = dict(envelope, license_data=dict(claims, customer="someone"))
    assert not licensing.sig.verify_envelope(public_key, tampered)


def test_generator_is_cached_per_key_pair(config):
    assert licensing.get_generator(config) is licensing.get_generator(config)


# ----------------------------------------------------------- anti-mixing --
FORBIDDEN_SOURCE_TOKENS = (
    "phase2_license_server",  # shipped PAM runtime
    "from backend.",          # cross-product package imports (engine only
    "import backend",         #  may arrive via the licensing bridge)
)


def test_master_source_never_references_the_pam_runtime():
    """The package runtime must not import the shipped PAM server or the
    backend package (extraction rule: only the licensing bridge may reach
    the shared engine, via its own flat imports). Tests are excluded from
    the scan — they legitimately name the forbidden module to assert on it."""
    package_dir = Path(licensing.__file__).resolve().parent
    offenders = [
        f"{path.name}: {token}"
        for path in sorted(package_dir.rglob("*.py"))
        for token in FORBIDDEN_SOURCE_TOKENS
        if token in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
