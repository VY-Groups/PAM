"""
Pytest suite for the Phase 1 IPAM licensing library.

Everything runs against keys and license files inside pytest's tmp_path, so
the suite is safe to run from any working directory and never touches the
production key pair in the repository root.

Run:  python -m pytest ipam_licensing -q
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization

from license import License, LicenseStatus, LicenseType
from license_tool import LicenseGenerator
from license_validator import LicenseValidator, validate_license


@pytest.fixture
def generator(tmp_path) -> LicenseGenerator:
    return LicenseGenerator(private_key_path=str(tmp_path / "license_private_key.pem"))


@pytest.fixture
def public_key_path(generator, tmp_path) -> str:
    path = tmp_path / "license_public_key.pem"
    path.write_bytes(generator.get_public_key_pem())
    return str(path)


@pytest.fixture
def validator(public_key_path) -> LicenseValidator:
    return LicenseValidator(public_key_path=public_key_path)


def _signed_file(generator: LicenseGenerator, license_obj: License, tmp_path):
    path = tmp_path / f"license_{license_obj.license_key}.json"
    generator.save_license_file(license_obj, str(path))
    return str(path)


def _trial(generator: LicenseGenerator, trial_days: int = 30) -> License:
    return generator.generate_license(
        license_type=LicenseType.TRIAL, issued_to="Acme Ltd", trial_days=trial_days
    )


# ---------------------------------------------------------------------------
# key handling
# ---------------------------------------------------------------------------
def test_private_key_is_created_once_and_reused(tmp_path):
    key_path = tmp_path / "key.pem"
    first = LicenseGenerator(private_key_path=str(key_path))
    original = key_path.read_bytes()
    second = LicenseGenerator(private_key_path=str(key_path))

    assert original  # written to disk
    assert key_path.read_bytes() == original  # untouched on reload
    assert first.private_key.private_numbers() == second.private_key.private_numbers()


def test_public_key_matches_private_key(generator, public_key_path):
    stored = open(public_key_path, "rb").read().strip()
    validator = LicenseValidator(public_key_path=public_key_path)

    # what the generator published...
    assert generator.get_public_key_pem().strip() == stored
    # ...is the same key the validator loads
    rederived = validator.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert rederived.strip() == stored


def test_missing_public_key_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        LicenseValidator(public_key_path=str(tmp_path / "absent.pem"))


# ---------------------------------------------------------------------------
# signing / verification
# ---------------------------------------------------------------------------
def test_sign_and_verify_round_trip(validator, generator):
    license_obj = _trial(generator)
    data = license_obj.to_dict()
    signature = generator.sign_license(data)

    assert validator.verify_signature(data, signature) is True
    assert base64.b64decode(signature)  # usable base64


def test_tampered_payload_fails_verification(validator, generator):
    data = _trial(generator).to_dict()
    signature = generator.sign_license(data)

    tampered = dict(data, issued_to="Someone Else")
    assert validator.verify_signature(tampered, signature) is False


def test_signature_from_a_different_key_fails(validator, tmp_path):
    foreign = LicenseGenerator(private_key_path=str(tmp_path / "other_key.pem"))
    data = License(
        license_key=str(uuid.uuid4()).upper(),
        license_type=LicenseType.TRIAL,
        issued_to="Impostor",
        issued_date=datetime.now(),
        expires_on=datetime.now() + timedelta(days=5),
    ).to_dict()

    # foreign signature is internally consistent but not ours
    foreign_signature = foreign.sign_license(data)
    assert validator.verify_signature(data, foreign_signature) is False


def test_garbage_signature_fails(validator, generator):
    data = _trial(generator).to_dict()
    assert validator.verify_signature(data, "not-base64!!") is False
    assert validator.verify_signature(data, base64.b64encode(b"short").decode()) is False


# ---------------------------------------------------------------------------
# file validation statuses
# ---------------------------------------------------------------------------
def test_valid_license_file_reports_valid(validator, generator, tmp_path):
    path = _signed_file(generator, _trial(generator), tmp_path)
    status, license_obj = validator.validate_license_file(path)

    assert status is LicenseStatus.VALID
    assert license_obj is not None
    assert license_obj.issued_to == "Acme Ltd"
    assert license_obj.is_expired() is False


def test_expired_license_file_reports_expired(validator, generator, tmp_path):
    expired = License(
        license_key=str(uuid.uuid4()).upper(),
        license_type=LicenseType.TRIAL,
        issued_to="Late Customer",
        issued_date=datetime.now() - timedelta(days=40),
        expires_on=datetime.now() - timedelta(days=10),
    )
    path = _signed_file(generator, expired, tmp_path)
    status, license_obj = validator.validate_license_file(path)

    assert status is LicenseStatus.EXPIRED
    assert license_obj is not None
    assert license_obj.is_expired() is True


def test_perpetual_license_never_expires(validator, generator, tmp_path):
    perpetual = generator.generate_license(
        license_type=LicenseType.PERPETUAL, issued_to="Owner Ltd"
    )
    assert perpetual.expires_on is None
    assert perpetual.is_expired() is False
    assert perpetual.days_until_expiry() is None

    path = _signed_file(generator, perpetual, tmp_path)
    status, _ = validator.validate_license_file(path)
    assert status is LicenseStatus.VALID


def test_tampered_license_file_reports_signature_invalid(validator, generator, tmp_path):
    path = _signed_file(generator, _trial(generator), tmp_path)
    with open(path) as handle:
        payload = json.load(handle)
    payload["license_data"]["issued_to"] = "Someone Else"
    with open(path, "w") as handle:
        json.dump(payload, handle)

    status, license_obj = validator.validate_license_file(path)
    assert status is LicenseStatus.SIGNATURE_INVALID
    assert license_obj is None


@pytest.mark.parametrize(
    "content",
    [
        "not json at all",
        "{}",
        '{"license_data": {"license_key": "X"}}',
        '{"signature": "abc"}',
        "[]",
    ],
)
def test_malformed_license_files_report_malformed(validator, tmp_path, content):
    path = tmp_path / "broken.json"
    path.write_text(content, encoding="utf-8")
    status, license_obj = validator.validate_license_file(str(path))
    assert status is LicenseStatus.MALFORMED
    assert license_obj is None


def test_missing_license_file_reports_malformed(validator, tmp_path):
    status, license_obj = validator.validate_license_file(str(tmp_path / "absent.json"))
    assert status is LicenseStatus.MALFORMED
    assert license_obj is None


def test_wrong_type_field_reports_malformed(validator, generator, tmp_path):
    data = _trial(generator).to_dict()
    data["license_type"] = "rainbow"
    signature = generator.sign_license(data)
    path = tmp_path / "bad_type.json"
    path.write_text(json.dumps({"license_data": data, "signature": signature}))

    status, _ = validator.validate_license_file(str(path))
    assert status is LicenseStatus.MALFORMED


# ---------------------------------------------------------------------------
# expiry arithmetic
# ---------------------------------------------------------------------------
def test_days_until_expiry_fresh_trial_reports_full_term():
    license_obj = License(
        license_key="K",
        license_type=LicenseType.TRIAL,
        issued_to="Acme",
        issued_date=datetime.now(),
        expires_on=datetime.now() + timedelta(days=30),
    )
    assert license_obj.days_until_expiry() == 30


def test_days_until_expiry_less_than_a_day_reports_zero():
    license_obj = License(
        license_key="K",
        license_type=LicenseType.TRIAL,
        issued_to="Acme",
        issued_date=datetime.now(),
        expires_on=datetime.now() + timedelta(hours=6),
    )
    assert license_obj.is_expired() is False
    assert license_obj.days_until_expiry() == 0


def test_days_until_expiry_expired_returns_none():
    license_obj = License(
        license_key="K",
        license_type=LicenseType.TRIAL,
        issued_to="Acme",
        issued_date=datetime.now() - timedelta(days=10),
        expires_on=datetime.now() - timedelta(days=1),
    )
    assert license_obj.is_expired() is True
    assert license_obj.days_until_expiry() is None


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------
def test_to_dict_from_dict_round_trip(generator):
    original = _trial(generator)
    restored = License.from_dict(original.to_dict())

    assert restored.license_key == original.license_key
    assert restored.license_type is original.license_type
    assert restored.issued_to == original.issued_to
    assert restored.features == original.features
    assert restored.usage_limits == original.usage_limits
    assert restored.expires_on is not None


def test_serialized_dates_are_iso_format(generator):
    payload = _trial(generator).to_dict()
    assert datetime.fromisoformat(payload["issued_date"])
    assert datetime.fromisoformat(payload["expires_on"])
    assert payload["license_type"] == "trial"


# ---------------------------------------------------------------------------
# features / usage limits / key format
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "license_type,expected_count",
    [
        (LicenseType.TRIAL, 3),
        (LicenseType.PERPETUAL, 4),
        (LicenseType.SUBSCRIPTION, 6),
        (LicenseType.ENTERPRISE, 9),
    ],
)
def test_default_features_per_license_type(generator, license_type, expected_count):
    license_obj = generator.generate_license(license_type=license_type, issued_to="Acme")
    assert len(license_obj.features) == expected_count
    assert "ip_discovery" in license_obj.features
    assert "subnet_management" in license_obj.features


@pytest.mark.parametrize(
    "license_type,max_users",
    [
        (LicenseType.TRIAL, 5),
        (LicenseType.PERPETUAL, 20),
        (LicenseType.SUBSCRIPTION, 50),
        (LicenseType.ENTERPRISE, 1000),
    ],
)
def test_default_usage_limits_per_license_type(generator, license_type, max_users):
    license_obj = generator.generate_license(license_type=license_type, issued_to="Acme")
    assert license_obj.usage_limits["max_users"] == max_users


def test_custom_features_and_limits_override_defaults(generator):
    license_obj = generator.generate_license(
        license_type=LicenseType.TRIAL,
        issued_to="Acme",
        features=["ip_discovery"],
        usage_limits={"max_users": 3},
    )
    assert license_obj.features == ["ip_discovery"]
    assert license_obj.usage_limits == {"max_users": 3}


def test_feature_access(validator, generator):
    license_obj = generator.generate_license(
        license_type=LicenseType.ENTERPRISE, issued_to="Acme"
    )
    assert validator.check_feature_access(license_obj, "ldap_integration") is True
    assert validator.check_feature_access(license_obj, "quantum_reporting") is False


def test_usage_limit_checks(validator, generator):
    license_obj = generator.generate_license(
        license_type=LicenseType.TRIAL, issued_to="Acme"
    )
    assert validator.check_usage_limit(license_obj, "max_users", 5) is True
    assert validator.check_usage_limit(license_obj, "max_users", 6) is False
    # unbounded dimension: no limit recorded means no restriction
    assert validator.check_usage_limit(license_obj, "max_sites", 9999) is True


@pytest.mark.parametrize(
    "key,expected",
    [
        ("0F7330E6-A47C-47AD-B420-1D774709960F", True),
        ("0f7330e6-a47c-47ad-b420-1d774709960f", True),
        ("not-a-key", False),
        ("0F7330E6A47C47ADB4201D774709960F", False),
        ("", False),
    ],
)
def test_license_key_format(validator, key, expected):
    assert validator.validate_license_key_format(key) is expected


def test_license_info_display(validator, generator):
    license_obj = _trial(generator, trial_days=14)
    info = validator.get_license_info(license_obj)

    assert info["type"] == "trial"
    assert info["status"] == "VALID"
    assert info["expires_on"] == (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
    assert info["days_until_expiry"] == 14
    assert info["issued_to"] == "Acme Ltd"


# ---------------------------------------------------------------------------
# CLI / helper functions
# ---------------------------------------------------------------------------
def test_validate_license_helper_prints_result(generator, public_key_path, tmp_path, capsys):
    path = _signed_file(generator, _trial(generator), tmp_path)
    validate_license(path, public_key_path=public_key_path)

    output = capsys.readouterr().out
    assert "License validation result: valid" in output
    assert "issued_to: Acme Ltd" in output


def test_validate_license_helper_reports_missing_file(public_key_path, tmp_path, capsys):
    validate_license(str(tmp_path / "absent.json"), public_key_path=public_key_path)

    output = capsys.readouterr().out
    assert "License validation result: malformed" in output
    assert "Invalid license file." in output


def test_cli_main_prints_validation(generator, public_key_path, tmp_path, monkeypatch, capsys):
    import license_validator

    path = _signed_file(generator, _trial(generator), tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        ["license_validator.py", path, "--public-key", public_key_path],
    )
    assert license_validator.main() is None

    assert "License validation result: valid" in capsys.readouterr().out


def test_cli_main_rejects_missing_arguments(monkeypatch):
    import license_validator

    monkeypatch.setattr("sys.argv", ["license_validator.py"])
    with pytest.raises(SystemExit):
        license_validator.main()


def test_generated_keys_and_files_stay_outside_the_cwd(tmp_path, monkeypatch):
    """Explicit paths keep key/license files out of whatever the CWD is."""
    monkeypatch.chdir(tmp_path)

    generator = LicenseGenerator(private_key_path=str(tmp_path / "signing.pem"))
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(generator.get_public_key_pem())
    license_path = _signed_file(generator, _trial(generator), tmp_path)

    assert os.path.exists(license_path)
    assert not (tmp_path / "license_private_key.pem").exists()  # CWD untouched
    assert not (tmp_path / "license_public_key.pem").exists()

    status, _ = LicenseValidator(
        public_key_path=str(public_path)
    ).validate_license_file(license_path)
    assert status is LicenseStatus.VALID


def test_demo_script_never_touches_cwd_keys(tmp_path, monkeypatch, capsys):
    """Regression guard: the demo must not delete keys from the CWD."""
    import test_licensing

    monkeypatch.chdir(tmp_path)
    private = tmp_path / "license_private_key.pem"
    public = tmp_path / "license_public_key.pem"
    private.write_text("production private key")
    public.write_text("production public key")

    test_licensing.test_license_generation_and_validation()
    capsys.readouterr()  # swallow the demo output

    assert private.read_text() == "production private key"
    assert public.read_text() == "production public key"
    assert not list(tmp_path.glob("license_*.json"))
