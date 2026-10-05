"""
Pytest suite for the enterprise licensing spec additions:

- Ed25519 signing alongside RSA-PSS-SHA256
- compact JWS/JWT tokens (the ``.lic`` / ``.jwt`` air-gap ingestion path)
- tier / plan / classification / license-id defaults
- node quota pools with enforcement levels
- entitlement module catalog

Everything runs inside pytest's tmp_path; the repository key pair is never
touched.  Run:  python -m pytest backend/ipam_licensing -q
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from license import (
    DEFAULT_CLASSIFICATIONS,
    DEFAULT_ISSUER,
    DEFAULT_MODULE_IDS,
    DEFAULT_PLANS,
    DEFAULT_TIERS,
    ENFORCEMENT_LEVELS,
    MODULE_CATALOG,
    MODULE_IDS,
    License,
    LicenseType,
    default_modules,
    default_quotas,
    optional_fields,
)
from license_tool import LicenseGenerator
from license_validator import LicenseValidator
import signature as sig


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


def _license(generator: LicenseGenerator, license_type=LicenseType.TRIAL) -> License:
    return generator.generate_license(
        license_type=license_type, issued_to="Acme Ltd"
    )


def _save(generator, license_obj, path, **kwargs) -> str:
    generator.save_license_file(license_obj, str(path), **kwargs)
    return str(path)


# ---------------------------------------------------------------------------
# Ed25519 key material
# ---------------------------------------------------------------------------
def test_ed25519_key_pair_created_beside_rsa_key(generator, tmp_path):
    generator.private_key_for(sig.ALGORITHM_ED25519)

    assert (tmp_path / "license_ed25519_private.pem").exists()
    public = tmp_path / "license_ed25519_public.pem"
    assert public.exists()
    # Validator's default path must find exactly this file.
    assert (
        LicenseValidator(public_key_path=str(tmp_path / "license_public_key.pem"))
        .ed25519_public_key_path
        == str(public)
    )


def test_ed25519_key_is_reused_not_regenerated(generator):
    first = generator.private_key_for(sig.ALGORITHM_ED25519)
    second = generator.private_key_for(sig.ALGORITHM_ED25519)
    assert first is second


def test_unsupported_algorithm_raises(generator):
    with pytest.raises(sig.UnsupportedAlgorithm):
        generator.private_key_for("DSA-SOMETHING")


# ---------------------------------------------------------------------------
# algorithm round trips (json envelope)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("algorithm", list(sig.SUPPORTED_ALGORITHMS))
def test_json_envelope_round_trip(generator, validator, tmp_path, algorithm):
    license_obj = _license(generator)
    path = _save(
        generator, license_obj, tmp_path / "lic.json", algorithm=algorithm
    )

    status, restored = validator.validate_license_file(path)
    assert status == LicenseStatus_from("valid")
    assert restored.license_key == license_obj.license_key


@pytest.mark.parametrize("algorithm", list(sig.SUPPORTED_ALGORITHMS))
def test_json_envelope_tamper_fails(generator, validator, tmp_path, algorithm):
    license_obj = _license(generator)
    path = _save(generator, license_obj, tmp_path / "lic.json", algorithm=algorithm)

    document = json.loads(Path(path).read_text())
    document["license_data"]["issued_to"] = "Someone Else"
    Path(path).write_text(json.dumps(document))

    status, restored = validator.validate_license_file(path)
    assert status == LicenseStatus_from("signature_invalid")
    assert restored is None


# ---------------------------------------------------------------------------
# compact JWS / JWT tokens (.lic / .jwt)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("algorithm", list(sig.SUPPORTED_ALGORITHMS))
@pytest.mark.parametrize("file_format", ["lic", "jwt"])
def test_token_round_trip(generator, validator, tmp_path, algorithm, file_format):
    license_obj = _license(generator, LicenseType.ENTERPRISE)
    path = _save(
        generator,
        license_obj,
        tmp_path / f"license_{license_obj.license_key}.{file_format}",
        algorithm=algorithm,
        file_format=sig.FORMAT_JWT,
    )

    raw = Path(path).read_text().strip()
    assert not raw.startswith("{")
    assert len(raw.split(".")) == 3

    status, restored = validator.validate_license_file(path)
    assert status == LicenseStatus_from("valid")
    assert restored.license_type == LicenseType.ENTERPRISE
    assert restored.license_id == license_obj.license_id


def test_token_claims_tamper_fails(generator, validator, tmp_path):
    license_obj = _license(generator)
    path = _save(
        generator, license_obj, tmp_path / "license.lic", file_format=sig.FORMAT_JWT
    )

    header_segment, payload_segment, signature_segment = Path(path).read_text().split(".")
    claims = json.loads(sig.b64url_decode(payload_segment))
    claims["issued_to"] = "Impostor Inc"
    forged = ".".join(
        [
            header_segment,
            sig.b64url_encode(sig.canonical_json(claims)),
            signature_segment,
        ]
    )
    Path(path).write_text(forged)

    status, restored = validator.validate_license_file(path)
    assert status == LicenseStatus_from("signature_invalid")
    assert restored is None


def test_algorithm_label_mismatch_fails_verification(generator, validator, tmp_path):
    """An RSA signature relabelled as Ed25519 must not verify."""
    license_obj = _license(generator)
    envelope = generator.build_license_file(license_obj, sig.ALGORITHM_RSA)
    envelope["algorithm"] = sig.ALGORITHM_ED25519

    assert validator.verify_envelope(envelope) is False
    assert validator.verify_envelope(
        generator.build_license_file(license_obj, sig.ALGORITHM_RSA)
    )


def test_token_without_ed25519_public_key_cannot_verify(generator, validator, tmp_path):
    """Missing Ed25519 public key => unverifiable, reported as signature_invalid."""
    license_obj = _license(generator)
    path = _save(
        generator,
        license_obj,
        tmp_path / "license.lic",
        algorithm=sig.ALGORITHM_ED25519,
        file_format=sig.FORMAT_JWT,
    )
    (tmp_path / "license_ed25519_public.pem").unlink(missing_ok=True)

    fresh = LicenseValidator(public_key_path=str(tmp_path / "license_public_key.pem"))
    assert fresh.public_key_for(sig.ALGORITHM_ED25519) is None
    status, _ = fresh.validate_license_file(path)
    assert status == LicenseStatus_from("signature_invalid")


# ---------------------------------------------------------------------------
# envelope parsing helpers
# ---------------------------------------------------------------------------
def test_parse_envelope_accepts_wrappers_and_plain_token(generator, tmp_path):
    license_obj = _license(generator)
    path = _save(
        generator, license_obj, tmp_path / "license.lic", file_format=sig.FORMAT_JWT
    )
    token = Path(path).read_text().strip()

    assert sig.parse_envelope(token)["license_data"]["license_key"] == license_obj.license_key
    assert sig.parse_envelope({"token": token})["format"] == sig.FORMAT_JWT
    assert sig.parse_envelope({"license": token})["format"] == sig.FORMAT_JWT
    assert sig.parse_envelope({"license": json.loads(Path(_save(
        generator, license_obj, tmp_path / "x.json")).read_text())})["format"] == sig.FORMAT_JSON

    for junk in ("", "not-a-token", {"random": 1}, None, 42, '{"license_data": '):
        assert sig.parse_envelope(junk) is None


def test_json_envelope_defaults_are_back_compatible(generator, validator):
    """Old envelopes without 'format'/'algorithm' still parse as JSON."""
    license_obj = _license(generator)
    legacy = {
        "license_data": license_obj.to_dict(),
        "signature": generator.sign_license(license_obj.to_dict()),
        "algorithm": "RSA-PSS-SHA256",
        "version": "1.0",
    }
    envelope = sig.parse_envelope(legacy)
    assert envelope["format"] == sig.FORMAT_JSON
    assert validator.verify_envelope(envelope)


def test_canonical_json_is_order_independent():
    first = sig.canonical_json({"b": 1, "a": {"d": 2, "c": 3}})
    second = sig.canonical_json({"a": {"c": 3, "d": 2}, "b": 1})
    assert first == second


# ---------------------------------------------------------------------------
# tier / plan / license id / fingerprint
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("license_type", list(LicenseType))
def test_commercial_spec_defaults_per_type(generator, license_type):
    license_obj = generator.generate_license(
        license_type=license_type, issued_to="Acme Ltd"
    )

    assert license_obj.tier == DEFAULT_TIERS[license_type]
    assert license_obj.plan == DEFAULT_PLANS[license_type]
    assert license_obj.classification == DEFAULT_CLASSIFICATIONS[license_type]
    assert license_obj.issuer == DEFAULT_ISSUER
    assert license_obj.subject_entity == "Acme Ltd"

    import re
    assert re.fullmatch(r"LIC-\d{4}-AEGIS-SEC-[A-Z0-9-]+", license_obj.license_id)
    assert license_obj.enclave_binding is None  # never claimed unless supplied


@pytest.mark.parametrize("license_type", list(LicenseType))
def test_quotas_and_modules_default_per_type(generator, license_type):
    license_obj = generator.generate_license(
        license_type=license_type, issued_to="Acme Ltd"
    )

    quotas = license_obj.quotas
    assert [pool["id"] for pool in quotas["pools"]] == [
        "aws-prod", "k8s-core", "baremetal", "staging"
    ]
    assert quotas["nodes"] == sum(pool["quota_nodes"] for pool in quotas["pools"])
    for pool in quotas["pools"]:
        assert pool["enforcement"] in ENFORCEMENT_LEVELS
        assert pool["quota_nodes"] > 0
    for scalar in ("concurrent_sessions", "bastion_tunnels", "max_lease_hours",
                   "worm_retention_days"):
        assert quotas[scalar] > 0

    module_ids = [module["id"] for module in license_obj.modules]
    # Granted set matches the tier, rendered in catalog (display) order.
    granted = set(DEFAULT_MODULE_IDS[license_type])
    assert set(module_ids) == granted
    assert module_ids == [m["id"] for m in MODULE_CATALOG if m["id"] in granted]
    assert all(module["status"] == "entitled" for module in license_obj.modules)
    assert all(module["id"] in MODULE_IDS for module in license_obj.modules)


def test_enterprise_matches_the_spec_numbers(generator):
    """The enterprise tier reproduces the numbers on the design screen."""
    license_obj = generator.generate_license(
        license_type=LicenseType.ENTERPRISE,
        issued_to="Aegis Global Financial Technologies Inc.",
    )

    quotas = license_obj.quotas
    assert quotas["nodes"] == 5000
    assert quotas["concurrent_sessions"] == 40
    assert quotas["bastion_tunnels"] == 1000
    assert quotas["max_lease_hours"] == 4
    assert quotas["worm_retention_days"] == 2555
    assert [pool["quota_nodes"] for pool in quotas["pools"]] == [2000, 1500, 800, 700]
    assert [pool["enforcement"] for pool in quotas["pools"]] == [
        "soft-warning", "auto-scale", "audit-log", "hard-block",
    ]
    assert len(license_obj.modules) == len(MODULE_CATALOG) == 8


def test_spec_overrides_flow_into_signed_claims(generator):
    license_obj = generator.generate_license(
        license_type=LicenseType.ENTERPRISE,
        issued_to="Acme Ltd",
        tier="CUSTOM TIER",
        plan="Two-Year Multi-Cloud",
        license_id="LIC-9942-AEGIS-SEC-PROD",
        subject_entity="Acme Holdings LLC",
        classification="Air-Gapped Production Enterprise (Multi-Region)",
        enclave_binding="TPM 2.0 PCR Registers 0 & 7",
        account={
            "customer_id": "CUST-88219-ENT",
            "tam": "Sarah Jenkins",
            "sla_response": "15-Minute Priority",
        },
        quotas={**default_quotas(LicenseType.ENTERPRISE), "nodes": 1234},
        modules=[m for m in default_modules(LicenseType.ENTERPRISE)
                 if m["id"] != "shamir_breakglass"],
    )

    data = license_obj.to_dict()
    assert data["tier"] == "CUSTOM TIER"
    assert data["license_id"] == "LIC-9942-AEGIS-SEC-PROD"
    assert data["enclave_binding"] == "TPM 2.0 PCR Registers 0 & 7"
    assert data["quotas"]["nodes"] == 1234
    assert "shamir_breakglass" not in [m["id"] for m in data["modules"]]
    assert data["account"]["customer_id"] == "CUST-88219-ENT"

    # and it survives the to_dict -> from_dict round trip byte for byte
    restored = License.from_dict(data)
    assert restored.to_dict() == data


def test_optional_fields_are_omitted_when_unset(generator):
    """Licenses signed before the spec existed rebuild without extra keys."""
    license_obj = generator.generate_license(
        license_type=LicenseType.TRIAL, issued_to="Acme Ltd"
    )
    license_obj.tier = None
    license_obj.plan = None
    license_obj.license_id = None
    license_obj.subject_entity = None
    license_obj.classification = None
    license_obj.issuer = None
    license_obj.quotas = {}
    license_obj.modules = []
    license_obj.account = {}

    data = license_obj.to_dict()
    for field in ("tier", "plan", "license_id", "subject_entity",
                  "classification", "issuer", "quotas", "modules", "account"):
        assert field not in data
    assert License.from_dict(data).to_dict() == data

    assert optional_fields(tier="X") == {"tier": "X"}
    assert optional_fields(quotas={}, modules=[], account={}) == {}


def test_fingerprint_is_sha256_of_the_signature(generator):
    for file_format in (sig.FORMAT_JSON, sig.FORMAT_JWT):
        envelope = generator.build_license_file(
            _license(generator), sig.DEFAULT_ALGORITHM, file_format
        )
        fingerprint = envelope["fingerprint"]
        assert fingerprint.startswith("sha256:")
        assert len(fingerprint) == len("sha256:") + 64


# ---------------------------------------------------------------------------
# access checks against the spec structures
# ---------------------------------------------------------------------------
def test_module_access_checks(generator, validator):
    license_obj = generator.generate_license(
        license_type=LicenseType.TRIAL, issued_to="Acme Ltd"
    )
    assert validator.check_module_access(license_obj, "zsp_dynamic_leases")
    assert not validator.check_module_access(license_obj, "shamir_breakglass")


def test_usage_limit_checks_fall_back_to_quotas(generator, validator):
    license_obj = generator.generate_license(
        license_type=LicenseType.ENTERPRISE, issued_to="Acme Ltd"
    )
    assert validator.check_usage_limit(license_obj, "nodes", 4999)
    assert not validator.check_usage_limit(license_obj, "nodes", 5001)
    assert validator.check_usage_limit(license_obj, "max_users", 1000)
    assert not validator.check_usage_limit(license_obj, "max_users", 1001)
    assert validator.check_usage_limit(license_obj, "unlimited_thing", 10 ** 9)


# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------
def test_cli_generates_ed25519_token(tmp_path, monkeypatch, capsys):
    import license_tool

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "license_tool.py",
            "--type", "enterprise",
            "--issued-to", "Acme Ltd",
            "--format", "jwt",
            "--algorithm", "Ed25519",
            "--tier", "CLI TIER",
        ],
    )
    assert license_tool.main() == 0

    tokens = list(tmp_path.glob("license_*.lic")) + list(tmp_path.glob("license_*.jwt"))
    # filename uses .jwt extension for the jwt format
    assert len(tokens) == 1
    assert len(tokens[0].read_text().strip().split(".")) == 3
    assert (tmp_path / "license_ed25519_public.pem").exists()

    from license import LicenseType  # noqa: F401  (kept local to avoid clutter)
    validator = LicenseValidator(
        public_key_path=str(tmp_path / "license_public_key.pem")
    )
    status, license_obj = validator.validate_license_file(str(tokens[0]))
    assert status == LicenseStatus_from("valid")
    assert license_obj.tier == "CLI TIER"


def test_cli_rejects_unknown_algorithm(tmp_path, monkeypatch, capsys):
    import license_tool

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        ["license_tool.py", "--type", "trial", "--issued-to", "Acme", "--algorithm", "DSA"],
    )
    with pytest.raises(SystemExit):
        license_tool.main()


# ---------------------------------------------------------------------------
# one signature, two serialisations
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("algorithm", list(sig.SUPPORTED_ALGORITHMS))
def test_re_served_license_verifies_in_the_other_wire_format(
    generator, validator, algorithm
):
    """
    The authority keeps a single signature (and fingerprint) per license but
    may re-serve the claims as either wire format without re-signing, so the
    verifier has to accept both signing inputs.
    """
    license_obj = _license(generator, LicenseType.ENTERPRISE)

    # issued as a compact token, re-served as a JSON envelope
    as_jwt = generator.build_license_file(
        license_obj, algorithm, file_format=sig.FORMAT_JWT
    )
    as_json = sig.rebuild_json_envelope(
        as_jwt["license_data"], as_jwt["signature"], algorithm
    )
    assert as_json["format"] == sig.FORMAT_JSON
    assert validator.verify_envelope(as_json) is True
    assert sig.fingerprint(base64.b64decode(as_json["signature"])) == as_jwt["fingerprint"]

    # issued as a JSON envelope, re-served as a compact token
    as_envelope = generator.build_license_file(
        license_obj, algorithm, file_format=sig.FORMAT_JSON
    )
    as_token = sig.rebuild_token(
        as_envelope["license_data"], as_envelope["signature"], algorithm
    )
    parsed = sig.parse_envelope(as_token)
    assert parsed is not None
    assert parsed["format"] == sig.FORMAT_JWT
    assert validator.verify_envelope(parsed) is True

    # neither serialisation forgives tampered claims
    forged = dict(as_json, license_data=dict(as_json["license_data"], issued_to="Impostor Inc"))
    assert validator.verify_envelope(forged) is False
    forged_token = sig.parse_envelope(
        sig.rebuild_token(
            dict(as_envelope["license_data"], issued_to="Impostor Inc"),
            as_envelope["signature"],
            algorithm,
        )
    )
    assert validator.verify_envelope(forged_token) is False


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def LicenseStatus_from(value: str):
    """Return the LicenseStatus member for a value (keeps assertions terse)."""
    from license import LicenseStatus
    return LicenseStatus(value)
