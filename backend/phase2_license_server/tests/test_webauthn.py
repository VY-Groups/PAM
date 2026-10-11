"""Phase 7 - WebAuthn / FIDO2 (Addendum C): real ceremony verification in
product - a strict CBOR decoder, the authData layout, clientData checks and
true ES256 signature verification through `cryptography`.

The tests build byte-exact artifacts with a tiny CBOR *encoder* whose
output is round-tripped through the product's own decoder first, then run
`none` and packed self-attestation registration, assertion with the
signature-counter clone rule, the identical decoy answer for unknown or
inactive usernames, and the last-factor fail-closed credential deletion.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from extensions import db  # noqa: E402
from models import AuthEvent, WebauthnChallenge  # noqa: E402
import identity  # noqa: E402
import service  # noqa: E402
import webauthn  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
GOOD_PASSWORD = "purple-mountain-passphrase"
RP_ID = "pam.test"
ORIGIN = "https://pam.test"
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


# ---------------------------------------------------------------------------
# the in-test authenticator: a tiny CBOR encoder + byte-exact artifacts
# ---------------------------------------------------------------------------
def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    raise ValueError("test cbor encoder limit")


def cbor_encode(value) -> bytes:
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        out = _cbor_head(5, len(value))
        for key, item in value.items():
            out += cbor_encode(key) + cbor_encode(item)
        return out
    raise TypeError(f"test cbor encoder cannot encode {type(value)}")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def rp_hash(rp_id: str = RP_ID) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def client_data_raw(challenge_b64: str, *, ctype: str, origin: str = ORIGIN) -> bytes:
    return json.dumps(
        {"type": ctype, "challenge": challenge_b64, "origin": origin},
        separators=(",", ":"),
    ).encode("utf-8")


def cose_key(private_key: ec.EllipticCurvePrivateKey) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        1: 2,  # kty EC2
        3: -7,  # alg ES256
        -1: 1,  # crv P-256
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def registration_payload(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    challenge_b64: str,
    credential_id: bytes,
    sign_count: int = 1,
    fmt: str = "none",
    rp_id: str = RP_ID,
    origin: str = ORIGIN,
    attestation_sig: bytes | None = None,
):
    auth_data = (
        rp_hash(rp_id)
        + bytes([FLAG_UP | FLAG_UV | FLAG_AT])
        + struct.pack(">I", sign_count)
        + b"\x00" * 16  # aaguid
        + struct.pack(">H", len(credential_id))
        + credential_id
        + cbor_encode(cose_key(private_key))
    )
    client_raw = client_data_raw(challenge_b64, ctype="webauthn.create", origin=origin)
    att_stmt = {}
    if fmt == "packed":
        att_stmt = {
            "alg": -7,
            "sig": attestation_sig
            if attestation_sig is not None
            else private_key.sign(
                auth_data + hashlib.sha256(client_raw).digest(), ec.ECDSA(hashes.SHA256())
            ),
        }
    attestation = cbor_encode(
        {"fmt": fmt, "attStmt": att_stmt, "authData": auth_data}
    )
    return {
        "client_data_json": b64u(client_raw),
        "attestation_object": b64u(attestation),
    }


def assertion_payload(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    challenge_b64: str,
    credential_id_raw: bytes,
    sign_count: int,
    rp_id: str = RP_ID,
    origin: str = ORIGIN,
    client_type: str = "webauthn.get",
    sign_key: ec.EllipticCurvePrivateKey | None = None,
):
    auth_data = rp_hash(rp_id) + bytes([FLAG_UP | FLAG_UV]) + struct.pack(">I", sign_count)
    client_raw = client_data_raw(challenge_b64, ctype=client_type, origin=origin)
    key = sign_key or private_key
    signature = key.sign(
        auth_data + hashlib.sha256(client_raw).digest(), ec.ECDSA(hashes.SHA256())
    )
    return {
        "credential_id": b64u(credential_id_raw),
        "client_data_json": b64u(client_raw),
        "authenticator_data": b64u(auth_data),
        "signature": b64u(signature),
    }


# ---------------------------------------------------------------------------
# fixtures + helpers
# ---------------------------------------------------------------------------
def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=f"sqlite:///{(tmp_path / 'licenses.db').as_posix()}",
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-webauthn-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-webauthn",
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


def create_user(client, username="alice", password=GOOD_PASSWORD, **fields):
    response = client.post(
        "/api/v1/users",
        json={"username": username, "password": password, **fields},
        headers=ADMIN,
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()


def login(client, username, password, **extra):
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, **extra},
    )


def configure_webauthn(client):
    response = client.put(
        "/api/v1/settings/webauthn",
        json={"rp_id": RP_ID, "rp_name": "VY-PAM Test", "allowed_origins": ORIGIN},
        headers=ADMIN,
    )
    assert response.status_code == 200, response.get_json()


def signed_in_session(client, app, username="alice"):
    """A live console session (MFA off) - returns the mint body; the client
    holds the cookie, so mutations need its CSRF token."""
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200
    minted = login(client, username, GOOD_PASSWORD)
    assert minted.status_code == 200, minted.get_json()
    return minted.get_json()


def register_key(client, app, *, username="alice", fmt="none", sign_count=1,
                 credential_id=None, challenge_overrides=None, **payload_kwargs):
    """Full registration against the live routes: options -> payload ->
    201. Returns (private_key, credential_id_raw, credential_dict)."""
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": username, "purpose": "register"},
    )
    assert options.status_code == 202, options.get_json()
    options = options.get_json()

    private_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = credential_id or (b"cred-" + hashlib.sha256(
        str(id(private_key)).encode()
    ).digest()[:16])
    payload = registration_payload(
        private_key,
        challenge_b64=options["challenge"],
        credential_id=credential_id,
        sign_count=sign_count,
        fmt=fmt,
        **payload_kwargs,
    )
    if challenge_overrides:
        payload.update(challenge_overrides)
    minted = signed_in_session(client, app, username=username)
    registered = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert registered.status_code == 201, registered.get_json()
    return private_key, credential_id, registered.get_json()["credential"], minted


def authn_challenge(app, username="alice"):
    response = app.test_client().post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": username, "purpose": "authenticate"},
    )
    assert response.status_code == 202, response.get_json()
    return response.get_json()


def action_count(app, action, subject=""):
    with app.app_context():
        query = AuthEvent.query.filter(AuthEvent.action == action)
        if subject:
            query = query.filter(AuthEvent.subject == subject)
        return query.count()


# ---------------------------------------------------------------------------
# the decoder understands the encoder (byte-level trust)
# ---------------------------------------------------------------------------


def test_cbor_encoder_round_trips_through_the_products_decoder(client, app):
    sample = {
        "fmt": "none",
        "attStmt": {"alg": -7, "sig": b"\x01\x02\x03"},
        "authData": b"\x00" * 40,
        1: 2,
        -3: b"x" * 32,
    }
    with app.app_context():
        assert webauthn.cbor_decode(cbor_encode(sample)) == sample


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


def test_register_none_attestation_stores_the_key_and_enables_the_factor(client, app):
    create_user(client)
    configure_webauthn(client)
    _key, credential_id, credential, _mint = register_key(client, app)

    assert credential["credential_id"] == b64u(credential_id)
    assert credential["name"] == "Security key"
    assert credential["sign_count"] == 1
    assert "public_key_b64" not in credential

    listed = client.get("/api/v1/auth/mfa/webauthn/credentials").get_json()[
        "credentials"
    ]
    assert [row["credential_id"] for row in listed] == [b64u(credential_id)]
    for row in listed:
        assert "public_key_b64" not in row

    factors = client.get("/api/v1/auth/mfa/factors").get_json()["factors"]
    assert [row["kind"] for row in factors] == ["webauthn"]
    assert action_count(app, "auth.mfa.enrolled", subject="alice") == 1


def test_register_packed_self_attestation_is_verified(client, app):
    create_user(client)
    configure_webauthn(client)
    _key, credential_id, credential, _mint = register_key(client, app, fmt="packed")
    assert credential["credential_id"] == b64u(credential_id)


def test_packed_attestation_with_a_foreign_signature_is_refused(client, app):
    create_user(client)
    configure_webauthn(client)
    attacker = ec.generate_private_key(ec.SECP256R1())

    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    key = ec.generate_private_key(ec.SECP256R1())
    payload = registration_payload(
        key,
        challenge_b64=options["challenge"],
        credential_id=b"cred-packed-attack",
        fmt="packed",
        attestation_sig=attacker.sign(
            b"whatever the authenticator meant to sign", ec.ECDSA(hashes.SHA256())
        ),
    )
    minted = signed_in_session(client, app)
    refused = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert refused.status_code == 400
    assert "packed attestation signature invalid" in refused.get_json()["error"]


def test_unsupported_attestation_format_is_refused_honestly(client, app):
    create_user(client)
    configure_webauthn(client)
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    key = ec.generate_private_key(ec.SECP256R1())
    payload = registration_payload(
        key,
        challenge_b64=options["challenge"],
        credential_id=b"cred-u2f",
        fmt="fido-u2f",
    )
    minted = signed_in_session(client, app)
    refused = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert refused.status_code == 400
    body = refused.get_json()
    assert "Unsupported attestation format" in body["error"]
    assert body["details"]["supported"] == ["none", "packed"]


def test_registration_refuses_when_webauthn_is_not_configured(client, app):
    create_user(client)
    # options still answers (the challenge mints from the stored settings),
    # but the register step refuses honestly while unconfigured
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    key = ec.generate_private_key(ec.SECP256R1())
    payload = registration_payload(
        key, challenge_b64=options["challenge"], credential_id=b"cred-nc"
    )
    minted = signed_in_session(client, app)
    refused = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert refused.status_code == 403
    assert refused.get_json()["details"]["configured"] is False


def test_wrong_rp_id_hash_is_refused(client, app):
    create_user(client)
    configure_webauthn(client)
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    key = ec.generate_private_key(ec.SECP256R1())
    payload = registration_payload(
        key,
        challenge_b64=options["challenge"],
        credential_id=b"cred-rp",
        rp_id="evil.test",  # the hash covers a different RP
    )
    minted = signed_in_session(client, app)
    refused = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert refused.status_code == 400
    assert "rpIdHash" in refused.get_json()["error"]


def test_foreign_origin_is_refused(client, app):
    create_user(client)
    configure_webauthn(client)
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    key = ec.generate_private_key(ec.SECP256R1())
    payload = registration_payload(
        key,
        challenge_b64=options["challenge"],
        credential_id=b"cred-origin",
        origin="https://evil.test",
    )
    minted = signed_in_session(client, app)
    refused = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert refused.status_code == 400
    body = refused.get_json()
    assert "is not an allowed origin" in body["error"]
    assert body["details"]["allowed"] == [ORIGIN]


def test_registration_challenge_is_single_use(client, app):
    create_user(client)
    configure_webauthn(client)
    key = ec.generate_private_key(ec.SECP256R1())
    csrf_client = app.test_client()
    options = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "register"},
    ).get_json()
    payload = registration_payload(
        key, challenge_b64=options["challenge"], credential_id=b"cred-replay"
    )
    minted = signed_in_session(client, app)
    first = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert first.status_code == 201
    replay = client.post(
        "/api/v1/auth/mfa/enroll/webauthn",
        json={"challenge_id": options["challenge_id"], **payload},
        headers={"X-CSRF-Token": minted["csrf_token"]},
    )
    assert replay.status_code == 403
    assert "challenge invalid or expired" in replay.get_json()["error"]


# ---------------------------------------------------------------------------
# assertion: signature, counter, clone rule
# ---------------------------------------------------------------------------


def test_assertion_verifies_and_enforces_the_counter(client, app):
    create_user(client)
    configure_webauthn(client)
    key, credential_id, _credential, _mint = register_key(client, app)

    # a rising counter is stored
    challenge = authn_challenge(app)
    ok = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=credential_id,
                    sign_count=5,
                ),
            }
        },
        headers={"X-CSRF-Token": _mint["csrf_token"]},
    )
    assert ok.status_code == 200, ok.get_json()
    assert ok.get_json() == {"status": "verified", "method": "webauthn"}

    # a non-zero rollback means a cloned authenticator: refused + alerted
    challenge = authn_challenge(app)
    clone = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=credential_id,
                    sign_count=3,
                ),
            }
        },
        headers={"X-CSRF-Token": _mint["csrf_token"]},
    )
    assert clone.status_code == 403
    assert "rolled back" in clone.get_json()["error"]
    assert action_count(app, "auth.webauthn.clone-detected", subject="alice") == 1

    # a zero counter is a key that does not count: allowed (spec)
    challenge = authn_challenge(app)
    zero = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=credential_id,
                    sign_count=0,
                ),
            }
        },
        headers={"X-CSRF-Token": _mint["csrf_token"]},
    )
    assert zero.status_code == 200, zero.get_json()


def test_assertion_with_a_foreign_key_is_refused_and_alerted(client, app):
    create_user(client)
    configure_webauthn(client)
    key, credential_id, _credential, mint = register_key(client, app)
    attacker = ec.generate_private_key(ec.SECP256R1())

    challenge = authn_challenge(app)
    refused = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    attacker,  # signed by a key the server never stored
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=credential_id,
                    sign_count=9,
                    sign_key=attacker,
                ),
            }
        },
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert refused.status_code == 400
    assert "signature invalid" in refused.get_json()["error"]
    assert action_count(app, "auth.mfa.failed", subject="alice") == 1

    # an unknown credential id is an honest 404, not a probe surface
    challenge = authn_challenge(app)
    unknown = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=b"never-registered",
                    sign_count=1,
                ),
            }
        },
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert unknown.status_code == 404


def test_login_completes_with_an_inline_webauthn_assertion(client, app):
    create_user(client)
    configure_webauthn(client)
    key, credential_id, _credential, _mint = register_key(client, app)

    # MFA back on: the login asks for the registered factor
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": True}, headers=ADMIN
    ).status_code == 200
    probe = app.test_client()
    challenged = login(probe, "alice", GOOD_PASSWORD)
    assert challenged.status_code == 403
    assert challenged.get_json()["methods"] == ["webauthn"]

    challenge = authn_challenge(app)
    minted = login(
        probe,
        "alice",
        GOOD_PASSWORD,
        login_challenge=challenged.get_json()["challenge"],
        webauthn={
            "challenge_id": challenge["challenge_id"],
            **assertion_payload(
                key,
                challenge_b64=challenge["challenge"],
                credential_id_raw=credential_id,
                sign_count=7,
            ),
        },
    )
    assert minted.status_code == 200, minted.get_json()
    assert minted.get_json()["mfa_methods"] == ["webauthn"]


# ---------------------------------------------------------------------------
# options: no enumeration, honest refusals
# ---------------------------------------------------------------------------


def test_options_answers_identically_for_unknown_and_inactive_users(client, app):
    create_user(client)
    configure_webauthn(client)
    mint = signed_in_session(client, app)
    csrf_client = app.test_client()

    real = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "authenticate"},
    ).get_json()
    unknown = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "ghost-user", "purpose": "authenticate"},
    ).get_json()
    created = create_user(client, "carol", email="carol@example.test")
    client.patch(
        f"/api/v1/users/{created['user']['id']}", json={"active": False}, headers=ADMIN
    )
    inactive = csrf_client.post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "carol", "purpose": "authenticate"},
    ).get_json()

    assert set(real) == set(unknown) == set(inactive)
    with app.app_context():
        backed = {
            row.id for row in WebauthnChallenge.query.with_entities(WebauthnChallenge.id)
        }
    assert real["challenge_id"] in backed
    assert unknown["challenge_id"] not in backed
    assert inactive["challenge_id"] not in backed
    assert real["rp_id"] == unknown["rp_id"] == RP_ID
    assert real["origins"] == [ORIGIN]

    # an assertion against the decoy challenge dies at the lookup
    key = ec.generate_private_key(ec.SECP256R1())
    refused = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": unknown["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=unknown["challenge"],
                    credential_id_raw=b"decoy-probe",
                    sign_count=1,
                ),
            }
        },
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert refused.status_code == 403
    assert "challenge invalid or expired" in refused.get_json()["error"]


def test_options_requires_a_username_or_a_session(client, app):
    anonymous = app.test_client().post(
        "/api/v1/auth/mfa/webauthn/options", json={"purpose": "authenticate"}
    )
    assert anonymous.status_code == 401
    assert anonymous.get_json()["error"] == "Sign in or present a username"

    create_user(client)
    bad_purpose = app.test_client().post(
        "/api/v1/auth/mfa/webauthn/options",
        json={"username": "alice", "purpose": "sideways"},
    )
    assert bad_purpose.status_code == 400


# ---------------------------------------------------------------------------
# credential management
# ---------------------------------------------------------------------------


def test_deleting_the_last_credential_is_fail_closed_while_mfa_required(client, app):
    create_user(client)
    configure_webauthn(client)
    _key, _credential_id, credential, mint = register_key(client, app)
    # register_key signs in with MFA off; the fail-closed rule needs it on
    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": True}, headers=ADMIN
    ).status_code == 200
    csrf = {"X-CSRF-Token": mint["csrf_token"]}

    refused = client.delete(
        f"/api/v1/auth/mfa/webauthn/credentials/{credential['id']}", headers=csrf
    )
    assert refused.status_code == 403
    assert refused.get_json()["details"]["mfa_required"] is True

    assert client.put(
        "/api/v1/settings/auth", json={"mfa_required": False}, headers=ADMIN
    ).status_code == 200
    removed = client.delete(
        f"/api/v1/auth/mfa/webauthn/credentials/{credential['id']}", headers=csrf
    )
    assert removed.status_code == 200
    assert removed.get_json()["credential"] == {
        "deleted": True,
        "credential_id": credential["id"],
    }
    assert client.get("/api/v1/auth/mfa/webauthn/credentials").get_json()[
        "credentials"
    ] == []
    factors = client.get("/api/v1/auth/mfa/factors").get_json()["factors"]
    assert factors == []  # the webauthn factor row went with its last key
    assert action_count(app, "auth.mfa.credential-deleted", subject="alice") == 1


def test_deleting_an_unknown_credential_is_404(client, app):
    create_user(client)
    configure_webauthn(client)
    _key, _credential_id, _credential, mint = register_key(client, app)
    refused = client.delete(
        "/api/v1/auth/mfa/webauthn/credentials/9999",
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert refused.status_code == 404


def test_expired_ceremony_challenge_is_refused(client, app):
    create_user(client)
    configure_webauthn(client)
    key, credential_id, _credential, mint = register_key(client, app)
    challenge = authn_challenge(app)
    with app.app_context():
        row = db.session.get(WebauthnChallenge, challenge["challenge_id"])
        row.expires_at = datetime.now() - timedelta(seconds=1)
        db.session.commit()
    refused = client.post(
        "/api/v1/auth/mfa/webauthn/assert",
        json={
            "webauthn": {
                "challenge_id": challenge["challenge_id"],
                **assertion_payload(
                    key,
                    challenge_b64=challenge["challenge"],
                    credential_id_raw=credential_id,
                    sign_count=2,
                ),
            }
        },
        headers={"X-CSRF-Token": mint["csrf_token"]},
    )
    assert refused.status_code == 403
    assert "challenge invalid or expired" in refused.get_json()["error"]
