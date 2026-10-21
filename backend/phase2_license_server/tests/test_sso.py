"""Phase 6c - SSO enforcement (architecture Identity: SAML 2.0 + OIDC).

The verification path runs for real: the tests generate an RSA keypair,
mint a self-signed IdP certificate, serve SAML metadata from a monkey-
patched fetcher, sign genuine SAML Responses (enveloped signature,
exclusive c14n, SHA-256 digests) and POST them to the ACS - so the same
canonicalization, digest and signature code that must stand up to a real
IdP is exercised end to end, together with its refusals (tampering,
wrapping, replay, unsolicited responses, missing MFA assertions). OIDC
runs the same way against a discovery/JWKS/token stub (RS256 only).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from xml.dom import minidom

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri  # noqa: E402
from extensions import db  # noqa: E402
from models import SsoFlow, SsoSession, SsoSubject  # noqa: E402
import sso as sso_module  # noqa: E402
import service as service_module  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}

_DS = "http://www.w3.org/2000/09/xmldsig#"
_SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

IDP_ENTITY = "https://idp.example.test/saml"
SP_ENTITY = "urn:aegispam.internal:sp:primary"
ACS_URL = "http://localhost/api/v1/auth/sso/saml/primary/acs"


def _config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_public_key.pem",
        secret_key="test-sso-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
        node_name="pam-node-sso",
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
def _reset_metadata_cache():
    """The IdP metadata cache is process-global and keyed on URL - without a
    reset, one test's IdP certificate would answer the next test's fetches."""
    yield
    sso_module._METADATA_CACHE.clear()


# ---------------------------------------------------------------------------
# a real (test-double) IdP: keypair, certificate, metadata, signed responses
# ---------------------------------------------------------------------------
class TestIdP:
    def __init__(self, entity: str = IDP_ENTITY):
        self.entity = entity
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")]))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=30))
            .sign(self.key, hashes.SHA256())
        )
        der = self.cert.public_bytes(serialization.Encoding.DER)
        self.cert_b64 = base64.b64encode(der).decode("ascii")

    def metadata(self) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'entityID="{self.entity}">'
            '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{_DS}">'
            f"<ds:X509Data><ds:X509Certificate>{self.cert_b64}</ds:X509Certificate></ds:X509Data>"
            "</ds:KeyInfo></md:KeyDescriptor>"
            f'<md:SingleSignOnService Binding="{_POST_BINDING}" '
            f'Location="https://idp.example.test/sso"/>'
            "</md:IDPSSODescriptor></md:EntityDescriptor>"
        ).encode("utf-8")

    def _sign_assertion(
        self, assertion_xml: str, *, key=None, assertion_id: str = "assertion-1"
    ) -> str:
        """Enveloped signature over the assertion: digest = sha256 over the
        canonicalized assertion, signature over the canonicalized
        SignedInfo - the verifier computes the same bytes backwards."""
        private_key = key or self.key
        digest = hashlib.sha256(
            sso_module._c14n(minidom.parseString(assertion_xml.encode("utf-8")))
        ).hexdigest()
        inner = (
            f'<ds:CanonicalizationMethod Algorithm="{_EXC_C14N}"/>'
            f'<ds:SignatureMethod Algorithm="{_DS}rsa-sha256"/>'
            f'<ds:Reference URI="#{assertion_id}">'
            f"<ds:Transforms>"
            f'<ds:Transform Algorithm="{_ENVELOPED}"/>'
            f'<ds:Transform Algorithm="{_EXC_C14N}"/>'
            f"</ds:Transforms>"
            f'<ds:DigestMethod Algorithm="{_DS}sha256"/>'
            f"<ds:DigestValue>{digest}</ds:DigestValue>"
            "</ds:Reference>"
        )
        signed_info = f'<ds:SignedInfo xmlns:ds="{_DS}">{inner}</ds:SignedInfo>'
        signature = private_key.sign(
            sso_module._c14n(minidom.parseString(signed_info.encode("utf-8"))),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature_xml = (
            f'<ds:Signature xmlns:ds="{_DS}">'
            f"<ds:SignedInfo>{inner}</ds:SignedInfo>"
            f"<ds:SignatureValue>{base64.b64encode(signature).decode('ascii')}</ds:SignatureValue>"
            "</ds:Signature>"
        )
        return assertion_xml.replace("</saml:Assertion>", signature_xml + "</saml:Assertion>")

    def assertion(
        self,
        *,
        subject: str = "alice@example.test",
        mfa: bool = True,
        audience: str = SP_ENTITY,
        key=None,
        assertion_id: str = "assertion-1",
        not_on_or_after_minutes: int = 5,
    ) -> str:
        now = datetime.utcnow()
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        context = (
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Muthn"
            if mfa
            else "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
        )
        xml = (
            f'<saml:Assertion xmlns:saml="{_SAML_ASSERTION}" ID="{assertion_id}" '
            f'Version="2.0" IssueInstant="{now.strftime(fmt)}">'
            f"<saml:Issuer>{self.entity}</saml:Issuer>"
            "<saml:Subject>"
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{subject}</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData Recipient="{ACS_URL}"/>'
            "</saml:SubjectConfirmation></saml:Subject>"
            f'<saml:Conditions NotBefore="{(now - timedelta(seconds=60)).strftime(fmt)}" '
            f'NotOnOrAfter="{(now + timedelta(minutes=not_on_or_after_minutes)).strftime(fmt)}">'
            f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
            "</saml:AudienceRestriction></saml:Conditions>"
            f'<saml:AuthnStatement AuthnInstant="{now.strftime(fmt)}">'
            "<saml:AuthnContext>"
            f"<saml:AuthnContextClassRef>{context}</saml:AuthnContextClassRef>"
            "</saml:AuthnContext></saml:AuthnStatement>"
            "<saml:AttributeStatement>"
            '<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
            f"<saml:AttributeValue>{subject}</saml:AttributeValue></saml:Attribute>"
            "</saml:AttributeStatement>"
            "</saml:Assertion>"
        )
        return self._sign_assertion(xml, key=key, assertion_id=assertion_id)

    def response(
        self,
        *,
        in_response_to: str,
        assertion_xml: str = "",
        destination: str = ACS_URL,
        issuer: str = "",
        status_value: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
    ) -> str:
        assertion = assertion_xml or self.assertion()
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        return (
            f'<samlp:Response xmlns:samlp="{_SAML_PROTOCOL}" ID="response-1" Version="2.0" '
            f'IssueInstant="{now}" Destination="{destination}" InResponseTo="{in_response_to}">'
            f"<saml:Issuer xmlns:saml=\"{_SAML_ASSERTION}\">{issuer or self.entity}</saml:Issuer>"
            f"<samlp:Status><samlp:StatusCode Value=\"{status_value}\"/></samlp:Status>"
            f"{assertion}</samlp:Response>"
        )


@pytest.fixture
def idp(monkeypatch) -> TestIdP:
    identity_provider = TestIdP()

    def fake_get(url):
        if url == "https://idp.example.test/metadata":
            return 200, identity_provider.metadata()
        raise AssertionError(f"unexpected fetch {url}")

    monkeypatch.setattr(sso_module, "_http_get", fake_get)
    return identity_provider


def configure_saml(client, **overrides):
    payload = {
        "protocol": "saml2",
        "primary_provider": "okta",
        "primary_metadata_url": "https://idp.example.test/metadata",
        "require_mfa": True,
        "jit_provisioning": True,
    }
    payload.update(overrides)
    response = client.put("/api/v1/settings/sso", json=payload, headers=ADMIN)
    assert response.status_code in (200, 201), response.get_json()


def start_login(client, slot="primary"):
    response = client.get(f"/api/v1/auth/sso/saml/{slot}/login")
    assert response.status_code == 302, response.get_data(as_text=True)
    location = response.headers["Location"]
    assert "SAMLRequest=" in location and "RelayState=" in location
    return location, response.headers["X-SSO-Flow"]


def post_acs(client, xml, slot="primary"):
    return client.post(
        f"/api/v1/auth/sso/saml/{slot}/acs",
        data={"SAMLResponse": base64.b64encode(xml.encode("utf-8")).decode("ascii")},
    )


# ---------------------------------------------------------------------------
# canonicalization (hand-computed expectations from the W3C rules)
# ---------------------------------------------------------------------------
def test_c14n_basic_element_and_namespace():
    xml = '<a xmlns="urn:x"><b k="v">t</b></a>'
    element = minidom.parseString(xml).documentElement
    assert sso_module._c14n(element) == b'<a xmlns="urn:x"><b k="v">t</b></a>'


def test_c14n_sorts_attributes_and_keeps_only_visible_namespaces():
    xml = '<r xmlns:p="urn:p" z="1" m="2"><p:a/></r>'
    element = minidom.parseString(xml).documentElement
    # canonical form never self-closes: an empty element is a tag pair
    assert sso_module._c14n(element) == b'<r m="2" z="1"><p:a xmlns:p="urn:p"></p:a></r>'


def test_c14n_redundant_redeclaration_and_escapes():
    # r visibly utilizes p (its own tag), so p:a's identical redeclaration
    # is dropped; text escaping follows the canonical rules
    xml = '<p:r xmlns:p="urn:p"><p:a xmlns:p="urn:p">x&amp;y&lt;z</p:a></p:r>'
    element = minidom.parseString(xml).documentElement
    assert sso_module._c14n(element) == b'<p:r xmlns:p="urn:p"><p:a>x&amp;y&lt;z</p:a></p:r>'


def test_c14n_unused_ancestor_declaration_does_not_suppress_child():
    # exc-c14n renders per VISIBLY-UTILIZED bindings: r declares p but does
    # not use it, so r renders nothing and p:a renders its own declaration
    xml = '<r xmlns:p="urn:p"><p:a/></r>'
    element = minidom.parseString(xml).documentElement
    assert sso_module._c14n(element) == b'<r><p:a xmlns:p="urn:p"></p:a></r>'


def test_c14n_attribute_escaping_and_namespaced_attribute_order():
    # attributes sort by (namespace uri, local): no-namespace first
    xml = '<r xmlns:n="urn:n" n:b="2" a="q&quot;t&amp;u"/>'
    element = minidom.parseString(xml).documentElement
    assert (
        sso_module._c14n(element)
        == b'<r xmlns:n="urn:n" a="q&quot;t&amp;u" n:b="2"></r>'
    )


def test_c14n_default_namespace_undo_with_xmlns_empty():
    # a child that re-declares the empty default undoes the rendered
    # non-empty default of its output ancestor
    xml = '<r xmlns="urn:d"><p:a xmlns:p="urn:p"><b xmlns=""/></p:a></r>'
    element = minidom.parseString(xml).documentElement
    assert (
        sso_module._c14n(element)
        == b'<r xmlns="urn:d"><p:a xmlns:p="urn:p"><b xmlns=""></b></p:a></r>'
    )


# ---------------------------------------------------------------------------
# metadata + login start
# ---------------------------------------------------------------------------
def test_sp_metadata_and_saml_metadata_endpoints(client):
    configure_saml(client)
    response = client.get("/api/v1/auth/sso/metadata")
    assert response.status_code == 200
    body = response.get_json()
    assert body["primary_entity_id"] == SP_ENTITY
    assert body["acs_url"] == ACS_URL
    assert body["protocol"] == "saml2"
    xml_response = client.get("/api/v1/auth/sso/saml/primary/metadata")
    assert xml_response.status_code == 200
    assert "EntityDescriptor" in xml_response.get_data(as_text=True)
    assert "saml-metadata+xml" in xml_response.mimetype
    assert xml_response.headers["X-SP-Entity-ID"] == SP_ENTITY


def test_login_start_redirects_to_idp_with_single_use_flow(client, idp):
    configure_saml(client)
    location, flow_id = start_login(client)
    assert location.startswith("https://idp.example.test/sso?")
    # the flow row exists and is single-use
    response = client.get("/api/v1/auth/sso/saml/primary/login")
    assert response.headers["X-SSO-Flow"] != flow_id


def test_unknown_slot_is_404(client):
    configure_saml(client)
    assert client.get("/api/v1/auth/sso/saml/tertiary/login").status_code == 404


def test_disabled_slot_is_409(client, idp):
    configure_saml(client, secondary_provider="disabled")
    assert client.get("/api/v1/auth/sso/saml/secondary/login").status_code == 409


# ---------------------------------------------------------------------------
# the happy path + RBAC integration
# ---------------------------------------------------------------------------
def test_full_saml_login_unbound_then_bound(client, idp, app):
    configure_saml(client)
    _location, flow_id = start_login(client)
    response = post_acs(client, idp.response(in_response_to=flow_id))
    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert body["subject"] == "alice@example.test"
    assert body["email"] == "alice@example.test"
    assert body["mfa"] is True
    assert body["bound"] is False and body["role"] is None
    assert body["jit_provisioned"] is True
    assert body["token"].startswith("vypam-sso1.")
    session_headers = {"Authorization": f"Bearer {body['token']}"}

    # unbound SSO identity: the honest 403, never the admin token
    refused = client.get("/api/v1/roles", headers=session_headers)
    assert refused.status_code == 403
    assert (
        "SSO identity 'alice@example.test' has no role binding"
        in refused.get_json()["error"]
    )

    # an admin grants the binding (kind sso); the same token now works
    granted = client.post(
        "/api/v1/role-bindings",
        json={"principal": "alice@example.test", "role": "admin", "kind": "sso"},
        headers=ADMIN,
    )
    assert granted.status_code == 201, granted.get_json()
    allowed = client.get("/api/v1/roles", headers=session_headers)
    assert allowed.status_code == 200

    who = client.get("/api/v1/auth/whoami", headers=session_headers).get_json()
    assert who["kind"] == "sso" and who["role"] == "admin"

    # revoking the binding puts the identity back to unbound
    binding_id = granted.get_json()["binding"]["id"]
    client.delete(f"/api/v1/role-bindings/{binding_id}", headers=ADMIN)
    refused_again = client.get("/api/v1/roles", headers=session_headers)
    assert refused_again.status_code == 403


def test_operator_sso_session_gets_the_operator_denial(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    token = post_acs(client, idp.response(in_response_to=flow_id)).get_json()["token"]
    client.post(
        "/api/v1/role-bindings",
        json={"principal": "alice@example.test", "role": "operator", "kind": "sso"},
        headers=ADMIN,
    )
    headers = {"Authorization": f"Bearer {token}"}
    who = client.get("/api/v1/auth/whoami", headers=headers).get_json()
    assert who["role"] == "operator"
    denied = client.get("/api/v1/roles", headers=headers)
    assert denied.status_code == 403
    assert (
        denied.get_json()["error"]
        == "Role 'operator' may not call GET /api/v1/roles"
    )


def test_sso_subject_is_jit_provisioned_once(client, idp, app):
    configure_saml(client)
    _location, flow_id = start_login(client)
    post_acs(client, idp.response(in_response_to=flow_id))
    _location2, flow2 = start_login(client)
    body = post_acs(client, idp.response(in_response_to=flow2)).get_json()
    assert body["jit_provisioned"] is False  # second login: not new
    with app.app_context():
        assert SsoSubject.query.count() == 1
        row = SsoSubject.query.first()
        assert row.logins == 2 and row.email == "alice@example.test"


def test_jit_off_refuses_unknown_subject(client, idp):
    configure_saml(client, jit_provisioning=False)
    _location, flow_id = start_login(client)
    response = post_acs(client, idp.response(in_response_to=flow_id))
    assert response.status_code == 403
    assert "jit_provisioning" in response.get_data(as_text=True)


# ---------------------------------------------------------------------------
# SAML refusals: every one is a real check, none is a rubber stamp
# ---------------------------------------------------------------------------
def test_tampered_assertion_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    signed = idp.assertion()
    tampered = signed.replace("alice@example.test", "mallory@example.test")
    response = post_acs(client, idp.response(in_response_to=flow_id, assertion_xml=tampered))
    assert response.status_code == 400
    assert "digest mismatch" in response.get_json()["error"]


def test_signature_from_another_key_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = idp.assertion(key=rogue)
    response = post_acs(client, idp.response(in_response_to=flow_id, assertion_xml=forged))
    assert response.status_code == 400
    assert "does not verify" in response.get_json()["error"]


def test_unsigned_assertion_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    # strip the signature entirely
    unsigned = idp.assertion().split("<ds:Signature")[0] + "</saml:Assertion>"
    response = post_acs(client, idp.response(in_response_to=flow_id, assertion_xml=unsigned))
    assert response.status_code == 400
    assert "not signed by the IdP" in response.get_json()["error"]


def test_replayed_flow_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    xml = idp.response(in_response_to=flow_id)
    first = post_acs(client, xml)
    assert first.status_code == 200
    second = post_acs(client, xml)
    assert second.status_code == 400
    assert "already-used" in second.get_json()["error"]


def test_unsolicited_response_is_refused(client, idp):
    configure_saml(client)
    response = post_acs(client, idp.response(in_response_to=""))
    assert response.status_code == 400
    assert "unsolicited" in response.get_json()["error"]


def test_wrong_audience_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    assertion = idp.assertion(audience="urn:someone-elses-sp")
    response = post_acs(client, idp.response(in_response_to=flow_id, assertion_xml=assertion))
    assert response.status_code == 400
    assert "audience" in response.get_json()["error"]


def test_wrong_destination_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    xml = idp.response(in_response_to=flow_id, destination="https://evil.example.test/acs")
    response = post_acs(client, xml)
    assert response.status_code == 400
    assert "Destination" in response.get_json()["error"]


def test_wrong_issuer_and_error_status_are_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    xml = idp.response(in_response_to=flow_id, issuer="https://other-idp.example.test")
    assert post_acs(client, xml).status_code == 400
    _location2, flow2 = start_login(client)
    xml2 = idp.response(
        in_response_to=flow2,
        status_value="urn:oasis:names:tc:SAML:2.0:status:Requester",
    )
    response = post_acs(client, xml2)
    assert response.status_code == 400
    assert "non-success" in response.get_json()["error"]


def test_two_assertions_and_duplicate_ids_are_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    # two DIFFERENT-ID signed assertions: the ID index accepts them, the
    # single-assertion rule refuses
    doubled = idp.response(in_response_to=flow_id)
    doubled = doubled.replace(
        "</samlp:Response>",
        idp.assertion(subject="bob@example.test", assertion_id="assertion-2")
        + "</samlp:Response>",
    )
    response = post_acs(client, doubled)
    assert response.status_code == 400
    assert "exactly one assertion" in response.get_json()["error"]

    _location2, flow2 = start_login(client)
    # duplicate ID values: the same signed assertion twice by value - the
    # index refuses before anything else looks at the document
    duplicated = idp.response(in_response_to=flow2)
    duplicated = duplicated.replace(
        "</samlp:Response>", idp.assertion() + "</samlp:Response>"
    )
    response2 = post_acs(client, duplicated)
    assert response2.status_code == 400
    assert "duplicate ID" in response2.get_json()["error"]


def test_dtd_documents_are_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    xml = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>' + idp.response(
        in_response_to=flow_id
    )[len('<?xml version="1.0"?>'):]
    response = post_acs(client, xml)
    assert response.status_code == 400
    assert "DTD" in response.get_json()["error"]


def test_expired_assertion_is_refused(client, idp):
    configure_saml(client)
    _location, flow_id = start_login(client)
    # built expired AND validly signed - a post-sign string swap would trip
    # the digest check before the expiry check
    expired = idp.assertion(not_on_or_after_minutes=-5)
    response = post_acs(client, idp.response(in_response_to=flow_id, assertion_xml=expired))
    assert response.status_code == 400
    assert "expired" in response.get_json()["error"].lower()


def test_mfa_is_fail_closed(client, idp):
    configure_saml(client, require_mfa=True)
    _location, flow_id = start_login(client)
    response = post_acs(
        client, idp.response(in_response_to=flow_id, assertion_xml=idp.assertion(mfa=False))
    )
    assert response.status_code == 403
    assert "multi-factor" in response.get_json()["error"]
    # the refusal is on the ledger with its own action
    export = client.get("/api/v1/audit/export", headers=ADMIN)
    actions = [json.loads(line)["action"] for line in export.get_data(as_text=True).splitlines() if line]
    assert "sso.login.mfa_failed" in actions
    assert "sso.login.started" in actions
    assert "sso.login.succeeded" not in actions


def test_mfa_not_required_allows_single_factor(client, idp):
    configure_saml(client, require_mfa=False)
    _location, flow_id = start_login(client)
    response = post_acs(
        client, idp.response(in_response_to=flow_id, assertion_xml=idp.assertion(mfa=False))
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.get_json()["mfa"] is False


# ---------------------------------------------------------------------------
# OIDC
# ---------------------------------------------------------------------------
OIDC_DISCOVERY = {
    "issuer": "https://idp.example.test",
    "authorization_endpoint": "https://idp.example.test/authorize",
    "token_endpoint": "https://idp.example.test/token",
    "jwks_uri": "https://idp.example.test/jwks",
}


def _oidc_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": base64.urlsafe_b64encode(
                    numbers.n.to_bytes(256, "big")
                ).decode().rstrip("="),
                "e": base64.urlsafe_b64encode(numbers.e.to_bytes(3, "big")).decode().rstrip("="),
            }
        ]
    }
    return key, jwks


def _mint_id_token(key, *, nonce, sub="alice-oidc", amr=("pwd", "mfa"), alg="RS256",
                   issuer=OIDC_DISCOVERY["issuer"], exp_offset=300):
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    now = int(time.time())
    header = {"alg": alg, "kid": "test-key", "typ": "JWT"}
    payload = {
        "iss": issuer,
        "sub": sub,
        "aud": SP_ENTITY,
        "exp": now + exp_offset,
        "iat": now,
        "nonce": nonce,
        "amr": list(amr),
        "email": f"{sub}@example.test",
        "name": "Alice OIDC",
    }
    signing_input = f"{b64(header)}.{b64(payload)}".encode("ascii")
    if alg == "none":
        return f"{b64(header)}.{b64(payload)}."
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{b64(header)}.{b64(payload)}." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


@pytest.fixture
def oidc(monkeypatch):
    key, jwks = _oidc_keypair()
    captured = {"verifier": None}

    def fake_get(url):
        if url == "https://idp.example.test/discovery":
            return 200, json.dumps(OIDC_DISCOVERY).encode()
        if url == OIDC_DISCOVERY["jwks_uri"]:
            return 200, json.dumps(jwks).encode()
        raise AssertionError(f"unexpected fetch {url}")

    def fake_post_form(url, fields):
        assert url == OIDC_DISCOVERY["token_endpoint"]
        captured["verifier"] = fields.get("code_verifier")
        nonce = captured["nonce"]
        id_token = _mint_id_token(key, nonce=nonce, **captured.get("claims", {}))
        return 200, json.dumps({"id_token": id_token, "token_type": "Bearer"}).encode()

    monkeypatch.setattr(sso_module, "_http_get", fake_get)
    monkeypatch.setattr(sso_module, "_http_post_form", fake_post_form)
    return {"key": key, "captured": captured}


def configure_oidc(client):
    response = client.put(
        "/api/v1/settings/sso",
        json={
            "protocol": "oidc",
            "primary_provider": "okta",
            "primary_metadata_url": "https://idp.example.test/discovery",
            "require_mfa": True,
        },
        headers=ADMIN,
    )
    assert response.status_code in (200, 201), response.get_json()


def start_oidc_login(client):
    response = client.get("/api/v1/auth/sso/oidc/primary/login")
    assert response.status_code == 302
    location = response.headers["Location"]
    assert "code_challenge=" in location and "nonce=" in location
    return location, response.headers["X-SSO-Flow"]


def test_oidc_full_login(client, oidc, app):
    configure_oidc(client)
    _location, flow_id = start_oidc_login(client)
    with app.app_context():
        row = db.session.get(SsoFlow, flow_id)
        nonce = row.nonce
        verifier = row.verifier
    oidc["captured"]["nonce"] = nonce
    response = client.get(
        f"/api/v1/auth/sso/oidc/primary/callback?code=authcode&state={flow_id}"
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert body["subject"] == "alice-oidc"
    assert body["mfa"] is True
    assert body["token"].startswith("vypam-sso1.")
    assert oidc["captured"]["verifier"] == verifier


def test_oidc_nonce_replay_and_bad_algorithms_are_refused(client, oidc, app):
    configure_oidc(client)
    _location, flow_id = start_oidc_login(client)
    with app.app_context():
        row = db.session.get(SsoFlow, flow_id)
        nonce = row.nonce
    # wrong nonce
    oidc["captured"]["nonce"] = "not-the-right-nonce"
    response = client.get(
        f"/api/v1/auth/sso/oidc/primary/callback?code=authcode&state={flow_id}"
    )
    assert response.status_code == 400
    assert "nonce" in response.get_json()["error"]

    # alg: none
    _location2, flow2 = start_oidc_login(client)
    with app.app_context():
        row2 = db.session.get(SsoFlow, flow2)
    oidc["captured"]["nonce"] = row2.nonce
    original = oidc["captured"].get("claims", {})
    oidc["captured"]["claims"] = dict(original, alg="none")
    response2 = client.get(
        f"/api/v1/auth/sso/oidc/primary/callback?code=authcode&state={flow2}"
    )
    assert response2.status_code == 400
    assert "algorithm" in response2.get_json()["error"]


def test_oidc_single_factor_is_fail_closed(client, oidc, app):
    configure_oidc(client)
    _location, flow_id = start_oidc_login(client)
    with app.app_context():
        row = db.session.get(SsoFlow, flow_id)
    oidc["captured"]["nonce"] = row.nonce
    oidc["captured"]["claims"] = {"amr": ["pwd"]}
    response = client.get(
        f"/api/v1/auth/sso/oidc/primary/callback?code=authcode&state={flow_id}"
    )
    assert response.status_code == 403
    assert "multi-factor" in response.get_json()["error"]


def test_oidc_unknown_state_is_refused(client, oidc):
    configure_oidc(client)
    response = client.get(
        "/api/v1/auth/sso/oidc/primary/callback?code=x&state=_deadbeef"
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# session lifecycle + admin surfaces + posture honesty
# ---------------------------------------------------------------------------
def _login(client, idp) -> str:
    _location, flow_id = start_login(client)
    return post_acs(client, idp.response(in_response_to=flow_id)).get_json()["token"]


def test_sessions_list_revoke_and_logout(client, idp, app):
    configure_saml(client)
    token = _login(client, idp)
    listing = client.get("/api/v1/auth/sso/sessions", headers=ADMIN).get_json()
    assert listing["active"] == 1 and listing["total"] == 1
    session_row = listing["sessions"][0]
    assert session_row["mfa"] is True and session_row["token_prefix"].startswith("vypam-sso1.")

    revoked = client.post(
        f"/api/v1/auth/sso/sessions/{session_row['id']}/revoke", headers=ADMIN
    )
    assert revoked.status_code == 200
    after = client.get(
        "/api/v1/auth/whoami", headers={"Authorization": f"Bearer {token}"}
    )
    assert after.status_code == 401  # revoked: stops authenticating immediately


def test_logout_revokes_own_session(client, idp):
    configure_saml(client)
    token = _login(client, idp)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/v1/auth/sso/logout", headers=headers)
    assert response.status_code == 200 and response.get_json()["revoked"] is True
    assert client.get("/api/v1/auth/whoami", headers=headers).status_code == 401
    # logout without a session bearer is refused
    assert client.post("/api/v1/auth/sso/logout").status_code in (401, 403)


def test_expired_session_stops_authenticating(client, idp, app):
    configure_saml(client)
    token = _login(client, idp)
    with app.app_context():
        row = SsoSession.query.first()
        row.expires_at = datetime.now() - timedelta(minutes=1)
        db.session.commit()
    assert client.get("/api/v1/auth/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_settings_validation_and_loopback_http(client):
    bad = client.put(
        "/api/v1/settings/sso", json={"protocol": "kerberos"}, headers=ADMIN
    )
    assert bad.status_code == 400
    assert "must be one of" in bad.get_json()["error"]
    insecure = client.put(
        "/api/v1/settings/sso",
        json={"primary_metadata_url": "http://idp.example.test/metadata"},
        headers=ADMIN,
    )
    assert insecure.status_code == 400
    loopback = client.put(
        "/api/v1/settings/sso",
        json={"primary_metadata_url": "http://127.0.0.1:9999/metadata"},
        headers=ADMIN,
    )
    assert loopback.status_code in (200, 201)


def test_posture_counts_real_logins(client, idp, app):
    configure_saml(client)
    before = client.get("/api/v1/overview", headers=ADMIN).get_json()
    sso_control = next(c for c in before["posture"]["controls"] if c["id"] == "sso_mfa")
    assert sso_control["passed"] is False
    assert "no logins" in sso_control["evidence"]
    _login(client, idp)
    after = client.get("/api/v1/overview", headers=ADMIN).get_json()
    sso_control = next(c for c in after["posture"]["controls"] if c["id"] == "sso_mfa")
    assert sso_control["passed"] is True
    assert "mfa asserted" in sso_control["evidence"]


def test_admin_operations_grew_and_whoami_reports_it(client):
    assert len(service_module.ADMIN_OPERATIONS) == 145  # 8a: +21 gateway; 11.11: +1 setup profile
    who = client.get("/api/v1/auth/whoami", headers=ADMIN).get_json()
    assert who["mode"] == "token" and who["operations_count"] == 145
