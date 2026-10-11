"""Single sign-on enforcement (architecture Identity: SAML 2.0 + OIDC).

The `sso` settings group becomes a real login path:

- SAML 2.0: AuthnRequest (HTTP-Redirect) -> IdP -> ACS POST. The response
  is verified end to end on stdlib + `cryptography` only: exclusive XML
  canonicalization (implemented here), enveloped-signature transform,
  RSA/ECDSA-SHA2 signature over the canonicalized SignedInfo, SHA-256
  digests over the signed element, and the XML-signature-wrapping defenses
  (the consumed assertion IS the signed node; duplicate IDs are refused;
  the signing key is pinned to the IdP metadata certificate - KeyInfo is
  never trusted on its own).
- OIDC: authorization-code + PKCE (S256). The id_token is verified against
  the provider's JWKS (RS256 only - `alg: none` and HMAC key-confusion are
  refused), with issuer/audience/expiry/nonce checks.

A successful login JIT-provisions the subject (existence only - `sso.
jit_provisioning`), enforces the MFA assertion fail-closed when
`sso.require_mfa` is on (SAML AuthnContext or OIDC `amr` must show a real
multi-factor step), and mints a server-side session. The session bearer
token `vypam-sso1.<id>.<secret>` (sha256 at rest, shown once) is accepted
beside the admin token and the 6b rbac token; a role binding (kind `sso`,
principal = subject) decides what the session may do - no binding, no
admin access, exactly like the LDAP rule. `sso.enforce_sso` is reported
honestly: the console has no password login at all, so "humans
authenticate via SSO" is true by construction, not by a switch.

Everything here runs without a new dependency: XML via stdlib minidom,
canonicalization written from the W3C exclusive-c14n rules, signatures via
`cryptography`."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as pysecrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from xml.dom import Node, minidom

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from audit import append_explicit
from errors import Conflict, Forbidden, NotFound, ServiceUnavailable, ValidationFailed
from extensions import db
from models import (
    SSO_CLOCK_SKEW_SECONDS,
    SSO_FLOW_TTL_SECONDS,
    SSO_MFA_AMR,
    SSO_MFA_AUTHN_CONTEXTS,
    SSO_PROTOCOLS,
    SSO_SLOTS,
    SSO_TOKEN_PREFIX,
    RoleBinding,
    SettingGroup,
    SsoFlow,
    SsoSession,
    SsoSubject,
)

HTTP_TIMEOUT_SECONDS = 5
_METADATA_TTL_SECONDS = 3600

_DS = "http://www.w3.org/2000/09/xmldsig#"
_SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

_SIG_ALGORITHMS = {
    _DS + "rsa-sha256": ("rsa", hashes.SHA256()),
    _DS + "rsa-sha384": ("rsa", hashes.SHA384()),
    _DS + "rsa-sha512": ("rsa", hashes.SHA512()),
    _DS + "ecdsa-sha256": ("ecdsa", hashes.SHA256()),
    _DS + "ecdsa-sha384": ("ecdsa", hashes.SHA384()),
}
_DIGEST_ALGORITHMS = {
    _DS + "sha256": hashlib.sha256,
    _DS + "sha384": hashlib.sha384,
    _DS + "sha512": hashlib.sha512,
}

# IdP metadata / discovery cache: url -> (fetched_at, payload)
_METADATA_CACHE: Dict[str, Tuple[float, Any]] = {}


# ---------------------------------------------------------------------------
# settings + small helpers
# ---------------------------------------------------------------------------
def _settings() -> Dict[str, Any]:
    row = SettingGroup.query.filter(SettingGroup.group_name == "sso").first()
    return dict(row.value) if row is not None and row.value else {}


def _slot_values(slot: str) -> Dict[str, Any]:
    if slot not in SSO_SLOTS:
        raise NotFound(f"Unknown SSO slot '{slot}'", {"allowed": list(SSO_SLOTS)})
    values = _settings()
    prefix = slot
    configured = values.get(f"{prefix}_provider") or "okta"
    if configured == "disabled":
        raise Conflict(
            f"SSO slot '{prefix}' is disabled",
            {"slot": prefix, "configured": False},
        )
    return {
        "provider": configured,
        "protocol": str(values.get("protocol") or "saml2"),
        "metadata_url": str(values.get(f"{prefix}_metadata_url") or "").strip(),
        "entity_id": str(values.get("primary_entity_id") or "").strip(),
        "jit_provisioning": bool(values.get("jit_provisioning")),
        "require_mfa": bool(values.get("require_mfa")),
        "session_ttl_minutes": int(values.get("session_ttl_minutes") or 480),
        "enforce_sso": bool(values.get("enforce_sso")),
    }


def _http_get(url: str) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except urllib.error.URLError as exc:
        raise ServiceUnavailable(
            f"SSO endpoint unreachable: {exc.reason}",
            {"url": url.split("?")[0], "idp_reachable": False},
        ) from exc


def _http_post_form(url: str, fields: Dict[str, str]) -> Tuple[int, bytes]:
    body = urllib.parse.urlencode(fields).encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except urllib.error.URLError as exc:
        raise ServiceUnavailable(
            f"SSO endpoint unreachable: {exc.reason}",
            {"url": url.split("?")[0], "idp_reachable": False},
        ) from exc


def _cached(url: str, fetch) -> Any:
    now = time.time()
    hit = _METADATA_CACHE.get(url)
    if hit and now - hit[0] < _METADATA_TTL_SECONDS:
        return hit[1]
    payload = fetch()
    _METADATA_CACHE[url] = (now, payload)
    return payload


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# exclusive XML canonicalization (W3C exc-c14n 1.0, omit comments)
# ---------------------------------------------------------------------------
_NS_DECL = "http://www.w3.org/2000/xmlns/"


def _escape_text(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "&#xD;")
    )


def _escape_attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def _element_qname(node) -> str:
    if node.prefix:
        return f"{node.prefix}:{node.localName}"
    return node.localName


def _attr_key(node):
    """Canonical sort key: namespaced attributes first (uri, local), then
    plain ones (c14n 1.0 section 1.1)."""
    uri = node.namespaceURI or ""
    return (uri != "", uri, node.localName)


def _own_namespaces(element) -> Dict[str, str]:
    """prefix -> uri declared on this element itself (xmlns / xmlns:p)."""
    declared: Dict[str, str] = {}
    for index in range(element.attributes.length):
        attr = element.attributes.item(index)
        if attr.name == "xmlns":
            # minidom hands back None (not "") for the xmlns="" undo marker
            declared[""] = attr.value or ""
        elif attr.prefix == "xmlns":
            declared[attr.localName] = attr.value or ""
    return declared


def _utilized_prefixes(element) -> List[str]:
    """Prefixes the element itself uses: its own tag prefix + attribute
    prefixes (the default namespace counts as prefix "")."""
    used = [element.prefix or ""]
    for index in range(element.attributes.length):
        attr = element.attributes.item(index)
        if attr.name == "xmlns" or attr.prefix == "xmlns":
            continue
        if attr.prefix:
            used.append(attr.prefix)
    seen: List[str] = []
    for prefix in used:
        if prefix not in seen:
            seen.append(prefix)
    return seen


def _c14n_walk(
    element,
    rendered: Dict[str, str],
    values: Dict[str, str],
    parts: List[str],
    apex_inclusive: set,
    apex: bool = False,
) -> None:
    """One element, W3C exclusive-c14n 1.0 section 3.1: a namespace node is
    rendered only when its prefix is visibly utilized (or listed in
    InclusiveNamespaces) AND the same prefix/value binding has not already
    been rendered by an output ancestor."""
    own = _own_namespaces(element)
    values_now = dict(values)
    values_now.update(own)

    utilized = _utilized_prefixes(element)
    if apex:
        for prefix in apex_inclusive:
            if prefix not in utilized:
                utilized.append(prefix)
    here: List[Tuple[str, str]] = []
    for prefix in utilized:
        uri = own.get(prefix)
        if uri is None:
            uri = values.get(prefix)  # inherited declaration (DOM or walk)
        if uri is None:
            continue  # visibly utilized but never declared: leave as parsed
        if rendered.get(prefix) == uri:
            continue  # an output ancestor already rendered this binding
        here.append((prefix, uri))
    if "" in utilized and "" not in own and "" not in values and "" in rendered:
        # an output ancestor rendered a non-empty default namespace and
        # this element must stay in no namespace: undo it with xmlns=""
        here.append(("", ""))
    # default namespace first, then prefixes in canonical order
    here.sort(key=lambda item: (item[0] == "", item[0]))
    next_rendered = dict(rendered)
    next_rendered.update(dict(here))

    parts.append("<" + _element_qname(element))
    for prefix, uri in here:
        if prefix == "":
            parts.append(f' xmlns="{_escape_attr(uri)}"')
        else:
            parts.append(f' xmlns:{prefix}="{_escape_attr(uri)}"')
    attributes = [
        element.attributes.item(index)
        for index in range(element.attributes.length)
        if element.attributes.item(index).name != "xmlns"
        and element.attributes.item(index).prefix != "xmlns"
    ]
    attributes.sort(key=_attr_key)
    for attr in attributes:
        parts.append(f' {_element_qname(attr)}="{_escape_attr(attr.value)}"')
    parts.append(">")

    for child in element.childNodes:
        if child.nodeType == Node.ELEMENT_NODE:
            _c14n_walk(child, next_rendered, values_now, parts, apex_inclusive)
        elif child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            parts.append(_escape_text(child.data))
        elif child.nodeType == Node.PROCESSING_INSTRUCTION_NODE:
            parts.append(
                f"<?{child.target} {_escape_text(child.data)}?>" if child.data else f"<?{child.target}?>"
            )
        # comments are omitted by design (omit-comments profile)
    parts.append("</" + _element_qname(element) + ">")


def _c14n(element, inclusive_prefixes: Tuple[str, ...] = ()) -> bytes:
    """Exclusive canonicalization (omit comments) of one element subtree,
    W3C exclusive-c14n 1.0 (the section 3.1 algorithm, verified against the
    Recommendation). Values resolve through the DOM - nearest declaration
    wins - but the render decision only counts bindings actually rendered:
    an unused ancestor declaration never suppresses a descendant's own
    rendering of the prefix, and a SignedInfo whose ds: prefix is declared
    on its Signature parent canonicalizes identically on both sides."""
    values: Dict[str, str] = {}
    if element.nodeType == Node.DOCUMENT_NODE:
        element = element.documentElement
    node = element
    while node is not None and node.nodeType == Node.ELEMENT_NODE:
        for prefix, uri in _own_namespaces(node).items():
            values.setdefault(prefix, uri)
        node = node.parentNode
    parts: List[str] = []
    _c14n_walk(element, {}, values, parts, set(inclusive_prefixes), apex=True)
    return "".join(parts).encode("utf-8")


# ---------------------------------------------------------------------------
# XML parsing + signature verification (SAML)
# ---------------------------------------------------------------------------
class SamlError(ValidationFailed):
    """A SAML verification failure with an honest reason."""


def _parse_xml(raw: bytes):
    """Parse SAML XML with DTDs/entities refused (no XXE, no expansion)."""
    head = raw[:2048].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in raw.upper():
        raise SamlError("SAML document carries a DTD or entity declaration - refused")
    try:
        return minidom.parseString(raw)
    except Exception as exc:  # expat raises several types
        raise SamlError(f"SAML document is not well-formed XML: {exc}") from exc


def _child(element, namespace: str, local: str):
    for child in element.childNodes:
        if (
            child.nodeType == Node.ELEMENT_NODE
            and child.namespaceURI == namespace
            and child.localName == local
        ):
            return child
    return None


def _children(element, namespace: str, local: str) -> List[Any]:
    return [
        child
        for child in element.childNodes
        if child.nodeType == Node.ELEMENT_NODE
        and child.namespaceURI == namespace
        and child.localName == local
    ]


def _text_of(element) -> str:
    return "".join(
        child.data
        for child in element.childNodes
        if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE)
    ).strip()


def _id_index(document) -> Dict[str, Any]:
    """Every element carrying an ID-like attribute; duplicate values are
    refused outright (the classic wrapping setup)."""
    index: Dict[str, Any] = {}

    def walk(node):
        for child in list(node.childNodes):
            if child.nodeType != Node.ELEMENT_NODE:
                continue
            for attr_name in ("ID", "Id", "id", "xml:id"):
                value = child.getAttribute(attr_name) if attr_name != "xml:id" else ""
                if attr_name == "xml:id":
                    for i in range(child.attributes.length):
                        a = child.attributes.item(i)
                        if a.localName == "id" and a.namespaceURI == "http://www.w3.org/XML/1998/namespace":
                            value = a.value
                if value:
                    if value in index and index[value] is not child:
                        raise SamlError("SAML document carries duplicate ID values - refused")
                    index[value] = child
            walk(child)

    walk(document.documentElement)
    return index


def _load_verification_key(cert_b64: str):
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(cert_b64[i : i + 64] for i in range(0, len(cert_b64), 64))
        + "\n-----END CERTIFICATE-----\n"
    )
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    return certificate.public_key()


def _verify_signature(signature, id_index: Dict[str, Any], public_key) -> List[Any]:
    """Verify one ds:Signature over SignedInfo and its digests; return the
    referenced (already digest-checked) element nodes."""
    signed_info = _child(signature, _DS, "SignedInfo")
    if signed_info is None:
        raise SamlError("Signature has no SignedInfo")
    c14n_method = _child(signed_info, _DS, "CanonicalizationMethod")
    c14n_alg = c14n_method.getAttribute("Algorithm") if c14n_method else ""
    if c14n_alg != _EXC_C14N:
        raise SamlError(
            f"Unsupported SignedInfo canonicalization '{c14n_alg}' (only exclusive c14n is accepted)"
        )
    inclusive: Tuple[str, ...] = ()
    if c14n_method is not None:
        inclusive = _prefix_list(c14n_method)

    signature_method = _child(signed_info, _DS, "SignatureMethod")
    sig_alg = signature_method.getAttribute("Algorithm") if signature_method else ""
    mapped = _SIG_ALGORITHMS.get(sig_alg)
    if mapped is None:
        raise SamlError(f"Unsupported signature algorithm '{sig_alg}'")
    kind, hash_alg = mapped

    signature_value_el = _child(signature, _DS, "SignatureValue")
    if signature_value_el is None:
        raise SamlError("Signature has no SignatureValue")
    signature_bytes = base64.b64decode(
        "".join(_text_of(signature_value_el).split()), validate=False
    )

    si_bytes = _c14n(signed_info, inclusive)
    try:
        if kind == "rsa":
            public_key.verify(signature_bytes, si_bytes, padding.PKCS1v15(), hash_alg)
        else:
            public_key.verify(signature_bytes, si_bytes, ec.ECDSA(hash_alg))
    except InvalidSignature as exc:
        raise SamlError("SAML signature does not verify against the IdP certificate") from exc

    signed_elements: List[Any] = []
    for reference in _children(signed_info, _DS, "Reference"):
        uri = reference.getAttribute("URI")
        if not uri.startswith("#") or len(uri) < 2:
            raise SamlError("Signature Reference must be a same-document '#id' URI")
        target = id_index.get(uri[1:])
        if target is None:
            raise SamlError("Signature Reference points at an element that is not in the document")
        transforms = _child(reference, _DS, "Transforms")
        enveloped = False
        ref_inclusive: Tuple[str, ...] = ()
        if transforms is not None:
            for transform in _children(transforms, _DS, "Transform"):
                algorithm = transform.getAttribute("Algorithm")
                if algorithm == _ENVELOPED:
                    enveloped = True
                elif algorithm == _EXC_C14N:
                    ref_inclusive = _prefix_list(transform)
                else:
                    raise SamlError(f"Unsupported reference transform '{algorithm}'")
        node = target
        if enveloped:
            # digest a copy: a second signature must still see the original
            # document, and the signed element itself is never mutated.
            # every descendant Signature goes - spec enveloped behavior.
            node = node.cloneNode(deep=True)
            for sig_descendant in list(node.getElementsByTagNameNS(_DS, "Signature")):
                sig_descendant.parentNode.removeChild(sig_descendant)
        digest_method = _child(reference, _DS, "DigestMethod")
        digest_alg_uri = digest_method.getAttribute("Algorithm") if digest_method else ""
        digest_fn = _DIGEST_ALGORITHMS.get(digest_alg_uri)
        if digest_fn is None:
            raise SamlError(f"Unsupported digest algorithm '{digest_alg_uri}'")
        digest_value = _child(reference, _DS, "DigestValue")
        if digest_value is None:
            raise SamlError("Reference has no DigestValue")
        expected = "".join(_text_of(digest_value).split()).lower()
        actual = digest_fn(_c14n(node, ref_inclusive)).hexdigest()
        if not hmac.compare_digest(expected, actual):
            raise SamlError("SAML digest mismatch (the signed element was altered or swapped)")
        signed_elements.append(target)
    return signed_elements


def _prefix_list(transform_parent) -> Tuple[str, ...]:
    """InclusiveNamespaces PrefixList: the listed prefixes are handled the
    inclusive way (`#default` denotes the default namespace = prefix \"\")."""
    for child in transform_parent.childNodes:
        if child.nodeType == Node.ELEMENT_NODE and child.localName == "InclusiveNamespaces":
            raw = child.getAttribute("PrefixList") or ""
            return tuple("" if p == "#default" else p for p in raw.split())
    return ()


def _certificates_from_metadata(xml_bytes: bytes) -> Tuple[str, List[str], List[str]]:
    """(entityID, signing certs, HTTP-POST SSO urls) from IdP metadata."""
    document = _parse_xml(xml_bytes)
    root = document.documentElement
    entity_id = root.getAttribute("entityID")
    certs: List[str] = []
    post_urls: List[str] = []
    for descriptor in _children(root, "urn:oasis:names:tc:SAML:2.0:metadata", "IDPSSODescriptor"):
        for key in _children(descriptor, "urn:oasis:names:tc:SAML:2.0:metadata", "KeyDescriptor"):
            if key.getAttribute("use") not in ("", "signing"):
                continue
            for info in _children(key, _DS, "KeyInfo"):
                for data in _children(info, _DS, "X509Data"):
                    for cert in _children(data, _DS, "X509Certificate"):
                        value = "".join(_text_of(cert).split())
                        if value:
                            certs.append(value)
        for service in _children(
            descriptor, "urn:oasis:names:tc:SAML:2.0:metadata", "SingleSignOnService"
        ):
            if service.getAttribute("Binding") == _POST_BINDING:
                location = service.getAttribute("Location")
                if location:
                    post_urls.append(location)
    if not entity_id or not certs or not post_urls:
        raise ServiceUnavailable(
            "IdP metadata is incomplete (entityID, signing certificate and "
            "HTTP-POST SingleSignOnService are all required)",
            {"idp_reachable": True},
        )
    return entity_id, certs, post_urls


def _idp_metadata(settings: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
    url = settings["metadata_url"]
    if not url:
        raise Conflict(
            "SSO metadata URL is not set",
            {"field": "primary_metadata_url", "configured": False},
        )

    def fetch():
        status, raw = _http_get(url)
        if status != 200:
            raise ServiceUnavailable(
                f"IdP metadata fetch failed (HTTP {status})", {"url": url}
            )
        return _certificates_from_metadata(raw)

    return _cached(url, fetch)


# ---------------------------------------------------------------------------
# flows (single-use, TTL-bound)
# ---------------------------------------------------------------------------
def _new_flow(slot: str, protocol: str, *, nonce: str = "", verifier: str = "") -> SsoFlow:
    flow = SsoFlow(
        id=f"_{uuid.uuid4().hex}",
        slot=slot,
        protocol=protocol,
        nonce=nonce or None,
        verifier=verifier or None,
        expires_at=datetime.now() + timedelta(seconds=SSO_FLOW_TTL_SECONDS),
    )
    db.session.add(flow)
    return flow


def _consume_flow(flow_id: str, *, result: str, detail: str = "") -> SsoFlow:
    flow = db.session.get(SsoFlow, str(flow_id or ""))
    if flow is None or flow.consumed_at is not None:
        raise ValidationFailed(
            "Unknown or already-used login flow", {"field": "state"}
        )
    if flow.expires_at < datetime.now():
        flow.consumed_at = datetime.now()
        flow.result = "failed"
        flow.detail = "flow expired"
        db.session.commit()
        raise ValidationFailed("Login flow expired - start again", {"field": "state"})
    flow.consumed_at = datetime.now()
    flow.result = result
    flow.detail = detail[:255]
    return flow


def _fail(flow_id: str, reason: str, *, action: str = "sso.login.failed"):
    """Consume the flow as failed (an already-consumed row is updated to
    `failed` too - the outcome must be the truth) and put the refusal on
    the ledger."""
    flow = None
    try:
        flow = _consume_flow(flow_id, result="failed", detail=reason)
    except ValidationFailed:
        row = db.session.get(SsoFlow, str(flow_id or ""))
        if row is not None:
            row.result = "failed"
            row.detail = reason[:255]
            flow = row
    append_explicit(
        source="sso",
        # the mint fold already owns "sso:flow:<id>"; an appended mutation
        # carries the action so the refs stay unique per flow+outcome
        event_ref=f"sso:flow:{flow_id}:{action}",
        action=action,
        actor="idp",
        subject="",
        detail={"reason": reason[:255], "slot": flow.slot if flow else ""},
    )
    db.session.commit()


# ---------------------------------------------------------------------------
# subject + session lifecycle
# ---------------------------------------------------------------------------
def _upsert_subject(slot: str, protocol: str, subject: str, email: str, name: str,
                    attributes: Dict[str, Any]) -> SsoSubject:
    row = SsoSubject.query.filter(SsoSubject.slot == slot, SsoSubject.subject == subject).first()
    now = datetime.now()
    if row is None:
        row = SsoSubject(
            slot=slot, protocol=protocol, subject=subject, email=email, name=name,
            attributes=attributes, first_login_at=now,
        )
        db.session.add(row)
    row.email = email or row.email
    row.name = name or row.name
    row.attributes = attributes
    row.last_login_at = now
    row.logins = (row.logins or 0) + 1
    return row


def _mint_session(slot: str, protocol: str, subject: str, email: str, *,
                  mfa: bool, amr: List[str], subject_row: Optional[SsoSubject],
                  ttl_minutes: int) -> Tuple[SsoSession, str]:
    session = SsoSession(
        subject_id=subject_row.id if subject_row is not None else None,
        subject=subject,
        email=email,
        slot=slot,
        protocol=protocol,
        mfa=mfa,
        amr=amr,
        expires_at=datetime.now() + timedelta(minutes=ttl_minutes),
    )
    secret = pysecrets.token_urlsafe(32)
    # the hash lands BEFORE the first flush: token_sha256 is NOT NULL, the
    # row is only ever inserted with its final credential state
    session.token_sha256 = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    db.session.add(session)
    db.session.flush()  # assigns the id the token prefix carries
    session.token_prefix = f"{SSO_TOKEN_PREFIX}.{session.id}."
    db.session.commit()
    return session, f"{session.token_prefix}{secret}"


def verify_sso_session(token: Any) -> Optional[SsoSession]:
    """The live session a presented `vypam-sso1.<id>.<secret>` bearer
    authenticates, else None (wrong prefix, unknown, revoked or expired -
    all indistinguishable)."""
    if not isinstance(token, str) or not token.startswith(SSO_TOKEN_PREFIX + "."):
        return None
    body = token[len(SSO_TOKEN_PREFIX) + 1 :]
    parts = body.split(".")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1]:
        return None
    session = db.session.get(SsoSession, int(parts[0]))
    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at < datetime.now()
        or not session.token_sha256
    ):
        return None
    digest = hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, session.token_sha256):
        return None
    session.last_used_at = datetime.now()
    db.session.commit()
    return session


def sso_principal(token: Any) -> Optional[Dict[str, Any]]:
    """The RBAC principal for a live SSO session: the binding (kind `sso`,
    principal = subject) decides the role - an unbound SSO identity is
    flagged exactly like an unbound LDAP one."""
    session = verify_sso_session(token)
    if session is None:
        return None
    binding = RoleBinding.query.filter(
        RoleBinding.principal == session.subject,
        RoleBinding.kind == "sso",
        RoleBinding.revoked_at.is_(None),
    ).first()
    if binding is None:
        return {"principal": session.subject, "unbound": True, "kind": "sso"}
    return {
        "principal": binding.principal,
        "role": binding.role,
        "kind": binding.kind,
        "scope": binding.scope or {},
    }


# ---------------------------------------------------------------------------
# MFA assertion check (fail-closed)
# ---------------------------------------------------------------------------
def _assert_mfa(*, require_mfa: bool, saml_contexts: List[str], amr: List[str]) -> bool:
    """True when a completed multi-factor step is evidenced (or MFA is not
    required). With `require_mfa` on and no evidence: refuses - never a
    silent pass."""
    evidenced = bool(set(amr) & set(SSO_MFA_AMR)) or any(
        context in SSO_MFA_AUTHN_CONTEXTS for context in saml_contexts
    )
    if require_mfa and not evidenced:
        raise Forbidden(
            "IdP did not assert a multi-factor step and sso.require_mfa is on",
            {"require_mfa": True, "evidenced": False},
        )
    return evidenced


# ---------------------------------------------------------------------------
# SAML: login start + ACS
# ---------------------------------------------------------------------------
def saml_metadata(*, external_base: str, slot: str = "primary") -> Tuple[str, str]:
    """Our SP metadata (XML, content type application/saml-metadata+xml)."""
    settings = _slot_values(slot)
    entity_id = settings["entity_id"]
    acs_url = f"{external_base}/api/v1/auth/sso/saml/{slot}/acs"
    login_url = f"{external_base}/api/v1/auth/sso/saml/{slot}/login"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{_escape_attr(entity_id)}">\n'
        '  <md:SPSSODescriptor AuthnRequestsSigned="false" '
        'WantAssertionsSigned="true" protocolSupportEnumeration="' + _SAML_PROTOCOL + '">\n'
        '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        "</md:NameIDFormat>\n"
        f'    <md:SingleLogoutService Binding="{_REDIRECT_BINDING}" '
        f'Location="{_escape_attr(login_url)}"/>\n'
        f'    <md:AssertionConsumerService Binding="{_POST_BINDING}" '
        f'Location="{_escape_attr(acs_url)}" index="0"/>\n'
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
    return xml, entity_id


def saml_login_redirect(*, external_base: str, slot: str) -> Tuple[str, str]:
    """Build a real AuthnRequest and return (redirect_url, flow_id)."""
    settings = _slot_values(slot)
    if settings["protocol"] != "saml2":
        raise Conflict(
            f"SSO slot '{slot}' is configured for OIDC, not SAML",
            {"slot": slot, "protocol": settings["protocol"]},
        )
    _entity_id, _certs, sso_urls = _idp_metadata(settings)
    flow = _new_flow(slot, "saml2")
    db.session.commit()
    request_id = flow.id
    issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    acs_url = f"{external_base}/api/v1/auth/sso/saml/{slot}/acs"
    authn_request = (
        '<samlp:AuthnRequest xmlns:samlp="' + _SAML_PROTOCOL + '" '
        'xmlns:saml="' + _SAML_ASSERTION + f'" ID="{request_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}" AssertionConsumerServiceURL="{_escape_attr(acs_url)}" '
        f'Destination="{_escape_attr(sso_urls[0])}">'
        f"<saml:Issuer>{_escape_text(settings['entity_id'])}</saml:Issuer>"
        "</samlp:AuthnRequest>"
    )
    deflated = base64.b64encode(
        zlib.compress(authn_request.encode("utf-8"))[2:-4]
    ).decode("ascii")
    query = urllib.parse.urlencode({"SAMLRequest": deflated, "RelayState": flow.id})
    return f"{sso_urls[0]}?{query}", flow.id


def _name_id_and_attributes(assertion) -> Tuple[str, str, str, Dict[str, Any]]:
    subject = _child(assertion, _SAML_ASSERTION, "Subject")
    if subject is None:
        raise SamlError("Assertion has no Subject")
    name_id_el = _child(subject, _SAML_ASSERTION, "NameID")
    if name_id_el is None or not _text_of(name_id_el):
        raise SamlError("Assertion Subject has no NameID")
    subject_id = _text_of(name_id_el)
    email = ""
    name = ""
    attributes: Dict[str, Any] = {}
    attr_statement = _child(assertion, _SAML_ASSERTION, "AttributeStatement")
    if attr_statement is not None:
        for attribute in _children(attr_statement, _SAML_ASSERTION, "Attribute"):
            friendly = attribute.getAttribute("FriendlyName")
            name_attr = attribute.getAttribute("Name")
            key = friendly or name_attr
            values = [_text_of(v) for v in _children(attribute, _SAML_ASSERTION, "AttributeValue")]
            if not key or not values:
                continue
            attributes[key] = values[0] if len(values) == 1 else values
            lowered = (friendly + " " + name_attr).lower()
            if not email and ("email" in lowered or "mail" in lowered):
                email = values[0]
            if not name and friendly.lower() in ("name", "displayname"):
                name = values[0]
    if not email and "@" in subject_id:
        email = subject_id
    return subject_id, email, name, attributes


def saml_acs(slot: str, saml_response_b64: str, *, external_base: str) -> Dict[str, Any]:
    """Consume the IdP's ACS POST: verify everything, then mint the session."""
    settings = _slot_values(slot)
    if settings["protocol"] != "saml2":
        raise Conflict(
            f"SSO slot '{slot}' is configured for OIDC, not SAML",
            {"slot": slot, "protocol": settings["protocol"]},
        )
    try:
        raw = base64.b64decode("".join(saml_response_b64.split()), validate=False)
    except Exception as exc:
        raise SamlError("SAMLResponse is not valid base64") from exc
    document = _parse_xml(raw)
    root = document.documentElement
    if root.localName != "Response" or root.namespaceURI != _SAML_PROTOCOL:
        raise SamlError("SAMLResponse is not a SAML 2.0 Response")
    id_index = _id_index(document)

    status = _child(root, _SAML_PROTOCOL, "Status")
    code = _child(status, _SAML_PROTOCOL, "StatusCode") if status is not None else None
    if code is None or code.getAttribute("Value").rsplit(":", 1)[-1] != "Success":
        raise SamlError("IdP reported a non-success Status")

    issuer_el = _child(root, _SAML_ASSERTION, "Issuer")
    expected_entity, idp_certs, _urls = _idp_metadata(settings)
    if issuer_el is None or _text_of(issuer_el) != expected_entity:
        raise SamlError("Response Issuer does not match the configured IdP entity id")

    destination = root.getAttribute("Destination")
    acs_url = f"{external_base}/api/v1/auth/sso/saml/{slot}/acs"
    if destination and destination != acs_url:
        raise SamlError("Response Destination does not match this ACS URL")

    in_response_to = root.getAttribute("InResponseTo")
    flow_id = in_response_to or ""
    if flow_id:
        # consume before verification so a bad signature still burns the flow
        _consume_flow(flow_id, result="verifying")
    else:
        # unsolicited responses are refused: every login starts at /login
        raise SamlError("Response carries no InResponseTo - unsolicited assertions are refused")

    assertions = _children(root, _SAML_ASSERTION, "Assertion")
    saml_contexts: List[str] = []
    try:
        if len(assertions) != 1:
            raise SamlError("Response must carry exactly one assertion")
        assertion = assertions[0]

        # signature: response-level or assertion-level, key pinned to metadata
        signatures = _children(root, _DS, "Signature") + _children(
            assertion, _DS, "Signature"
        )
        signed_by_response = False
        signed_assertion = False
        if signatures:
            for signature in signatures:
                signed_nodes = _verify_signature(
                    signature, id_index, _load_verification_key(idp_certs[0])
                )
                if any(node is root for node in signed_nodes):
                    signed_by_response = True
                if any(node is assertion for node in signed_nodes):
                    signed_assertion = True
        if not (signed_by_response or signed_assertion):
            raise SamlError(
                "Assertion is not signed by the IdP (neither the Response nor the "
                "Assertion carries a verifiable signature)"
            )

        conditions = _child(assertion, _SAML_ASSERTION, "Conditions")
        if conditions is None:
            raise SamlError("Assertion carries no Conditions element")
        now = time.time()
        not_before = conditions.getAttribute("NotBefore")
        not_on_or_after = conditions.getAttribute("NotOnOrAfter")
        if not_before and now + SSO_CLOCK_SKEW_SECONDS < _saml_time(not_before):
            raise SamlError("Assertion is not yet valid (NotBefore)")
        if not_on_or_after and now - SSO_CLOCK_SKEW_SECONDS >= _saml_time(not_on_or_after):
            raise SamlError("Assertion expired (NotOnOrAfter)")
        audience_ok = False
        for restriction in _children(conditions, _SAML_ASSERTION, "AudienceRestriction"):
            audiences = [
                _text_of(a) for a in _children(restriction, _SAML_ASSERTION, "Audience")
            ]
            if settings["entity_id"] in audiences:
                audience_ok = True
        if not audience_ok:
            raise SamlError("Assertion audience does not include this SP")

        subject_id, email, name, attributes = _name_id_and_attributes(assertion)

        # MFA evidence from the AuthnStatement
        for statement in _children(assertion, _SAML_ASSERTION, "AuthnStatement"):
            context = _child(statement, _SAML_ASSERTION, "AuthnContext")
            if context is None:
                continue
            class_ref = _child(context, _SAML_ASSERTION, "AuthnContextClassRef")
            if class_ref is not None and _text_of(class_ref):
                saml_contexts.append(_text_of(class_ref))
    except SamlError as exc:
        # the flow is already burned as "verifying" - a forged, tampered or
        # expired assertion must still leave ledger evidence of the attempt
        _fail(flow_id, str(exc.message))
        raise
    try:
        mfa = _assert_mfa(require_mfa=settings["require_mfa"], saml_contexts=saml_contexts, amr=[])
    except Forbidden:
        _fail(flow_id, "multi-factor step not asserted", action="sso.login.mfa_failed")
        raise

    return _finish_login(
        settings=settings, slot=slot, protocol="saml2", subject=subject_id,
        email=email, name=name, attributes=attributes, mfa=mfa,
        amr=saml_contexts, flow_id=flow_id,
    )


def _saml_time(value: str) -> float:
    try:
        # SAML times are UTC ("Z"): a naive .timestamp() would read the
        # wall clock as local time and expire valid assertions on any
        # machine whose timezone is ahead of UTC
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return moment.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        raise SamlError(f"Unparseable SAML time '{value}'")


# ---------------------------------------------------------------------------
# OIDC: login start + callback
# ---------------------------------------------------------------------------
def _oidc_discovery(settings: Dict[str, Any]) -> Dict[str, Any]:
    url = settings["metadata_url"]
    if not url:
        raise Conflict(
            "OIDC discovery URL is not set",
            {"field": "primary_metadata_url", "configured": False},
        )

    def fetch():
        status, raw = _http_get(url)
        if status != 200:
            raise ServiceUnavailable(
                f"OIDC discovery fetch failed (HTTP {status})", {"url": url}
            )
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise ServiceUnavailable("OIDC discovery document is not JSON", {"url": url}) from exc
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
            if not data.get(field):
                raise ServiceUnavailable(
                    f"OIDC discovery document lacks '{field}'", {"url": url}
                )
        return data

    return _cached(url, fetch)


def oidc_login_redirect(*, external_base: str, slot: str) -> Tuple[str, str]:
    """Build the authorization URL (PKCE S256 + nonce) -> (url, flow_id)."""
    settings = _slot_values(slot)
    if settings["protocol"] != "oidc":
        raise Conflict(
            f"SSO slot '{slot}' is configured for SAML, not OIDC",
            {"slot": slot, "protocol": settings["protocol"]},
        )
    discovery = _oidc_discovery(settings)
    verifier = pysecrets.token_urlsafe(48)
    flow = _new_flow(
        slot, "oidc", nonce=pysecrets.token_urlsafe(24), verifier=verifier
    )
    db.session.commit()
    redirect_uri = f"{external_base}/api/v1/auth/sso/oidc/{slot}/callback"
    query = urllib.parse.urlencode(
        {
            "client_id": settings["entity_id"],
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": flow.id,
            "nonce": flow.nonce,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in discovery["authorization_endpoint"] else "?"
    return f"{discovery['authorization_endpoint']}{separator}{query}", flow.id


def _jwks_key(jwks: Dict[str, Any], kid: str):
    for key in jwks.get("keys") or []:
        if key.get("kty") == "RSA" and key.get("kid") == kid:
            n = int.from_bytes(_b64url_decode(key["n"]), "big")
            e = int.from_bytes(_b64url_decode(key["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
    raise SamlError(f"JWKS carries no RSA key for kid '{kid}'")


def _verify_id_token(id_token: str, settings: Dict[str, Any], flow: SsoFlow) -> Dict[str, Any]:
    parts = id_token.split(".")
    if len(parts) != 3:
        raise SamlError("id_token is not a three-part JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except ValueError as exc:
        raise SamlError("id_token header/payload is not base64url JSON") from exc
    algorithm = str(header.get("alg") or "")
    if algorithm not in ("RS256", "RS384", "RS512"):
        # `none` and HS* are refused outright (key-confusion defense)
        raise SamlError(f"Unsupported id_token algorithm '{algorithm}' (RS256 family only)")
    discovery = _oidc_discovery(settings)
    jwks = _cached(discovery["jwks_uri"], lambda: _fetch_json(discovery["jwks_uri"]))
    public_key = _jwks_key(jwks, str(header.get("kid") or ""))
    hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[algorithm]
    signature = _b64url_decode(parts[2])
    signed_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        public_key.verify(signature, signed_input, padding.PKCS1v15(), hash_alg)
    except InvalidSignature as exc:
        raise SamlError("id_token signature does not verify against the JWKS") from exc

    now = time.time()
    if payload.get("iss") != discovery["issuer"]:
        raise SamlError("id_token issuer mismatch")
    audiences = payload.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    if not audiences or settings["entity_id"] not in audiences:
        raise SamlError("id_token audience does not include this client")
    if isinstance(audiences, list) and len(audiences) > 1 and payload.get("azp") != settings["entity_id"]:
        raise SamlError("id_token has multiple audiences without a matching azp")
    if int(payload.get("exp") or 0) < now - SSO_CLOCK_SKEW_SECONDS:
        raise SamlError("id_token expired")
    if int(payload.get("iat") or 0) > now + SSO_CLOCK_SKEW_SECONDS:
        raise SamlError("id_token was issued in the future")
    if not flow.nonce or payload.get("nonce") != flow.nonce:
        raise SamlError("id_token nonce does not match the login flow")
    return payload


def _fetch_json(url: str) -> Dict[str, Any]:
    status, raw = _http_get(url)
    if status != 200:
        raise ServiceUnavailable(f"JWKS fetch failed (HTTP {status})", {"url": url})
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ServiceUnavailable("JWKS document is not JSON", {"url": url}) from exc
    if not isinstance(data, dict):
        raise ServiceUnavailable("JWKS document is not an object", {"url": url})
    return data


def oidc_callback(slot: str, code: str, state: str, *, external_base: str) -> Dict[str, Any]:
    """Exchange the code, verify the id_token, mint the session."""
    settings = _slot_values(slot)
    if settings["protocol"] != "oidc":
        raise Conflict(
            f"SSO slot '{slot}' is configured for SAML, not OIDC",
            {"slot": slot, "protocol": settings["protocol"]},
        )
    flow = db.session.get(SsoFlow, str(state or ""))
    if flow is None or flow.protocol != "oidc" or flow.consumed_at is not None:
        raise ValidationFailed("Unknown or already-used login flow", {"field": "state"})
    if flow.expires_at < datetime.now():
        _fail(state, "flow expired")
        raise ValidationFailed("Login flow expired - start again", {"field": "state"})
    _consume_flow(state, result="verifying")

    discovery = _oidc_discovery(settings)
    status, raw = _http_post_form(
        discovery["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": f"{external_base}/api/v1/auth/sso/oidc/{slot}/callback",
            "client_id": settings["entity_id"],
            "code_verifier": flow.verifier or "",
        },
    )
    if status != 200:
        _fail(state, f"token exchange HTTP {status}")
        raise ServiceUnavailable(
            f"OIDC token exchange failed (HTTP {status})", {"idp_reachable": True}
        )
    try:
        token_data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        _fail(state, "token response is not JSON")
        raise ServiceUnavailable("OIDC token response is not JSON", {}) from exc
    id_token = str(token_data.get("id_token") or "")
    if not id_token:
        _fail(state, "token response carries no id_token")
        raise SamlError("OIDC token response carries no id_token")

    try:
        claims = _verify_id_token(id_token, settings, flow)
    except SamlError as exc:
        _fail(state, str(exc.message))
        raise
    amr = [str(value) for value in claims.get("amr") or []]
    try:
        mfa = _assert_mfa(require_mfa=settings["require_mfa"], saml_contexts=[], amr=amr)
    except Forbidden:
        _fail(state, "multi-factor step not asserted", action="sso.login.mfa_failed")
        raise
    subject = str(claims.get("sub") or "")
    if not subject:
        _fail(state, "id_token has no subject")
        raise SamlError("id_token has no subject (sub)")
    email = str(claims.get("email") or "")
    name = str(claims.get("name") or claims.get("preferred_username") or "")
    return _finish_login(
        settings=settings, slot=slot, protocol="oidc", subject=subject,
        email=email, name=name, attributes={"amr": amr, "acr": claims.get("acr", "")},
        mfa=mfa, amr=amr, flow_id=state,
    )


# ---------------------------------------------------------------------------
# shared finish: JIT + session
# ---------------------------------------------------------------------------
def _finish_login(*, settings: Dict[str, Any], slot: str, protocol: str, subject: str,
                  email: str, name: str, attributes: Dict[str, Any], mfa: bool,
                  amr: List[str], flow_id: str) -> Dict[str, Any]:
    if not settings["jit_provisioning"]:
        existing = SsoSubject.query.filter(
            SsoSubject.slot == slot, SsoSubject.subject == subject
        ).first()
        if existing is None:
            _fail(flow_id, "subject not provisioned and jit_provisioning is off")
            raise Forbidden(
                "SSO subject is not provisioned and sso.jit_provisioning is off",
                {"subject": subject, "jit_provisioning": False},
            )
    subject_row = _upsert_subject(slot, protocol, subject, email, name, attributes)
    session, token = _mint_session(
        slot, protocol, subject, email, mfa=mfa, amr=amr, subject_row=subject_row,
        ttl_minutes=settings["session_ttl_minutes"],
    )
    binding = RoleBinding.query.filter(
        RoleBinding.principal == subject,
        RoleBinding.kind == "sso",
        RoleBinding.revoked_at.is_(None),
    ).first()
    return {
        "session_id": session.id,
        "token": token,
        "token_prefix": session.token_prefix,
        "subject": subject,
        "email": email,
        "name": name,
        "slot": slot,
        "protocol": protocol,
        "mfa": mfa,
        "expires_at": session.expires_at.isoformat(),
        "jit_provisioned": subject_row.logins == 1,
        "role": binding.role if binding is not None else None,
        "bound": binding is not None,
        "note": (
            None
            if binding is not None
            else "no role binding for this subject - an admin must grant one "
            "(POST /api/v1/role-bindings, kind `sso`)"
        ),
    }


# ---------------------------------------------------------------------------
# admin + status surfaces
# ---------------------------------------------------------------------------
def list_sessions(*, active_only: bool = True) -> Dict[str, Any]:
    query = SsoSession.query
    now = datetime.now()
    total = query.count()
    active = [
        session
        for session in query.all()
        if session.revoked_at is None and session.expires_at >= now
    ]
    rows = active if active_only else query.all()
    return {
        "total": total,
        "active": len(active),
        "sessions": [session.to_dict() for session in rows],
    }


def revoke_session(session_id: int, *, actor: str) -> Dict[str, Any]:
    session = db.session.get(SsoSession, int(session_id))
    if session is None:
        raise NotFound(f"Unknown SSO session {session_id}")
    if session.revoked_at is not None:
        raise Conflict(f"SSO session {session.id} is already revoked")
    session.revoked_at = datetime.now()
    append_explicit(
        source="sso",
        # mint fold owns "sso:session:<id>" - the mutation carries its action
        event_ref=f"sso:session:{session.id}:revoked",
        action="sso.session.revoked",
        actor=actor,
        subject=session.subject,
        detail={"slot": session.slot, "protocol": session.protocol},
    )
    db.session.commit()
    return session.to_dict()


def logout(token: str) -> Dict[str, Any]:
    """End the caller's own session (the bearer is the authorization)."""
    session = verify_sso_session(token)
    if session is None:
        raise Forbidden("Not an active SSO session", {"authenticated": False})
    if session.revoked_at is None:
        session.revoked_at = datetime.now()
        append_explicit(
            source="sso",
            event_ref=f"sso:session:{session.id}:logout",
            action="sso.session.revoked",
            actor=session.subject,
            subject=session.subject,
            detail={"slot": session.slot, "protocol": session.protocol, "logout": True},
        )
        db.session.commit()
    return {"revoked": True, "session_id": session.id}


def status(*, external_base: str = "") -> Dict[str, Any]:
    """Honest runtime state for GET /auth/sso/status, the settings screen
    and the posture widget - what is configured AND what has actually
    happened."""
    values = _settings()
    now = datetime.now()
    sessions = SsoSession.query.all()
    active_sessions = [
        s for s in sessions if s.revoked_at is None and s.expires_at >= now
    ]
    recent = sorted(
        (s for s in sessions if s.revoked_at is None and s.expires_at >= now),
        key=lambda s: s.created_at,
    )
    last = recent[-1] if recent else None
    slots: Dict[str, Any] = {}
    for slot in SSO_SLOTS:
        provider = str(values.get(f"{slot}_provider") or "")
        slots[slot] = {
            "provider": provider,
            "enabled": provider not in ("", "disabled"),
            "protocol": str(values.get("protocol") or "saml2"),
            "metadata_url": str(values.get(f"{slot}_metadata_url") or ""),
        }
    return {
        "configured": any(slot["enabled"] for slot in slots.values()),
        "enforce_sso": bool(values.get("enforce_sso")),
        "jit_provisioning": bool(values.get("jit_provisioning")),
        "require_mfa": bool(values.get("require_mfa")),
        "session_ttl_minutes": int(values.get("session_ttl_minutes") or 480),
        "primary_entity_id": values.get("primary_entity_id"),
        "slots": slots,
        "subjects": SsoSubject.query.count(),
        "sessions_total": len(sessions),
        "sessions_active": len(active_sessions),
        "last_login_at": last.created_at.isoformat() if last else None,
        "sp_metadata_url": f"{external_base}/api/v1/auth/sso/saml/primary/metadata"
        if external_base
        else "",
    }
