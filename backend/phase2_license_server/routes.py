"""HTTP routes for the Phase 2 license server."""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import re
from functools import wraps
from typing import Any, Dict, Optional

from flask import Blueprint, Response, current_app, g, jsonify, redirect, request

import hsm
import identity
import gateway
import mfa
import otp
import radius_client
import scim
import service
import setup
import sso
import webauthn
from config import Config
from datetime import datetime
from errors import Conflict, Forbidden, NotFound, ServiceUnavailable, Unauthorized, ValidationFailed
from extensions import db
from licensing_bridge import sig
from models import ConsoleSession, LoginChallenge

api = Blueprint("api", __name__, url_prefix="/api/v1")

MAX_PAGE_SIZE = 200


@api.before_request
def _passive_node_gate():
    """HA / DC / DR (architecture section 18): while this node's registry
    role is `passive`, every write outside the cluster module itself is
    refused with 409.

    That is what active-passive honestly means for this product: a passive
    DR node answers reads (the screens, the ledger, the evidence - that is
    what a standby is for) and runs its own cluster operations (probe,
    sync, backup, promote - a standby must be able to prove its peers are
    dead and take over), but it never takes a product write: not vault, not
    sessions, not settings, not licenses, not agent tasks. The gate is
    method-based and deliberately blunt - every POST/PUT/PATCH/DELETE
    outside those exemptions, including read-shaped ones like license
    validation: the load balancer keeps traffic on the active node, and a
    request that reaches the standby is told the truth (promote it) rather
    than answered from state this node does not replicate (licenses are
    not part of the pull replication - only the audit chain, the sealed
    vault and session metadata are).

    Two exemptions, both deliberate:
    - `/api/v1/auth/*` is how a caller proves who they are, and reads need
      credentials in token mode - gating authentication would lock
      operators out of the very node they must inspect (or promote), and
      6c's SSO login lands here too.
    - Cluster operations stay writable because they are the standby's own
      job: evidence, backups and the promote action itself.

    The check runs before auth on purpose: it consults nothing but this
    node's own row, and a 409 naming the promote route leaks no data - it
    tells a caller exactly why the write was refused and how to lift it.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.path.startswith(("/api/v1/cluster/", "/api/v1/auth/")):
        return None
    if service.cluster_self_role() != "passive":
        return None
    return (
        jsonify(
            {
                "error": (
                    "This node is passive (DR standby): every write outside "
                    "/api/v1/cluster/* (authentication excepted) is refused "
                    "until it is promoted"
                ),
                "details": {
                    "role": "passive",
                    "promote": "POST /api/v1/cluster/failover",
                },
            }
        ),
        409,
    )


def _config() -> Config:
    return current_app.config["LICENSE_CONFIG"]


def _json_body(*, required: bool = True) -> Dict[str, Any]:
    data = request.get_json(silent=True)
    if data is None:
        if required:
            raise ValidationFailed("Request body must be valid JSON")
        return {}
    if not isinstance(data, dict):
        raise ValidationFailed("Request body must be a JSON object")
    return data


def _int_param(name: str, default: int, *, minimum: int = 0) -> int:
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationFailed(f"Query parameter '{name}' must be an integer") from None
    if value < minimum:
        raise ValidationFailed(f"Query parameter '{name}' must be >= {minimum}")
    return value


_RULE_PARAM = re.compile(r"<(?:[a-z_][a-z0-9_]*:)?([a-z_][a-z0-9_]*)>")


def _operation_rule() -> str:
    """The request's URL rule in contract form: Flask writes path params
    as `/x/<int:item_id>`, the openapi document (and ROLE_OPERATIONS) as
    `/x/{item_id}` - the two must be the same key for the role policy to
    match what the contract documents."""
    rule = request.url_rule.rule if request.url_rule is not None else request.path
    return _RULE_PARAM.sub(r"{\1}", rule)


def _presented_credential() -> str:
    """The token this request presents as its admin-side credential: the
    X-Admin-Token header, or the Authorization bearer value when present,
    else the session cookie (browser clients - the same value, so the
    identity machinery sees one shape)."""
    token = request.headers.get("X-Admin-Token")
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("vypam_session") or ""
    return (token or "").strip()


def _unbound_principal_error(principal: Dict[str, Any]) -> Forbidden:
    """The honest refusal for an authenticated identity with no role
    binding - the directory rule, now shared with SSO subjects and console
    users."""
    if principal.get("kind") == "sso":
        return Forbidden(
            f"SSO identity '{principal['principal']}' has no role binding - "
            "an admin must grant one (POST /api/v1/role-bindings, kind `sso`)",
            {"principal": principal["principal"], "role_required": True},
        )
    if principal.get("kind") == "user":
        return Forbidden(
            f"Console user '{principal['principal']}' has no role binding - "
            "an admin must grant one (POST /api/v1/role-bindings, kind `user`)",
            {"principal": principal["principal"], "role_required": True},
        )
    return Forbidden(
        f"Directory identity '{principal['principal']}' has no role "
        "binding - an admin must grant one (POST /api/v1/role-bindings)",
        {"principal": principal["principal"], "role_required": True},
    )


def _require_admin_credential() -> None:
    """Raise Unauthorized unless a valid admin-side credential is presented,
    and Forbidden unless that credential's role may call this operation
    (RBAC/ABAC, architecture section 10).

    Three credentials are accepted in token mode. The admin token is
    `admin` - every operation. A role binding's `vypam-rbac1.<id>.<secret>`
    token is its binding's role - exactly the operations ROLE_OPERATIONS
    grants it. A signed LDAP login ticket (minted by POST /api/v1/auth/ldap
    after a real bind) authenticates the directory username - and a role
    binding decides what that username may do, so an unbound directory
    identity is refused instead of silently holding the admin token. The
    acting principal is left on `g.rbac_principal` for the audit actor and
    the attribute checks. When LICENSE_ADMIN_TOKEN is unset the server runs
    in open/dev mode and every route is allowed (the response header
    reports this).
    """
    config = _config()
    if not config.admin_token:
        return
    principal = service.resolve_principal(_presented_credential(), config=config)
    if principal is None:
        raise Unauthorized(
            "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
        )
    if principal.get("unbound"):
        raise _unbound_principal_error(principal)
    g.rbac_principal = principal
    role = principal["role"]
    rule = _operation_rule()
    if not service.role_allows(role, request.method, rule):
        raise Forbidden(
            f"Role '{role}' may not call {request.method} {rule}",
            {"role": role, "operation": f"{request.method.lower()} {rule}"},
        )


def _require_scope(*, item_id: Optional[int] = None, target: Optional[str] = None) -> None:
    """ABAC (architecture section 10): enforce the acting principal's
    binding scope on a vault item operation or a session target. The admin
    role and unscoped bindings are unrestricted; a scoped binding only
    reaches the vault items and target patterns its admin granted it."""
    principal = getattr(g, "rbac_principal", None)
    if principal is None or principal.get("role") == "admin":
        return
    scope = principal.get("scope") or {}
    if item_id is not None:
        allowed_items = scope.get("vault_items") or []
        if allowed_items and item_id not in allowed_items:
            raise Forbidden(
                f"Role binding '{principal['principal']}' is not scoped to "
                f"vault item {item_id}",
                {"scope": scope, "item_id": item_id},
            )
    if target is not None:
        patterns = scope.get("targets") or []
        if patterns and not any(fnmatch.fnmatch(target, pattern) for pattern in patterns):
            raise Forbidden(
                f"Role binding '{principal['principal']}' is not scoped to "
                f"target '{target}'",
                {"scope": scope, "target": target},
            )


def require_admin(view):
    """Reject the request unless a valid admin credential is presented and
    its role may call this operation (see _require_admin_credential)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        _require_admin_credential()
        return view(*args, **kwargs)

    return wrapped


def _pipeline_token() -> str:
    """A pipeline's broker API token: the X-Broker-Token header, or a
    `vypam-ci1.` bearer value in Authorization - a plain bearer token stays
    the admin credential, so the two are never confused on dual-auth
    routes."""
    token = (request.headers.get("X-Broker-Token") or "").strip()
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer.startswith(service.BROKER_TOKEN_PREFIX + "."):
            return bearer
    return ""


def require_pipeline(view):
    """Reject the request unless a valid broker API token authenticates the
    pipeline (architecture section 15). Unlike the admin token this is
    never waived in open/dev mode: the machine identity is the point - the
    pipeline *is* its policy row, and X-Actor is not consulted."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.broker_policy = service.verify_broker_token(_pipeline_token())
        return view(*args, **kwargs)

    return wrapped


def _agent_token() -> str:
    """An AI agent's API token: the X-Agent-Token header, or a
    `vypam-agt1.` bearer value in Authorization - a plain bearer token
    stays the admin credential, so the two are never confused on dual-auth
    routes."""
    token = (request.headers.get("X-Agent-Token") or "").strip()
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer.startswith(service.AGENT_TOKEN_PREFIX + "."):
            return bearer
    return ""


def require_agent(view):
    """Reject the request unless a valid agent API token authenticates the
    agent (architecture section 16). Like the pipeline token this is never
    waived in open/dev mode: the agent identity is the point, X-Actor is
    not consulted, and the actor on every record is the identity's name."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.agent_identity = service.verify_agent_token(_agent_token())
        return view(*args, **kwargs)

    return wrapped


def _gateway_node_token() -> str:
    """A gateway node's API token: the X-Gateway-Token header, or a
    `vypam-gwn1.` bearer value in Authorization - a plain bearer token
    stays the admin credential, so the two are never confused."""
    token = (request.headers.get("X-Gateway-Token") or "").strip()
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer.startswith(gateway.GATEWAY_NODE_TOKEN_PREFIX + "."):
            return bearer
    return ""


def require_gateway_node(view):
    """Reject the request unless a valid gateway node token authenticates
    the daemon (plan phase 8a). Never waived in open/dev mode: the node
    identity is the point, X-Actor is not consulted, and - unlike every
    admin credential - it is exactly what the connect-args route *requires*:
    a node credential is not an admin credential, and vice versa."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        g.gateway_node = gateway.verify_node_token(_gateway_node_token())
        # the path's node id must match the token's node: one node may not
        # read another node's queue or connect args
        path_node = kwargs.get("node_id")
        if path_node is not None and int(path_node) != g.gateway_node.id:
            raise NotFound("Gateway node not found")
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# installing vendor-signed licenses
# ---------------------------------------------------------------------------
@api.post("/licenses/import")
@require_admin
def import_license():
    """Install the vendor-signed .lic from the delivery bundle.

    The shipped server verifies the signature and records the claims — it
    never signs (issuing belongs to PAM-MASTER).
    """
    body = _json_body()
    record, license_file = service.import_license(_config(), body)
    return (
        jsonify(
            {
                "license": record.to_dict(),
                "license_file": license_file,
                "token": license_file.get("token"),
                "message": "License imported",
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------
@api.get("/meta")
def server_meta():
    """Capabilities: algorithms, formats, tier names, entitlement catalog."""
    return jsonify(service.meta())


@api.get("/licenses")
def list_licenses():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    records, total = service.list_licenses(
        status=request.args.get("status"),
        license_type=request.args.get("license_type"),
        issued_to=request.args.get("issued_to"),
        tier=request.args.get("tier"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "licenses": [record.to_dict() for record in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/licenses/<string:license_key>")
def get_license(license_key: str):
    record = service.get_record(license_key)
    payload = record.to_dict(include_events=True)
    payload["usage"] = record.usage_summary()
    return jsonify({"license": payload})


@api.get("/licenses/<string:license_key>/file")
@require_admin
def download_license_file(license_key: str):
    record = service.get_record(license_key)
    fmt = request.args.get("format", record.signature_format or sig.FORMAT_JSON)
    if fmt not in sig.SUPPORTED_FORMATS:
        raise ValidationFailed(
            f"Unknown format '{fmt}'",
            {"field": "format", "allowed": list(sig.SUPPORTED_FORMATS)},
        )

    if fmt == sig.FORMAT_JWT:
        payload = record.license_token()
        mimetype = "text/plain"
    else:
        payload = json.dumps(record.license_file(), indent=2)
        mimetype = "application/json"

    response = current_app.response_class(payload, mimetype=mimetype)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="license_{record.license_key}.{fmt}"'
    )
    return response


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------
@api.post("/licenses/<string:license_key>/revoke")
@require_admin
def revoke_license(license_key: str):
    body = _json_body(required=False)
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ValidationFailed("'reason' must be a string", {"field": "reason"})

    record = service.revoke_license(license_key, reason)
    return jsonify({"license": record.to_dict(), "message": "License revoked"})


@api.post("/licenses/<string:license_key>/restore")
@require_admin
def restore_license(license_key: str):
    record = service.restore_license(license_key)
    return jsonify({"license": record.to_dict(), "message": "License restored"})


# ---------------------------------------------------------------------------
# runtime usage reporting (admin)
# ---------------------------------------------------------------------------
@api.post("/licenses/<string:license_key>/usage")
@require_admin
def report_license_usage(license_key: str):
    record = service.report_usage(license_key, _json_body())
    return (
        jsonify(
            {
                "license": record.to_dict(),
                "usage": record.usage_summary(),
                "message": "Usage recorded",
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# validation (public)
# ---------------------------------------------------------------------------
@api.post("/licenses/validate")
def validate_license():
    """
    Validate a license payload.

    Accepts a JSON envelope, ``{"license": ...}`` / ``{"token": ...}`` wrappers,
    or a compact token sent as a raw string body (curl --data-binary @file.lic).
    """
    payload = request.get_json(silent=True)
    if payload is None:
        raw = request.get_data(as_text=True).strip()
        # A compact token is three dot-separated segments; anything else that
        # is not valid JSON is a bad request rather than a malformed license.
        if not raw or raw.startswith("{") or len(raw.split(".")) != 3:
            raise ValidationFailed(
                "Request body must be a valid JSON license envelope "
                "or a compact token (header.payload.signature)"
            )
        payload = raw
    return jsonify(service.validate_license_payload(_config(), payload))


@api.post("/licenses/<string:license_key>/check")
def check_license_access(license_key: str):
    body = _json_body()
    result = service.check_access(
        license_key,
        feature=body.get("feature"),
        module_id=body.get("module_id"),
        limit_type=body.get("limit_type"),
        current_usage=body.get("current_usage"),
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# platform settings (Platform Settings screen)
# ---------------------------------------------------------------------------
@api.get("/settings")
def get_platform_settings():
    """Every settings group (defaults merged in) plus the render schema."""
    return jsonify(
        {"settings": service.get_settings(), "schema": service.settings_schema()}
    )


@api.get("/settings/audit")
def get_settings_audit():
    """Config audit changelog: which fields changed, by whom, and when."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.settings_audit(limit))


@api.put("/settings/<string:group>")
@require_admin
def put_platform_settings(group: str):
    """Replace fields in one settings group (validated, audited, committed)."""
    body = _json_body()
    actor = (request.headers.get("X-Actor") or "admin").strip()[:64] or "admin"
    return jsonify(service.update_settings(group, body, actor=actor))


# ---------------------------------------------------------------------------
# dashboard (Command Center + Compliance screens)
# ---------------------------------------------------------------------------
def _actor(default: str = "admin") -> str:
    """Who is acting: a bound principal's own name (its credential is the
    identity - X-Actor is not consulted, as for pipeline and agent tokens),
    else a live console session's username (a session is an identity too,
    not an ambient header), else the X-Actor header, else the configured
    default. The admin token keeps the X-Actor convention."""
    principal = getattr(g, "rbac_principal", None)
    if principal is not None and principal.get("kind") != "admin-token":
        return str(principal.get("principal") or default)[:64] or default
    if principal is None:
        console_user = getattr(g, "console_user", None)
        if console_user is not None:
            return str(getattr(console_user, "username", "") or default)[:64] or default
    return (request.headers.get("X-Actor") or default).strip()[:64] or default


@api.get("/overview")
def get_overview():
    """One aggregate: health, license posture, vault, settings, activity."""
    return jsonify(service.overview())


@api.get("/events")
def get_events():
    """Recent entries from the immutable audit ledger (architecture 19),
    across every trail, newest first."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.unified_events(source=request.args.get("source"), limit=limit))


# ---------------------------------------------------------------------------
# enterprise integrations (architecture section 20: MFA / ITSM / SIEM / LDAP)
# ---------------------------------------------------------------------------
@api.get("/integrations/status")
def get_integrations_status():
    """Every connector's real state - MFA factor, ITSM, SIEM outbound
    push, LDAP - plus the last push result. `not connected` is a measured
    fact here, never a placeholder."""
    return jsonify(service.integrations_status())


@api.post("/mfa/enroll")
@require_admin
def enroll_mfa_factor():
    """Generate this operator's TOTP factor (RFC 6238). The secret is
    returned exactly once, for the authenticator app, and stored sealed."""
    body = _json_body(required=False)
    return jsonify(service.mfa_enroll(body, actor=_actor())), 201


@api.post("/mfa/verify")
@require_admin
def verify_mfa_code():
    """Check a 6-digit code against the enrolled factor for real."""
    return jsonify(service.mfa_verify(_json_body(), actor=_actor()))


@api.post("/itsm/verify")
@require_admin
def verify_itsm_ticket():
    """Ask the configured ITSM instance whether a ticket exists - a real
    HTTP GET, 409 when no instance is configured."""
    body = _json_body()
    ticket = body.get("ticket")
    if not isinstance(ticket, str) or not ticket.strip():
        raise ValidationFailed("'ticket' is required", {"field": "ticket"})
    ticket = ticket.strip()
    if len(ticket) > 64:
        raise ValidationFailed(
            "'ticket' must be at most 64 characters",
            {"field": "ticket", "max_length": 64},
        )
    outcome = service.itsm_verify_ticket(ticket, actor=_actor())
    if not outcome["configured"]:
        raise Conflict(
            "ITSM is not configured",
            {"field": "itsm", "configured": False, "detail": outcome["detail"]},
        )
    return jsonify(outcome)


@api.post("/auth/ldap")
def ldap_login():
    """Verify credentials with a real LDAP bind (section 20 IAM). In token
    mode a successful bind returns a short-lived ticket the admin routes
    accept beside the admin token - and a role binding (kind `ldap`) decides
    what that directory username may do with it; in open dev mode there is
    nothing to grant and the response says so."""
    result = service.ldap_login(
        _json_body(), actor=_actor(default=""), config=_config()
    )
    return jsonify(result)


@api.get("/auth/whoami")
def whoami():
    """Who the caller is and what their role may call (section 10): open
    mode, the admin token, a role binding's token, or a directory login
    ticket. Honest 401 without a credential, honest 403 for a directory
    identity that has no binding."""
    config = _config()
    if not config.admin_token:
        return jsonify(
            {
                "mode": "open",
                "principal": "open-dev-mode",
                "role": "admin",
                "kind": "open",
                "scope": None,
                "operations": "all",
                "operations_count": len(service.ADMIN_OPERATIONS),
            }
        )
    principal = service.resolve_principal(_presented_credential(), config=config)
    if principal is None:
        raise Unauthorized(
            "Admin token required (Authorization: Bearer <token> or X-Admin-Token)"
        )
    if principal.get("unbound"):
        raise _unbound_principal_error(principal)
    operations = service.operations_for_role(principal["role"])
    return jsonify(
        {
            "mode": "token",
            "principal": principal["principal"],
            "role": principal["role"],
            "kind": principal["kind"],
            "scope": principal.get("scope"),
            "operations": operations,
            "operations_count": len(operations),
        }
    )


# ---------------------------------------------------------------------------
# SSO (architecture Identity: SAML 2.0 + OIDC) - the settings group as a
# real login path. The login/callback/metadata routes are public by design
# (they are the IdP handshake); the session an SSO login mints carries the
# caller's role through a binding (kind `sso`) exactly like the 6b rules.
# ---------------------------------------------------------------------------
def _external_base() -> str:
    return request.host_url.rstrip("/")


@api.get("/auth/sso/status")
def sso_status():
    """Runtime truth for the settings screen: what is configured AND what
    has actually happened (subjects, active sessions, last login)."""
    return jsonify(sso.status(external_base=_external_base()))


@api.get("/auth/sso/metadata")
def sso_sp_metadata():
    """Our SP configuration as JSON (entity id, ACS URL, protocols) - what
    an IdP admin needs to register this SP, with no secrets on it."""
    base = _external_base()
    return jsonify(
        {
            "primary_entity_id": sso._slot_values("primary")["entity_id"],
            "acs_url": f"{base}/api/v1/auth/sso/saml/primary/acs",
            "login_urls": {
                slot: f"{base}/api/v1/auth/sso/saml/{slot}/login" for slot in sso.SSO_SLOTS
            },
            "oidc_redirect_uris": {
                slot: f"{base}/api/v1/auth/sso/oidc/{slot}/callback" for slot in sso.SSO_SLOTS
            },
            "saml_metadata_urls": {
                slot: f"{base}/api/v1/auth/sso/saml/{slot}/metadata" for slot in sso.SSO_SLOTS
            },
            "protocol": sso._settings().get("protocol", "saml2"),
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
    )


@api.get("/auth/sso/saml/<slot>/metadata")
def sso_saml_metadata(slot):
    """Our SP metadata as SAML XML - paste straight into the IdP."""
    xml, entity_id = sso.saml_metadata(external_base=_external_base(), slot=slot)
    return Response(
        xml,
        mimetype="application/saml-metadata+xml",
        headers={"X-SP-Entity-ID": entity_id},
    )


@api.get("/auth/sso/saml/<slot>/login")
def sso_saml_login(slot):
    """Start a SAML login: a real AuthnRequest (single-use flow row) and a
    302 to the IdP's HTTP-POST SingleSignOnService."""
    url, flow_id = sso.saml_login_redirect(external_base=_external_base(), slot=slot)
    response = redirect(url)
    response.headers["X-SSO-Flow"] = flow_id
    return response


@api.post("/auth/sso/saml/<slot>/acs")
def sso_saml_acs(slot):
    """The IdP's ACS POST: verify the signature chain end to end, then mint
    the session. Refusals are recorded on the `sso` ledger trail."""
    result = sso.saml_acs(
        slot, request.form.get("SAMLResponse") or "", external_base=_external_base()
    )
    return jsonify(result)


@api.get("/auth/sso/oidc/<slot>/login")
def sso_oidc_login(slot):
    """Start an OIDC login: authorization-code + PKCE (S256) + nonce, 302
    to the provider's authorization endpoint."""
    url, flow_id = sso.oidc_login_redirect(external_base=_external_base(), slot=slot)
    response = redirect(url)
    response.headers["X-SSO-Flow"] = flow_id
    return response


@api.get("/auth/sso/oidc/<slot>/callback")
def sso_oidc_callback(slot):
    """The OIDC callback: exchange the code, verify the id_token against the
    provider JWKS (RS256 only), mint the session."""
    result = sso.oidc_callback(
        slot,
        request.args.get("code") or "",
        request.args.get("state") or "",
        external_base=_external_base(),
    )
    return jsonify(result)


@api.post("/auth/sso/logout")
def sso_logout():
    """End the caller's own SSO session - the bearer token is the
    authorization, no admin role required (self-service)."""
    return jsonify(sso.logout(_presented_credential()))


@api.get("/auth/sso/sessions")
@require_admin
def sso_sessions_list():
    """Every SSO session (active by default; ?active=all includes expired
    and revoked ones as evidence)."""
    return jsonify(sso.list_sessions(active_only=request.args.get("active") != "all"))


@api.post("/auth/sso/sessions/<int:session_id>/revoke")
@require_admin
def sso_sessions_revoke(session_id):
    """Revoke one SSO session: the bearer stops authenticating immediately."""
    return jsonify(sso.revoke_session(session_id, actor=_actor(default="admin")))


# ---------------------------------------------------------------------------
# HSM / KMS master-key custody (architecture section 20)
# ---------------------------------------------------------------------------
@api.get("/hsm/status")
@require_admin
def hsm_status():
    """Custody state: provider, advisory/enforced mode, seal, wrap file,
    rotation due, last health probe."""
    return jsonify(hsm.status(config=_config()))


@api.post("/hsm/seal")
@require_admin
def hsm_seal():
    """Seal the vault: drop every trace of key material from this process;
    vault operations now fail with 503 until an explicit unseal."""
    payload = _json_body() or {}
    reason = str(payload.get("reason") or "operator seal")
    if len(reason) > 200:
        raise ValidationFailed("reason must be at most 200 characters", {"field": "reason"})
    return jsonify(hsm.seal_vault(actor=_actor(default="admin"), reason=reason))


@api.post("/hsm/unseal")
@require_admin
def hsm_unseal():
    """Unseal: advisory mode reloads the file key; enforced mode must unwrap
    through the provider (a dead provider keeps the vault sealed, said so)."""
    return jsonify(hsm.unseal_vault(actor=_actor(default="admin"), config=_config()))


@api.post("/hsm/keys/rotate")
@require_admin
def hsm_keys_rotate():
    """Re-wrap (or first-wrap) the same master key under the configured
    provider - custody moves, key material never changes, every existing
    ciphertext stays valid."""
    return jsonify(hsm.wrap_current_key(_config(), actor=_actor(default="admin")))


# ---------------------------------------------------------------------------
# immutable audit ledger (architecture 19, Compliance screen)
# ---------------------------------------------------------------------------
@api.get("/audit/stats")
def audit_stats():
    """Ledger aggregates: totals by source, chain head, trigger protection."""
    return jsonify(service.audit_stats())


@api.get("/audit/verify")
def audit_verify():
    """Walk the whole hash chain and report the first break, if any."""
    return jsonify(service.audit_verify())


@api.get("/audit/export")
def audit_export():
    """The full ledger in chain order as newline-delimited JSON (NDJSON) -
    the same records a SIEM would ingest."""
    # evaluated inside the request context; the generator only serialises it
    records = service.audit_export_rows()

    def generate():
        for row in records:
            yield json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="vy-pam-audit.ndjson"'
        },
    )


# ---------------------------------------------------------------------------
# credential vault (Credential Vault screen)
# ---------------------------------------------------------------------------
@api.get("/vault/stats")
def get_vault_stats():
    """Inventory aggregates: totals by type/status, rotation compliance."""
    return jsonify(service.vault_stats())


@api.get("/vault/items")
def list_vault_items():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_vault_items(
        q=request.args.get("q"),
        secret_type=request.args.get("type"),
        status=request.args.get("status"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/vault/items/<int:item_id>")
def get_vault_item(item_id: int):
    item = service.get_vault_item(item_id)
    payload = item.to_dict()
    payload["events"] = [
        event.to_dict() for event in service.vault_item_events(item_id, limit=10)
    ]
    return jsonify({"item": payload})


@api.post("/vault/items")
@require_admin
def create_vault_item():
    item = service.onboard_vault_item(_json_body(), actor=_actor())
    return jsonify({"item": item.to_dict(), "message": "Credential onboarded"}), 201


@api.post("/vault/items/<int:item_id>/checkout")
@require_admin
def checkout_vault_item(item_id: int):
    _require_scope(item_id=item_id)
    body = _json_body(required=False)
    item = service.checkout_vault_item(
        item_id, actor=_actor(), reason=body.get("reason")
    )
    return jsonify({"item": item.to_dict(), "message": "Credential checked out"})


@api.post("/vault/items/<int:item_id>/revoke")
@require_admin
def revoke_vault_checkout(item_id: int):
    _require_scope(item_id=item_id)
    item = service.revoke_vault_checkout(item_id, actor=_actor())
    return jsonify({"item": item.to_dict(), "message": "Checkout revoked"})


@api.get("/vault/items/<int:item_id>/secret")
@require_admin
def reveal_vault_secret(item_id: int):
    """Decrypt and return the current secret version (admin-only reveal);
    the reveal itself is an audited ledger event."""
    _stepup_if_human()
    _require_scope(item_id=item_id)
    return jsonify(service.reveal_vault_secret(item_id, actor=_actor()))


@api.post("/vault/items/<int:item_id>/rotate")
@require_admin
def rotate_vault_item(item_id: int):
    _require_scope(item_id=item_id)
    item, detail = service.rotate_vault_item(item_id, actor=_actor())
    return jsonify(
        {"item": item.to_dict(), "rotation": detail, "message": "Rotation recorded"}
    )


@api.get("/vault/events")
def get_vault_events():
    """Vault audit trail (onboarding, checkouts, rotations), newest first."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    return jsonify(service.vault_events(limit, action=request.args.get("action")))


# ---------------------------------------------------------------------------
# rotation engine (module 5: scheduled + event-based password rotation)
# ---------------------------------------------------------------------------
@api.post("/rotation/run")
@require_admin
def run_rotations():
    """Run the engine over due credentials (or explicit `item_ids`)."""
    return jsonify(service.run_rotations(_json_body(required=False), actor=_actor()))


@api.post("/rotation/session-end")
@require_admin
def rotation_session_end():
    """Event-based trigger: a checkout's session ended -> rotate now."""
    item, detail = service.rotation_session_end(_json_body(), actor=_actor())
    return jsonify(
        {
            "item": item.to_dict(),
            "rotation": detail,
            "message": "Session-end rotation recorded",
        }
    )


# ---------------------------------------------------------------------------
# JIT / JEA access (module 6: request -> risk -> approvals -> grant -> expiry)
# ---------------------------------------------------------------------------
@api.get("/jit/stats")
def jit_stats():
    """Real queue counts: totals, per-status, per-risk."""
    return jsonify(service.jit_stats())


@api.get("/jit/requests")
def list_jit_requests():
    """JIT queue, newest first (status/requester filters, pagination)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_jit_requests(
        status=request.args.get("status"),
        requester=request.args.get("requester"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [item.to_dict() for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/jit/requests")
@require_admin
def create_jit_request():
    """File one access request: risk is evaluated over real context."""
    item = service.create_jit_request(_json_body(), actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Request filed"}), 201


@api.get("/jit/requests/<int:request_id>")
def get_jit_request(request_id: int):
    """One request with its audit trail (evaluates expiry on the way)."""
    return jsonify(service.jit_request_detail(request_id))


@api.post("/jit/requests/<int:request_id>/approve")
@require_admin
def approve_jit_request(request_id: int):
    """Record a manager/security approval (403 for self-approval)."""
    _stepup_if_human()
    item = service.approve_jit_request(
        request_id, actor=_actor(), payload=_json_body()
    )
    return jsonify({"request": item.to_dict(), "message": "Approval recorded"})


@api.post("/jit/requests/<int:request_id>/deny")
@require_admin
def deny_jit_request(request_id: int):
    """Reject a pending or policy-blocked request (audited)."""
    item = service.deny_jit_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify({"request": item.to_dict(), "message": "Request denied"})


@api.post("/jit/requests/<int:request_id>/consume")
@require_admin
def consume_jit_request(request_id: int):
    """Grant an approved request: credential checked out until expires_at."""
    item = service.consume_jit_request(request_id, actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Access granted"})


@api.post("/jit/requests/<int:request_id>/close")
@require_admin
def close_jit_request(request_id: int):
    """End an active grant early: release the checkout and rotate."""
    item = service.close_jit_request(request_id, actor=_actor())
    return jsonify({"request": item.to_dict(), "message": "Access closed and credential rotated"})


# ---------------------------------------------------------------------------
# privileged session management (module 8: record -> monitor -> control)
# ---------------------------------------------------------------------------
@api.get("/sessions/stats")
def session_stats():
    """Real monitoring aggregates: per-status counts and recording totals."""
    return jsonify(service.session_stats())


@api.get("/sessions")
def list_sessions():
    """Live session list, newest first (status/protocol/search filters)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    items, total = service.list_sessions(
        status=request.args.get("status"),
        protocol=request.args.get("protocol"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    rows = [item.to_dict() for item in items]
    states = gateway.states_for_sessions([item.id for item in items])
    for row, item in zip(rows, items):
        # phase 8a: the compact data-plane state per row (node + zone +
        # injection fact) so live monitoring sees the real gateway view
        row["gateway"] = states.get(item.id)
    return jsonify(
        {
            "items": rows,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/sessions")
@require_admin
def create_session():
    """Start a session: protocol + target, optional checkout or JIT grant.
    The request is scored first (architecture 7); CRITICAL/HIGH-without-
    approval answers 403 with the evaluation that refused it."""
    body = _json_body()
    if body.get("target"):
        _require_scope(target=str(body["target"]))
    session, risk = service.create_session(body, actor=_actor())
    return (
        jsonify(
            {
                "session": session.to_dict(),
                "risk": risk.to_dict(),
                # phase 8a: this request's broker verdict - the node it was
                # dispatched to, or the honest reason it was not
                "gateway": getattr(session, "_gateway_info", None),
                "message": "Session started",
            }
        ),
        201,
    )


@api.get("/sessions/<int:session_id>")
def get_session(session_id: int):
    """One session with its latest recorded events (evaluates grant expiry)."""
    return jsonify(service.session_detail(session_id))


@api.get("/sessions/<int:session_id>/events")
def get_session_events(session_id: int):
    """Playback: the recording in sequence order (asc by default)."""
    limit = min(_int_param("limit", 500), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_session_events(
        session_id,
        limit=limit,
        offset=offset,
        event_type=request.args.get("type"),
        order=request.args.get("order", "asc"),
    )
    return jsonify(
        {
            "events": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/sessions/<int:session_id>/events")
@require_admin
def post_session_event(session_id: int):
    """Record one channel event; controls are enforced for real and command
    events carry their policy decision (an escalated block also returns the
    incident it raised)."""
    event, escalation = service.post_session_event(
        session_id, _json_body(), actor=_actor()
    )
    body = {"event": event.to_dict(), "message": "Event recorded"}
    if escalation is not None:
        body["escalation"] = escalation
    return jsonify(body), 201


@api.post("/sessions/<int:session_id>/controls")
@require_admin
def update_session_controls(session_id: int):
    """Flip control flags (record, watermark, clipboard, transfer...)."""
    session = service.update_session_controls(
        session_id, _json_body(), actor=_actor()
    )
    return jsonify({"session": session.to_dict(), "message": "Controls updated"})


@api.post("/sessions/<int:session_id>/pause")
@require_admin
def pause_session(session_id: int):
    """Supervisor pause: the channel refuses events until resumed."""
    session = service.pause_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session paused"})


@api.post("/sessions/<int:session_id>/lock")
@require_admin
def lock_session(session_id: int):
    """Lock pending review: events refused until resumed."""
    session = service.lock_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session locked"})


@api.post("/sessions/<int:session_id>/resume")
@require_admin
def resume_session(session_id: int):
    """Resume a paused or locked session."""
    session = service.resume_session(session_id, actor=_actor())
    return jsonify({"session": session.to_dict(), "message": "Session resumed"})


@api.post("/sessions/<int:session_id>/terminate")
@require_admin
def terminate_session(session_id: int):
    """Kill switch: end the session, release its checkout, rotate once."""
    session, detail = service.end_session(
        session_id,
        actor=_actor(),
        outcome="terminated",
        payload=_json_body(required=False),
    )
    return jsonify(
        {
            "session": session.to_dict(),
            "cascade": detail,
            "message": "Session terminated",
        }
    )


@api.post("/sessions/<int:session_id>/complete")
@require_admin
def complete_session(session_id: int):
    """Natural end: same release-and-rotate cascade as terminate."""
    session, detail = service.end_session(
        session_id,
        actor=_actor(),
        outcome="completed",
        payload=_json_body(required=False),
    )
    return jsonify(
        {
            "session": session.to_dict(),
            "cascade": detail,
            "message": "Session completed",
        }
    )


# ---------------------------------------------------------------------------
# command control (module 9: policy rules, dry-run, approvals, incidents)
# ---------------------------------------------------------------------------
@api.get("/command-control/stats")
def command_control_stats():
    """Real aggregates: rule counts, today's intercepts, approval queue,
    incident posture and a content hash of the current policy."""
    return jsonify(service.command_control_stats())


@api.get("/command-control/rules")
def list_command_rules():
    """Every rule in evaluation order with its real match counts."""
    raw_enabled = request.args.get("enabled")
    enabled = None
    if raw_enabled is not None:
        if raw_enabled not in ("true", "false", "1", "0"):
            raise ValidationFailed(
                "Query parameter 'enabled' must be true or false",
                {"field": "enabled"},
            )
        enabled = raw_enabled in ("true", "1")
    return jsonify(
        service.list_command_rules(
            action=request.args.get("action"),
            q=request.args.get("q"),
            enabled=enabled,
        )
    )


@api.post("/command-control/rules")
@require_admin
def create_command_rule():
    """Add a policy rule (name, pattern, action, optional target scope)."""
    rule = service.create_command_rule(_json_body(), actor=_actor())
    return jsonify({"rule": rule.to_dict(), "message": "Rule created"}), 201


@api.put("/command-control/rules/<int:rule_id>")
@require_admin
def update_command_rule(rule_id: int):
    """Edit a rule in place (partial update: send only what changed)."""
    rule = service.update_command_rule(rule_id, _json_body(), actor=_actor())
    return jsonify({"rule": rule.to_dict(), "message": "Rule updated"})


@api.delete("/command-control/rules/<int:rule_id>")
@require_admin
def delete_command_rule(rule_id: int):
    """Remove a rule; recorded events keep their rule_id as history."""
    result = service.delete_command_rule(rule_id)
    return jsonify({"deleted": result["deleted"], "message": "Rule deleted"})


@api.post("/command-control/evaluate")
def evaluate_command():
    """Dry-run one command line against the live policy - no state changes."""
    payload = _json_body()
    command = payload.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValidationFailed("'command' is required", {"field": "command"})
    if len(command) > 4096:
        raise ValidationFailed(
            "'command' must be at most 4096 characters", {"field": "command"}
        )
    target = payload.get("target", "")
    if target is None:
        target = ""
    if not isinstance(target, str) or len(target) > 255:
        raise ValidationFailed(
            "'target' must be a string of at most 255 characters",
            {"field": "target"},
        )
    return jsonify({"result": service.evaluate_command(command, target)})


@api.get("/command-control/approvals")
def pending_command_approvals():
    """Held commands awaiting a decision (active sessions only)."""
    return jsonify(service.pending_command_approvals())


@api.get("/command-control/incidents")
def list_command_incidents():
    """Escalation incidents, newest first (status: open/closed/all)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    return jsonify(
        service.list_command_incidents(
            status=request.args.get("status"), limit=limit, offset=offset
        )
    )


@api.get("/command-control/incidents/<int:incident_id>")
def get_command_incident(incident_id: int):
    """One incident with its preserved evidence."""
    return jsonify({"incident": service.get_command_incident(incident_id).to_dict()})


@api.post("/command-control/incidents/<int:incident_id>/close")
@require_admin
def close_command_incident(incident_id: int):
    """Close an incident after review (note optional, recorded with who/when)."""
    incident = service.close_command_incident(
        incident_id, _json_body(required=False), actor=_actor()
    )
    return jsonify({"incident": incident.to_dict(), "message": "Incident closed"})


@api.post("/sessions/<int:session_id>/events/<int:seq>/approve")
@require_admin
def approve_session_command(session_id: int, seq: int):
    """Release a held command: the recording gets an `approved` row that
    references it (append-only - the hold itself is never edited)."""
    original, resolution = service.resolve_command_approval(
        session_id, seq, approve=True, actor=_actor()
    )
    return jsonify(
        {
            "event": original.to_dict(),
            "resolution": resolution.to_dict(),
            "message": "Command approved",
        }
    )


@api.post("/sessions/<int:session_id>/events/<int:seq>/deny")
@require_admin
def deny_session_command(session_id: int, seq: int):
    """Deny a held command: an append-only `denied` row records the decision."""
    original, resolution = service.resolve_command_approval(
        session_id, seq, approve=False, actor=_actor()
    )
    return jsonify(
        {
            "event": original.to_dict(),
            "resolution": resolution.to_dict(),
            "message": "Command denied",
        }
    )


# ---------------------------------------------------------------------------
# discovery engine (Discovery / Target Infrastructure screen)
# ---------------------------------------------------------------------------
@api.get("/discovery/stats")
def get_discovery_stats():
    """Aggregate counts: total assets, per-type/risk/status, last scan."""
    return jsonify(service.discovery_stats())


@api.get("/discovery/assets")
def list_discovered_assets():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    assets, total = service.list_discovered_assets(
        q=request.args.get("q"),
        asset_type=request.args.get("type"),
        risk=request.args.get("risk"),
        pam_status=request.args.get("pam_status"),
        limit=limit,
        offset=offset,
    )
    counts = service.vault_counts_by_target([asset.address for asset in assets])
    return jsonify(
        {
            "assets": [
                dict(asset.to_dict(), vault_count=counts.get(asset.address, 0))
                for asset in assets
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/discovery/assets")
@require_admin
def onboard_discovered_asset():
    """Manual target registration + vault ingestion in one call."""
    asset, item = service.onboard_asset(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "asset": asset.to_dict(),
                "vault_item": item.to_dict(),
                "message": "Target onboarded",
            }
        ),
        201,
    )


@api.patch("/discovery/assets/<int:asset_id>")
@require_admin
def patch_discovered_asset(asset_id: int):
    """Operator overrides: pam_status (ignore/restore), reclassification."""
    asset = service.update_asset(asset_id, _json_body(), actor=_actor())
    return jsonify({"asset": asset.to_dict(), "message": "Asset updated"})


@api.post("/discovery/assets/<int:asset_id>/onboard")
@require_admin
def adopt_discovered_asset(asset_id: int):
    """Adopt a discovered asset: mark managed + ingest its admin account."""
    asset, item = service.adopt_asset(asset_id, _json_body(), actor=_actor())
    return (
        jsonify(
            {
                "asset": asset.to_dict(),
                "vault_item": item.to_dict(),
                "message": "Target onboarded",
            }
        ),
        201,
    )


@api.get("/discovery/accounts")
def list_discovered_accounts():
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    accounts, total = service.list_discovered_accounts(
        q=request.args.get("q"),
        kind=request.args.get("kind"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "accounts": [account.to_dict() for account in accounts],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/discovery/scans")
def list_discovery_scans():
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    scans, total = service.list_scans(limit=limit)
    return jsonify(
        {
            "scans": [scan.to_dict() for scan in scans],
            "total": total,
            "limit": limit,
        }
    )


@api.post("/discovery/scans")
@require_admin
def start_discovery_scan():
    """Run a real TCP-connect scan (bounded, single-flight, synchronous)."""
    scan = service.start_scan(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "scan": scan.to_dict(),
                "message": (
                    f"Scan finished: {scan.hosts_open}/{scan.hosts_probed} hosts "
                    f"open, {scan.findings} new asset(s)"
                ),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# risk-based access engine (architecture section 7, Policy screen)
# ---------------------------------------------------------------------------
@api.post("/risk/evaluate")
@require_admin
def evaluate_risk():
    """Score one access request over the eight components (user, device,
    asset, time, location, behavior, ticket, command) - every point traces
    to a measured input - and record the evaluation."""
    evaluation = service.evaluate_risk(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "evaluation": evaluation.to_dict(),
                "message": (
                    f"Scored {evaluation.score}/100 - {evaluation.band} "
                    f"({evaluation.decision})"
                ),
            }
        ),
        201,
    )


@api.get("/risk/evaluations")
def list_risk_evaluations():
    """The recorded evaluations, newest first (band/context filters)."""
    limit = min(_int_param("limit", 20), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_risk_evaluations(
        band=request.args.get("band"),
        context=request.args.get("context"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "evaluations": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/risk/stats")
def risk_stats():
    """Real aggregates over the evaluations: bands, decisions, refusals."""
    return jsonify(service.risk_stats())


# ---------------------------------------------------------------------------
# UEBA behavior baselines and anomaly incidents (architecture section 11)
# ---------------------------------------------------------------------------


@api.get("/risk/baselines")
def list_risk_baselines():
    """Trained per-principal behavior baselines (hours, devices, source
    IPs, targets, command verbs, privilege verbs, cadence) - learned only
    from real history rows inside the rolling window."""
    return jsonify(service.list_behavior_baselines())


@api.post("/risk/baselines/train")
@require_admin
def train_risk_baselines():
    """Learn or refresh baselines from the product's own history: every
    principal in the window, or just `subject` when the body names one.
    No history, no baseline - normality is never invented."""
    payload = _json_body(required=False)
    rows = service.train_behavior_baselines(
        subject=payload.get("subject"), actor=_actor()
    )
    return (
        jsonify(
            {
                "trained": len(rows),
                "baselines": [row.to_dict() for row in rows],
                "message": (
                    f"Trained {len(rows)} baseline(s) from real history"
                ),
            }
        ),
        200,
    )


@api.get("/risk/anomalies")
def list_risk_anomalies():
    """Recorded UEBA incidents (architecture section 11), newest first:
    the evaluation, the named deviations and the response chain it ran."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    return jsonify(
        service.list_anomaly_events(
            subject=request.args.get("subject"), limit=limit, offset=offset
        )
    )


# ---------------------------------------------------------------------------
# PAM bypass detection (architecture section 10, Command Center screen)
# ---------------------------------------------------------------------------
@api.post("/bypass/ingest")
@require_admin
def ingest_bypass_signals():
    """Parse a real log bundle (auth.log / Windows / EDR export) into
    connection observations - evidence only, no verdicts yet."""
    detail = service.ingest_bypass_signals(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "ingest": detail,
                "message": (
                    f"Stored {detail['stored']}/{detail['lines']} line(s) from "
                    f"{detail['origin']} ({detail['malformed']} malformed, "
                    f"{detail['duplicates']} duplicate)"
                ),
            }
        ),
        201,
    )


@api.get("/bypass/signals")
def list_bypass_signals():
    """Parsed observations, newest first (status + text-search filters)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_bypass_signals(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "signals": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.post("/bypass/scans")
@require_admin
def scan_bypass_signals():
    """Correlate every unscanned observation: managed target + no covering
    session opens an incident with the section-10 ACTION block."""
    result = service.scan_bypass_signals(actor=_actor())
    return (
        jsonify(
            {
                "scan": result,
                "message": (
                    f"Correlated {result['scanned']}: {result['covered']} covered, "
                    f"{result['out_of_scope']} out of scope, "
                    f"{result['incidents']} new incident(s), "
                    f"{result['rotations_forced']} forced rotation(s)"
                ),
            }
        ),
        201,
    )


@api.get("/bypass/incidents")
def list_bypass_incidents():
    """Detected direct-access incidents, newest first (open/closed/all)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_bypass_incidents(
        status=request.args.get("status"), limit=limit, offset=offset
    )
    return jsonify(
        {
            "incidents": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/bypass/incidents/<int:incident_id>")
def get_bypass_incident(incident_id: int):
    """One incident with its parsed log-line evidence."""
    incident, signal = service.get_bypass_incident(incident_id)
    return jsonify(
        {"incident": incident.to_dict(), "evidence": signal.to_dict() if signal else None}
    )


@api.post("/bypass/incidents/<int:incident_id>/close")
@require_admin
def close_bypass_incident(incident_id: int):
    """Analyst closure - recorded on the `bypass` trail in the same commit."""
    incident = service.close_bypass_incident(
        incident_id, _json_body(required=False), actor=_actor()
    )
    return jsonify(
        {
            "incident": incident.to_dict(),
            "message": f"Incident {incident.incident_ref} closed",
        }
    )


@api.get("/bypass/stats")
def bypass_stats():
    """Real aggregates: signal states, open incidents, forced rotations."""
    return jsonify(service.bypass_stats())


# ---------------------------------------------------------------------------
# break glass (architecture section 17)
# ---------------------------------------------------------------------------
@api.post("/break-glass/requests")
@require_admin
def create_break_glass_request():
    """File one emergency request: reason + severity + target, awaiting two
    distinct approvals before any credential is released."""
    _stepup_if_human()
    req = service.create_break_glass_request(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "request": service.break_glass_view(req),
                "message": (
                    f"Emergency request {req.request_ref} filed "
                    "(2 distinct approvals required)"
                ),
            }
        ),
        201,
    )


@api.get("/break-glass/requests")
def list_break_glass_requests():
    """Emergency requests, newest first (status filter + paging)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_break_glass_requests(
        status=request.args.get("status"), limit=limit, offset=offset
    )
    return jsonify(
        {
            "requests": [service.break_glass_view(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/break-glass/requests/<int:request_id>")
def get_break_glass_request(request_id: int):
    """One request with its approval snapshots and its recorded session."""
    return jsonify(service.get_break_glass_detail(request_id))


@api.post("/break-glass/requests/<int:request_id>/approve")
@require_admin
def approve_break_glass_request(request_id: int):
    """Record one approval signature (1/2, then 2/2 flips to approved)."""
    _stepup_if_human()
    view = service.approve_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    signed = view["approvals_signed"]
    message = (
        f"Dual approval complete for {view['request_ref']} (2/2)"
        if signed >= 2
        else f"Approval {signed}/2 recorded for {view['request_ref']}"
    )
    return jsonify({"request": view, "message": message})


@api.post("/break-glass/requests/<int:request_id>/deny")
@require_admin
def deny_break_glass_request(request_id: int):
    """Turn the request down before anything was released."""
    view = service.deny_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "request": view,
            "message": (
                f"Request {view['request_ref']} denied by {view['denied_by']}"
            ),
        }
    )


@api.post("/break-glass/requests/<int:request_id>/open")
@require_admin
def open_break_glass_request(request_id: int):
    """Release the emergency credential through the real vault checkout and
    start the mandatory recorded session (record=true forced)."""
    _stepup_if_human()
    result = service.open_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    return (
        jsonify(
            {
                **result,
                "message": (
                    f"Emergency credential released; recorded session "
                    f"{result['session']['session_ref']} is open"
                ),
            }
        ),
        201,
    )


@api.post("/break-glass/requests/<int:request_id>/close")
@require_admin
def close_break_glass_request(request_id: int):
    """End the emergency: session stopped, credential rotated, post-incident
    review note filed (the note is required)."""
    result = service.close_break_glass_request(
        request_id, actor=_actor(), payload=_json_body(required=False)
    )
    rotation = result["rotation"]
    return jsonify(
        {
            **result,
            "message": (
                f"Emergency {result['request']['request_ref']} closed; "
                f"rotation {rotation.get('status')}"
            ),
        }
    )


@api.get("/break-glass/stats")
def break_glass_stats():
    """Real aggregates: request states, approval signatures, ledger actions."""
    return jsonify(service.break_glass_stats())



# ---------------------------------------------------------------------------
# third-party / vendor PAM (architecture section 13)
# ---------------------------------------------------------------------------
@api.post("/vendors")
@require_admin
def invite_vendor():
    """Invite a third-party vendor (201): the account starts `invited` and
    the TOTP seed + otpauth URI come back once, here, never again."""
    view = service.invite_vendor(_json_body(), actor=_actor())
    name = view["vendor"]["name"]
    return (
        jsonify(
            {
                **view,
                "message": (
                    f"Vendor {name} invited - MFA secret shown once"
                ),
            }
        ),
        201,
    )


@api.get("/vendors")
def list_vendors():
    """Vendor accounts, newest first (status filter + search + paging)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_vendors(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "vendors": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/vendors/<int:vendor_id>")
def get_vendor(vendor_id: int):
    """The vendor dashboard payload: chain steps, access/denied lists,
    valid window, recording state, grants raised and the recent trail."""
    return jsonify(service.vendor_detail(vendor_id))


@api.patch("/vendors/<int:vendor_id>")
@require_admin
def update_vendor(vendor_id: int):
    """Edit contact and access scope (allowed/denied targets, valid window,
    recording, expiry) on an invited or approved account."""
    view = service.update_vendor(vendor_id, _json_body(), actor=_actor())
    return jsonify({"vendor": view, "message": f"Vendor {view['name']} updated"})


@api.post("/vendors/<int:vendor_id>/mfa")
@require_admin
def verify_vendor_mfa(vendor_id: int):
    """Step 1 - verify the vendor's TOTP code (real RFC-6238)."""
    view = service.verify_vendor_mfa(vendor_id, _json_body(), actor=_actor())
    return jsonify(
        {"vendor": view, "message": f"MFA verified for {view['name']}"}
    )


@api.post("/vendors/<int:vendor_id>/nda")
@require_admin
def sign_vendor_nda(vendor_id: int):
    """Step 2 - record the NDA/agreement acceptance."""
    view = service.sign_vendor_nda(vendor_id, _json_body(required=False), actor=_actor())
    ref = view["nda"]["ref"]
    return jsonify(
        {
            "vendor": view,
            "message": (
                f"NDA signed for {view['name']}"
                + (f" ({ref})" if ref else "")
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/ticket")
@require_admin
def verify_vendor_ticket(vendor_id: int):
    """Step 3 - verify the ITSM ticket for real (409 while ITSM is not
    configured; the upstream's own answer on a failed check)."""
    view = service.verify_vendor_ticket(vendor_id, _json_body(), actor=_actor())
    return jsonify(
        {
            "vendor": view,
            "message": f"Ticket {view['ticket']} verified against ITSM",
        }
    )


@api.post("/vendors/<int:vendor_id>/approve")
@require_admin
def approve_vendor(vendor_id: int):
    """Step 4 - approve, refused with the exact steps still outstanding."""
    view = service.approve_vendor(vendor_id, actor=_actor())
    return jsonify(
        {
            "vendor": view,
            "message": (
                f"Vendor {view['name']} approved - access enabled inside its scope"
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/deny")
@require_admin
def deny_vendor(vendor_id: int):
    """Refuse the invite outright (the name may be re-invited later)."""
    view = service.deny_vendor(vendor_id, _json_body(required=False), actor=_actor())
    return jsonify({"vendor": view, "message": f"Vendor {view['name']} denied"})


@api.post("/vendors/<int:vendor_id>/revoke")
@require_admin
def revoke_vendor(vendor_id: int):
    """Withdraw the vendor: active grants close (credential rotated, live
    sessions ended) and the account turns `revoked`."""
    view = service.revoke_vendor(vendor_id, _json_body(required=False), actor=_actor())
    ended = view["grants_ended"]
    return jsonify(
        {
            "vendor": view["vendor"],
            "grants_ended": ended,
            "message": (
                f"Vendor {view['vendor']['name']} revoked"
                + (
                    f"; {len(ended)} grant(s) closed"
                    if ended
                    else ""
                )
            ),
        }
    )


@api.post("/vendors/<int:vendor_id>/requests")
@require_admin
def create_vendor_jit_request(vendor_id: int):
    """The vendor requests access inside its scope (201): the normal
    section-6 JIT request, linked to this account, ticket defaulting to
    the vendor's verified ITSM reference."""
    view = service.create_vendor_jit_request(
        vendor_id, _json_body(), actor=_actor()
    )
    return (
        jsonify(
            {
                "request": view,
                "message": (
                    f"Access request #{view['id']} filed for this vendor "
                    f"(risk: {view['risk']['level']}, status: {view['status']})"
                ),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# cloud PAM (architecture section 14: AWS / Azure / GCP / Kubernetes)
# ---------------------------------------------------------------------------
@api.post("/cloud/connectors")
@require_admin
def create_cloud_connector():
    """Register a cloud account/cluster (201): the credential stays in the
    vault and the row starts honest - `not connected`/`configured`, never
    `connected` before a real probe."""
    view = service.create_cloud_connector(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "connector": view,
                "message": (
                    f"Cloud connector {view['name']} registered "
                    f"({view['provider']}, {view['status']})"
                ),
            }
        ),
        201,
    )


@api.get("/cloud/connectors")
def list_cloud_connectors():
    """Cloud connectors, newest first (provider/status filters + search)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_cloud_connectors(
        provider=request.args.get("provider"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "connectors": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/cloud/connectors/<int:connector_id>")
def get_cloud_connector(connector_id: int):
    """The cloud console payload: connector, recent section-14 trail, RBAC
    grants raised through it, last inventory run."""
    return jsonify(service.cloud_connector_detail(connector_id))


@api.patch("/cloud/connectors/<int:connector_id>")
@require_admin
def update_cloud_connector(connector_id: int):
    """Edit the configuration; changing the endpoint drops the connector
    back to `configured` (the old probe described the old endpoint)."""
    view = service.update_cloud_connector(
        connector_id, _json_body(), actor=_actor()
    )
    return jsonify(
        {"connector": view, "message": f"Cloud connector {view['name']} updated"}
    )


@api.delete("/cloud/connectors/<int:connector_id>")
@require_admin
def delete_cloud_connector(connector_id: int):
    """Remove a connector (409 while open RBAC grants still ride it)."""
    return jsonify(service.delete_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/test")
@require_admin
def test_cloud_connector(connector_id: int):
    """A real reachability probe: GET the endpoint (with the vault
    credential when one is bound) and record what happened - 2xx makes it
    `connected`, anything else `error` with the honest reason."""
    return jsonify(service.test_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/discover")
@require_admin
def discover_cloud_connector(connector_id: int):
    """Inventory the cloud for real: the cloud's own API answers, new
    assets land under the `cloud` discovery source, and a failed run
    records the honest reason instead of inventing anything."""
    return jsonify(service.discover_cloud_connector(connector_id, actor=_actor()))


@api.post("/cloud/connectors/<int:connector_id>/rbac/requests")
@require_admin
def create_cloud_rbac_request(connector_id: int):
    """Kubernetes -> RBAC -> JIT -> ephemeral privilege -> audit (201):
    raise a section-6 JIT request whose grant applies a real RoleBinding
    for exactly the requested window; close/expiry removes it."""
    view = service.create_cloud_rbac_request(
        connector_id, _json_body(), actor=_actor()
    )
    return (
        jsonify(
            {
                "request": view["request"],
                "connector": view["connector"],
                "message": view["message"],
            }
        ),
        201,
    )


@api.get("/cloud/stats")
def cloud_stats():
    """Real aggregates: connectors by provider and state, the section-14
    trail's size, RBAC grants, cloud-discovered assets."""
    return jsonify(service.cloud_stats())


# ---------------------------------------------------------------------------
# CI/CD credential broker (architecture section 15: pipelines request
# short-lived credentials with an API token - no static secrets in CI)
# ---------------------------------------------------------------------------
@api.post("/broker/policies")
@require_admin
def create_broker_policy():
    """Register a pipeline identity (201). The API token is returned
    exactly once - it is stored as a sha256 hash and cannot be recovered."""
    policy, token = service.create_broker_policy(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "policy": policy.to_dict(),
                "token": token,
                "message": (
                    f"Broker policy {policy.name} registered "
                    f"({policy.ci_system}, {policy.approval_mode} approval) - "
                    "the API token is shown once"
                ),
            }
        ),
        201,
    )


@api.get("/broker/policies")
@require_admin
def list_broker_policies():
    """Pipeline identities and their policies, newest first."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_broker_policies(
        ci_system=request.args.get("ci_system"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "policies": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/broker/policies/<int:policy_id>")
@require_admin
def broker_policy_detail(policy_id: int):
    """One policy with its open credential count and latest trail."""
    return jsonify(service.broker_policy_detail(policy_id))


@api.patch("/broker/policies/<int:policy_id>")
@require_admin
def update_broker_policy(policy_id: int):
    """Edit the policy knobs (approval mode, TTL cap, scope, contact,
    expiry); a revoked policy's settings are frozen."""
    view = service.update_broker_policy(policy_id, _json_body(), actor=_actor())
    return jsonify(
        {"policy": view, "message": f"Broker policy {view['name']} updated"}
    )


@api.delete("/broker/policies/<int:policy_id>")
@require_admin
def revoke_broker_policy(policy_id: int):
    """Withdraw the identity: open credentials are closed first (released
    grants rotate like a JIT expiry), then the token stops authenticating."""
    view = service.revoke_broker_policy(
        policy_id, actor=_actor(), payload=_json_body(required=False)
    )
    closed_count = view.pop("credentials_closed", 0)
    return jsonify(
        {
            "policy": view,
            "credentials_closed": closed_count,
            "message": (
                f"Broker policy {view['name']} revoked "
                f"({closed_count} credential(s) closed)"
            ),
        }
    )


@api.post("/broker/credentials")
@require_pipeline
def create_broker_credential():
    """One credential request from the pipeline (201). An `auto` policy
    releases the secret in this same response; a `manual` policy lands the
    request in the approval queue and the pipeline releases it later."""
    policy = g.broker_policy
    credential, auto = service.create_broker_credential(_json_body(), policy=policy)
    if auto:
        released = service.release_broker_credential(credential.id, policy=policy)
        return (
            jsonify(
                {
                    "credential": released["credential"],
                    "secret": released["secret"],
                    "message": (
                        f"Credential {credential.id} approved by policy and "
                        "released once - it expires at the timestamp above"
                    ),
                }
            ),
            201,
        )
    return (
        jsonify(
            {
                "credential": credential.to_dict(),
                "message": (
                    f"Credential {credential.id} requested - awaiting admin approval"
                ),
            }
        ),
        201,
    )


@api.get("/broker/credentials")
@require_admin
def list_broker_credentials():
    """Every pipeline credential, newest first (never the secret - the
    row records only that it was released)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    policy_id = None
    if request.args.get("policy_id") is not None:
        policy_id = _int_param("policy_id", 0)
    rows, total = service.list_broker_credentials(
        status=request.args.get("status"),
        policy_id=policy_id,
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "credentials": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/broker/credentials/<int:credential_id>")
@require_admin
def broker_credential_detail(credential_id: int):
    """One credential with its policy and full trail."""
    return jsonify(service.broker_credential_detail(credential_id))


@api.post("/broker/credentials/<int:credential_id>/approve")
@require_admin
def approve_broker_credential(credential_id: int):
    """Sign off a queued request; the pipeline then releases it."""
    view = service.approve_broker_credential(
        credential_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "credential": view.to_dict(),
            "message": (
                f"Credential {view.id} approved - the pipeline can now release it"
            ),
        }
    )


@api.post("/broker/credentials/<int:credential_id>/deny")
@require_admin
def deny_broker_credential(credential_id: int):
    """Refuse a queued request; nothing was released."""
    view = service.deny_broker_credential(
        credential_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {"credential": view.to_dict(), "message": f"Credential {view.id} denied"}
    )


@api.post("/broker/credentials/<int:credential_id>/release")
@require_pipeline
def release_broker_credential(credential_id: int):
    """The pipeline fetches its approved credential: the secret appears in
    this response exactly once and expires at the timestamp returned."""
    released = service.release_broker_credential(
        credential_id, policy=g.broker_policy
    )
    return jsonify(
        {
            "credential": released["credential"],
            "secret": released["secret"],
            "message": "Credential released once - it expires at the timestamp above",
        }
    )


@api.post("/broker/credentials/<int:credential_id>/close")
def close_broker_credential(credential_id: int):
    """End the grant early (deploy finished or cancelled). The pipeline
    closes its own credential with its API token; an admin closes any."""
    token = _pipeline_token()
    if token:
        policy = service.verify_broker_token(token)
        view = service.close_broker_credential(
            credential_id, actor=policy.name, policy=policy
        )
    else:
        _require_admin_credential()
        view = service.close_broker_credential(credential_id, actor=_actor())
    return jsonify(
        {
            "credential": view.to_dict(),
            "message": f"Credential {view.id} {view.status}",
        }
    )


@api.get("/broker/stats")
def broker_stats():
    """Real aggregates: policies by state and CI system, credentials by
    state, the section-15 trail's size."""
    return jsonify(service.broker_stats())


# ---------------------------------------------------------------------------
# AI-agent PAM (architecture section 16: the agent is a first-class
# principal - identity -> task -> risk -> JIT credential -> task-scoped
# command restrictions -> monitored session -> expiry)
# ---------------------------------------------------------------------------
@api.post("/agents")
@require_admin
def create_agent_identity():
    """Register an AI-agent identity (201). The API token is returned
    exactly once - it is stored as a sha256 hash and cannot be recovered."""
    agent, token = service.create_agent_identity(_json_body(), actor=_actor())
    return (
        jsonify(
            {
                "agent": agent.to_dict(),
                "token": token,
                "message": (
                    f"Agent identity {agent.name} registered "
                    f"({agent.max_ttl_minutes} min cap) - "
                    "the API token is shown once"
                ),
            }
        ),
        201,
    )


@api.get("/agents")
@require_admin
def list_agent_identities():
    """AI-agent identities, newest first."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    rows, total = service.list_agent_identities(
        status=request.args.get("status"),
        q=request.args.get("q"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "agents": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/agents/<int:agent_id>")
@require_admin
def agent_identity_detail(agent_id: int):
    """One identity with its task scopes, open access and latest trail."""
    return jsonify(service.agent_identity_detail(agent_id))


@api.patch("/agents/<int:agent_id>")
@require_admin
def update_agent_identity(agent_id: int):
    """Edit the identity knobs (description, contact, window cap,
    enable/disable); the name and token are never editable and a revoked
    identity's settings are frozen."""
    view = service.update_agent_identity(agent_id, _json_body(), actor=_actor())
    return jsonify(
        {"agent": view, "message": f"Agent identity {view['name']} updated"}
    )


@api.delete("/agents/<int:agent_id>")
@require_admin
def revoke_agent_identity(agent_id: int):
    """Withdraw the identity: open access is closed first (active grants
    release and rotate like a JIT expiry), then the token stops
    authenticating."""
    agent, closed = service.revoke_agent_identity(
        agent_id, actor=_actor(), payload=_json_body(required=False)
    )
    return jsonify(
        {
            "agent": agent.to_dict(),
            "grants_closed": closed,
            "message": (
                f"Agent identity {agent.name} revoked "
                f"({closed} access request(s) closed)"
            ),
        }
    )


@api.get("/agents/<int:agent_id>/tasks")
@require_admin
def list_agent_tasks(agent_id: int):
    """The declared task scopes under one identity."""
    rows = service.list_agent_tasks(agent_id)
    return jsonify({"tasks": [row.to_dict() for row in rows], "total": len(rows)})


@api.post("/agents/<int:agent_id>/tasks")
@require_admin
def create_agent_task(agent_id: int):
    """Declare one task the agent may perform (201): the exhaustive
    allowed-command list, an optional target scope and the window cap."""
    task = service.create_agent_task(agent_id, _json_body(), actor=_actor())
    return (
        jsonify(
            {
                "task": task.to_dict(),
                "message": (
                    f"Task {task.name} declared with "
                    f"{len(task.allowed_commands)} allowed command(s), "
                    f"{task.max_minutes} min cap"
                ),
            }
        ),
        201,
    )


@api.patch("/agents/<int:agent_id>/tasks/<int:task_id>")
@require_admin
def update_agent_task(agent_id: int, task_id: int):
    """Edit a declared task (allow-list, targets, cap, description); the
    name stays put because access requests reference it."""
    task = service.update_agent_task(agent_id, task_id, _json_body(), actor=_actor())
    return jsonify({"task": task.to_dict(), "message": f"Task {task.name} updated"})


@api.delete("/agents/<int:agent_id>/tasks/<int:task_id>")
@require_admin
def delete_agent_task(agent_id: int, task_id: int):
    """Withdraw the task: access riding it ends first, then the scope goes."""
    view, closed = service.delete_agent_task(agent_id, task_id, actor=_actor())
    return jsonify(
        {
            "task": view,
            "grants_closed": closed,
            "message": (
                f"Task {view['name']} removed "
                f"({closed} access request(s) closed)"
            ),
        }
    )


@api.post("/agent-access/requests")
@require_agent
def request_agent_access():
    """The agent files a task-scoped access request (201): the declared
    task is verified first, then the section-7 risk evaluation decides the
    state it lands in (low auto-approved, medium/high queued for sign-off,
    critical blocked)."""
    item = service.request_agent_access(_json_body(), agent=g.agent_identity)
    binding = item.agent_binding or {}
    return (
        jsonify(
            {
                "request": item.to_dict(),
                "message": (
                    f"Request #{item.id} filed for task '{binding.get('task')}' "
                    f"- risk {item.risk_level} (score {item.risk_score}), "
                    f"status {item.status}"
                ),
            }
        ),
        201,
    )


@api.get("/agent-access/requests")
@require_admin
def list_agent_access():
    """Every agent-raised access request, newest first (never a secret)."""
    limit = min(_int_param("limit", 50), MAX_PAGE_SIZE)
    offset = _int_param("offset", 0)
    agent_id = None
    if request.args.get("agent_id") is not None:
        agent_id = _int_param("agent_id", 0)
    rows, total = service.list_agent_access(
        status=request.args.get("status"),
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": [row.to_dict() for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@api.get("/agent-access/requests/<int:request_id>")
@require_admin
def agent_access_detail(request_id: int):
    """One agent access request with the identity it rides and its
    section-16 trail."""
    return jsonify(service.agent_access_detail(request_id))


@api.post("/agent-access/requests/<int:request_id>/open")
@require_agent
def open_agent_access(request_id: int):
    """The agent's JIT credential: the approved request is consumed (real
    vault checkout under the identity) and a mandatory recorded session is
    started against the grant - task-restricted, monitored, expiring with
    the grant. The raw secret is never returned."""
    opened = service.open_agent_access(
        request_id, agent=g.agent_identity, payload=_json_body(required=False)
    )
    return jsonify(opened), 201


@api.post("/agent-access/requests/<int:request_id>/close")
def close_agent_access(request_id: int):
    """End an active agent grant early. The agent closes its own access
    with its API token; an admin closes any."""
    token = _agent_token()
    if token:
        agent = service.verify_agent_token(token)
        view = service.close_agent_access(
            request_id, actor=agent.name, agent=agent
        )
    else:
        _require_admin_credential()
        view = service.close_agent_access(request_id, actor=_actor())
    return jsonify(
        {
            "request": view.to_dict(),
            "message": "Access closed and credential rotated",
        }
    )


@api.get("/agent-access/stats")
def agent_stats():
    """Real aggregates: identities by state, declared tasks, agent access
    requests by state with the open count, the section-16 trail's size."""
    return jsonify(service.agent_stats())


# ---------------------------------------------------------------------------
# HA / DC / DR (architecture section 18): node registry with real health
# probes, pull replication (hash-verified audit chain, sealed vault
# ciphertext, session metadata), role-enforced failover, backups.
# ---------------------------------------------------------------------------
@api.get("/cluster")
@require_admin
def cluster_overview_route():
    """One aggregate for the cluster screen: this node's identity and role,
    the peer table with each node's last real probe, replica posture (what
    this DR node holds and how much of it verified) and the backup ledger."""
    return jsonify(service.cluster_overview())


@api.get("/cluster/nodes")
@require_admin
def list_cluster_nodes_route():
    """Every registered node - this one first, then peers by name - each
    with the honest health state of its last real probe."""
    return jsonify({"nodes": [node.to_dict() for node in service.list_cluster_nodes()]})


@api.post("/cluster/nodes")
@require_admin
def register_cluster_node_route():
    """Register a peer node (201): its site (dc/dr), its role in the
    topology (active/passive) and where its /health answers. The node is
    `unknown` until the first real probe - health is never assumed."""
    node = service.register_cluster_node(_json_body(), actor=_actor())
    return jsonify({"node": node.to_dict(), "message": "Node registered"}), 201


@api.get("/cluster/nodes/<int:node_id>")
@require_admin
def get_cluster_node_route(node_id: int):
    """One registered node with its last probe state."""
    return jsonify({"node": service.get_cluster_node(node_id).to_dict()})


@api.patch("/cluster/nodes/<int:node_id>")
@require_admin
def update_cluster_node_route(node_id: int):
    """Update a registered node's topology (site, role, base_url, name).
    Each change lands on the cluster trail with the value it replaced."""
    node = service.update_cluster_node(node_id, _json_body(), actor=_actor())
    return jsonify({"node": node.to_dict(), "message": "Node updated"})


@api.delete("/cluster/nodes/<int:node_id>")
@require_admin
def delete_cluster_node_route(node_id: int):
    """Unregister a peer. Replicated evidence stays (it is this node's own
    DR record); the response says exactly how much stays behind."""
    return jsonify(service.delete_cluster_node(node_id, actor=_actor()))


@api.post("/cluster/nodes/<int:node_id>/probe")
@require_admin
def probe_cluster_node_route(node_id: int):
    """Probe the peer's real /health now: measured latency, honest
    unreachable (with the transport error verbatim) or degraded. The
    cluster trail only records health *changes*."""
    return jsonify(service.probe_cluster_node(node_id, actor=_actor()))


@api.post("/cluster/nodes/<int:node_id>/sync")
@require_admin
def sync_cluster_node_route(node_id: int):
    """Pull replication from the peer: its immutable audit chain (re-hashed
    record by record here), its sealed vault ciphertext and its session
    metadata. A `peer_token` body field authenticates the outbound calls
    only - never stored, never echoed, never on the trail. The response is
    the honest per-kind result, including a broken peer chain or the
    transport error verbatim."""
    return jsonify(
        service.sync_cluster_node(node_id, _json_body(required=False), actor=_actor())
    )


@api.get("/cluster/replicas")
@require_admin
def cluster_replicas_route():
    """Replica posture per peer: audit records held and how many verified
    locally, replicated secrets (and whether this node's own key could
    open them), sessions mirrored, last sync time."""
    return jsonify(service.cluster_replica_summary())


@api.post("/cluster/failover")
@require_admin
def cluster_failover_route():
    """Promote or demote THIS node (section 18's failover): a real role
    flip on the own registry row, recorded with the role it replaced.
    While passive, the app-level gate refuses every write outside
    /api/v1/cluster/* with 409 - the role is enforced, not decorative."""
    body = _json_body(required=False)
    action = body.get("action", "promote")
    if not isinstance(action, str) or action not in ("promote", "demote"):
        raise ValidationFailed(
            "'action' must be 'promote' or 'demote'", {"field": "action"}
        )
    return jsonify(service.failover_cluster(action, body, actor=_actor()))


@api.post("/cluster/monitor/tick")
@require_admin
def cluster_monitor_tick_route():
    """Run one automatic-failover tick synchronously (the CLUSTER_MONITOR
    thread runs this same function): while this node is passive, probe
    every registered active peer; when all of them have failed enough real
    consecutive probes, promote with those failures as the reason."""
    return jsonify(service.run_cluster_monitor(actor=_actor(default="admin-monitor")))


@api.get("/cluster/backups")
@require_admin
def list_cluster_backups_route():
    """Every recorded backup of this node's database, newest first - path,
    sha256, size, ledger head at backup time and the re-walk verdict."""
    return jsonify({"backups": [b.to_dict() for b in service.list_cluster_backups()]})


@api.post("/cluster/backups")
@require_admin
def create_cluster_backup_route():
    """Take a real backup now (201): SQLite's online backup API copies the
    live file without stopping writes, the copy is hashed and re-opened
    read-only to re-walk its audit chain - a backup that cannot be
    verified says why, honestly."""
    backup = service.create_cluster_backup(actor=_actor())
    return jsonify({"backup": backup.to_dict(), "message": "Backup created"}), 201


@api.get("/cluster/export/vault")
@require_admin
def cluster_export_vault_route():
    """This node's sealed vault ciphertext for a peer's replication pull:
    each item's current version with the blob exactly as stored. The
    plaintext never crosses this endpoint - only the AES-GCM wire form."""
    return jsonify(service.export_vault_secrets())


@api.get("/cluster/export/sessions")
@require_admin
def cluster_export_sessions_route():
    """This node's session metadata for a peer's replication pull: who had
    access to what, when, and how it ended."""
    return jsonify(service.export_sessions())


# ---------------------------------------------------------------------------
# RBAC / ABAC (architecture section 10: roles + attribute rules)
# ---------------------------------------------------------------------------
@api.get("/roles")
@require_admin
def list_roles():
    """The five built-in roles with the exact number of admin operations
    each may call - the policy is computed, never a stale copy."""
    return jsonify({"roles": service.list_roles_with_operations()})


@api.get("/role-bindings")
@require_admin
def list_role_bindings_route():
    """Who holds a role: active bindings by default, revoked rows kept as
    evidence behind ?include_revoked=1. The token itself is shown once at
    creation and never again - only whether a credential exists."""
    include_revoked = (
        (request.args.get("include_revoked") or "").strip().lower()
        in ("1", "true", "yes")
    )
    return jsonify(
        {"bindings": service.list_role_bindings(include_revoked=include_revoked)}
    )


@api.post("/role-bindings")
@require_admin
def create_role_binding_route():
    """Create a role binding: a `local` principal receives its API token
    once (`vypam-rbac1.<id>.<secret>` - sha256 at rest, never recoverable);
    an `ldap` principal is a directory username that a signed login ticket
    will carry. Optional `scope` carries the ABAC attribute rules."""
    binding, token = service.create_role_binding(_json_body(), actor=_actor())
    payload: Dict[str, Any] = {
        "binding": binding,
        "message": "Role binding created",
    }
    if token is not None:
        payload["token"] = token
        payload["token_notice"] = (
            "Shown once - store it now; it cannot be recovered."
        )
    return jsonify(payload), 201


@api.delete("/role-bindings/<int:binding_id>")
@require_admin
def delete_role_binding_route(binding_id: int):
    """Revoke a role binding: its token stops working immediately and a
    directory binding stops counting; the row stays as evidence."""
    binding = service.revoke_role_binding(binding_id, actor=_actor())
    return jsonify({"binding": binding, "message": "Role binding revoked"})


# ---------------------------------------------------------------------------
# first-run setup (ADR-0018): the public state, the officers' profile
# write, and the two-password completion
# ---------------------------------------------------------------------------
@api.get("/setup/state")
def setup_get_state():
    """First-run state for the login card and the /setup wizard: the
    branding this instance presents, whether the wizard is still open,
    whether SMTP has a host, and the two officer names. Public before
    sign-in, secret-free by construction - no password field ever lands
    in this reply, whoever asks."""
    return jsonify(setup.setup_state())


@api.put("/setup/profile")
@require_admin
def setup_put_profile():
    """Company name / logo / contact. While setup runs the instance
    belongs to the two bootstrap officers: their own console session,
    checked here, is the only key (in open mode the decorator above is a
    no-op, so this branch does the refusing). Once configured it is a
    normal admin write - the company may rebrand (ADR-0018 Decision 2)."""
    if not setup.instance_configured():
        ensure_console_session()
        user = g.console_user
        if user.username not in setup.BOOTSTRAP_OFFICERS:
            raise Forbidden(
                "Setup is still running - only the VY-PAM bootstrap officers "
                "may configure this instance",
                {"phase": "first-run", "officers": list(setup.BOOTSTRAP_OFFICERS)},
            )
        actor = user.username
    else:
        actor = _actor()
    return jsonify(setup.update_profile(_json_body(), actor=actor))


@api.post("/setup/complete")
def setup_post_complete():
    """The maker-checker attestation that ends first-run setup: BOTH
    bootstrap passwords verified in one request (two humans, two live
    authentications). Public by design - the passwords are the
    credential - and 409 forever afterwards (ADR-0018 Decision 2)."""
    body = _json_body()
    return jsonify(
        setup.complete(
            maker_password=str(body.get("maker_password") or ""),
            checker_password=str(body.get("checker_password") or ""),
            source_ip=request.remote_addr or "",
        )
    )


# ---------------------------------------------------------------------------
# real identity & login security (phase 7, Addendum C)
# ---------------------------------------------------------------------------
SESSION_COOKIE = "vypam_session"


def _cookie_for_session(session) -> Response:
    """Attach the HttpOnly/SameSite session cookie to a JSON response (the
    bearer twin is in the body, shown once, for API clients)."""
    response = jsonify(session)
    response.set_cookie(
        SESSION_COOKIE,
        f"{session['session_token']}",
        httponly=True,
        samesite="Lax",
        secure=bool(request.is_secure),
        path="/",
    )
    return response


def ensure_console_session() -> None:
    """Populate g.console_session / g.console_user from the presented
    credential when the cookie CSRF middleware has not already done it."""
    if getattr(g, "console_session", None) is None:
        user, session = identity.verify_console_session(_presented_credential())
        g.console_session = session
        g.console_user = user


def require_console(view):
    """The route needs a live console session (own-actions surface; role
    bindings decide the admin surface, not this decorator)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        ensure_console_session()
        return view(*args, **kwargs)

    return wrapped


def _stepup_if_human() -> None:
    """Sensitive actions demand a fresh MFA assertion from a human console
    session (reveal, break-glass, critical approval, emergency, factor
    changes). Machine credentials assert per-request and are not human
    sessions, so they pass - the honest scope of a step-up control."""
    session = getattr(g, "console_session", None)
    if session is not None and identity.stepup_stale(session):
        raise Forbidden(
            "Step-up MFA required for this action "
            f"(POST /api/v1/auth/mfa/stepup within {identity.auth_settings()['stepup_ttl_minutes']} min)",
            {"reason": "stepup_required"},
        )


def _split_prefixed(presented: str, prefix: str) -> Optional[Any]:
    """`<prefix>.<id>.<secret>` -> (id, secret), else None."""
    if not isinstance(presented, str) or not presented.startswith(prefix + "."):
        return None
    body = presented[len(prefix) + 1 :]
    id_part, dot, secret = body.partition(".")
    if not dot or not id_part or not secret:
        return None
    return id_part, secret


def _consume_enrol_ticket(body: Dict[str, Any], *, consume: bool) -> Any:
    """Validate (and optionally consume) the forced-enrolment ticket
    `vypam-enr1.<id>.<secret>`; returns the user on success. Without a
    ticket a live console session stands in (re-enrolment/rotation from
    the signed-in account - the step-up guard runs in each route first)."""
    ticket = body.get("enrol_ticket") or request.headers.get("X-Enrol-Ticket") or ""
    parts = _split_prefixed(str(ticket), identity.ENROL_TICKET_PREFIX)
    if parts is None:
        user = getattr(g, "console_user", None)
        if user is None:
            credential = _presented_credential()
            if credential:
                try:
                    user, session = identity.verify_console_session(credential)
                    g.console_session = session
                    g.console_user = user
                except Unauthorized:
                    user = None
        if user is not None:
            return user
        raise Unauthorized("An enrol ticket is required (from POST /api/v1/auth/login)")
    challenge_id, secret = parts
    if consume:
        user, _challenge = identity.consume_challenge(
            challenge_id, secret, kind="enrol"
        )
        return user
    import hashlib as _hashlib
    import hmac as _hmac

    challenge = db.session.get(LoginChallenge, str(challenge_id or ""))
    if (
        challenge is None
        or challenge.kind != "enrol"
        or challenge.consumed_at is not None
        or challenge.expires_at <= datetime.now()
        or not _hmac.compare_digest(
            _hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            challenge.secret_sha256 or "",
        )
    ):
        raise Unauthorized("Enrol ticket invalid or expired")
    return db.session.get(identity.User, challenge.user_id)


def db_get_login_challenge(challenge_id: str):
    return db.session.get(LoginChallenge, str(challenge_id or ""))


def _minted(result: Dict[str, Any]) -> Response:
    """The login/step-up success response: HttpOnly cookie + the bearer
    and CSRF twins shown exactly once."""
    return _cookie_for_session(result)


@api.post("/auth/login")
def auth_login():
    """Local console login. The password check yields a session (no factor
    and `mfa_required` off), an MFA challenge (`vypam-mfa1` - pass a factor
    inline: `totp_code`, `otp_challenge_id`+`otp_code`, `backup_code`, or
    the WebAuthn assertion after `/auth/mfa/webauthn/options`), or an
    enrolment ticket (`vypam-enr1`, fail-closed). Lockout, per-account and
    per-IP rate limits, progressive delay and spray detection run first;
    `X-Actor` is never read - the session is the identity."""
    body = _json_body()
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    result = identity.login(
        username=username,
        password=password,
        source_ip=request.remote_addr or "",
        user_agent=str(request.headers.get("User-Agent") or "")[:255],
        device_token=str(body.get("device_token") or ""),
        remember_device=bool(body.get("remember_device")),
    )
    if result.get("status") == "mfa_required":
        assertion_material = any(
            body.get(key)
            for key in (
                "totp_code",
                "code",
                "otp_code",
                "radius_code",
                "backup_code",
                "webauthn",
            )
        )
        if not assertion_material:
            # No factor presented yet: deliver the step challenge in a 403
            # (the same shape as enrolment_required) - the retry presents it
            # as `login_challenge` alongside the assertion. The challenge is
            # never swallowed into a bare 401: that would make the MFA step
            # impossible to complete.
            return jsonify(result), 403
        challenge = str(body.get("login_challenge") or result["challenge"])
        parts = _split_prefixed(challenge, identity.MFA_CHALLENGE_PREFIX)
        if parts is None:
            raise Unauthorized("MFA challenge invalid or expired")
        challenge_id, secret = parts
        # verify the assertion against the challenge's user first, consume
        # the challenge only when the assertion passed
        row = db.session.get(LoginChallenge, str(challenge_id or ""))
        if (
            row is None
            or row.kind != "mfa"
            or row.consumed_at is not None
            or row.expires_at <= datetime.now()
            or not hmac.compare_digest(
                hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                row.secret_sha256 or "",
            )
        ):
            raise Unauthorized("MFA challenge invalid or expired")
        user = db.session.get(identity.User, row.user_id)
        assertion = body.get("webauthn")
        method = None
        if isinstance(assertion, dict) and assertion:
            method = webauthn.verify_assertion(
                user,
                challenge_id=str(assertion.get("challenge_id") or ""),
                credential_id=str(assertion.get("credential_id") or ""),
                client_data_json=str(assertion.get("client_data_json") or ""),
                authenticator_data=str(assertion.get("authenticator_data") or ""),
                signature=str(assertion.get("signature") or ""),
            )
        else:
            method = mfa.verify_assertion(user, body)
        if method is None:
            raise Unauthorized("MFA assertion failed")
        user, _consumed = identity.consume_challenge(challenge_id, secret, kind="mfa")
        result = identity.mint_session(
            user,
            methods=[method],
            source_ip=request.remote_addr or "",
            user_agent=str(request.headers.get("User-Agent") or "")[:255],
        )
        result = identity.maybe_remember_device(
            user,
            result,
            requested=bool(body.get("remember_device")),
            source_ip=request.remote_addr or "",
        )
    if result.get("status") == "enrolment_required":
        return jsonify(result), 403
    return _minted(result)


@api.post("/auth/logout")
@require_console
def auth_logout():
    """Revoke this console session (the cookie is cleared on the way out)."""
    session = g.console_session
    identity.revoke_session(session.id, actor=_actor(), reason="logout")
    response = jsonify({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@api.get("/auth/sessions")
@require_console
def auth_list_sessions():
    """This user's live console sessions (idle/absolute deadlines, last
    seen, where from) - the self-service view of `log out everywhere`."""
    user = g.console_user
    include_revoked = (
        (request.args.get("include_revoked") or "").strip().lower() in ("1", "true", "yes")
    )
    return jsonify(
        {
            "sessions": identity.list_user_sessions(
                user.id, include_revoked=include_revoked
            ),
            "current_session_id": g.console_session.id,
        }
    )


@api.delete("/auth/sessions/<int:session_id>")
@require_console
def auth_revoke_session(session_id: int):
    """Revoke one console session: your own, or any when you hold the
    admin role."""
    session = g.console_session
    principal = getattr(g, "rbac_principal", None)
    is_admin = (
        not _config().admin_token
        or (principal is not None and principal.get("role") == "admin")
    )
    target = db_get_console_session(session_id)
    if target is None:
        raise NotFound(f"Unknown console session {session_id}")
    if target.user_id != session.user_id and not is_admin:
        raise Forbidden("You may only revoke your own sessions")
    data = identity.revoke_session(session_id, actor=_actor(), reason="revoked-by-user")
    return jsonify({"session": data, "message": "Session revoked"})


def db_get_console_session(session_id: int):
    return db.session.get(ConsoleSession, session_id)


@api.post("/auth/logout-all")
@require_console
def auth_logout_all():
    """Log out everywhere: every other session of this user dies now."""
    user = g.console_user
    count = identity.logout_all(
        user.id, actor=user.username, keep_session_id=g.console_session.id
    )
    return jsonify({"revoked": count, "message": f"{count} other session(s) revoked"})


@api.post("/auth/mfa/stepup")
@require_console
def auth_stepup():
    """Refresh the step-up window with a fresh factor assertion (TOTP,
    e-mail OTP challenge, RADIUS, backup code or WebAuthn)."""
    body = _json_body()
    session = g.console_session
    user = g.console_user
    assertion = body.get("webauthn")
    method = None
    if isinstance(assertion, dict) and assertion:
        method = webauthn.verify_assertion(
            user,
            challenge_id=str(assertion.get("challenge_id") or ""),
            credential_id=str(assertion.get("credential_id") or ""),
            client_data_json=str(assertion.get("client_data_json") or ""),
            authenticator_data=str(assertion.get("authenticator_data") or ""),
            signature=str(assertion.get("signature") or ""),
        )
    else:
        method = mfa.verify_assertion(user, body)
    if method is None:
        raise Unauthorized("MFA assertion failed")
    identity.touch_stepup(session)
    return jsonify({"status": "verified", "method": method, "mfa_at": session.mfa_at.isoformat()})


@api.post("/auth/password")
def auth_change_password():
    """Change your password: authenticated by the current password (with or
    without a live session - this is the first-login forced change path
    too). Old sessions die except the one making the change."""
    body = _json_body()
    session = None
    username = str(body.get("username") or "")
    if not username:
        try:
            user, session = identity.verify_console_session(_presented_credential())
            username = user.username
        except Unauthorized:
            raise ValidationFailed("'username' is required when signed out") from None
    result = identity.change_password(
        username=username,
        old_password=str(body.get("old_password") or ""),
        new_password=str(body.get("new_password") or ""),
        session=session,
    )
    return jsonify(
        {
            "user": result["user"],
            "sessions_revoked": result["sessions_revoked"],
            "message": "Password changed",
        }
    )


@api.post("/auth/otp/start")
def auth_otp_start():
    """Start an e-mail OTP challenge (login second factor, step-up or
    password recovery). The answer is identical whether or not the account
    exists - no user enumeration, ever."""
    body = _json_body()
    result = otp.start_otp(
        str(body.get("username") or ""),
        purpose=str(body.get("purpose") or "login"),
    )
    return jsonify(result), 202


@api.post("/auth/recovery/start")
def auth_recovery_start():
    """Password-recovery start: the same generic 202 for every username."""
    body = _json_body()
    result = otp.start_otp(str(body.get("username") or ""), purpose="recovery")
    return jsonify(result), 202


@api.post("/auth/recovery/reset")
def auth_recovery_reset():
    """Password reset after a verified recovery OTP (single use, attempt-
    capped). Every session dies; the MFA factors stay."""
    body = _json_body()
    username = str(body.get("username") or "").strip().lower()
    try:
        otp.verify_code(
            str(body.get("challenge_id") or ""),
            str(body.get("code") or ""),
            purpose="recovery",
            username=username,
        )
    except otp.UnauthorizedOtp as exc:
        raise Unauthorized("One-time code invalid or expired") from exc
    result = identity.set_password_with_recovery(
        username=username, new_password=str(body.get("new_password") or "")
    )
    return jsonify(
        {
            "user": result["user"],
            "sessions_revoked": result["sessions_revoked"],
            "message": "Password reset - sign in again",
        }
    )


# --- MFA enrolment + management (enrol ticket or a live session) ----------
@api.post("/auth/mfa/enroll/totp")
def auth_enroll_totp():
    """Mint (or rotate) your TOTP factor: the seed + otpauth URI come back
    exactly once - scan it, then verify. Works with the forced-enrolment
    ticket or a live session."""
    _stepup_if_human()
    body = _json_body()
    user = _consume_enrol_ticket(body, consume=False)
    data = mfa.enroll_totp(user, actor=user.username)
    return jsonify(data), 201


@api.post("/auth/mfa/enroll/totp/verify")
def auth_enroll_totp_verify():
    """Verify the first code (replay-protected). With an enrol ticket this
    consumes it and mints the session - enrolment complete."""
    body = _json_body()
    user = _consume_enrol_ticket(body, consume=False)
    if not mfa.verify_totp_code(user, str(body.get("code") or ""), actor=user.username):
        raise Unauthorized("TOTP code invalid")
    ticket = body.get("enrol_ticket") or request.headers.get("X-Enrol-Ticket") or ""
    parts = _split_prefixed(str(ticket), identity.ENROL_TICKET_PREFIX)
    if parts is not None:
        user, _ = identity.consume_challenge(parts[0], parts[1], kind="enrol")
        result = identity.mint_session(
            user,
            methods=["totp"],
            source_ip=request.remote_addr or "",
            user_agent=str(request.headers.get("User-Agent") or "")[:255],
        )
        return _minted(result)
    if getattr(g, "console_session", None) is not None:
        identity.touch_stepup(g.console_session)
    return jsonify({"status": "verified", "method": "totp"})


@api.post("/auth/mfa/enroll/email")
def auth_enroll_email():
    """Enrol e-mail OTP as a factor: a real code goes to your registered
    mailbox; verify it to activate (proof of mailbox ownership)."""
    _stepup_if_human()
    body = _json_body()
    user = _consume_enrol_ticket(body, consume=False)
    if not user.email:
        raise ValidationFailed(
            "This account has no e-mail address - an admin sets it first "
            "(PATCH /api/v1/users/{user_id})"
        )
    result = otp.start_otp(user.username, purpose="stepup")
    return jsonify({"status": "sent", "challenge_id": result.get("challenge_id")}), 202


@api.post("/auth/mfa/enroll/email/verify")
def auth_enroll_email_verify():
    """Verify the enrolment code and activate the email factor."""
    body = _json_body()
    user = _consume_enrol_ticket(body, consume=False)
    try:
        otp.verify_code(
            str(body.get("challenge_id") or ""),
            str(body.get("code") or ""),
            purpose="stepup",
            username=user.username,
        )
    except otp.UnauthorizedOtp as exc:
        raise Unauthorized("One-time code invalid or expired") from exc
    from models import MfaFactor as _MfaFactor

    factor = _MfaFactor.query.filter(
        _MfaFactor.user_id == user.id, _MfaFactor.kind == "email"
    ).first()
    if factor is None:
        factor = _MfaFactor(user_id=user.id, kind="email", name="E-mail OTP")
        db.session.add(factor)
    factor.active = True
    identity.auth_event(
        "auth.mfa.enrolled",
        actor=user.username,
        subject=user.username,
        detail={"kind": "email"},
    )
    db.session.commit()
    return jsonify({"status": "enrolled", "kind": "email"})


@api.post("/auth/mfa/enroll/radius")
@require_console
def auth_enroll_radius():
    """Enrol the RADIUS push/OTP factor (the code arrives on the
    authenticator the configured RADIUS server owns)."""
    _stepup_if_human()
    body = _json_body()
    data = radius_client.enroll_radius(g.console_user, actor=_actor())
    return jsonify({"factor": data}), 201


@api.post("/auth/mfa/backup-codes")
@require_console
def auth_backup_codes():
    """Generate ten single-use backup codes (shown once, hashed at rest);
    every earlier code dies. Step-up fresh required."""
    _stepup_if_human()
    codes = mfa.generate_backup_codes(g.console_user, actor=_actor())
    return jsonify(
        {
            "codes": codes,
            "count": len(codes),
            "message": "Shown once - store them now; they cannot be recovered.",
        }
    )


@api.get("/auth/mfa/factors")
@require_console
def auth_list_factors():
    """Your enrolled factors (kind, when last used) - never a seed."""
    return jsonify({"factors": mfa.list_factors(g.console_user.id)})


@api.delete("/auth/mfa/factors/<int:factor_id>")
@require_console
def auth_delete_factor(factor_id: int):
    """Remove one of your factors. The last factor with `mfa_required` on
    is refused (fail-closed) - use the two-admin recovery instead."""
    _stepup_if_human()
    data = mfa.delete_factor(g.console_user.id, factor_id, actor=_actor())
    return jsonify({"factor": data, "message": "Factor removed"})


@api.post("/auth/mfa/webauthn/options")
def auth_webauthn_options():
    """Start a WebAuthn ceremony (register with a session/ticket later,
    authenticate for login or step-up): a server-side challenge, the
    relying party id and the allowed origins."""
    body = _json_body()
    username = str(body.get("username") or "").strip().lower()
    purpose = str(body.get("purpose") or "authenticate")
    if username:
        user = identity.get_user(username)
        if user is None or not user.is_active:
            # identical challenge shape for unknown/inactive usernames (no
            # enumeration): the random challenge backs no server-side row,
            # so no assertion against it can ever verify
            return jsonify(webauthn.decoy_challenge()), 202
    elif getattr(g, "console_session", None) is not None:
        user = g.console_user
    else:
        try:
            user, session = identity.verify_console_session(_presented_credential())
            g.console_session, g.console_user = session, user
        except Unauthorized:
            raise Unauthorized("Sign in or present a username") from None
    if purpose not in ("register", "authenticate"):
        raise ValidationFailed("purpose must be 'register' or 'authenticate'")
    # one status for both answers: 202 whether the username exists or not -
    # the status code itself must not be an enumeration surface
    return jsonify(webauthn.start_challenge(user, purpose=purpose)), 202


@api.post("/auth/mfa/webauthn/assert")
def auth_webauthn_assert():
    """Consume a WebAuthn assertion: with an enrol ticket it mints the
    session (login), with a live session it is a step-up."""
    body = _json_body()
    assertion = body.get("webauthn") if isinstance(body.get("webauthn"), dict) else body
    ticket = body.get("enrol_ticket") or request.headers.get("X-Enrol-Ticket") or ""
    parts = _split_prefixed(str(ticket), identity.ENROL_TICKET_PREFIX)
    if parts is not None:
        user = _consume_enrol_ticket(body, consume=False)
        method = webauthn.verify_assertion(
            user,
            challenge_id=str(assertion.get("challenge_id") or ""),
            credential_id=str(assertion.get("credential_id") or ""),
            client_data_json=str(assertion.get("client_data_json") or ""),
            authenticator_data=str(assertion.get("authenticator_data") or ""),
            signature=str(assertion.get("signature") or ""),
        )
        user, _ = identity.consume_challenge(parts[0], parts[1], kind="enrol")
        result = identity.mint_session(
            user,
            methods=[method],
            source_ip=request.remote_addr or "",
            user_agent=str(request.headers.get("User-Agent") or "")[:255],
        )
        return _minted(result)
    try:
        user, session = identity.verify_console_session(_presented_credential())
    except Unauthorized:
        raise Unauthorized("Console session or enrol ticket required") from None
    g.console_session, g.console_user = session, user
    method = webauthn.verify_assertion(
        user,
        challenge_id=str(assertion.get("challenge_id") or ""),
        credential_id=str(assertion.get("credential_id") or ""),
        client_data_json=str(assertion.get("client_data_json") or ""),
        authenticator_data=str(assertion.get("authenticator_data") or ""),
        signature=str(assertion.get("signature") or ""),
    )
    identity.touch_stepup(session)
    return jsonify({"status": "verified", "method": method})


@api.post("/auth/mfa/enroll/webauthn")
@require_console
def auth_register_webauthn():
    """Register a security key / passkey (attestation verified in-product:
    `none` and packed self-attestation; every other format refused)."""
    _stepup_if_human()
    body = _json_body()
    data = webauthn.register_credential(
        g.console_user,
        challenge_id=str(body.get("challenge_id") or ""),
        client_data_json=str(body.get("client_data_json") or ""),
        attestation_object=str(body.get("attestation_object") or ""),
        name=str(body.get("name") or ""),
        transports=body.get("transports") if isinstance(body.get("transports"), list) else None,
    )
    return jsonify({"credential": data, "message": "Security key registered"}), 201


@api.get("/auth/mfa/webauthn/credentials")
@require_console
def auth_list_webauthn():
    """Your registered security keys (public keys never leave the server
    side of this API - the list carries ids and counters only)."""
    return jsonify({"credentials": webauthn.list_credentials(g.console_user.id)})


@api.delete("/auth/mfa/webauthn/credentials/<int:credential_id>")
@require_console
def auth_delete_webauthn(credential_id: int):
    """Remove one registered security key (last-factor fail-closed)."""
    _stepup_if_human()
    data = webauthn.delete_credential(
        g.console_user.id, credential_id, actor=_actor()
    )
    return jsonify({"credential": data, "message": "Credential removed"})


@api.post("/auth/factor-recovery/request")
def auth_factor_recovery_request():
    """Ask for factor recovery (lost every factor): an enrol ticket or a
    live session proves the password; two admins must approve before any
    factor is deleted."""
    body = _json_body()
    user = _consume_enrol_ticket(body, consume=False)
    data = identity.request_factor_recovery(user.id, reason=str(body.get("reason") or ""))
    return jsonify({"request": data}), 201


# --- admin: users, sessions, recovery, emergency, report -------------------
@api.get("/users")
@require_admin
def list_users_route():
    """Every console user (local, SCIM-managed, the sealed emergency row):
    lockout state, source, last login - never a hash or a seed."""
    return jsonify({"users": identity.list_users(source=str(request.args.get("source") or ""))})


@api.post("/users")
@require_admin
def create_user_route():
    """Create a local console user (201). No password given means a strong
    one is generated and returned exactly once, with `must_change_password`."""
    body = _json_body()
    data, generated = identity.create_user(
        username=str(body.get("username") or ""),
        email=str(body.get("email") or ""),
        display_name=str(body.get("display_name") or ""),
        password=str(body.get("password") or ""),
        actor=_actor(),
    )
    payload = {"user": data, "message": "User created"}
    if generated:
        payload["generated_password"] = generated
        payload["password_notice"] = "Shown once - the user must change it at first sign-in."
    return jsonify(payload), 201


@api.patch("/users/<int:user_id>")
@require_admin
def patch_user_route(user_id: int):
    """Activate/deactivate (deactivation revokes every live session), edit
    contact fields, and mark/clear change-password-at-next-sign-in
    (ADR-0017 batch 11.10)."""
    body = _json_body()
    data = identity.update_user(
        user_id,
        actor=_actor(),
        active=body.get("active") if "active" in body else None,
        email=body.get("email") if "email" in body else None,
        display_name=body.get("display_name") if "display_name" in body else None,
        must_change_password=(
            body.get("must_change_password") if "must_change_password" in body else None
        ),
    )
    return jsonify({"user": data, "message": "User updated"})


@api.post("/users/<int:user_id>/unlock")
@require_admin
def unlock_user_route(user_id: int):
    """Clear a lockout (the failure counters reset with it)."""
    data = identity.unlock_user(user_id, actor=_actor())
    return jsonify({"user": data, "message": "User unlocked"})


@api.post("/users/<int:user_id>/password-reset")
@require_admin
def admin_reset_password_route(user_id: int):
    """Admin-assisted reset: a fresh password (generated when not given,
    shown once) with `must_change_password`; every session dies. The body
    is optional, as the contract documents."""
    body = _json_body(required=False)
    data = identity.admin_reset_password(
        user_id, actor=_actor(), password=str(body.get("password") or "")
    )
    payload = {"user": data, "message": "Password reset - every session revoked"}
    if data.get("generated_password"):
        payload["generated_password"] = data["generated_password"]
        payload["password_notice"] = "Shown once - store it now."
    return jsonify(payload)


@api.get("/users/<int:user_id>/sessions")
@require_admin
def user_sessions_route(user_id: int):
    """This user's console sessions (live by default; ?include_revoked=1
    keeps the evidence)."""
    include_revoked = (
        (request.args.get("include_revoked") or "").strip().lower() in ("1", "true", "yes")
    )
    return jsonify(
        {"sessions": identity.list_user_sessions(user_id, include_revoked=include_revoked)}
    )


@api.delete("/users/<int:user_id>/sessions")
@require_admin
def revoke_user_sessions_route(user_id: int):
    """Revoke every live session of this user now (offboarding, suspected
    compromise)."""
    user = db.session.get(identity.User, user_id)
    if user is None:
        raise NotFound(f"Unknown user {user_id}")
    count = identity._revoke_all_sessions(user, reason="admin-revoked", actor=_actor())
    db.session.commit()
    return jsonify({"revoked": count, "message": f"{count} session(s) revoked"})


@api.get("/auth/factor-recovery")
@require_admin
def list_factor_recovery_route():
    """Every factor-recovery request with its approvals (two distinct
    admins close a request; one denial kills it)."""
    status = str(request.args.get("status") or "")
    return jsonify({"requests": identity.list_factor_recovery_requests(status=status)})


@api.post("/auth/factor-recovery/<int:request_id>/approve")
@require_admin
def approve_factor_recovery_route(request_id: int):
    """Approve (or deny) a factor recovery. Two distinct approvers delete
    the factors; the next sign-in forces a fresh enrolment."""
    _stepup_if_human()
    body = _json_body() or {}
    data = identity.approve_factor_recovery(
        request_id,
        approver=_actor(),
        decision=str(body.get("decision") or "approve"),
        note=str(body.get("note") or ""),
    )
    return jsonify({"request": data, "message": f"Recovery {data['status']}"})


@api.get("/auth/emergency")
@require_admin
def list_emergency_route():
    """The sealed emergency admin's grant history + current state (open
    window, pending requests)."""
    return jsonify(
        {
            "grants": identity.list_emergency_grants(),
            "username": identity.EMERGENCY_USERNAME,
        }
    )


@api.post("/auth/emergency/open")
@require_admin
def open_emergency_route():
    """Request to open the emergency admin: a pending grant awaiting two
    distinct approvals (never the requester)."""
    _stepup_if_human()
    body = _json_body() or {}
    data = identity.request_emergency_open(
        actor=_actor(),
        reason=str(body.get("reason") or ""),
        ticket=str(body.get("ticket") or ""),
    )
    return jsonify({"grant": data, "message": "Emergency grant requested"}), 201


@api.post("/auth/emergency/grants/<int:grant_id>/approve")
@require_admin
def approve_emergency_route(grant_id: int):
    """Approve (or deny) an emergency grant. Two distinct approvals open a
    short window; every state change is alerted on the `auth` trail."""
    _stepup_if_human()
    body = _json_body() or {}
    data = identity.approve_emergency_open(
        grant_id,
        approver=_actor(),
        decision=str(body.get("decision") or "approve"),
        note=str(body.get("note") or ""),
    )
    return jsonify({"grant": data, "message": f"Emergency grant {data['status']}"})


@api.post("/auth/emergency/login")
def emergency_login_route():
    """One login through the sealed credential while a grant is open. The
    seal rotates on success (the used password never works twice) and the
    use is alerted."""
    body = _json_body() or {}
    result = identity.emergency_login(
        password=str(body.get("password") or ""),
        source_ip=request.remote_addr or "",
        user_agent=str(request.headers.get("User-Agent") or "")[:255],
    )
    return _minted(result)


@api.get("/auth/report")
@require_admin
def auth_report_route():
    """The login-security report for auditors: counts per action plus the
    newest `auth` ledger events (never a secret)."""
    window = _int_param("window_hours", 24, minimum=1)
    return jsonify(identity.auth_report(window_hours=window))


@api.get("/auth/deliveries")
@require_admin
def auth_deliveries_route():
    """OTP e-mail delivery status for admins: measured `sent`/`failed`/
    `queued` with the provider's error - never a code."""
    return jsonify({"deliveries": otp.delivery_status()})


@api.post("/settings/smtp/test")
@require_admin
def smtp_test_route():
    """Send a real test message through the configured SMTP server (503
    with the honest reason when it is not configured)."""
    body = _json_body() or {}
    delivery = otp.send_test_email(str(body.get("to") or ""), actor=_actor())
    return jsonify({"delivery": delivery, "message": "Test message sent"})


@api.post("/settings/scim/rotate")
@require_admin
def scim_rotate_route():
    """Mint a fresh SCIM bearer token for the identity provider (shown
    exactly once; only its sha256 is stored)."""
    token = scim.rotate_token()
    return jsonify(
        {
            "token": token,
            "message": "Shown once - configure it on the identity provider now.",
        }
    )


# --- SCIM 2.0 lifecycle surface (the identity provider's credential) ------
def _require_scim():
    auth_header = request.headers.get("Authorization", "")
    presented = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if not scim.verify_token(presented):
        raise Unauthorized("SCIM bearer token required")


@api.get("/scim/v2/Users")
def scim_list_users():
    """SCIM Users (filter userName eq, startIndex/count paging)."""
    _require_scim()
    filter_raw = str(request.args.get("filter") or "").strip()
    user_name = ""
    if filter_raw:
        match = re.match(r'^userName\s+eq\s+"?([^"]+)"?$', filter_raw)
        if match is None:
            raise scim.ScimError(400, f"Unsupported filter: {filter_raw}")
        user_name = match.group(1).strip()
    return jsonify(
        scim.list_users(
            start_index=int(request.args.get("startIndex") or 1),
            count=int(request.args.get("count") or 100),
            user_name=user_name,
        )
    )


@api.post("/scim/v2/Users")
def scim_create_user():
    """SCIM create: a provider-managed user (password login refused - the
    IdP owns the credential)."""
    _require_scim()
    return jsonify(scim.create_user(_json_body())), 201


@api.get("/scim/v2/Users/<string:scim_id>")
def scim_get_user(scim_id: str):
    _require_scim()
    return jsonify(scim.get_user(scim_id))


@api.put("/scim/v2/Users/<string:scim_id>")
def scim_replace_user(scim_id: str):
    _require_scim()
    return jsonify(scim.replace_user(scim_id, _json_body()))


@api.patch("/scim/v2/Users/<string:scim_id>")
def scim_patch_user(scim_id: str):
    """SCIM PATCH (`replace active false` = offboard: sessions die now)."""
    _require_scim()
    return jsonify(scim.patch_user(scim_id, _json_body()))


@api.delete("/scim/v2/Users/<string:scim_id>")
def scim_delete_user(scim_id: str):
    _require_scim()
    scim.delete_user(scim_id)
    return "", 204


@api.get("/scim/v2/Groups")
def scim_list_groups():
    _require_scim()
    return jsonify(
        scim.list_groups(
            start_index=int(request.args.get("startIndex") or 1),
            count=int(request.args.get("count") or 100),
        )
    )


@api.post("/scim/v2/Groups")
def scim_create_group():
    _require_scim()
    return jsonify(scim.create_group(_json_body())), 201


@api.get("/scim/v2/Groups/<string:scim_id>")
def scim_get_group(scim_id: str):
    _require_scim()
    return jsonify(scim.get_group(scim_id))


@api.put("/scim/v2/Groups/<string:scim_id>")
def scim_replace_group(scim_id: str):
    _require_scim()
    return jsonify(scim.replace_group(scim_id, _json_body()))


# ---------------------------------------------------------------------------
# session gateway & recording (plan phase 8a - the data plane)
# ---------------------------------------------------------------------------
@api.get("/zones")
@require_admin
def list_zones():
    """Network zones with node and asset-binding counts."""
    return jsonify({"zones": gateway.list_zones()})


@api.post("/zones")
@require_admin
def create_zone():
    """Create a zone (a network the gateway nodes live in)."""
    return jsonify(gateway.create_zone(_json_body(), actor=_actor())), 201


@api.get("/zones/<int:zone_id>")
@require_admin
def zone_detail(zone_id: int):
    """One zone with its nodes, pools and bound assets."""
    return jsonify(gateway.zone_detail(zone_id))


@api.delete("/zones/<int:zone_id>")
@require_admin
def delete_zone(zone_id: int):
    """Delete a zone - refused while live nodes, bindings or pools remain
    (revoked/denied node rows are history and do not block)."""
    return jsonify(gateway.delete_zone(zone_id, actor=_actor()))


@api.put("/discovery/assets/<int:asset_id>/zone")
@require_admin
def set_asset_zone(asset_id: int):
    """Bind a discovered asset to a zone ({'zone_id': null} unbinds)."""
    return jsonify(gateway.set_asset_zone(asset_id, _json_body(), actor=_actor()))


@api.get("/gateway/pools")
@require_admin
def list_gateway_pools():
    """Gateway pools with node counts."""
    return jsonify({"pools": gateway.list_pools()})


@api.post("/gateway/pools")
@require_admin
def create_gateway_pool():
    """Create a pool of gateway nodes inside one zone."""
    return jsonify(gateway.create_pool(_json_body(), actor=_actor())), 201


@api.delete("/gateway/pools/<int:pool_id>")
@require_admin
def delete_gateway_pool(pool_id: int):
    """Delete a pool - refused while nodes remain in it."""
    return jsonify(gateway.delete_pool(pool_id, actor=_actor()))


@api.get("/gateway/nodes")
@require_admin
def list_gateway_nodes():
    """Nodes with derived state (offline = stale heartbeat, never stored),
    heartbeat age and capacity."""
    return jsonify({"nodes": gateway.list_nodes()})


@api.post("/gateway/nodes")
@require_admin
def register_gateway_node():
    """Register a node: created `pending`; the token is shown once. A
    distinct approver activates it - the requester never may."""
    node, token = gateway.register_node(_json_body(), actor=_actor())
    return jsonify({"node": node, "token": token, "shown_once": True}), 201


@api.post("/gateway/nodes/<int:node_id>/approve")
@require_admin
def approve_gateway_node(node_id: int):
    """Approve or deny a pending node (maker-checker, never the requester)."""
    return jsonify(gateway.approve_node(node_id, _json_body(), actor=_actor()))


@api.post("/gateway/nodes/<int:node_id>/drain")
@require_admin
def drain_gateway_node(node_id: int):
    """Drain a node: no new sessions; live ones finish."""
    return jsonify(gateway.drain_node(node_id, actor=_actor()))


@api.delete("/gateway/nodes/<int:node_id>")
@require_admin
def revoke_gateway_node(node_id: int):
    """Revoke a node: its token dies; live sessions are terminated."""
    return jsonify(gateway.revoke_node(node_id, actor=_actor()))


@api.post("/gateway/nodes/<int:node_id>/heartbeat")
@require_gateway_node
def gateway_node_heartbeat(node_id: int):
    """Node heartbeat: liveness + capacity; the reply carries directives."""
    return jsonify(gateway.heartbeat(g.gateway_node, _json_body()))


@api.get("/gateway/nodes/<int:node_id>/work")
@require_gateway_node
def gateway_node_work(node_id: int):
    """The node's queue: pending sessions + live control state."""
    return jsonify(gateway.node_work(g.gateway_node))


@api.get("/gateway/sessions/<int:gateway_session_id>/connect-args")
def gateway_connect_args(gateway_session_id: int):
    """Guacd connection arguments with the injected credential: node token
    only, exactly once. An admin credential is *refused by name* here - a
    node credential is not an admin credential, and vice versa."""
    token = _gateway_node_token()
    if not token:
        admin_presented = bool(request.headers.get("X-Admin-Token"))
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            admin_presented = True
        if admin_presented:
            raise Forbidden(
                "connect-args require the gateway node token - "
                "the admin token is refused by design"
            )
        raise Unauthorized(
            "Gateway node token required "
            "(Authorization: Bearer vypam-gwn1.<id>.<secret>)"
        )
    node = gateway.verify_node_token(token)
    return jsonify(gateway.connect_args(gateway_session_id, node))


@api.post("/gateway/sessions/<int:gateway_session_id>/progress")
@require_gateway_node
def gateway_session_progress(gateway_session_id: int):
    """Node progress: state transitions, sealed segments, the end."""
    return jsonify(
        gateway.progress(gateway_session_id, g.gateway_node, _json_body())
    )


@api.get("/gateway/sessions/<int:gateway_session_id>/recording")
@require_admin
def gateway_recording(gateway_session_id: int):
    """Recording segments + key state: pointers and hashes, never bytes."""
    return jsonify(gateway.recording_meta(gateway_session_id))


@api.get("/gateway/sessions/<int:gateway_session_id>/recording/<int:seq>/data")
@require_admin
def gateway_recording_data(gateway_session_id: int, seq: int):
    """Playback one segment: decrypt + decompress the native stream.
    A destroyed key answers 410 (crypto-shredded)."""
    return jsonify(
        gateway.playback_segment(gateway_session_id, seq, actor=_actor())
    )


@api.post("/gateway/recordings/retention/run")
@require_admin
def gateway_retention_run():
    """Apply retention: prune files, crypto-shred keys, land the ledger."""
    return jsonify(gateway.run_retention(_json_body(required=False), actor=_actor()))


@api.get("/gateway/stats")
@require_admin
def gateway_stats():
    """Gateway posture: nodes, sessions, storage bytes by tier, spool."""
    return jsonify(gateway.stats())

