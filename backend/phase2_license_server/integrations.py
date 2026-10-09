"""Enterprise integrations foundation (architecture section 20).

Everything here talks to the outside world for real - stdlib only, no new
dependencies:

- **TOTP (RFC 6238)** - enrol/verify codes for the `mfa` band gate; pure
  `hmac`/`hashlib`/`secrets`, SHA-1/6 digits/30 s period (what authenticator
  apps expect by default), +/-1 step window, constant-time comparison.
- **ITSM ticket verification** - a real HTTPS/HTTP GET against the configured
  ServiceNow / Jira / Freshservice / BMC REST surface; a ticket is `verified`
  only when the vendor answers 2xx. Never simulated: unconfigured callers are
  told so by the service layer, connection failures come back as honest
  errors.
- **SIEM outbound** - the ledger batch (same NDJSON serialization as
  `GET /audit/export`) POSTed to a configured webhook with an HMAC-SHA256
  signature over the exact bytes.
- **LDAP bind** - a minimal BER encoder/decoder for the LDAPv3 bind exchange
  (RFC 4511): what goes on the wire is a real BindRequest, what comes back
  is parsed from a real BindResponse. No third-party LDAP client.

Nothing in this module reads configuration or writes the database: callers
pass the settings they read, and decide what the results mean.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as pysecrets
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# TOTP (RFC 6238 / HOTP RFC 4226)
# ---------------------------------------------------------------------------
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_ALGORITHM = "sha1"
TOTP_SECRET_BYTES = 20  # 160-bit secret, the common authenticator default


def generate_totp_secret() -> str:
    """A fresh base32 secret (no padding, what otpauth URIs expect)."""
    return base64.b32encode(pysecrets.token_bytes(TOTP_SECRET_BYTES)).decode(
        "ascii"
    ).rstrip("=")


def _totp_key(secret: str) -> bytes:
    pad = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + pad, casefold=True)


def hotp(secret: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    """HOTP over SHA-1: dynamic truncation, zero-padded (RFC 4226)."""
    digest = hmac.new(
        _totp_key(secret), struct.pack(">Q", counter), TOTP_ALGORITHM
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def totp_now(secret: str, at: Optional[float] = None) -> str:
    """The code that is valid right now (or at `at`, epoch seconds)."""
    moment = time.time() if at is None else at
    return hotp(secret, int(moment // TOTP_PERIOD))


def verify_totp(
    secret: str,
    code: Any,
    *,
    at: Optional[float] = None,
    window: int = 1,
) -> bool:
    """True when `code` matches this step or +/-`window` steps.

    Every candidate is compared with `hmac.compare_digest` regardless of a
    match, so the answer does not leak where in the window it landed.
    """
    if not secret or not isinstance(code, str):
        return False
    candidate = code.strip().replace(" ", "")
    if not candidate or not candidate.isdigit():
        return False
    moment = time.time() if at is None else at
    step = int(moment // TOTP_PERIOD)
    try:
        key_check = _totp_key(secret)
    except (ValueError, TypeError):
        return False
    if not key_check:
        return False
    valid = False
    for offset in range(-window, window + 1):
        expected = hotp(secret, step + offset)
        valid = hmac.compare_digest(expected, candidate) or valid
    return valid


def otpauth_uri(
    secret: str,
    *,
    account: str,
    issuer: str = "VY-PAM",
    digits: int = TOTP_DIGITS,
    period: int = TOTP_PERIOD,
) -> str:
    """The URI authenticator apps scan or paste (manual-entry key included)."""
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": digits,
            "period": period,
        }
    )
    return f"otpauth://totp/{label}?{query}"


# ---------------------------------------------------------------------------
# ITSM ticket verification (real REST, honest failures)
# ---------------------------------------------------------------------------
# Vendor presets: relative path templates over the instance base URL. BMC has
# no preset on purpose - Helix deployments differ, so the operator supplies
# `path_template` instead of us guessing a REST surface.
ITSM_VENDOR_PATHS = {
    "servicenow": "api/now/table/incident/{ticket}",
    "jira": "rest/api/2/issue/{ticket}",
    "freshservice": "api/v2/tickets/{ticket}",
}
ITSM_VENDORS = tuple(sorted(ITSM_VENDOR_PATHS)) + ("bmc",)


def itsm_ticket_url(
    base_url: str, vendor: str, path_template: str, ticket: str
) -> str:
    template = (path_template or "").strip() or ITSM_VENDOR_PATHS.get(vendor, "")
    if not template:
        raise ValueError(
            "no path template for this vendor - set itsm.path_template "
            "(we do not guess REST surfaces)"
        )
    path = template.replace("{ticket}", urllib.parse.quote(ticket, safe=""))
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def verify_itsm_ticket(
    *,
    base_url: str,
    vendor: str,
    path_template: str,
    username: str,
    token: str,
    ticket: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Ask the ITSM instance whether this ticket exists.

    Returns `{verified, detail, url?, http_status?}` - never raises: a
    refused connection is `verified: false` with the real error, because an
    unreachable ITSM must not look like an invalid ticket and vice versa.
    """
    if not base_url:
        return {"verified": False, "detail": "itsm is not configured"}
    if not ticket or not isinstance(ticket, str):
        return {"verified": False, "detail": "no ticket supplied"}
    try:
        url = itsm_ticket_url(base_url, vendor, path_template, ticket)
    except ValueError as exc:
        return {"verified": False, "detail": str(exc)}

    credentials = base64.b64encode(
        f"{username}:{token}".encode("utf-8")
    ).decode("ascii")
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
            "User-Agent": "VY-PAM/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            response.read(1024)  # drain a prefix; the status is the answer
    except urllib.error.HTTPError as exc:
        status = exc.code
        detail = f"HTTP {status}" + (
            " - ticket not found" if status == 404 else ""
        )
        return {"verified": False, "detail": detail, "url": url, "http_status": status}
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return {
            "verified": False,
            "detail": f"connection failed: {reason}",
            "url": url,
        }
    except (TimeoutError, socket.timeout) as exc:
        return {
            "verified": False,
            "detail": f"request timed out after {timeout:g}s",
            "url": url,
        }
    except Exception as exc:  # pragma: no cover - defensive, still honest
        return {"verified": False, "detail": f"{type(exc).__name__}: {exc}", "url": url}

    verified = 200 <= int(status) < 300
    return {
        "verified": verified,
        "detail": f"HTTP {status}" + ("" if verified else " - not an accepted response"),
        "url": url,
        "http_status": int(status),
    }


# ---------------------------------------------------------------------------
# SIEM outbound (signed NDJSON batch)
# ---------------------------------------------------------------------------
SIGNATURE_HEADER = "X-VY-PAM-Signature"


def ndjson_batch(records: List[Dict[str, Any]]) -> bytes:
    """Exactly what `GET /audit/export` emits, batched - one JSON per line."""
    return "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in records
    ).encode("utf-8")


def siem_signature(body: bytes, secret: str) -> str:
    """HMAC-SHA256 over the exact bytes sent, `sha256=<hex>` (GitHub-style)."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def siem_push(
    records: List[Dict[str, Any]],
    *,
    webhook_url: str,
    signing_secret: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """POST one batch; returns `{ok, http_status?, records, detail/error}`.

    Never raises: the caller's transaction has already committed, and a
    failed push is an honest status - never a broken request.
    """
    if not records:
        return {"ok": False, "detail": "no records to push"}
    if not webhook_url:
        return {"ok": False, "detail": "siem webhook is not configured"}
    if not signing_secret:
        return {"ok": False, "detail": "siem signing secret is not configured"}

    body = ndjson_batch(records)
    request = urllib.request.Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/x-ndjson",
            SIGNATURE_HEADER: siem_signature(body, signing_secret),
            "X-VY-PAM-Batch": str(len(records)),
            "X-VY-PAM-Source": "vy-pam",
            "User-Agent": "VY-PAM/1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            response.read(1024)
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "http_status": exc.code,
            "records": len(records),
            "detail": f"HTTP {exc.code}",
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "records": len(records),
            "detail": f"connection failed: {getattr(exc, 'reason', exc)}",
        }
    except (TimeoutError, socket.timeout):
        return {
            "ok": False,
            "records": len(records),
            "detail": f"request timed out after {timeout:g}s",
        }
    except Exception as exc:  # pragma: no cover - defensive, still honest
        return {
            "ok": False,
            "records": len(records),
            "detail": f"{type(exc).__name__}: {exc}",
        }
    accepted = 200 <= int(status) < 300
    return {
        "ok": accepted,
        "http_status": int(status),
        "records": len(records),
        "detail": f"HTTP {status}" + ("" if accepted else " - rejected"),
    }


# ---------------------------------------------------------------------------
# Cloud / Kubernetes API calls (architecture section 14)
# ---------------------------------------------------------------------------
# One honest HTTP layer for every section-14 call: a real request against
# the connector's endpoint, the outcome recorded verbatim (status, body
# verdict, connection error). Nothing is simulated, nothing is guessed -
# an unreachable cloud is an unreachable cloud.
CLOUD_HTTP_CAP = 262144  # 256 KiB: enough for inventory pages, not a dump


def cloud_http(
    url: str,
    *,
    token: str = "",
    method: str = "GET",
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """One real HTTP call to a cloud or Kubernetes API endpoint.

    Returns `{ok, http_status?, detail, json?, elapsed_ms}` - never raises:
    a refused connection, a 401 from the cluster, an unparseable body are
    all honest outcomes the caller records. `json` carries the parsed body
    when the answer was JSON (used by inventory); `ok` is strictly the
    2xx-ness of the transport answer, so a reachability probe never
    overclaims what it proved."""
    headers = {"Accept": "application/json", "User-Agent": "VY-PAM/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, headers=headers, data=data, method=method)
    started = time.monotonic()

    def _finish(status: Optional[int], raw: bytes, ok: bool, detail: str) -> Dict[str, Any]:
        parsed: Any = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except ValueError:
                parsed = None
        return {
            "ok": ok,
            "http_status": int(status) if status is not None else None,
            "detail": detail,
            "json": parsed,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read(CLOUD_HTTP_CAP)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read(CLOUD_HTTP_CAP)
        except Exception:  # pragma: no cover - defensive, still honest
            raw = b""
        return _finish(status, raw, False, f"HTTP {status}")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return _finish(None, b"", False, f"connection failed: {reason}")
    except (TimeoutError, socket.timeout):
        return _finish(
            None, b"", False, f"request timed out after {timeout:g}s"
        )
    except Exception as exc:  # pragma: no cover - defensive, still honest
        return _finish(None, b"", False, f"{type(exc).__name__}: {exc}")

    ok = 200 <= int(status) < 300
    return _finish(status, raw, ok, f"HTTP {status}")


def k8s_apply_binding(
    endpoint: str,
    namespace: str,
    binding: str,
    role: str,
    subject: str,
    *,
    session_ref: str,
    expires_at: str,
    token: str = "",
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Create an ephemeral RoleBinding (architecture section 14's
    *Kubernetes -> RBAC -> JIT -> ephemeral privilege* step): a real POST
    to the cluster's RBAC API. The annotations record who the grant is
    for and when it must end; the enforcement of that ending is the
    removal this code also performs - Kubernetes has no TTL on bindings."""
    url = (
        endpoint.rstrip("/")
        + f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings"
    )
    manifest = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": binding,
            "namespace": namespace,
            "annotations": {
                "vypam.io/session-ref": session_ref,
                "vypam.io/expires-at": expires_at,
            },
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role,
        },
        "subjects": [{"kind": "User", "name": subject}],
    }
    return cloud_http(
        url, token=token, method="POST", body=manifest, timeout=timeout
    )


def k8s_remove_binding(
    endpoint: str,
    namespace: str,
    binding: str,
    *,
    token: str = "",
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Delete the ephemeral RoleBinding - the real DELETE that ends the
    privilege (close, expiry, or a grant that failed after applying)."""
    url = (
        endpoint.rstrip("/")
        + f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}"
        + f"/rolebindings/{binding}"
    )
    return cloud_http(url, token=token, method="DELETE", timeout=timeout)


# ---------------------------------------------------------------------------
# LDAP bind (RFC 4511 over TCP/TLS - minimal, real, stdlib only)
# ---------------------------------------------------------------------------
# BER: a BindRequest is [APPLICATION 0] SEQUENCE { version, name,
# authentication }, wrapped in an LDAPMessage with messageID 1; the answer is
# [APPLICATION 1] BindResponse { resultCode ENUMATED, matchedDN, diagnostic }.
_LDAP_SUCCESS = 0
_LDAP_RESULT_NAMES = {
    0: "success",
    4: "authMethodNotSupported",
    13: "confidentialityRequired",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    51: "busy",
    81: "serverDown",
    85: "timeLimitExceeded",
    91: "unavailable",
}


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_tlv(sock: socket.socket) -> tuple:
    header = _read_exact(sock, 2)
    tag = header[0]
    length = header[1]
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported BER length encoding")
        length = int.from_bytes(_read_exact(sock, count), "big")
    return tag, _read_exact(sock, length)


def _next_tlv(buffer: bytes, pos: int) -> tuple:
    """Parse one TLV out of a byte buffer: (tag, payload, next position)."""
    if pos + 2 > len(buffer):
        raise ValueError("truncated TLV")
    tag = buffer[pos]
    length = buffer[pos + 1]
    start = pos + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported BER length encoding")
        length = int.from_bytes(buffer[start : start + count], "big")
        start += count
    end = start + length
    if end > len(buffer):
        raise ValueError("TLV extends past the message")
    return tag, buffer[start:end], end


def ldap_bind(
    *,
    server: str,
    port: int,
    use_ssl: bool,
    dn: str,
    password: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Attempt a real LDAP bind. Returns `{ok, result_code?, detail}`.

    The password only ever travels inside the BindRequest on this socket;
    it is never logged, never stored and never part of the result.
    """
    if not server:
        return {"ok": False, "detail": "ldap is not configured"}
    if not dn:
        return {"ok": False, "detail": "bind DN is empty after the user template"}

    version = _tlv(0x02, b"\x03")  # LDAP version 3
    auth = _tlv(0x80, password.encode("utf-8"))  # simple authentication
    bind_request = _tlv(
        0x60, version + _tlv(0x04, dn.encode("utf-8")) + auth
    )
    message = _tlv(0x30, _tlv(0x02, b"\x01") + bind_request)  # messageID 1

    sock = None
    try:
        sock = socket.create_connection((server, int(port)), timeout=timeout)
        sock.settimeout(timeout)
        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=server)
        sock.sendall(message)

        tag, payload = _read_tlv(sock)
        if tag != 0x30:
            return {"ok": False, "detail": "unexpected LDAP response"}
        # LDAPMessage = messageID TLV, then protocolOp TLV
        _mid_tag, _mid, pos = _next_tlv(payload, 0)
        op_tag, op, _ = _next_tlv(payload, pos)
        if op_tag != 0x61:
            return {"ok": False, "detail": "response is not a BindResponse"}
        # BindResponse = resultCode ENUMATED, matchedDN, diagnosticMessage
        code_tag, code_bytes, _ = _next_tlv(op, 0)
        if code_tag != 0x0A:
            return {"ok": False, "detail": "malformed BindResponse"}
        result_code = int.from_bytes(code_bytes, "big")
    except ssl.SSLError as exc:
        return {"ok": False, "detail": f"TLS failed: {exc}"}
    except (ConnectionRefusedError, socket.gaierror, OSError) as exc:
        return {"ok": False, "detail": f"connection failed: {exc}"}
    except (ValueError, ConnectionError, IndexError) as exc:
        return {"ok": False, "detail": f"malformed LDAP response: {exc}"}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover
                pass

    name = _LDAP_RESULT_NAMES.get(result_code, f"result {result_code}")
    return {
        "ok": result_code == _LDAP_SUCCESS,
        "result_code": result_code,
        "detail": "bind succeeded" if result_code == _LDAP_SUCCESS else name,
        "dn": dn,
    }
