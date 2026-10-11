"""HSM/KMS-backed custody for the vault master key (architecture section 20).

The master key stays the same 32 bytes - existing ciphertexts remain valid;
what changes is *who holds it*.

- ``advisory`` (default): the key lives in the key file exactly as phase 4
  left it. The providers are reachable for explicit wrap/unwrap operations,
  but the vault does not depend on them.
- ``enforced``: the master key is held *wrapped* by the configured provider
  (envelope encryption - the provider wraps the 32-byte key, AES-256-GCM
  still protects every secret). The server never falls back to the file
  key: a provider outage or an explicit seal makes the vault refuse to
  decrypt (503) instead of quietly opening from disk.

Providers - all real HTTP or PKCS#11, no new hard dependency:

- ``hashicorp-vault``  transit encrypt/decrypt REST (``X-Vault-Token`` from
                       the ``PAM_HSM_VAULT_TOKEN`` environment variable)
- ``aws-cloudhsm``     AWS KMS REST (Encrypt/Decrypt/DescribeKey) signed
                       with SigV4 built on stdlib hashlib/hmac; CloudHSM
                       custom key stores are driven through this same KMS
                       API. Credentials are the standard AWS environment
                       variables.
- ``azure-dedicated-hsm``
                       Azure Dedicated HSM keys are administered through the
                       Key Vault wrapkey/unwrapkey REST with an OAuth
                       client-credentials token (``PAM_HSM_AZURE_TENANT_ID``
                       / ``_CLIENT_ID`` / ``_CLIENT_SECRET``); the schema name
                       matches the phase-4 settings enum
- ``local-pkcs11``     a PKCS#11 token via PyKCS11 (optional import - when
                       absent the provider reports it honestly instead of
                       pretending to be reachable)

Key material never enters a ledger record, an error payload or a log line.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from config import Config
from errors import ServiceUnavailable, ValidationFailed
from extensions import db
from models import HsmKeyEvent, SettingGroup
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import sessionmaker

HTTP_TIMEOUT_SECONDS = 5
_WRAP_WIRE_VERSION = 1

# in-memory seal state: sealed means "no key material in this process".
_SEAL_LOCK = threading.Lock()
_SEALED = False
_SEAL_REASON = ""
# the unwrapped master key in enforced mode (dropped on seal/unload)
_KEY_LOCK = threading.Lock()
_UNWRAPPED_KEY: Optional[bytes] = None
# provider health watchdog state (consumed by the monitor tick)
_HEALTH_FAILING_SINCE: Optional[float] = None
_LAST_HEALTH: Dict[str, Any] = {}
# azure OAuth token cache: {"token": str, "expires_at": float}
_AZURE_TOKEN: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# settings + mode
# ---------------------------------------------------------------------------
def _settings() -> Dict[str, Any]:
    try:
        row = SettingGroup.query.filter(SettingGroup.group_name == "hsm").first()
        return dict(row.value) if row is not None and row.value else {}
    except InvalidRequestError:
        # `load_key` runs inside `after_commit` too (the SIEM drain reads
        # settings there), where the writing session sits in SQLAlchemy's
        # `committed` state and refuses new SQL - audit._post_commit_session
        # documents the same behaviour. Retry on a session of our own: same
        # engine, same authoritative row, no custody shortcut.
        session = sessionmaker(bind=db.engine)()
        try:
            row = session.query(SettingGroup).filter(SettingGroup.group_name == "hsm").first()
            return dict(row.value) if row is not None and row.value else {}
        finally:
            session.close()


def mode() -> str:
    """`advisory` (file key in use) or `enforced` (provider-held key)."""
    value = str(_settings().get("enforcement") or "advisory").strip()
    return "enforced" if value == "enforced" else "advisory"


def is_sealed() -> bool:
    with _SEAL_LOCK:
        return _SEALED


def seal_reason() -> str:
    with _SEAL_LOCK:
        return _SEAL_REASON


# ---------------------------------------------------------------------------
# HTTP plumbing (stdlib only)
# ---------------------------------------------------------------------------
def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> (int, bytes):
    request = urllib.request.Request(url, data=body, method=method)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:  # a real HTTP answer is data
        return int(exc.code), exc.read()
    except urllib.error.URLError as exc:
        raise ServiceUnavailable(
            f"HSM provider endpoint unreachable: {exc.reason}",
            {"url": url.split("?")[0], "provider_reachable": False},
        ) from exc


def _http_json(
    url: str, *, method: str = "POST", headers: Optional[Dict[str, str]] = None, payload: Any = None
) -> (int, Dict[str, Any]):
    body = None
    merged = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        merged.setdefault("Content-Type", "application/json")
    status, raw = _http_request(url, method=method, headers=merged, body=body)
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        data = {}
    return status, data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------
class _Provider:
    """wrap/unwrap the 32-byte master key + a reachability probe."""

    name = "base"

    def __init__(self, values: Dict[str, Any]):
        self.values = values

    def healthcheck(self) -> Dict[str, Any]:
        raise NotImplementedError

    def wrap_key(self, key: bytes) -> bytes:
        raise NotImplementedError

    def unwrap_key(self, blob: bytes) -> bytes:
        raise NotImplementedError


class HashicorpVaultProvider(_Provider):
    """Vault transit engine: encrypt/decrypt the master key under a named
    symmetric key (the runbook creates it once:
    ``vault write transit/keys/<master_key_label> type=aes256-gcm96``)."""

    name = "hashicorp-vault"

    def _addr(self) -> str:
        return str(self.values.get("kms_endpoint") or "").rstrip("/")

    def _headers(self) -> Dict[str, str]:
        token = os.getenv("PAM_HSM_VAULT_TOKEN", "").strip()
        if not token:
            raise ServiceUnavailable(
                "HashiCorp Vault token missing",
                {"env": "PAM_HSM_VAULT_TOKEN", "provider_reachable": False},
            )
        return {"X-Vault-Token": token}

    def _key_name(self) -> str:
        return str(self.values.get("master_key_label") or "pam-master-key")

    def healthcheck(self) -> Dict[str, Any]:
        status, _raw = _http_request(
            self._addr() + "/v1/sys/health", method="GET", headers=self._headers()
        )
        if status == 200:
            return {"reachable": True, "detail": "vault unsealed"}
        if status == 429:
            return {"reachable": False, "detail": "vault is sealed"}
        return {"reachable": False, "detail": f"HTTP {status} from /v1/sys/health"}

    def wrap_key(self, key: bytes) -> bytes:
        status, data = _http_json(
            f"{self._addr()}/v1/transit/encrypt/{self._key_name()}",
            headers=self._headers(),
            payload={"plaintext": base64.b64encode(key).decode("ascii")},
        )
        ciphertext = str(data.get("ciphertext") or "")
        if status != 200 or not ciphertext:
            raise ServiceUnavailable(
                "Vault transit encrypt failed",
                {"http_status": status, "detail": str(data.get("errors") or "")[:200]},
            )
        return ciphertext.encode("ascii")

    def unwrap_key(self, blob: bytes) -> bytes:
        status, data = _http_json(
            f"{self._addr()}/v1/transit/decrypt/{self._key_name()}",
            headers=self._headers(),
            payload={"ciphertext": blob.decode("ascii")},
        )
        plaintext_b64 = str(data.get("plaintext") or "")
        if status != 200 or not plaintext_b64:
            raise ServiceUnavailable(
                "Vault transit decrypt failed",
                {"http_status": status, "detail": str(data.get("errors") or "")[:200]},
            )
        key = base64.b64decode(plaintext_b64)
        if len(key) != 32:
            raise ServiceUnavailable(
                "Vault transit decrypt returned unexpected key length",
                {"expected_bytes": 32},
            )
        return key


class AwsCloudHsmProvider(_Provider):
    """AWS KMS REST with SigV4 (stdlib hashlib/hmac). CloudHSM custom key
    stores are driven through this same API, so `master_key_label` is the
    KMS key id/arn and `region` the signing region."""

    name = "aws-cloudhsm"
    _SERVICE = "kms"
    _TARGET_PREFIX = "TMS_20141111"

    def _region(self) -> str:
        return str(self.values.get("region") or "us-east-1")

    def _creds(self) -> Dict[str, str]:
        access = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
        secret = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
        if not access or not secret:
            raise ServiceUnavailable(
                "AWS credentials missing",
                {"env": "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY", "provider_reachable": False},
            )
        return {
            "access_key": access,
            "secret_key": secret,
            "session_token": os.getenv("AWS_SESSION_TOKEN", "").strip(),
        }

    def _key_id(self) -> str:
        return str(self.values.get("master_key_label") or "")

    def _sign(self, creds: Dict[str, str], target: str, payload: bytes) -> Dict[str, str]:
        """SigV4: canonical request -> string-to-sign -> signing key -> auth."""
        region = self._region()
        now = datetime.now()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        canonical_headers = (
            f"content-type:application/json\n"
            f"host:kms.{region}.amazonaws.com\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-target:{self._TARGET_PREFIX}.{target}\n"
        )
        signed_headers = "content-type;host;x-amz-date;x-amz-target"
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_request = "\n".join(
            [
                "POST",
                "/",
                "",
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        scope = f"{date_stamp}/{region}/{self._service}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )

        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        signing_key = _hmac(
            _hmac(_hmac(_hmac(("AWS4" + creds["secret_key"]).encode("utf-8"), date_stamp), region), "kms"),
            "aws4_request",
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Host": f"kms.{region}.amazonaws.com",
            "X-Amz-Date": amz_date,
            "X-Amz-Target": f"{self._TARGET_PREFIX}.{target}",
            "Authorization": (
                f"AWS4-HMAC-SHA256 Credential={creds['access_key']}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
        }
        if creds.get("session_token"):
            headers["X-Amz-Security-Token"] = creds["session_token"]
        return headers

    def _call(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        creds = self._creds()
        body = json.dumps(payload).encode("utf-8")
        headers = self._sign(creds, target, body)
        # the signed body must travel exactly as signed: send it verbatim
        request = urllib.request.Request(
            f"https://kms.{self._region()}.amazonaws.com/", data=body, method="POST"
        )
        for name, value in headers.items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                status, raw = int(response.status), response.read()
        except urllib.error.HTTPError as exc:
            status, raw = int(exc.code), exc.read()
        except urllib.error.URLError as exc:
            raise ServiceUnavailable(
                f"HSM provider endpoint unreachable: {exc.reason}",
                {"provider": self.name, "provider_reachable": False},
            ) from exc
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return {"status": status, "data": data if isinstance(data, dict) else {}}

    def healthcheck(self) -> Dict[str, Any]:
        result = self._call("DescribeKey", {"KeyId": self._key_id()})
        if result["status"] == 200:
            return {"reachable": True, "detail": "kms key reachable"}
        return {
            "reachable": False,
            "detail": f"DescribeKey HTTP {result['status']}",
        }

    def wrap_key(self, key: bytes) -> bytes:
        result = self._call(
            "Encrypt",
            {
                "KeyId": self._key_id(),
                "Plaintext": base64.b64encode(key).decode("ascii"),
                "EncryptionAlgorithm": "AES_256_GCM",
            },
        )
        blob_b64 = str(result["data"].get("CiphertextBlob") or "")
        if result["status"] != 200 or not blob_b64:
            raise ServiceUnavailable(
                "KMS Encrypt failed",
                {"http_status": result["status"]},
            )
        return base64.b64decode(blob_b64)

    def unwrap_key(self, blob: bytes) -> bytes:
        result = self._call(
            "Decrypt",
            {
                "KeyId": self._key_id(),
                "CiphertextBlob": base64.b64encode(blob).decode("ascii"),
                "EncryptionAlgorithm": "AES_256_GCM",
            },
        )
        plaintext_b64 = str(result["data"].get("Plaintext") or "")
        if result["status"] != 200 or not plaintext_b64:
            raise ServiceUnavailable(
                "KMS Decrypt failed",
                {"http_status": result["status"]},
            )
        key = base64.b64decode(plaintext_b64)
        if len(key) != 32:
            raise ServiceUnavailable(
                "KMS Decrypt returned unexpected key length", {"expected_bytes": 32}
            )
        return key


class AzureKeyVaultProvider(_Provider):
    """Azure Dedicated HSM keys through the Key Vault wrapkey/unwrapkey REST
    (that is the plane Dedicated HSM keys are administered on). Credentials
    come from the environment (PAM_HSM_AZURE_TENANT_ID/_CLIENT_ID/
    _CLIENT_SECRET); the token is an OAuth client-credentials grant, cached
    until expiry. The provider id matches the phase-4 schema enum."""

    name = "azure-dedicated-hsm"

    def _vault_url(self) -> str:
        return str(self.values.get("kms_endpoint") or "").rstrip("/")

    def _key_name(self) -> str:
        return str(self.values.get("master_key_label") or "")

    def _token(self) -> str:
        now = time.time()
        cached = _AZURE_TOKEN.get("token")
        if cached and float(_AZURE_TOKEN.get("expires_at") or 0) > now + 30:
            return str(cached)
        tenant = os.getenv("PAM_HSM_AZURE_TENANT_ID", "").strip()
        client_id = os.getenv("PAM_HSM_AZURE_CLIENT_ID", "").strip()
        client_secret = os.getenv("PAM_HSM_AZURE_CLIENT_SECRET", "").strip()
        if not (tenant and client_id and client_secret):
            raise ServiceUnavailable(
                "Azure credentials missing",
                {
                    "env": "PAM_HSM_AZURE_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET",
                    "provider_reachable": False,
                },
            )
        status, data = _http_json(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            payload={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://vault.azure.net/.default",
            },
        )
        token = str(data.get("access_token") or "")
        if status != 200 or not token:
            raise ServiceUnavailable(
                "Azure OAuth token request failed", {"http_status": status}
            )
        _AZURE_TOKEN["token"] = token
        _AZURE_TOKEN["expires_at"] = now + float(data.get("expires_in") or 3600)
        return token

    def _wrap(self, op: str, value_b64: str) -> Dict[str, Any]:
        return _http_json(
            f"{self._vault_url()}/keys/{self._key_name()}/{op}?api-version=7.4",
            headers={"Authorization": "Bearer " + self._token()},
            payload={"alg": "RSA-OAEP-256", "value": value_b64},
        )

    def healthcheck(self) -> Dict[str, Any]:
        status, _data = _http_json(
            f"{self._vault_url()}/?api-version=7.4",
            method="GET",
            headers={"Authorization": "Bearer " + self._token()},
        )
        if status == 200:
            return {"reachable": True, "detail": "key vault reachable"}
        return {"reachable": False, "detail": f"HTTP {status}"}

    def wrap_key(self, key: bytes) -> bytes:
        status, data = self._wrap("wrapkey", base64.b64encode(key).decode("ascii"))
        wrapped = str(data.get("value") or "")
        if status != 200 or not wrapped:
            raise ServiceUnavailable("Azure wrapkey failed", {"http_status": status})
        return base64.b64decode(wrapped)

    def unwrap_key(self, blob: bytes) -> bytes:
        status, data = self._wrap("unwrapkey", base64.b64encode(blob).decode("ascii"))
        wrapped = str(data.get("value") or "")
        if status != 200 or not wrapped:
            raise ServiceUnavailable("Azure unwrapkey failed", {"http_status": status})
        key = base64.b64decode(wrapped)
        if len(key) != 32:
            raise ServiceUnavailable(
                "Azure unwrapkey returned unexpected key length", {"expected_bytes": 32}
            )
        return key


class LocalPkcs11Provider(_Provider):
    """A PKCS#11 token (Thales/SafeNet, AWS CloudHSM client, SoftHSM).
    PyKCS11 is an optional import: when it is absent the provider is
    honestly unreachable with an actionable message - never a silent
    fallback."""

    name = "local-pkcs11"

    def _lib(self) -> str:
        return os.getenv("PAM_HSM_PKCS11_LIB", "").strip()

    def _pin(self) -> str:
        return os.getenv("PAM_HSM_PKCS11_PIN", "").strip()

    def _session(self):
        try:
            import PyKCS11  # type: ignore
        except ImportError as exc:
            raise ServiceUnavailable(
                "PyKCS11 is not installed",
                {
                    "hint": "pip install PyKCS11 and set PAM_HSM_PKCS11_LIB / PAM_HSM_PKCS11_PIN",
                    "provider_reachable": False,
                },
            ) from exc
        lib = self._lib()
        if not lib:
            raise ServiceUnavailable(
                "PKCS#11 library path missing",
                {"env": "PAM_HSM_PKCS11_LIB", "provider_reachable": False},
            )
        pkcs11 = PyKCS11.PKCS11(lib)
        pkcs11.open()
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
        session = pkcs11.openSession(slot)
        pin = self._pin()
        if pin:
            session.login(pin)
        return session, pkcs11

    def _object(self, session, pkcs11) -> Any:
        label = str(self.values.get("master_key_label") or "")
        for obj in session.findObjects([("label", label)]):
            return obj
        raise ServiceUnavailable(
            "PKCS#11 object not found", {"label": label, "provider_reachable": False}
        )

    def healthcheck(self) -> Dict[str, Any]:
        session, pkcs11 = self._session()
        try:
            self._object(session, pkcs11)
            return {"reachable": True, "detail": "pkcs#11 token + key object present"}
        finally:
            try:
                session.close()
            except Exception:  # pragma: no cover - provider cleanup
                pass

    def wrap_key(self, key: bytes) -> bytes:
        session, pkcs11 = self._session()
        try:
            obj = self._object(session, pkcs11)
            mechanisms = pkcs11.getMechanisms(obj)
            mechanism = mechanisms[0] if mechanisms else None
            return bytes(session.encrypt(obj, key, mechanism=mechanism))
        finally:
            try:
                session.close()
            except Exception:  # pragma: no cover - provider cleanup
                pass

    def unwrap_key(self, blob: bytes) -> bytes:
        session, pkcs11 = self._session()
        try:
            obj = self._object(session, pkcs11)
            mechanisms = pkcs11.getMechanisms(obj)
            mechanism = mechanisms[0] if mechanisms else None
            key = bytes(session.decrypt(obj, blob, mechanism=mechanism))
            if len(key) != 32:
                raise ServiceUnavailable(
                    "PKCS#11 decrypt returned unexpected key length",
                    {"expected_bytes": 32},
                )
            return key
        finally:
            try:
                session.close()
            except Exception:  # pragma: no cover - provider cleanup
                pass


_PROVIDERS: Dict[str, Any] = {
    "hashicorp-vault": HashicorpVaultProvider,
    "aws-cloudhsm": AwsCloudHsmProvider,
    "azure-dedicated-hsm": AzureKeyVaultProvider,
    "local-pkcs11": LocalPkcs11Provider,
}


def current_provider() -> _Provider:
    values = _settings()
    name = str(values.get("provider") or "")
    provider_cls = _PROVIDERS.get(name)
    if provider_cls is None:
        raise ServiceUnavailable(
            f"Unknown HSM provider '{name}'",
            {"allowed": sorted(_PROVIDERS), "provider_reachable": False},
        )
    return provider_cls(values)


# ---------------------------------------------------------------------------
# events (folded into the ledger under source `hsm`)
# ---------------------------------------------------------------------------
def hsm_event(
    action: str,
    *,
    actor: str = "system",
    status: str = "ok",
    detail: Optional[Dict[str, Any]] = None,
) -> HsmKeyEvent:
    """Queue one custody-trail record; the flush listener folds it into the
    audit ledger under source `hsm` in the same commit. Key material never
    enters `detail`."""
    values = _settings()
    event = HsmKeyEvent(
        action=action,
        provider=str(values.get("provider") or ""),
        mode=mode(),
        key_label=str(values.get("master_key_label") or ""),
        status=status,
        actor=actor or "system",
        detail=detail or {},
    )
    db.session.add(event)
    return event


# ---------------------------------------------------------------------------
# wrap file + master key custody
# ---------------------------------------------------------------------------
def _wrap_path(config: Config) -> Path:
    return Path(str(config.vault_key_path) + ".wrap")


def _read_wrap(config: Config) -> Dict[str, Any]:
    path = _wrap_path(config)
    if not path.is_file():
        raise ServiceUnavailable(
            "No wrapped master key on disk",
            {
                "path": str(path),
                "hint": "POST /api/v1/hsm/keys/rotate to wrap the current master key under the provider",
            },
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ServiceUnavailable("Wrapped master key file is malformed", {"path": str(path)}) from exc
    if not isinstance(data, dict) or data.get("v") != _WRAP_WIRE_VERSION:
        raise ServiceUnavailable("Wrapped master key has an unsupported format", {"path": str(path)})
    return data


def _write_wrap(config: Config, provider_name: str, blob: bytes) -> Dict[str, Any]:
    path = _wrap_path(config)
    record = {
        "v": _WRAP_WIRE_VERSION,
        "provider": provider_name,
        "key_label": str(_settings().get("master_key_label") or ""),
        "wrapped_at": datetime.now().isoformat(),
        "blob": base64.b64encode(blob).decode("ascii"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - platform without POSIX modes
        pass
    return record


def master_key(config: Config) -> bytes:
    """The master key in enforced mode: unwrapped through the provider and
    cached in memory. Sealed, unreachable or misconfigured - all honest
    503s; there is no file fallback in enforced mode, ever."""
    global _UNWRAPPED_KEY
    if is_sealed():
        raise ServiceUnavailable(
            "Vault is sealed",
            {"sealed": True, "reason": seal_reason(), "hint": "POST /api/v1/hsm/unseal"},
        )
    with _KEY_LOCK:
        if _UNWRAPPED_KEY is not None:
            return _UNWRAPPED_KEY
        record = _read_wrap(config)
        provider = current_provider()
        if record.get("provider") != provider.name:
            raise ServiceUnavailable(
                "Wrapped master key belongs to a different provider",
                {"wrapped_provider": record.get("provider"), "configured_provider": provider.name},
            )
        key = provider.unwrap_key(base64.b64decode(record["blob"]))
        _UNWRAPPED_KEY = key
        # no commit here: this runs inside whoever needed the key; the event
        # row rides their transaction and the flush listener folds it
        hsm_event("hsm.key.unwrapped", detail={"via": provider.name})
        return key


def wrap_current_key(config: Config, *, actor: str) -> Dict[str, Any]:
    """Re-wrap (or first-wrap) the same master key under the configured
    provider. The key material itself never changes, so every existing
    ciphertext stays valid; only its custody moves."""
    import secrets_store  # local import: secrets_store consults this module

    provider = current_provider()
    values = _settings()
    if is_sealed():
        raise ServiceUnavailable(
            "Vault is sealed", {"sealed": True, "hint": "POST /api/v1/hsm/unseal"}
        )
    if mode() == "enforced":
        key = master_key(config)  # current custody: the provider itself
    else:
        key = secrets_store.load_key(config)  # advisory: the file key
    blob = provider.wrap_key(key)
    record = _write_wrap(config, provider.name, blob)
    global _UNWRAPPED_KEY
    with _KEY_LOCK:
        _UNWRAPPED_KEY = key if mode() == "enforced" else None
    hsm_event(
        "hsm.key.wrapped",
        actor=actor,
        detail={"via": provider.name, "wrapped_at": record["wrapped_at"]},
    )
    db.session.commit()
    return {
        "provider": provider.name,
        "mode": mode(),
        "key_label": values.get("master_key_label"),
        "wrapped_at": record["wrapped_at"],
        "key_changed": False,
        "detail": "same master key re-wrapped - existing ciphertexts stay valid",
    }


# ---------------------------------------------------------------------------
# seal / unseal + status + watchdog
# ---------------------------------------------------------------------------
def seal_vault(*, actor: str, reason: str = "operator seal") -> Dict[str, Any]:
    """Drop every trace of key material from this process: vault operations
    now fail with 503 until an explicit unseal."""
    global _SEALED, _SEAL_REASON, _UNWRAPPED_KEY, _HEALTH_FAILING_SINCE
    import secrets_store

    with _SEAL_LOCK:
        _SEALED = True
        _SEAL_REASON = reason
    with _KEY_LOCK:
        _UNWRAPPED_KEY = None
    secrets_store.drop_key_cache()
    hsm_event("hsm.sealed", actor=actor, detail={"reason": reason, "mode": mode()})
    db.session.commit()
    return {"sealed": True, "reason": reason, "mode": mode()}


def unseal_vault(*, actor: str, config: Optional[Config] = None) -> Dict[str, Any]:
    """Bring the vault back: in advisory mode the file key simply reloads;
    in enforced mode the provider must unwrap successfully - a dead provider
    keeps the vault sealed and says so."""
    global _SEALED, _SEAL_REASON, _HEALTH_FAILING_SINCE
    config = config or Config()
    if mode() == "enforced":
        with _SEAL_LOCK:
            _SEALED = False
            _SEAL_REASON = ""
        try:
            master_key(config)
        except ServiceUnavailable:
            with _SEAL_LOCK:
                _SEALED = True
                _SEAL_REASON = "provider unwrap failed during unseal"
            hsm_event("hsm.unseal", actor=actor, status="error")
            db.session.commit()
            raise
    else:
        with _SEAL_LOCK:
            _SEALED = False
            _SEAL_REASON = ""
    with _SEAL_LOCK:
        _HEALTH_FAILING_SINCE = None
    hsm_event("hsm.unsealed", actor=actor, detail={"mode": mode()})
    db.session.commit()
    return {"sealed": False, "mode": mode()}


def health() -> Dict[str, Any]:
    """One provider probe, recorded on the custody trail (state change
    only - a flip between ok and error)."""
    global _LAST_HEALTH, _HEALTH_FAILING_SINCE
    global _SEALED, _SEAL_REASON
    provider = current_provider()
    try:
        result = provider.healthcheck()
    except ServiceUnavailable as exc:
        result = {"reachable": False, "detail": str(exc.message)}
    previous = _LAST_HEALTH.get("reachable")
    _LAST_HEALTH = {
        "reachable": bool(result.get("reachable")),
        "detail": str(result.get("detail") or ""),
        "at": datetime.now().isoformat(),
    }
    if previous is not True and result.get("reachable"):
        hsm_event("hsm.provider.health", status="ok", detail={"detail": _LAST_HEALTH["detail"]})
        db.session.commit()
        _HEALTH_FAILING_SINCE = None
    elif previous is not False and not result.get("reachable"):
        hsm_event("hsm.provider.health", status="error", detail={"detail": _LAST_HEALTH["detail"]})
        db.session.commit()
        _HEALTH_FAILING_SINCE = time.monotonic()
    return dict(_LAST_HEALTH)


def watchdog_tick(*, actor: str = "monitor") -> Optional[Dict[str, Any]]:
    """The monitor tick's HSM half: while enforcement is on, a provider
    that stays unreachable for `seal_delay_seconds` seals the vault (the
    configured grace period exists exactly so a blip does not seal)."""
    global _SEALED, _SEAL_REASON
    if mode() != "enforced" or is_sealed():
        return None
    result = health()
    if result.get("reachable"):
        return None
    values = _settings()
    delay = int(values.get("seal_delay_seconds") or 0)
    failing_since = _HEALTH_FAILING_SINCE
    if failing_since is None or (time.monotonic() - failing_since) < delay:
        return {
            "sealed": False,
            "provider_reachable": False,
            "detail": result.get("detail"),
            "sealing_in_seconds": max(
                0, int(delay - (time.monotonic() - failing_since))
            )
            if failing_since
            else delay,
        }
    sealed = seal_vault(actor=actor, reason="provider health watchdog")
    sealed["detail"] = result.get("detail")
    return sealed


def status(config: Optional[Config] = None) -> Dict[str, Any]:
    """Honest custody state for GET /hsm/status and the posture widget."""
    config = config or Config()
    values = _settings()
    current_mode = mode()
    provider_name = str(values.get("provider") or "")
    sealed = is_sealed()
    wrap: Optional[Dict[str, Any]] = None
    wrap_error = None
    try:
        record = _read_wrap(config)
        wrap = {
            "provider": record.get("provider"),
            "key_label": record.get("key_label"),
            "wrapped_at": record.get("wrapped_at"),
        }
    except ServiceUnavailable as exc:
        wrap_error = str(exc.message)
    rotation_hours = int(values.get("key_rotation_hours") or 24)
    rotation_due = False
    if wrap and wrap.get("wrapped_at"):
        try:
            wrapped_at = datetime.fromisoformat(str(wrap["wrapped_at"]))
            rotation_due = datetime.now() > wrapped_at + timedelta(hours=rotation_hours)
        except ValueError:
            rotation_due = True
    return {
        "provider": provider_name,
        "mode": current_mode,
        "sealed": sealed,
        "seal_reason": seal_reason() if sealed else "",
        "key_label": values.get("master_key_label"),
        "cluster_id": values.get("cluster_id"),
        "region": values.get("region"),
        "fips_profile": values.get("fips_profile"),
        "key_rotation_hours": rotation_hours,
        "seal_delay_seconds": values.get("seal_delay_seconds"),
        "wrapped_key": wrap,
        "wrap_error": wrap_error,
        "rotation_due": rotation_due,
        "key_in_use": "provider" if (current_mode == "enforced" and not sealed) else "file",
        "last_health": dict(_LAST_HEALTH),
    }


def enforce_settings(values: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the additive 6c settings fields (called by the settings
    writer before anything is stored)."""
    enforcement = values.get("enforcement")
    if enforcement is not None and enforcement not in ("advisory", "enforced"):
        raise ValidationFailed(
            "enforcement must be 'advisory' or 'enforced'",
            {"field": "enforcement", "allowed": ["advisory", "enforced"]},
        )
    return values
