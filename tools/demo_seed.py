#!/usr/bin/env python3
"""Demo seed for the VY-PAM console (frontend-completion phase).

Fills a fresh rig through the PUBLIC API only - no direct DB writes:

  1. policy - PUT /api/v1/settings/auth: the shipped auth policy is
       fail-closed MFA (mfa_required=True), which blocks a password-only
       console login until a factor is enrolled. A demo rig logs in from
       the login screen, so the seed relaxes the policy through the
       PUBLIC audited settings API (exactly like an admin would) and
       verifies the write stuck. Real deployments keep MFA required and
       enrol factors instead - this is a dev/CI-rig affordance only.
  2. users   - POST /api/v1/users (explicit passwords; the console login
               is password-only after step 1, exactly like the login
               screen).
  3. rbac    - POST /api/v1/role-bindings (local principals; each one-shot
               API token is printed, shown once, never recoverable).
  4. license - generated OFFLINE with backend/ipam_licensing/license_tool.py
               against the repo dev keypair (the PAM-MASTER issuing flow),
               then installed via POST /api/v1/licenses/import - the server
               verifies the signature before recording the claims.

Idempotent: an already-seeded rig re-runs cleanly (existing users and
bindings are skipped; the license import is skipped when one is already
installed). Exit 0 on success, 1 on any refusal. The generated .lic lives in
the system temp dir and is deleted - nothing lands in the repo.

The demo passwords are PUBLIC dev-rig values, not secrets: they only ever
exist on a local open-mode rig that anyone on the machine can already
administrate. Never reuse them anywhere else.

Usage:  python tools/demo_seed.py [--base http://127.0.0.1:5000]
                                  [--admin-token <LICENSE_ADMIN_TOKEN>]
                                  [--private-key <signing key path>]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
LICENSING_DIR = REPO_ROOT / "backend" / "ipam_licensing"

DEMO_USERS: List[Tuple[str, str, str, str]] = [
    ("admin", "Demo Administrator", "admin@vypam.local", "Zephyr-Console-7391-Qx!"),
    ("operator", "Demo Operator", "operator@vypam.local", "Harbor-Session-4826-Kv!"),
    ("auditor", "Demo Auditor", "auditor@vypam.local", "Lantern-Audit-5173-Nt!"),
]

DEMO_BINDINGS: List[Dict[str, str]] = [
    {"principal": "demo-admin", "role": "admin", "kind": "local"},
    {"principal": "demo-operator", "role": "operator", "kind": "local"},
    {"principal": "demo-auditor", "role": "auditor", "kind": "local"},
]


def http(
    base: str,
    method: str,
    path: str,
    body: Optional[dict] = None,
    timeout: int = 30,
    admin_token: str = "",
) -> Tuple[int, Dict[str, Any]]:
    """One API call against the rig (path like '/users'). Returns
    (status_code, parsed_json). A token-mode rig (LICENSE_ADMIN_TOKEN set)
    requires the admin credential on every call - pass it with
    --admin-token; open-mode rigs ignore it."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "X-Actor": "demo-seed"}
    if admin_token:
        headers["X-Admin-Token"] = admin_token
    req = urllib.request.Request(
        base.rstrip("/") + "/api/v1" + path,
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            raw = res.read().decode("utf-8")
            return res.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw) if raw else {}
        except ValueError:
            return exc.code, {"error": raw[:200]}
    except urllib.error.URLError as exc:
        return 0, {"error": "cannot reach rig: %s" % (exc.reason,)}


def health(base: str) -> Tuple[int, Dict[str, Any]]:
    """GET /health at the rig root (outside the /api/v1 blueprint)."""
    try:
        with urllib.request.urlopen(base.rstrip("/") + "/health", timeout=10) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        code = getattr(exc, "code", 0)
        return code, {"error": str(exc)}


def generate_license(tmpdir: Path, private_key_path: Path) -> Path:
    """The PAM-MASTER issuing flow, offline: sign an enterprise license with
    the given keypair through license_tool (stdlib + cryptography only)."""
    sys.path.insert(0, str(LICENSING_DIR))
    from license import LicenseType  # noqa: E402  (path set above)
    from license_tool import LicenseGenerator  # noqa: E402

    generator = LicenseGenerator(private_key_path=str(private_key_path))
    path = generator.generate_and_save_license(
        LicenseType.ENTERPRISE,
        issued_to="VY-PAM Demo Deployment",
        output_dir=str(tmpdir),
        trial_days=365,
        tier="Enterprise",
        plan="Annual Subscription",
    )
    return Path(path)


def relax_demo_mfa_policy(base: str, admin_token: str = "") -> None:
    """The shipped auth policy is fail-closed (auth.mfa_required=True): a
    console login with no enrolled factor gets an enrolment ticket, never a
    silent pass. A demo rig has no enrolment UI path, so this relaxes the
    policy through the public, audited PUT /settings/auth - the same call an
    admin makes - then re-reads the group to prove the write stuck."""
    status, body = http(base, "GET", "/settings", admin_token=admin_token)
    if status != 200:
        print("ABORT: GET /settings refused (%s): %s" % (status, body.get("error")))
        sys.exit(1)
    # GET /settings returns settings.<group>.values.<field>
    auth = ((body.get("settings") or {}).get("auth") or {}).get("values") or {}
    if auth.get("mfa_required") is False:
        print("auth policy: mfa_required already False - skipped")
        return
    status, body = http(base, "PUT", "/settings/auth",
                        {"mfa_required": False}, admin_token=admin_token)
    if status != 200:
        print("ABORT: PUT /settings/auth refused (%s): %s"
              % (status, body.get("error")))
        sys.exit(1)
    status, body = http(base, "GET", "/settings", admin_token=admin_token)
    auth = ((body.get("settings") or {}).get("auth") or {}).get("values") or {}
    if status != 200 or auth.get("mfa_required") is not False:
        print("ABORT: mfa_required still %r after the audited PUT"
              % (auth.get("mfa_required"),))
        sys.exit(1)
    print("auth policy: mfa_required set to False via audited "
          "PUT /settings/auth (dev-rig demo login only)")


def seed_users(base: str, admin_token: str = "") -> int:
    """Create the demo console users; returns how many were created."""
    status, body = http(base, "GET", "/users", admin_token=admin_token)
    if status != 200:
        print("ABORT: GET /users refused (%s): %s" % (status, body.get("error")))
        sys.exit(1)
    existing = {u.get("username") for u in body.get("users", [])}
    created = 0
    for username, display, email, password in DEMO_USERS:
        if username in existing:
            print("user %-9s already exists - skipped" % username)
            continue
        status, body = http(
            base,
            "POST",
            "/users",
            {
                "username": username,
                "email": email,
                "display_name": display,
                "password": password,
            },
            admin_token=admin_token,
        )
        if status != 201:
            print("ABORT: POST /users %s refused (%s): %s"
                  % (username, status, body.get("error")))
            sys.exit(1)
        print("user %-9s created (demo password documented in this file)" % username)
        created += 1
    return created


def seed_bindings(base: str, admin_token: str = "") -> int:
    """Create the demo RBAC bindings; prints the one-shot tokens."""
    status, body = http(base, "GET", "/role-bindings", admin_token=admin_token)
    if status != 200:
        print("ABORT: GET /role-bindings refused (%s): %s" % (status, body.get("error")))
        sys.exit(1)
    existing = {b.get("principal") for b in body.get("bindings", [])}
    created = 0
    for binding in DEMO_BINDINGS:
        if binding["principal"] in existing:
            print("binding %-14s already exists - skipped" % binding["principal"])
            continue
        status, body = http(base, "POST", "/role-bindings", binding,
                            admin_token=admin_token)
        if status != 201:
            print("ABORT: POST /role-bindings %s refused (%s): %s"
                  % (binding["principal"], status, body.get("error")))
            sys.exit(1)
        token = body.get("token")
        print("binding %-14s role=%-9s token(shown once): %s"
              % (binding["principal"], binding["role"], token))
        created += 1
    return created


def seed_license(base: str, admin_token: str = "", private_key: str = "") -> bool:
    """Import one vendor-signed license when the ledger is empty."""
    status, body = http(base, "GET", "/licenses", admin_token=admin_token)
    if status != 200:
        print("ABORT: GET /licenses refused (%s): %s" % (status, body.get("error")))
        sys.exit(1)
    if body.get("total"):
        print("license already installed (%d on the ledger) - skipped" % body["total"])
        return False
    key_path = Path(private_key) if private_key else REPO_ROOT / "license_private_key.pem"
    tmpdir = Path(tempfile.mkdtemp(prefix="vypam-demo-seed-"))
    try:
        lic_path = generate_license(tmpdir, key_path)
        envelope = json.loads(lic_path.read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)  # ephemeral - never committed
    status, body = http(base, "POST", "/licenses/import", envelope,
                        admin_token=admin_token)
    if status != 201:
        print("ABORT: POST /licenses/import refused (%s): %s" % (status, body.get("error")))
        sys.exit(1)
    record = body.get("license") or {}
    print("license imported: %s type=%s tier=%s"
          % (record.get("license_key"), record.get("license_type"),
             record.get("tier")))
    # Re-read the ledger: the import must PERSIST before we claim success.
    status, body = http(base, "GET", "/licenses", admin_token=admin_token)
    keys = [l.get("license_key") for l in body.get("licenses", [])]
    if status != 200 or record.get("license_key") not in keys:
        print("ABORT: license %s not on the ledger after import (status=%s)"
              % (record.get("license_key"), status))
        sys.exit(1)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed a fresh rig with demo data")
    parser.add_argument("--base", default="http://127.0.0.1:5000",
                        help="rig base URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--admin-token", default="",
                        help="LICENSE_ADMIN_TOKEN value when the rig enforces "
                             "token auth (open-mode rigs ignore it)")
    parser.add_argument("--private-key", default="",
                        help="private key the offline license is signed with "
                             "(default: <repo>/license_private_key.pem; CI "
                             "passes an ephemeral keypair the rig trusts)")
    args = parser.parse_args()

    status, health_json = health(args.base)
    if status != 200 or health_json.get("status") != "ok":
        print("ABORT: rig not reachable at %s (%s): %s" % (args.base, status, health_json))
        return 1
    print("rig %s: node=%s site=%s auth=%s"
          % (args.base, health_json.get("node"), health_json.get("site"),
             health_json.get("auth")))
    if health_json.get("auth") == "token" and not args.admin_token:
        print("ABORT: rig enforces token auth - pass --admin-token")
        return 1

    relax_demo_mfa_policy(args.base, args.admin_token)
    users = seed_users(args.base, args.admin_token)
    bindings = seed_bindings(args.base, args.admin_token)
    imported = seed_license(args.base, args.admin_token, args.private_key)
    print("seed done: %d users created, %d bindings created, license %s"
          % (users, bindings, "imported" if imported else "already present"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
