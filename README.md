# IPAM Licensing

Cryptographic licensing for the IPAM tool: a signing/validation library
(Phase 1) and an issuing/revocation server (Phase 2).

```
PAM/
├── license_private_key.pem          # RSA-2048 signing key      (NEVER commit)
├── license_public_key.pem           # RSA verification key      (ships to clients)
├── license_ed25519_private.pem      # Ed25519 signing key       (NEVER commit)
├── license_ed25519_public.pem       # Ed25519 verification key  (ships to clients)
├── license_<UUID>.json / .lic       # licenses issued so far (envelope / token)
├── ipam_licensing/                  # Phase 1: library + CLIs
│   ├── license.py               #   data model: tiers, plans, quotas, 8-module catalog
│   ├── signature.py             #   algorithms, canonical JSON, JWS, envelope parsing
│   ├── license_tool.py          #   LicenseGenerator (sign) + issuing CLI
│   ├── license_validator.py     #   LicenseValidator (verify) + validating CLI
│   ├── test_licensing.py        #   sandboxed demo script
│   ├── test_license_core.py     #   pytest suite (47 tests)
│   └── test_license_spec.py     #   spec/crypto suite (35 tests)
├── stitch_pam_suite_dashboard_ui/  # Stitch design suite (AegisPAM)
│   ├── zero_trust_sentinel/DESIGN.md   # design tokens + system spec
│   ├── enterprise_licensing_tier_entitlements_node_quotas/  # spec screen (source of truth)
│   ├── pam_command_center_threat_dashboard/ ...  # static suite screens
│   └── license_entitlement_center/code.html      # live screen (served by Phase 2)
└── phase2_license_server/       # Phase 2: Flask API (see its README.md)
    ├── app.py / routes.py / service.py / models.py
    ├── tests/test_api.py        #   pytest suite (49 tests)
    └── README.md                #   full API reference
```

## Quick start

```bash
pip install -r ipam_licensing/requirements.txt -r phase2_license_server/requirements.txt

# Phase 1: generate a license from the CLI, then verify it
python ipam_licensing/license_tool.py --type subscription --issued-to "Acme Ltd" --output-dir .
python ipam_licensing/license_validator.py license_<UUID>.json --public-key license_public_key.pem

# same license, post-quantum-ish air-gap flavour: Ed25519 signed, compact .lic token
python ipam_licensing/license_tool.py --type enterprise --issued-to "Acme Ltd" \
    --algorithm Ed25519 --format jwt --output-dir .
python ipam_licensing/license_validator.py license_<UUID>.lic

# Phase 2: run the issuing/revocation server
cd phase2_license_server && python app.py     # http://127.0.0.1:5000

# Tests (both phases)
python -m pytest -q                           # 131 tests
```

## How it fits together

- Licenses are signed over **canonical JSON** (sorted keys, no whitespace) and
  served in either wire format: a **JSON envelope**
  (`{license_data, signature, algorithm, version}`) or a **compact JWS token**
  (`header.payload.signature`, `.lic` / `.jwt`).
- Two algorithms are supported: **RSA-PSS-SHA256** (default) and **Ed25519**.
  Both live in `ipam_licensing/signature.py`, which is the only place signing
  and verification are implemented — Phase 2 imports it through
  `licensing_bridge.py`.
- One signature is kept per license; the authority may re-serve the same claims
  as an envelope or as a token, so the verifier accepts either signing input.
- Phase 1 verifies a license **offline**: signature → structure → expiry.
- Phase 2 adds the things that cannot be known offline — **revocation**, an
  issuing **audit trail**, and a central place to look up who holds what. A
  license issued by the server validates with the Phase 1 CLI and vice versa.

## What a license carries

Beyond the identity fields, the signed payload mirrors the enterprise
licensing spec: **tier / plan / license ID** (`LIC-9942-AEGIS-SEC-PROD`),
subject entity, classification, issuer, optional hardware **enclave binding**,
**node quota pools** with per-pool enforcement
(`soft-warning` / `auto-scale` / `audit-log` / `hard-block`), session and
bastion-tunnel quotas, **eight entitlement modules**, and an optional account
& SLA block. Everything except the core identity fields is omitted when unset,
so licenses issued before a field existed stay byte-identical and valid.

## Key management

- `license_private_key.pem` and `license_ed25519_private.pem` **never leave the
  server** and must never be committed or attached to a support ticket; both are
  excluded via `.gitignore`.
- `license_public_key.pem` / `license_ed25519_public.pem` are what clients embed
  for offline validation (the Ed25519 pair is created on first use when
  `LICENSE_AUTOGENERATE_KEYS=1`).
- Rotating a private key invalidates every license signed by that algorithm —
  keep the old public key around if previously issued licenses must still
  verify.
- Server startup fails fast if a public/private pair does not match
  (`phase2_license_server/keys.py`).
