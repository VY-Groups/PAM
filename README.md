# VY-PAM

Enterprise privileged identity security platform (full requirements:
`VY-PAM_Enterprise_PAM_Architecture.md`). What exists today — the
cryptographic licensing core (Phase 1), its issuing/revocation API
(Phase 2) and the web console — is laid out for growth as
`frontend/` + `apis/` + `backend/`.

```
PAM/
├── license_private_key.pem          # RSA-2048 signing key      (NEVER commit)
├── license_public_key.pem           # RSA verification key      (ships to clients)
├── license_ed25519_private.pem      # Ed25519 signing key       (NEVER commit)
├── license_ed25519_public.pem       # Ed25519 verification key  (ships to clients)
├── license_<UUID>.json / .lic       # licenses issued so far (envelope / token)
├── frontend/                        # Web console (product UI, served by Phase 2)
│   ├── index.html               #   launcher: every screen, LIVE/STATIC/SPEC badges
│   ├── screens/<name>/          #   one folder per screen: code.html + screen.png
│   └── README.md                #   layout + how to add a screen (the contract)
├── apis/                            # HTTP contract for every backend service
│   ├── openapi.yaml             #   OpenAPI 3.1: all 13 routes (synced by a test)
│   └── README.md                #   conventions + how to view
├── backend/
│   ├── ipam_licensing/              # Phase 1: library + CLIs
│   │   ├── license.py           #   data model: tiers, plans, quotas, 8-module catalog
│   │   ├── signature.py         #   algorithms, canonical JSON, JWS, envelope parsing
│   │   ├── license_tool.py      #   LicenseGenerator (sign) + issuing CLI
│   │   ├── license_validator.py #   LicenseValidator (verify) + validating CLI
│   │   ├── test_licensing.py    #   sandboxed demo script
│   │   ├── test_license_core.py #   pytest suite (47 tests)
│   │   └── test_license_spec.py #   spec/crypto suite (35 tests)
│   └── phase2_license_server/   # Phase 2: Flask API (see its README.md)
│       ├── app.py / routes.py / service.py / models.py
│       ├── tests/test_api.py            # license API suite (49 tests)
│       ├── tests/test_settings_and_ui.py # settings API + frontend nav (32 tests)
│       ├── tests/test_openapi_contract.py # apis/openapi.yaml ↔ routes (5 tests)
│       └── README.md                # full API reference
└── stitch_pam_suite_dashboard_ui/  # Frozen design reference (frontend/ started as a copy)
    ├── index.html                #   launcher (reference copy)
    ├── zero_trust_sentinel/DESIGN.md   # design tokens + system spec
    ├── enterprise_licensing_tier_entitlements_node_quotas/  # spec screen (source of truth)
    └── platform_settings_idp_hsm_configuration/  # settings spec (source of truth)
```

## Quick start

```bash
pip install -r backend/ipam_licensing/requirements.txt -r backend/phase2_license_server/requirements.txt

# Phase 1: generate a license from the CLI, then verify it
python backend/ipam_licensing/license_tool.py --type subscription --issued-to "Acme Ltd" --output-dir .
python backend/ipam_licensing/license_validator.py license_<UUID>.json --public-key license_public_key.pem

# same license, post-quantum-ish air-gap flavour: Ed25519 signed, compact .lic token
python backend/ipam_licensing/license_tool.py --type enterprise --issued-to "Acme Ltd" \
    --algorithm Ed25519 --format jwt --output-dir .
python backend/ipam_licensing/license_validator.py license_<UUID>.lic

# Phase 2: run the API + console server
cd backend/phase2_license_server && python app.py     # http://127.0.0.1:5000
#   /            live licensing screen     /settings   live settings screen
#   /index.html  console launcher          /screens/…  every other screen

# Tests (both phases + the API contract)
python -m pytest backend/ipam_licensing backend/phase2_license_server/tests -q   # 187 tests
```

## How it fits together

- Licenses are signed over **canonical JSON** (sorted keys, no whitespace) and
  served in either wire format: a **JSON envelope**
  (`{license_data, signature, algorithm, version}`) or a **compact JWS token**
  (`header.payload.signature`, `.lic` / `.jwt`).
- Two algorithms are supported: **RSA-PSS-SHA256** (default) and **Ed25519**.
  Both live in `backend/ipam_licensing/signature.py`, which is the only place
  signing and verification are implemented — Phase 2 imports it through
  `licensing_bridge.py`.
- One signature is kept per license; the authority may re-serve the same claims
  as an envelope or as a token, so the verifier accepts either signing input.
- Phase 1 verifies a license **offline**: signature → structure → expiry.
- Phase 2 adds the things that cannot be known offline - **revocation**, an
  issuing **audit trail**, and a central place to look up who holds what. A
  license issued by the server validates with the Phase 1 CLI and vice versa.
- The HTTP surface is contracted in `apis/openapi.yaml` (OpenAPI 3.1);
  `test_openapi_contract.py` cross-checks it against the live routes in both
  directions, so docs cannot drift from the server.
- The console lives in `frontend/` — a copy of the frozen design reference in
  `stitch_pam_suite_dashboard_ui/`. Every screen carries the same sidebar with
  real links, `frontend/index.html` is the launcher. Served by Phase 2, five
  screens are **live**: licensing (`/`), platform settings (`/settings`,
  backed by `GET/PUT /api/v1/settings` with an audit changelog), the Command
  Center and Compliance screens (backed by `GET /api/v1/overview` and the
  unified `GET /api/v1/events` feed), and the Credential Vault (backed by
  `GET/POST /api/v1/vault/*` — inventory, rotation SLA and JIT checkouts).
  The rest are static pages under `/screens/`.

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
  (`backend/phase2_license_server/keys.py`).
