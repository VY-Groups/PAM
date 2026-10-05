# IPAM License Server (Phase 2)

Flask service that issues, stores, revokes and validates IPAM licenses.

It does **not** re-implement cryptography: signing and verification come
straight from the Phase 1 library in `../ipam_licensing`, imported through
`licensing_bridge.py`. A license produced by this server is byte-for-byte
compatible with the Phase 1 `license_validator` CLI.

Supported wire formats and algorithms:

| | values |
| --- | --- |
| Algorithms | `RSA-PSS-SHA256` (default), `Ed25519` |
| Formats | `json` envelope, `jwt` compact JWS (`.lic` / `.jwt` tokens) |
| Keys | `LICENSE_*_KEY_PATH` (RSA), `LICENSE_ED25519_*_KEY_PATH` (Ed25519) |

## Layout

| File | Responsibility |
| --- | --- |
| `app.py` | Flask app factory, error handlers, `/health`, screen routes, `python app.py` entrypoint |
| `config.py` | Environment-driven configuration (`.env` supported) |
| `routes.py` | HTTP layer: parsing, auth, status codes |
| `service.py` | Business logic: issue, list, revoke, restore, validate, usage, checks, `meta`, platform settings |
| `models.py` | `LicenseRecord` (signed license + spec fields), `LicenseEvent`, `SettingGroup` + `SettingsEvent` (config changelog) |
| `keys.py` | Startup key checks (fail fast, public/private must match, both algorithms) |
| `licensing_bridge.py` | Path bootstrap + cached Phase 1 `LicenseGenerator`/`LicenseValidator` |
| `tests/test_api.py` | End-to-end license API tests |
| `tests/test_settings_and_ui.py` | Settings CRUD/auth/validation/audit + frontend navigation tests |
| `tests/test_openapi_contract.py` | `apis/openapi.yaml` ↔ live route map (both directions) |

## Quick start

```bash
cd backend/phase2_license_server     # from the repository root
pip install -r requirements.txt

python app.py                 # http://127.0.0.1:5000  -> web UI at /
# or
flask --app app run
# production:
waitress-serve --port 5000 wsgi:app     # pip install waitress
```

## Web UI

`GET /` (alias `/license`) serves the **Enterprise Licensing, Tier
Entitlements & Node Quotas** screen, a live page in the suite's design system
that drives the API below. It renders the spec layout against real data:

- attestation header (validity, algorithm, enclave binding) with upload /
  export / renew actions
- tier & plan, node quota, session-quota and cryptographic-signature cards
- entitlement module list (8 modules from the catalog) with per-module metrics
- node quota pool table: assigned / consumed / headroom / utilization and the
  pool's enforcement action
- payload signature card (subject, classification, fingerprint, issuer) with a
  decoded-claims inspector, offline air-gap ingestion, and the account & SLA
  block
- entitlement registry (search + status/type filters, issue/detail/revoke) and
  a public signature-validation console

Source: `../frontend/screens/license_entitlement_center/code.html`
(kept with the rest of the console screens so the visual language stays in one
place; built against the spec screen
`enterprise_licensing_tier_entitlements_node_quotas/`). It is served
**same-origin** — its `fetch('api/v1/...')` calls resolve against this server,
so no CORS is needed or enabled. Open it at `http://127.0.0.1:5000/` rather
than as a `file://` page.

Admin actions (issue / revoke / restore / download) send the token as
`X-Admin-Token`; enter it once in the UI (kept in `sessionStorage` for that tab
only). If `LICENSE_ADMIN_TOKEN` is unset the server runs in open mode.

`GET /settings` serves the **Platform Settings** screen
(`frontend/screens/platform_settings_center/`), built from the spec screen
`platform_settings_idp_hsm_configuration/` and wired to the settings API below:
it loads the four configuration groups plus their schema, renders editable
controls, tracks dirty fields, saves through the admin token and shows the live
configuration changelog.

The rest of the console is served read-only from `../frontend` by a
catch-all route: open `GET /index.html` for the launcher (every screen with
LIVE / STATIC / SPEC badges), then any `screens/<name>/code.html`. The
catch-all never shadows `/health` or `/api/v1/*` and refuses any path
resolving outside the frontend folder.

First start creates `licenses.db` in this folder (override with
`LICENSE_DATABASE_URI`), validates the key pairs in the repository root and
adds any columns introduced by a later spec revision.

```bash
python -m pytest tests -q     # 86 tests  (168 across both phases, run from the repo root)
```

## Configuration

See `.env.example`. Highlights:

- `LICENSE_ADMIN_TOKEN` — bearer token guarding issue/revoke/restore/usage/
  download. Unset means open mode (responses then carry `X-Auth-Mode: open`);
  always set it outside a trusted network.
- `LICENSE_PRIVATE_KEY_PATH` / `LICENSE_PUBLIC_KEY_PATH` — RSA pair, defaults to
  the Phase 1 keys at the repository root. Startup aborts if the pair does not
  match.
- `LICENSE_ED25519_PRIVATE_KEY_PATH` / `LICENSE_ED25519_PUBLIC_KEY_PATH` —
  optional second algorithm (default `license_ed25519_*.pem` at the repository
  root); created on first Ed25519 issuance when autogeneration is enabled.
- `LICENSE_AUTOGENERATE_KEYS=1` — allow creating a missing key pair (dev only;
  it changes which licenses are verifiable).
- `LICENSE_DATABASE_URI` — defaults to SQLite next to this README.

## API

Base path `/api/v1`. All bodies are JSON except raw-token validation. The
machine-readable contract lives in `../../apis/openapi.yaml` and is
cross-checked against these routes by `tests/test_openapi_contract.py`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | – | Liveness + DB check, key paths, algorithms, formats |
| GET | `/meta` | – | Capabilities: algorithms, formats, tiers, quota/usage fields, module catalog |
| POST | `/licenses` | admin | Issue and sign a license (201) |
| GET | `/licenses` | – | List/filter licenses (`status`, `license_type`, `issued_to`, `tier`, `q`, `limit`, `offset`) |
| GET | `/licenses/<key>` | – | Detail incl. usage summary and audit events (`<key>` = license key **or** license ID) |
| GET | `/licenses/<key>/file` | admin | Signed file, `?format=json` (envelope) or `?format=jwt` (compact token) |
| POST | `/licenses/<key>/revoke` | admin | Soft-revoke with optional `{"reason"}` |
| POST | `/licenses/<key>/restore` | admin | Undo a revocation |
| POST | `/licenses/<key>/usage` | admin | Record runtime consumption (returns the recomputed summary) |
| POST | `/licenses/<key>/check` | – | Feature / module / quota-limit checks |
| POST | `/licenses/validate` | – | Full check: structure → signature → revocation → expiry |
| GET | `/settings` | – | Stored configuration + editable schema (`sso`, `hsm`, `zsp`, `worm`) |
| GET | `/settings/audit?limit=` | – | Configuration changelog, newest first |
| PUT | `/settings/<group>` | admin | Merge-update one group, returns the per-field change diff |

Admin auth: `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.

### Issue

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "license_type": "enterprise",
    "issued_to": "Northwind Federal Systems",
    "license_id": "LIC-9942-AEGIS-SEC-PROD",
    "tier": "ENTERPRISE ZSP ULTIMATE",
    "plan": "Annual Multi-Cloud",
    "subject_entity": "Northwind Federal Systems - AegisPAM Cluster PROD-7734",
    "classification": "ENTERPRISE ZSP ULTIMATE - Tier 4 / Quantum-Safe",
    "issuer": "licensing.aegispam.internal (Air-Gap Root)",
    "enclave_binding": "TPM 2.0 PCR Registers 0 & 7",
    "algorithm": "Ed25519",
    "format": "jwt",
    "usage_limits": {"max_users": 5000, "max_subnets": 512, "max_devices": 12000},
    "account": {"customer_id": "ENT-88214-AEGIS", "tam": "Sasha Quill",
                "tam_email": "sasha.quill@aegispam.internal",
                "po_number": "PO-77193", "sla_response": "15 MIN P1",
                "invoicing": "Annual Upfront"}
  }'
```

- `license_type`: `trial`, `subscription`, `perpetual`, `enterprise`.
- Signing: `algorithm` (`RSA-PSS-SHA256` | `Ed25519`) and `format`
  (`json` | `jwt`), both defaulting to the Phase 1 defaults.
- Spec fields (all optional): `tier`, `plan`, `license_id` (auto-generated as
  `LIC-####-AEGIS-SEC-ENV` when omitted), `subject_entity`, `classification`,
  `issuer`, `enclave_binding`, `environment`.
- Quotas: `quotas` overrides the tier defaults — node quota, `concurrent_sessions`,
  `bastion_tunnels`, `max_lease_hours`, `worm_retention_days` and a `pools` list
  (`id`, `name`, `regions`, `quota_nodes`, `enforcement` with
  `soft-warning` / `auto-scale` / `audit-log` / `hard-block`).
- Entitlements: `modules` selects from the 8-module catalog; `features`,
  `usage_limits`, `metadata` behave as before. `trial_days` applies to trials.
- The response carries the stored record, the ready-to-deliver `license_file`
  and, for `format: "jwt"`, the compact `token`.

Optional fields that are not supplied are **omitted from the signed payload**,
so a license issued before a field existed rebuilds byte-identically and stays
valid.

### Report runtime usage

Quota numbers are signed ceilings; consumption is reported by the platform at
runtime (never invented by the server):

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/<KEY>/usage \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"nodes_consumed": 2875, "sessions_active": 14, "bastion_tunnels_used": 482,
       "pools": [{"id": "aws-prod", "nodes_consumed": 1420}]}'
```

The response's `usage` block recomputes quota, consumed, headroom, utilization
and `over_quota` for the totals and for every pool (an over-quota report is
flagged, not clamped), plus `reported` / `reported_at`.

### Validate

```bash
# JSON envelope
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/validate \
  -H "Content-Type: application/json" -d @license_<KEY>.json

# compact token, pasted verbatim
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/validate \
  -H "Content-Type: text/plain" --data-binary @license_<KEY>.lic
```

Responds with `valid`, `status` (`valid` / `revoked` / `expired` /
`signature_invalid` / `malformed`), `algorithm`, `format`, `fingerprint`,
`registered` (present in this server's database), `matches_registered_record`,
and the human-readable license info.

The check order is: structure → signature → revocation list → expiry. A license
issued offline with the same key pair still validates (`registered: false`);
only revocation and expiry are enforced by this server.

Because one signature is kept per license, the authority can re-serve the same
claims in either serialization (`?format=`); the verifier accepts both signing
inputs, so the fingerprint and `matches_registered_record` stay true.

### Check features, modules and quotas

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/<KEY>/check \
  -H "Content-Type: application/json" \
  -d '{"feature": "api_access", "module_id": "hsm_integration",
       "limit_type": "max_users", "current_usage": 12}'
```

Any combination of `feature`, `module_id` (one of the 8 catalog ids) and
`limit_type` + `current_usage` may be asked in one call.

### Platform settings

```bash
# read everything (public) - values + per-field schema with defaults/ranges
curl -s http://127.0.0.1:5000/api/v1/settings

# change one group (admin) - X-Actor names who made the change
curl -s -X PUT http://127.0.0.1:5000/api/v1/settings/zsp \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"tier0_quorum_approvers": 4}'

# the configuration changelog this write produced
curl -s "http://127.0.0.1:5000/api/v1/settings/audit?limit=20"
```

- Four groups: `sso` (9 fields), `hsm` (9), `zsp` (4), `worm` (6). The schema
  lives in `service.py` (`SETTINGS_SCHEMA`); defaults mirror the values the
  spec screen displays (2-of-3 quorum, 120-minute TTL extension, 2,555-day
  retention, the spec's bucket and cluster host).
- Writes merge into the stored row. Unknown groups/fields, wrong types,
  out-of-range numbers, non-`https` metadata URLs, invalid enum values and
  malformed bucket names are rejected with
  `400 {"error": "...", "details": {"field": ...}}` before anything is saved;
  a no-op write returns `{"message": "No changes"}` and writes no event.
- Every accepted change records a `SettingsEvent` with the actor
  (`X-Actor`, else the authenticated admin) and a per-field old/new diff.
- Reads are public so the screen can render read-only without a token; `PUT`
  requires the admin token unless `LICENSE_ADMIN_TOKEN` is unset (open mode,
  responses then carry `X-Auth-Mode: open`).

## Design notes

- **Revocation is server-side.** Phase 1 licenses are stateless; this server keeps
  the revocation list, so `POST /licenses/validate` is the authority for
  "is this license still good?".
- **Audit trail.** Every issue/revoke/restore/usage report writes a
  `LicenseEvent` row, returned with `GET /licenses/<key>`.
- **Usage is reported, not simulated.** The screen renders
  `POST /licenses/<key>/usage` results only.
- **Settings are stored, not re-derived.** One `SettingGroup` row per group is
  upserted on write and merged with the built-in defaults on read, so a field
  that was never changed still shows its spec value; every write is mirrored
  into `SettingsEvent` for the changelog.
- **Naive local datetimes.** Expiry is compared in Python, not SQL, so results do
  not depend on the database's timezone handling.
- **Errors are JSON**: `{"error": "...", "details": {...}}` with 400/401/404/405/500.
