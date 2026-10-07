# IPAM License Server (Phase 2)

Flask service that imports, stores, revokes and validates IPAM licenses.

It does **not** re-implement cryptography: verification comes straight from the
Phase 1 library in `../ipam_licensing`, imported through `licensing_bridge.py`.
It does **not** sign either — issuing belongs to the vendor tool (`pam_master/`)
or the Phase 1 CLI; this server verifies a vendor-signed file, records its
claims exactly as signed, and serves them back byte-for-byte, so what validates
offline with the Phase 1 `license_validator` CLI is the very file the vendor
produced.

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
| `service.py` | Business logic: import, list, revoke, restore, validate, usage, checks, `meta`, platform settings, credential vault, dashboard overview + unified events, infrastructure discovery, JIT access grants, privileged sessions |
| `models.py` | `LicenseRecord` (signed license + spec fields), `LicenseEvent`, `SettingGroup` + `SettingsEvent` (config changelog), `VaultItem` + `VaultEvent` + `VaultSecretVersion` (vault inventory + audit + immutable versions), `DiscoveredAsset`/`DiscoveredAccount`/`DiscoveryScan`/`DiscoveryEvent`, `JitRequest` + `JitEvent` (grants + trail), `PrivilegedSession` + `SessionEvent` (session recording, append-only) |
| `keys.py` | Startup key checks (fail fast, public/private must match, both algorithms) |
| `licensing_bridge.py` | Path bootstrap + cached Phase 1 `LicenseGenerator`/`LicenseValidator` |
| `tests/test_api.py` | End-to-end license API tests |
| `tests/test_settings_and_ui.py` | Settings CRUD/auth/validation/audit + frontend navigation tests |
| `tests/test_vault_dashboard.py` | Vault inventory/rotation/checkout + dashboard overview + unified event feed tests |
| `tests/test_rotation.py` | AES-256-GCM-at-rest secret versions and the rotation engine tests |
| `tests/test_discovery.py` | Infrastructure discovery (onboard, scan, adopt, ignore) tests |
| `tests/test_jit.py` | JIT access: deterministic risk bands, approvals, time-boxed grants, expiry rotation |
| `tests/test_sessions.py` | Privileged sessions: start/attach, channel events, control gating, lifecycle + cascades |
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
- entitlement registry (search + status/type filters, detail/revoke) and
  a public signature-validation console

Source: `../frontend/screens/license_entitlement_center/code.html`
(kept with the rest of the console screens so the visual language stays in one
place; built against the spec screen
`enterprise_licensing_tier_entitlements_node_quotas/`). It is served
**same-origin** — its `fetch('api/v1/...')` calls resolve against this server,
so no CORS is needed or enabled. Open it at `http://127.0.0.1:5000/` rather
than as a `file://` page.

Admin actions (import / revoke / restore / download) send the token as
`X-Admin-Token`; enter it once in the UI (kept in `sessionStorage` for that tab
only). If `LICENSE_ADMIN_TOKEN` is unset the server runs in open mode.

`GET /settings` serves the **Platform Settings** screen
(`frontend/screens/platform_settings_center/`), built from the spec screen
`platform_settings_idp_hsm_configuration/` and wired to the settings API below:
it loads the four configuration groups plus their schema, renders editable
controls, tracks dirty fields, saves through the admin token and shows the live
configuration changelog.

Five more screens render from their own APIs: the **Command Center** and
**Compliance** screens (`GET /api/v1/overview` + the unified
`GET /api/v1/events` feed — health, license posture, vault stats, computed
control posture, recent activity), the **Credential Vault**
(`GET/POST /api/v1/vault/*` — onboarding via **Onboard New Credential**, rotation
SLA, type/status filters, JIT checkouts and an audit trail), the
**Infrastructure Discovery** screen (`GET/POST /api/v1/discovery/*` — register,
scan, adopt, ignore), the **JIT access** console (`GET/POST /api/v1/jit/*` —
requests, risk, approvals, time-boxed grants) and the **live session hub**
(`GET/POST /api/v1/sessions/*` — start a session against a vault credential or
an active grant, replay its append-only recording, gate controls, and end it
through the release-and-rotate cascade). Each fetches on load
and keeps its honest placeholder content as the fallback, so it still renders
when opened as `file://` or when the API is unreachable.

The rest of the console is served read-only from `../frontend` by a
catch-all route: open `GET /index.html` for the launcher (every screen with
LIVE / STATIC / SPEC badges), then any `screens/<name>/code.html`. The
catch-all never shadows `/health` or `/api/v1/*` and refuses any path
resolving outside the frontend folder.

First start creates `licenses.db` in this folder (override with
`LICENSE_DATABASE_URI`), validates the key pairs in the repository root and adds
any columns introduced by a later spec revision. The vault starts empty — there
is no seed inventory: every credential enters through **Onboard New Credential**
(`POST /api/v1/vault/items`), and the screens show real counts or honest
"not connected" states instead of sample rows.

```bash
python -m pytest tests -q     # 205 tests (from backend/phase2_license_server)
python -m pytest backend -q   # 287 tests from the repo root (+ shared crypto core)
```

## Configuration

See `.env.example`. Highlights:

- `LICENSE_ADMIN_TOKEN` — bearer token guarding import/revoke/restore/usage/
  download. Unset means open mode (responses then carry `X-Auth-Mode: open`);
  always set it outside a trusted network.
- `LICENSE_PRIVATE_KEY_PATH` / `LICENSE_PUBLIC_KEY_PATH` — RSA pair, defaults to
  the Phase 1 keys at the repository root. Startup aborts if the pair does not
  match.
- `LICENSE_ED25519_PRIVATE_KEY_PATH` / `LICENSE_ED25519_PUBLIC_KEY_PATH` —
  optional second algorithm (default `license_ed25519_*.pem` at the repository
  root). The server verifies with the public key only; issuing (and any key
  generation) lives in PAM-MASTER / the Phase 1 CLI.
- `LICENSE_AUTOGENERATE_KEYS=1` — allow creating a missing key pair (dev only;
  it changes which licenses are verifiable).
- `LICENSE_DATABASE_URI` — defaults to SQLite next to this README.
- `VAULT_KEY_PATH` — AES-256-GCM master key for credential-vault secrets
  (default `vault_master.key` next to the database; `*.key` is gitignored).
  `VAULT_AUTOGENERATE_KEY=1` (default) creates a missing key once on first
  use — write-once, never overwritten; with it disabled a missing/unusable
  key fails requests with **503** rather than ever storing plaintext.
- `ROTATION_SCHEDULER=1` — start the background rotation scheduler
  (`ROTATION_SCHEDULER_INTERVAL_SECONDS`, default 300). It rotates only
  credentials whose SLA window elapsed, through the same audited pipeline as
  the console; a quiet clock produces no events.

## API

Base path `/api/v1`. All bodies are JSON except raw-token validation. The
machine-readable contract lives in `../../apis/openapi.yaml` and is
cross-checked against these routes by `tests/test_openapi_contract.py`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | – | Liveness + DB check, key paths, algorithms, formats |
| GET | `/meta` | – | Capabilities: algorithms, formats, tiers, quota/usage fields, module catalog |
| POST | `/licenses/import` | admin | Import a vendor-signed license file (201; 400 malformed/foreign/expired/invalid claims, 409 already installed) |
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
| GET | `/overview` | – | Dashboard aggregate: health, license posture, vault stats, settings, counters, computed control posture, recent activity |
| GET | `/events?limit=&source=` | – | Unified audit feed across the license / settings / vault / discovery trails, newest first |
| GET | `/vault/stats` | – | Inventory aggregates: totals by type/status, rotation compliance, `secrets` coverage (`managed`/`unmanaged`/`versions`), checkouts, today's events |
| GET | `/vault/items?…` | – | List inventory (`q`, `type`, `status`, `limit`, `offset`) |
| POST | `/vault/items` | admin | Onboard a credential (201, strictly validated; optional `secret`, else a real type-appropriate value is generated — sealed with AES-256-GCM either way) |
| GET | `/vault/items/<id>` | – | One credential plus its recent audit events (never includes the secret) |
| GET | `/vault/items/<id>/secret` | admin | Reveal the current secret version (decrypts for the response only; 404 for metadata-only records, 503 if the vault key is unavailable) |
| POST | `/vault/items/<id>/checkout` | admin | JIT checkout (body `{"reason"}`), records who and when |
| POST | `/vault/items/<id>/revoke` | admin | End an active checkout |
| POST | `/vault/items/<id>/rotate` | admin | Full rotation pipeline for one credential (mint + seal new version, validate by decrypt round-trip, audit); also retries a failed rotation; no cascade |
| POST | `/rotation/run` | admin | Run the engine over due (+failed) credentials or explicit `item_ids`; `cascade` (default true) also rotates same-target dependents, reporting real skip reasons |
| POST | `/rotation/session-end` | admin | Event trigger: release the checkout (audited), then rotate with `trigger=session_end` + cascade (body `{"item_id", "session_id"?}`) |
| GET | `/jit/stats` | – | JIT aggregates: totals, `by_status`, `by_risk` |
| GET | `/jit/requests?status=&requester=&limit=&offset=` | – | Access requests, newest first (nested `risk {score, level, factors}`, `approvals {manager, security}`, `minutes_left` while active) |
| POST | `/jit/requests` | admin | File a request (201; `item_id`, `reason` ≥8 chars, `ticket`, `minutes` 1–480) — deterministic risk is evaluated immediately over tier/duration/clock/24h history/ticket shape/credential health |
| GET | `/jit/requests/<id>` | – | One request plus its full `jit_events` trail, newest first |
| POST | `/jit/requests/<id>/approve` | admin | Record one approval (body `{"role": "manager"\|"security"}`); self-approval → 403; critical-risk requests → 400 (blocked, deny only) |
| POST | `/jit/requests/<id>/deny` | admin | Move pending/blocked → denied (body `{"reason"?}`) |
| POST | `/jit/requests/<id>/consume` | admin | Grant: approved → active, checks the credential out (`session_ref=jit-<id>`) until `expires_at` |
| POST | `/jit/requests/<id>/close` | admin | End a grant early: release the checkout and rotate the credential (audited) |
| GET | `/sessions/stats` | – | Session aggregates: per-status counts, event and blocked totals |
| GET | `/sessions?status=&protocol=&q=&limit=&offset=` | – | Sessions, newest first (live and archived; `status`/`protocol`/search filters) |
| POST | `/sessions` | admin | Start a privileged session (201; `protocol` (13), `target`, optional `item_id` — checks the credential out — or `jit_request_id` that must be an active grant, plus the 7 control flags). One live session per grant → 409 |
| GET | `/sessions/<id>` | – | One session plus stats and its latest events (evaluates linked grant expiry) |
| GET | `/sessions/<id>/events?order=&type=&limit=&offset=` | – | The append-only recording: `seq`, type, content, `allowed`/`blocked_reason`, `withheld`, `watermark`, actor |
| POST | `/sessions/<id>/events` | admin | Record a channel event. Not-live → 409; typed content while `record=false` → 403; gated channels store `allowed=false` + reason (blocked evidence); `keystroke_log=false` stores content `null` + `withheld=true` |
| POST | `/sessions/<id>/controls` | admin | Update control flags mid-session (live only; JSON keys are the flags) |
| POST | `/sessions/<id>/pause` | admin | Suspend the session: further channel events → 409 until resumed |
| POST | `/sessions/<id>/lock` | admin | Lock the session (same refusal semantics as pause) |
| POST | `/sessions/<id>/resume` | admin | Resume a paused/locked session |
| POST | `/sessions/<id>/terminate` | admin | End with `outcome=terminated` (body `{"reason"?}`); linked grant closes with it, own checkout releases and rotates exactly once — response carries the real `cascade` detail |
| POST | `/sessions/<id>/complete` | admin | End with `outcome=completed` (body `{"reason"?}`), same cascade rules |
| GET | `/vault/events?limit=&action=` | – | Vault audit trail (onboarding, checkouts, rotations); `action` filters to one type |
| GET | `/discovery/stats` | – | Discovery aggregates: totals, per-type/risk/status, recorded accounts, last scan |
| GET | `/discovery/assets?…` | – | Discovered targets (`q`, `type`, `risk`, `pam_status`, `limit`, `offset`), each with `vault_count` |
| POST | `/discovery/assets` | admin | Register + classify a target, ingest its admin account (201) |
| PATCH | `/discovery/assets/<id>` | admin | Ignore/restore, reclassify (recomputes risk), edit hostname/detail/notes |
| POST | `/discovery/assets/<id>/onboard` | admin | Adopt a discovered asset into the vault (201) |
| GET | `/discovery/accounts?…` | – | Recorded privileged accounts (`q`, `kind`, `limit`, `offset`) |
| GET | `/discovery/scans?limit=` | – | Scan history, newest first |
| POST | `/discovery/scans` | admin | Run a real TCP-connect scan (201; IPv4/CIDR/hostname, ≤256 hosts, ≤24 ports) |

Admin auth: `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.

### Import

Issuing belongs to the vendor — PAM-MASTER (`pam_master/`) or the Phase 1 CLI
sign the file and deliver it. This endpoint only verifies and records it:

```bash
# JSON envelope straight from the delivery bundle
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/import \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "Content-Type: application/json" \
  --data-binary @delivery/license_01J2f3g4.json

# compact .lic token -> wrap it
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/import \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"token\": \"$(cat delivery/license_01J2f3g4.lic)\"}"
```

- The signature is checked against this deployment's trusted public key. A file
  signed by any other key is refused (400), as are malformed envelopes, unknown
  `algorithm`/`format`, expired licenses, and structurally invalid claims — the
  same shape rules the old issuing form enforced (`license_type` in the
  catalog, non-empty `issued_to`, `quotas`/`usage_limits`/`modules` well-formed,
  module ids from the catalog, node pools with `id`, `name` and `quota_nodes`).
- An already-installed file is refused with **409** (the existing record is
  returned under `details`).
- Claims are stored **exactly as signed** — never normalised or back-filled —
  so a file signed before a field existed imports byte-identically and stays
  valid.
- The response carries the stored record, the verified `license_file` (echoed,
  so the console can re-download it) and, when the file was a compact `.lic`
  JWT, its `token`.

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

### Vault & dashboard

```bash
# dashboard aggregate powering the Command Center / Compliance screens
curl -s http://127.0.0.1:5000/api/v1/overview

# unified audit feed (license + settings + vault + discovery trails, newest first)
curl -s "http://127.0.0.1:5000/api/v1/events?limit=10"

# inventory aggregates: rotation compliance, checkouts, attention list
curl -s http://127.0.0.1:5000/api/v1/vault/stats

# filter the inventory: q / type / status / limit / offset
curl -s "http://127.0.0.1:5000/api/v1/vault/items?type=ssh_key&status=available"

# inventory starts empty: onboard first (POST /api/v1/vault/items) and use the
# returned id below - JIT checkout then release (admin), both write the vault audit trail
curl -s -X POST http://127.0.0.1:5000/api/v1/vault/items/3/checkout \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"reason": "INC-9942 database maintenance"}'
curl -s -X POST http://127.0.0.1:5000/api/v1/vault/items/3/revoke \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice"

# rotate now - the full pipeline for one credential (also the retry path for a
# failed rotation): mint + seal a new version, decrypt round-trip validation, audit
curl -s -X POST http://127.0.0.1:5000/api/v1/vault/items/5/rotate \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice"

# reveal the current secret version (admin only; decrypts for this response,
# 404 when the record is metadata-only, 503 if the vault key is unavailable)
curl -s http://127.0.0.1:5000/api/v1/vault/items/5/secret \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN"

# run the rotation engine over everything due (failed included so Retry works);
# cascade (default true) also rotates other managed credentials on each target
curl -s -X POST http://127.0.0.1:5000/api/v1/rotation/run \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{}'

# event-based trigger: a checkout's session ended -> release, rotate, cascade
curl -s -X POST http://127.0.0.1:5000/api/v1/rotation/session-end \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"item_id": 5, "session_id": "sess-77"}'

# JIT flow: file -> risk is computed from real inputs -> approvals by band
curl -s -X POST http://127.0.0.1:5000/api/v1/jit/requests \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"item_id": 5, "reason": "Emergency patch window for payments db",
       "ticket": "INC-1234", "minutes": 30, "requester": "oncall.eng"}'
# low band auto-approves; medium needs {"role":"manager"}; high needs
# manager + security; critical is blocked and only deniable:
curl -s -X POST http://127.0.0.1:5000/api/v1/jit/requests/1/approve \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: carol" \
  -H "Content-Type: application/json" -d '{"role": "manager"}'
# grant (checkout + expires_at), then close early (release + rotate):
curl -s -X POST http://127.0.0.1:5000/api/v1/jit/requests/1/consume \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{}'
curl -s -X POST http://127.0.0.1:5000/api/v1/jit/requests/1/close \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{}'

# session flow: start against a vault credential (checks it out) or attach an
# active grant via "jit_request_id"; bare sessions need neither
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"protocol": "ssh", "target": "bastion.example:22", "item_id": 5,
       "clipboard_allowed": false}'

# record channel events (append-only); gated channels keep blocked attempts
# as evidence instead of dropping them
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/events \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: recorder" \
  -H "Content-Type: application/json" \
  -d '{"type": "command", "content": "df -h"}'
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/events \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: recorder" \
  -H "Content-Type: application/json" \
  -d '{"type": "clipboard", "content": "copied rows"}'   # allowed=false (gate)

# control the live session: flags mid-session, then pause/lock/resume;
# ending it releases the checkout and rotates the credential exactly once
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/controls \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{"upload_allowed": false}'
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/pause \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{}'
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/resume \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{}'
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/terminate \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{"reason": "change window closed"}'
# -> "cascade": {"grant_closed": false, "rotated": true, ...} or, with a JIT
#    session, grant_closed=true; the vault trail carries one rotated event.
```

- The vault starts empty — there is no seed inventory. Onboard credentials via
  the screen's **Onboard New Credential** button or `POST /api/v1/vault/items`;
  tests build their own fixtures.
- **At-rest encryption**: every credential value is sealed with AES-256-GCM
  under `VAULT_KEY_PATH`, with the item id as additional authenticated data
  (a ciphertext moved between rows fails its integrity check). Plaintext is
  produced only by an explicit admin reveal or an in-process rotation — never
  by list/detail responses, logs or the database file. Each rotation appends an
  immutable `vault_secret_versions` row; the item points at the current
  version. Per-type generation is real: mixed-class passwords (24 chars),
  `token_urlsafe` API tokens, cloud id/secret pairs, ED25519 private keys.
- **Rotation pipeline** (architecture module 5, in order): mint + seal the new
  value → update same-target dependents → validate by local decrypt round-trip
  → emit the `rotated` audit event with measured duration/version/dependents.
  Manual single rotate has no cascade; `/rotation/run` and the session-end
  trigger do, and skipped dependents are reported with their real reason
  (e.g. `checked_out`). Failures mark the item `failed` and write a
  `rotation_failed` event; a later run/retry re-runs the real pipeline.
  Optional scheduler: `ROTATION_SCHEDULER=1` (due items only; failed items
  stay for manual Retry).
- Rotation compliance = `in-policy / total` where in-policy excludes
  rotation-due and failed items. The dashboard posture score computes from
  eight real controls (`worm_retention`, `audit_evidence`, `quantum_safe`,
  `rotation_sla`, `sso_mfa`, `tier0_quorum`, `admin_auth`, `hsm_backed`) —
  `audit_evidence` only passes once the audit trail has entries, so a fresh
  database honestly reports a lower score.
- **JIT access** (module 6) runs request → risk → approvals → time-boxed
  grant → expiry → rotation. The risk score is deterministic and built only
  from measured inputs: target tier (30/15/0), window length (up to +20),
  off-hours from the real local clock (+20), repeat requests in the last 24h
  (up to +15), ticket shape (+10 when it does not look like an ITSM
  reference) and failed credential health (+10); bands are ≤25 low (auto),
  ≤50 medium (manager), ≤75 high (manager + security), above that critical
  (blocked — deny only). A grant checks the credential out under
  `session_ref=jit-<id>`; expiry is lazy on every JIT read and on each
  scheduler tick (`ROTATION_SCHEDULER=1`), releasing the checkout and
  rotating the credential with `trigger=session_end`. Every state change is
  a `jit_events` row (requester, approver, risk policy or system as actor).
- **Privileged sessions** (module 8) start against a vault credential (a real
  checkout) or an active JIT grant (one live session per grant → 409), and
  every channel event lands in append-only `session_events` with `seq`,
  custody watermark and actor. Controls gate for real: typed content while
  `record=false` is refused (403), gated channels store the attempt with
  `allowed=false` + reason (kept as blocked evidence), and
  `keystroke_log=false` stores content `null` + `withheld=true`. Lifecycle:
  pause/lock refuse further events (409) until resume; terminate/complete run
  the cascade — the linked grant closes together, the own checkout is
  released and the credential rotated exactly once (`cascade` in the
  response). Ending a session whose grant expired in a detail read does the
  same through the lazy path (`end_reason=grant_expired`).
- Reads are public; the write routes (settings, vault, discovery, rotation,
  jit, sessions)
  require the admin token in token mode (open mode stays open) and record who
  acted via `X-Actor`. The secret reveal (`GET /vault/items/<id>/secret`) is
  gated like a write route — it is never one of the public reads.

### Discovery

```bash
# run a real TCP-connect scan (bounded: <=256 hosts, <=24 ports, single-flight)
curl -s -X POST http://127.0.0.1:5000/api/v1/discovery/scans \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"scope": "10.20.0.0/28"}'

# register + classify a target, ingesting its admin account into the vault
curl -s -X POST http://127.0.0.1:5000/api/v1/discovery/assets \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"address": "10.20.0.5", "asset_type": "linux", "principal": "root"}'
```

- Scans are **real**: TCP connects against the operator-supplied scope only
  (no default range), a short banner grab per open port, discovery events in
  the unified feed. Type classification = port-to-service mapping refined by
  greeting text (SSH family from an `SSH-` banner); anything unproven stays
  `unknown` instead of being guessed.
- Risk comes from `BASE_RISK` (rules v1, mirrors the reference architecture's
  example scores) and `recommended_policy` is advisory only — onboarding is
  always operator-triggered.
- Rescans refresh ports/`last_seen` and reclassify only **unmanaged** rows;
  managed rows keep the operator's classification. New hosts land as
  `unmanaged` until adopted via `POST /discovery/assets/<id>/onboard`.

## Design notes

- **Revocation is server-side.** Phase 1 licenses are stateless; this server keeps
  the revocation list, so `POST /licenses/validate` is the authority for
  "is this license still good?".
- **Audit trail.** Every import/revoke/restore/usage report writes a
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
