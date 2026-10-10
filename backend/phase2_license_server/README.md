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
| `service.py` | Business logic: import, list, revoke, restore, validate, usage, checks, `meta`, platform settings, credential vault, dashboard overview + unified events, infrastructure discovery, JIT access grants, privileged sessions, zero-trust command-control policy engine, risk-based access engine (§7), PAM bypass detection (§10), break-glass emergency path (§17), immutable §19 audit ledger, §20 integrations (MFA gate, ITSM verify, SIEM status, LDAP login) |
| `models.py` | `LicenseRecord` (signed license + spec fields), `LicenseEvent`, `SettingGroup` + `SettingsEvent` (config changelog), `VaultItem` + `VaultEvent` + `VaultSecretVersion` (vault inventory + audit + immutable versions), `DiscoveredAsset`/`DiscoveredAccount`/`DiscoveryScan`/`DiscoveryEvent`, `JitRequest` + `JitEvent` (grants + trail), `PrivilegedSession` + `SessionEvent` (session recording, append-only), `CommandRule` + `CommandIncident` (zero-trust policy + escalations, append-only), `RiskEvent` (§7 scored access evaluations), `BypassSignal` + `BypassIncident` + `BypassEvent` (§10 direct-access evidence, incidents, action log), `BreakGlassRequest` + `BreakGlassApproval` + `BreakGlassEvent` (§17 emergencies, dual-approval snapshots, action log), `AuditEvent` (immutable §19 hash chain), `IntegrationEvent` (§20 integration trail, fan-in 11) |
| `audit.py` | The §19 ledger: flush listener fans every module trail into `audit_events`, sha256 chain (`prev_hash`/`event_hash`), boot backfill, append-only triggers, verify/stats/export, plus the §20 SIEM drain — committed batches pushed outbound as signed NDJSON after commit |
| `integrations.py` | §20 stdlib connectors: RFC-6238 TOTP (HMAC-SHA1/256/512, ±1 window), ITSM ticket verification (ServiceNow/Jira REST), SIEM push signing (`sha256=` HMAC, NDJSON), RFC-4515 LDAP filter escape + BER bind probe, LDAP login tickets |
| `keys.py` | Startup key checks (fail fast, public/private must match, both algorithms) |
| `licensing_bridge.py` | Path bootstrap + cached Phase 1 `LicenseGenerator`/`LicenseValidator` |
| `tests/test_api.py` | End-to-end license API tests |
| `tests/test_settings_and_ui.py` | Settings CRUD/auth/validation/audit + frontend navigation tests |
| `tests/test_vault_dashboard.py` | Vault inventory/rotation/checkout + dashboard overview + unified event feed tests |
| `tests/test_rotation.py` | AES-256-GCM-at-rest secret versions and the rotation engine tests |
| `tests/test_discovery.py` | Infrastructure discovery (onboard, scan, adopt, ignore) tests |
| `tests/test_jit.py` | JIT access: deterministic risk bands, approvals, time-boxed grants, expiry rotation |
| `tests/test_sessions.py` | Privileged sessions: start/attach, channel events, control gating, lifecycle + cascades |
| `tests/test_command_control.py` | Zero-trust command policy: rule CRUD, dry-run decisions, approval queue, incident escalation |
| `tests/test_audit.py` | Immutable §19 ledger: fourteen-source fan-in, hash chain, append-only triggers, backfill, verify/export, drift guard |
| `tests/test_risk.py` | §7 risk-based access engine: the eight scored components, bands/decisions, the session-start gate, ledger fan-in |
| `tests/test_bypass.py` | §10 PAM bypass detection: log/JSON ingest, dedupe, correlation (candidate/covered/out_of_scope), incidents with forced rotation + honest `not_connected`, closure, stats, ledger fan-in |
| `tests/test_break_glass.py` | §17 break-glass: request lifecycle, dual approval (self/second-signature rules), risk-gated open → recorded session → close with forced rotation + review, stats, ledger fan-in |
| `tests/test_integrations.py` | §20 integrations: RFC-6238 TOTP + MFA gate/break-glass enforcement, ITSM ticket verify, SIEM signed push + drain failure event, LDAP login + ticket, settings secrets/readonly, contract |
| `tests/test_ueba.py` | §11 UEBA behavior baselines: explicit training, deviation reasons, incident chain fan-in |
| `tests/test_watermark.py` | §12 dynamic watermark: six fields from the session's own row, pause/resume/terminate movement, control gating |
| `tests/test_vendor_pam.py` | §13 third-party PAM: invite → one-time seed → MFA → NDA → real ITSM ticket → approval gate → scoped JIT; refusals + §13 dashboard |
| `tests/test_cloud.py` | §14 cloud PAM: connector lifecycle + honest states, endpoint rules, real probes, inventory upsert/refusals, K8s RBAC → JIT → real RoleBinding apply/remove, delete guard, stats, ledger fan-in |
| `tests/test_broker.py` | §15 CI/CD credential broker: pipeline token auth (shown once, sha256, never waived), auto/manual policies, TTL cap + target scope refusals, approval queue, release (secret once) → close/expiry rotation, revoke cascade, stats, ledger fan-in |
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
it loads the eight configuration groups plus their schema, renders editable
controls (readonly factor fields disabled with a badge, secrets as
sealed `not set` boxes), tracks dirty fields, saves through the admin token,
shows the live configuration changelog and the §20 **Enterprise Integrations**
cards with live chips over `GET /api/v1/integrations/status` (including
**Enroll MFA Factor**, whose secret is shown once).

More screens render from their own APIs: the **Command Center** and
**Compliance** screens (`GET /api/v1/overview` + the unified
`GET /api/v1/events` feed — health, license posture, vault stats, computed
control posture, recent activity; the Command Center also carries the §10
bypass detection section over `GET/POST /api/v1/bypass/*` — ingest a log
bundle, run the correlation scan, review/close incidents; the Compliance
screen also reads
`GET /api/v1/audit/stats` for the immutable digest, runs `GET /api/v1/audit/verify`
on its **Verify Hash Chain** button, exports `GET /api/v1/audit/export`, and its
per-trail filter fetches one of the fourteen sources — license, settings, vault,
discovery, jit, session, command, risk, bypass, break-glass, integration,
vendor, cloud, broker — on
click, and its header chip reads the §20 SIEM push state), the **Credential Vault**
(`GET/POST /api/v1/vault/*` — onboarding via **Onboard New Credential**, rotation
SLA, type/status filters, JIT checkouts and an audit trail), the
**Infrastructure Discovery** screen (`GET/POST /api/v1/discovery/*` — register,
scan, adopt, ignore, plus the §14 cloud connectors over
`GET/POST /api/v1/cloud/*`: honest connector states from real probes,
inventory from the cloud's own API under the `cloud` trail, and Kubernetes
RBAC → JIT grants that apply and remove a real RoleBinding), the **JIT access** console (`GET/POST /api/v1/jit/*` —
requests, risk, approvals, time-boxed grants — plus the §15 Pipeline
Credential Broker over `GET/POST /api/v1/broker/*`: pipeline identities
with a one-time API token, the auto/manual credential queue, and the
release → close/rotate cascade), the **live session hub**
(`GET/POST /api/v1/sessions/*` — start a session against a vault credential or
an active grant, replay its append-only recording, gate controls, and end it
through the release-and-rotate cascade) and the **zero-trust policy console**
(`GET/POST /api/v1/command-control/*` — the shipped §9 rules as editable cards,
a dry-run simulator, the approval queue and the incident trail — plus
`GET/POST /api/v1/risk/*` — the §7 scorer: score one request from eight
components, the band legend, live stats and the recorded evaluations - plus the section 11 UEBA layer: baselines learned from the platform's own history (`/risk/baselines`, trained explicitly via `/risk/baselines/train`), named deviations on the behavior component - unusual time, device, IP, target, command and privilege, 5 points each - and the incident chain a critical deviation runs: refuse the start, end standing sessions through the release-and-rotate cascade, rotate the sought credential and record the incident on `/risk/anomalies` and the ledger's risk trail), and the
**Emergency Break-Glass console** (`GET/POST /api/v1/break-glass/*` — file an
emergency, collect two distinct approval signatures, open the recorded
session that releases a real vault credential, close with forced rotation
and a required review note), and the **Vendor Access** console
(`GET/POST /api/v1/vendors/*` — the §13 chain: invite with a one-time
per-vendor MFA seed, NDA, real ITSM ticket check, approval gate naming any
missing step, scope- and window-checked JIT requests, deny/revoke with the
grant-close cascade). Each fetches on load
and keeps its honest placeholder content as the fallback, so it still renders
when opened as `file://` or when the API is unreachable.

The rest of the console is served read-only from `../frontend` by a
catch-all route: open `GET /index.html` for the launcher (every screen with
LIVE / SPEC badges), then any `screens/<name>/code.html`. The
catch-all never shadows `/health` or `/api/v1/*` and refuses any path
resolving outside the frontend folder.

First start creates `licenses.db` in this folder (override with
`LICENSE_DATABASE_URI`), validates the key pairs in the repository root and adds
any columns introduced by a later spec revision. The vault starts empty — there
is no seed inventory: every credential enters through **Onboard New Credential**
(`POST /api/v1/vault/items`), and the screens show real counts or honest
"not connected" states instead of sample rows.

```bash
python -m pytest tests -q     # 430 tests (from backend/phase2_license_server)
python -m pytest backend -q   # 512 tests from the repo root (+ shared crypto core)
```

**Docker (development/runtime testing only — never a shipping instruction):**
`Dockerfile` + `docker-compose.yml` in this folder build a dev-only image from
the repository root (`docker compose up --build` → host **5010 → container
5000**, throwaway `dev-admin-token`, fresh in-container database per `up`;
`.dockerignore` keeps `*.pem`/`*.key`/`.env`/`*.db` out of every build
context). The same image runs this suite in its Linux runtime:
`docker run --rm vypam-license-server:dev python -m pytest tests -q`.

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
| GET | `/settings` | – | Stored configuration + editable schema (8 groups: `sso`, `hsm`, `zsp`, `worm`, `mfa`, `itsm`, `siem`, `ldap`; per-field `readonly`/`secret` flags included) |
| POST | `/mfa/enroll` | admin | Mint an RFC-6238 TOTP factor (secret shown **once** + `otpauth://` URI; re-enroll rotates and resets `last_verified_at`) |
| POST | `/mfa/verify` | admin | Check a code against the factor (`no-factor` → 409, missing code → 400, invalid → 401 with `details.field=code`; the failed attempt lands on the `integration` trail, the code itself never does; no lockout exists) |
| POST | `/itsm/verify` | admin | Verify an ITSM ticket over REST (not configured → 409; configured → 200 with the honest `verified`/`http_status`/`detail` — upstream 404, refused connection or a missing path template stay `verified: false`, never a fabricated pass; missing/oversized ticket → 400) |
| POST | `/auth/ldap` | – | LDAP bind login: token mode issues `vypam-ldap1.<b64url>.<hmac>`; open mode honest (`verified: true`, `note` "open dev mode") |
| GET | `/integrations/status` | – | §20 connector aggregate: MFA factor + gate line, ITSM, SIEM state + last push result, LDAP, `event_count` |
| GET | `/settings/audit?limit=` | – | Configuration changelog, newest first |
| PUT | `/settings/<group>` | admin | Merge-update one group, returns the per-field change diff (secrets seal AES-256-GCM → changelog `<set>`/`<cleared>`; readonly `mfa.*` factor fields → 400 with `details.fields` + the `POST /mfa/enroll` hint; URL fields must be `https` unless flagged `allow_http` — `itsm.base_url`/`siem.webhook_url` accept plain http for internal instances — bad shape → 400 with `details.field`/`details.scheme`) |
| GET | `/overview` | – | Dashboard aggregate: health, license posture, vault stats, settings, counters, computed control posture, recent activity |
| GET | `/events?limit=&source=` | - | Unified audit feed across all fourteen trails (license, settings, vault, discovery, jit, session, command, risk, bypass, break-glass, integration, vendor, cloud, broker), newest first |
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
| POST | `/sessions` | admin | Start a privileged session (201; `protocol` (13), `target`, optional `device` and `source_ip` (both scored at start), `item_id` - checks the credential out — or `jit_request_id` that must be an active grant, plus the 7 control flags). The response carries the §7 `risk` evaluation; a band the gate refuses (critical, or high without an active grant) → 403 with `details.risk` — the evaluation is already committed as ledger evidence. A critical band carrying named baseline deviations (section 11) additionally runs the anomaly response chain, reported in `details.anomaly`: the principal's standing sessions end through the release-and-rotate cascade, the credential the request sought is rotated, and the incident is recorded on `/risk/anomalies` and the ledger's `risk` trail. One live session per grant → 409. When a TOTP factor is enrolled the §7 `mfa` decision additionally demands `mfa_code` in the body (no factor → 201 without it; missing/wrong → 403 with `details.mfa`, committed as `mfa-gate` evidence) |
| GET | `/sessions/<id>` | - | One session plus stats, its latest events, and the §12 `watermark` payload (`state`/`fields`/`text`, evaluated linked grant expiry) |
| GET | `/sessions/<id>/events?order=&type=&limit=&offset=` | – | The append-only recording: `seq`, type, content, `allowed`/`blocked_reason`, `withheld`, `watermark`, actor |
| POST | `/sessions/<id>/events` | admin | Record a channel event. Not-live → 409; typed content while `record=false` → 403; gated channels store `allowed=false` + reason (blocked evidence); `keystroke_log=false` stores content `null` + `withheld=true` |
| POST | `/sessions/<id>/controls` | admin | Update control flags mid-session (live only; JSON keys are the flags) |
| POST | `/sessions/<id>/pause` | admin | Suspend the session: further channel events → 409 until resumed |
| POST | `/sessions/<id>/lock` | admin | Lock the session (same refusal semantics as pause) |
| POST | `/sessions/<id>/resume` | admin | Resume a paused/locked session |
| POST | `/sessions/<id>/terminate` | admin | End with `outcome=terminated` (body `{"reason"?}`); linked grant closes with it, own checkout releases and rotates exactly once — response carries the real `cascade` detail |
| POST | `/sessions/<id>/complete` | admin | End with `outcome=completed` (body `{"reason"?}`), same cascade rules |
| GET | `/command-control/stats` | – | Engine aggregates: real rule counts by action, enabled ratio, `engine_hash`, today's intercepts, approvals by state, incidents by state, `last_sync`/`last_sync_by` |
| GET | `/command-control/rules?action=&q=&enabled=` | – | Every rule in evaluation order (block → approval → allow; scoped first, longest pattern, lowest id) with its real `match_count` |
| POST | `/command-control/rules` | admin | Create a rule (201): `name` (≤120) and `pattern` (≤160) required, `action` ∈ `allow`/`approval`/`block`, optional `target_pattern` fnmatch glob, `terminate_on_match` only on block rules |
| PUT | `/command-control/rules/<id>` | admin | Partial edit (send only what changed); `updated_by`/`updated_at` follow the caller (`X-Actor`) |
| DELETE | `/command-control/rules/<id>` | admin | Remove a rule — events/incidents keep their own snapshot, so past decisions stay explainable; seeding runs only on an empty table, so the deletion sticks |
| POST | `/command-control/evaluate` | – | Dry-run one command line (`command` ≤4096 chars, optional `target` ≤255) against the live policy — writes nothing; returns `decision`, the matched `rule`, `terminate`, `default` |
| GET | `/command-control/approvals` | – | Held commands awaiting a decision (event + its active session), newest first |
| GET | `/command-control/incidents?status=&limit=&offset=` | – | Escalation trail newest first (`status`: `open`/`closed`/all) |
| GET | `/command-control/incidents/<id>` | – | One incident with its preserved evidence (unknown id → 404) |
| POST | `/command-control/incidents/<id>/close` | admin | Close after review (`{"note"?}`, recorded with who/when); already closed → 409 |
| POST | `/sessions/<id>/events/<seq>/approve` | admin | Release a held command: append-only `type=approval` row (`decision=approved`) referencing the hold — the hold itself is never edited; already resolved → 409 |
| POST | `/sessions/<id>/events/<seq>/deny` | admin | Deny a held command: append-only `denied` row (`blocked_reason=approval_denied`), same 409 guards |
| GET | `/vault/events?limit=&action=` | – | Vault audit trail (onboarding, checkouts, rotations); `action` filters to one type |
| GET | `/discovery/stats` | – | Discovery aggregates: totals, per-type/risk/status, recorded accounts, last scan |
| GET | `/discovery/assets?…` | – | Discovered targets (`q`, `type`, `risk`, `pam_status`, `limit`, `offset`), each with `vault_count` |
| POST | `/discovery/assets` | admin | Register + classify a target, ingest its admin account (201) |
| PATCH | `/discovery/assets/<id>` | admin | Ignore/restore, reclassify (recomputes risk), edit hostname/detail/notes |
| POST | `/discovery/assets/<id>/onboard` | admin | Adopt a discovered asset into the vault (201) |
| GET | `/discovery/accounts?…` | – | Recorded privileged accounts (`q`, `kind`, `limit`, `offset`) |
| GET | `/discovery/scans?limit=` | – | Scan history, newest first |
| POST | `/discovery/scans` | admin | Run a real TCP-connect scan (201; IPv4/CIDR/hostname, ≤256 hosts, ≤24 ports) |
| GET | `/risk/stats` | – | §7 aggregates: `total`, `by_band`, `by_decision`, `by_result`, `by_context`, `refused`, `avg_score`, `last_evaluated_at` |
| GET | `/risk/evaluations?band=&context=&limit=&offset=` | – | Every evaluation, newest first: score, band, decision, result, context and all 8 scored components with their measured-input details |
| POST | `/risk/evaluate` | admin | Score one access request (201; `subject` required ≤160, optional `target`, `device`, `source_ip`, `ticket`, `command`) — always `result=advisory`; the same scorer gates `POST /sessions` |
| GET | `/risk/baselines` | – | Trained UEBA baselines (§11): per principal the real hours, devices, source IPs, targets, command/privilege verbs and session cadence learned from history rows in the rolling window — empty until trained; normality is never invented |
| POST | `/risk/baselines/train` | admin | Learn or refresh baselines from real history (200; optional `subject` to train one principal, otherwise every principal in the window) — no history, no baseline |
| GET | `/risk/anomalies?subject=&limit=&offset=` | – | UEBA incidents (§11), newest first: the refused critical evaluation, its named deviations and the response chain it ran (sessions ended, rotations, honest failure notes); each also fans into the ledger's `risk` trail as `anomaly-incident` |
| POST | `/bypass/ingest` | admin | Parse a real log bundle into connection observations (201; `origin` + `content` required ≤200000, optional `target` for OpenSSH lines) — every raw line kept verbatim; dedupe by origin+target+raw |
| GET | `/bypass/signals?status=&protocol=&q=&limit=&offset=` | – | Parsed observations, newest first (`observed`, `candidate`, `covered`, `out_of_scope`) |
| POST | `/bypass/scans` | admin | Correlate unscanned `observed` signals (201; `candidates`, `covered`, `out_of_scope`, `incidents`, `rotations_forced`) — a managed target outside any recorded session opens an incident with forced rotation; re-scans never duplicate |
| GET | `/bypass/incidents?status=&limit=&offset=` | – | Direct-access incidents, newest first (`byp-` ref, signal snapshot, ACTION block: alert / rotation / block_source) |
| GET | `/bypass/incidents/{incident_id}` | – | One incident with its verbatim `evidence.raw` log line |
| POST | `/bypass/incidents/{incident_id}/close` | admin | Analyst closure (optional `note`; records who/when and fans into the ledger) |
| GET | `/bypass/stats` | – | §10 aggregates: `signals` by status, `incidents` open/closed, `rotations_forced`, action counters, last ingest/scan timestamps |
| POST | `/break-glass/requests` | admin | File an emergency request (201; `target` required, `reason`, optional `severity` `sev1`\|`sev2`\|`sev3` and `protocol`) — a `bg-` ref in `pending`; `mfa` recorded honestly as `not configured` until a factor exists |
| GET | `/break-glass/requests?status=&severity=&limit=&offset=` | – | Emergency requests, newest first (status/severity filters, approval snapshots per row) |
| GET | `/break-glass/requests/<id>` | – | One request with its append-only approval signatures and the recorded session (or `null` while unopened) |
| POST | `/break-glass/requests/<id>/approve` | admin | Record one approval signature (200; optional `note`) — the requester cannot approve their own emergency (403), a repeat signature from the same approver is rejected (400), two distinct signatures flip the request to `approved` |
| POST | `/break-glass/requests/<id>/deny` | admin | Refuse a pending request with a note (any actor may, including the requester — the refusal itself is always recorded with who/when; 400 once the request is decided) |
| POST | `/break-glass/requests/<id>/open` | admin | Release the approved credential (201): dual approval checked first, then the §7 risk gate (critical → 403 with `details.risk`, nothing released) and the §20 MFA gate (factor enrolled → `mfa_code` required; refusal → 401 with `details.mfa`); real vault checkout + mandatory recorded session (`session_id` stored on the request) |
| POST | `/break-glass/requests/<id>/close` | admin | End the emergency (200): session stopped, credential force-rotated through the §5 pipeline (`trigger=break-glass`, outcome recorded), review note required |
| GET | `/break-glass/stats` | – | §17 aggregates: requests by status + total, approval signatures recorded/outstanding, action counters, `last_request_at`/`last_opened_at`/`last_closed_at`, `open_emergencies` |
| POST | `/vendors` | admin | Invite a vendor (201): seals a fresh per-vendor TOTP seed, `qr_png` + `otpauth_uri` returned exactly once (409 same name) |
| GET | `/vendors?status=&q=&limit=&offset=` | – | Vendor accounts, newest first (§13 dashboard source) |
| GET | `/vendors/<id>` | – | §13 dashboard payload: 8-step chain (done_at/due_at + `missing`), access/denied lists, validity window, recording flag, vendor requests, lifecycle trail |
| PATCH | `/vendors/<id>` | admin | Edit contact + access scope (`allowed_targets`/`denied_targets`), window, recording, expiry |
| POST | `/vendors/<id>/mfa` | admin | Step 1 — vendor MFA verification: real RFC-6238 over the sealed per-vendor seed (wrong code → 401, recorded) |
| POST | `/vendors/<id>/nda` | admin | Step 2 — record NDA acceptance (reference optional, timestamp not) |
| POST | `/vendors/<id>/ticket` | admin | Step 3 — real ITSM check (unconfigured ITSM → 409 honest refusal) |
| POST | `/vendors/<id>/approve` | admin | Step 4 — approve (409 `details.missing` while a step is outstanding; already-approved → 409) |
| POST | `/vendors/<id>/deny` | admin | Refuse the invite (reason recorded; the name may be re-invited) |
| POST | `/vendors/<id>/revoke` | admin | Withdraw an approved vendor (denied → 409); active grants close through the JIT path |
| POST | `/vendors/<id>/requests` | admin | Vendor-scoped JIT request (approved account only; allow/deny lists + window checked pre-creation → 403 `Vendor access refused` evidence; ticket defaults to the verified one) |
| POST | `/cloud/connectors` | admin | Register a cloud account/cluster (201; provider `aws`/`azure`/`gcp`/`kubernetes`, `https` endpoint (`http` loopback-only), credential federated into the vault — row starts honest `not connected`/`configured`) |
| GET | `/cloud/connectors?provider=&status=&q=&limit=&offset=` | – | Cloud connectors, newest first (§14) |
| GET | `/cloud/connectors/<id>` | – | Console payload: connector, recent §14 trail, RBAC grants raised through it, last inventory run |
| PATCH | `/cloud/connectors/<id>` | admin | Edit config: endpoint change drops the row back to `configured`, clearing it → `not connected` |
| DELETE | `/cloud/connectors/<id>` | admin | Remove the connector (409 while open RBAC grants ride it; the trail stays) |
| POST | `/cloud/connectors/<id>/test` | admin | Real reachability probe (vault credential revealed per call, audited; 2xx → `connected`, failure → `error` + reason; no endpoint → 409) |
| POST | `/cloud/connectors/<id>/discover` | admin | Real inventory from the cloud's own API (assets under `source=cloud`, method = provider API; failed/unrecognized answer records the honest reason and invents nothing) |
| POST | `/cloud/connectors/<id>/rbac/requests` | admin | K8s path (201): section-6 JIT request with `cloud_binding`; the grant applies a real RoleBinding `vypam-jit-<id>`, close/expiry removes it |
| GET | `/cloud/stats` | – | §14 aggregates: connectors by provider/state, trail size, RBAC grants, cloud-discovered assets |
| POST | `/broker/policies` | admin | Register a pipeline identity (201; `vypam-ci1.<id>.<secret>` returned exactly once, stored as a sha256 hash) |
| GET | `/broker/policies?ci_system=&status=&q=&limit=&offset=` | admin | Pipeline identities, newest first (§15) |
| GET | `/broker/policies/<id>` | admin | One policy with its open credential count and latest trail |
| PATCH | `/broker/policies/<id>` | admin | Edit approval mode / TTL cap / allowed targets / contact / expiry (never name, CI system or token; revoked → 409 frozen) |
| DELETE | `/broker/policies/<id>` | admin | Revoke: open credentials closed first (released ones rotate), then the token stops authenticating |
| POST | `/broker/credentials` | pipeline | Request a time-boxed credential with the API token (201; `auto` releases the secret in this response, `manual` queues it; target outside `allowed_targets` → 403 + `refused`) |
| GET | `/broker/credentials?status=&policy_id=&limit=&offset=` | admin | Every pipeline credential, newest first (never the secret — `secret_released` flag only) |
| GET | `/broker/credentials/<id>` | admin | One credential with its policy and full §15 trail |
| POST | `/broker/credentials/<id>/approve` | admin | Sign off a queued request; the pipeline then releases it with its own token |
| POST | `/broker/credentials/<id>/deny` | admin | Refuse a queued request (reason recorded; nothing released) |
| POST | `/broker/credentials/<id>/release` | pipeline | Real vault checkout under the pipeline's name; the secret appears in this response exactly once |
| POST | `/broker/credentials/<id>/close` | pipeline or admin | End the grant early: checkout released and the credential rotated (`session_ref broker-<id>`) |
| GET | `/broker/stats` | admin | §15 aggregates: policies by state/CI system, credentials by state, trail size |
| GET | `/audit/stats` | - | Immutable ledger aggregates (§19): `total`, per-source counts for all fourteen trails, `last_seq`, `head_hash`, oldest/newest, `trigger_protection` |
| GET | `/audit/verify` | – | Walk the whole chain: recomputes every record's hash and reports `intact`, `checked`, `head_hash` plus the first `broken_at`/`reason` (sequence gap, content change, re-link) |
| GET | `/audit/export` | – | The full ledger in chain order as NDJSON (`application/x-ndjson`, `vy-pam-audit.ndjson`) — one record per line for SIEM ingest |

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

- Eight groups: `sso` (9 fields), `hsm` (9), `zsp` (4), `worm` (6), plus the
  §20 connector groups `mfa` (4), `itsm` (6), `siem` (4), `ldap` (6). The schema
  lives in `service.py` (`SETTINGS_SCHEMA`); defaults mirror the values the
  spec screen displays (2-of-3 quorum, 120-minute TTL extension, 2,555-day
  retention, the spec's bucket and cluster host).
- Writes merge into the stored row. Unknown **fields**, wrong types,
  out-of-range numbers, URL fields outside their allowed scheme (plain
  `http` is accepted only where the schema flags `allow_http` —
  `itsm.base_url` and `siem.webhook_url`, which commonly sit on internal
  instances), invalid enum values and malformed bucket names are rejected
  with `400 {"error": "...", "details": {"field": ...}}` before anything is
  saved; an unknown **group** is a 404. A no-op write returns
  `{"message": "No changes"}` and writes no event.
- `secret` fields (`itsm.api_token`, `siem.signing_secret`) seal AES-256-GCM
  with AAD `settings:{group}:{field}` — reads never echo them (empty string),
  the changelog stores `<set>`/`<cleared>` instead of a value, and clearing
  is `""`. `readonly` fields (`mfa.factor_*`) are rejected with
  `400 details.readonly` and the hint to mint/rotate through
  `POST /mfa/enroll`.
- Every accepted change records a `SettingsEvent` with the actor
  (`X-Actor`, else the authenticated admin) and a per-field old/new diff.
- Reads are public so the screen can render read-only without a token; `PUT`
  requires the admin token unless `LICENSE_ADMIN_TOKEN` is unset (open mode,
  responses then carry `X-Auth-Mode: open`).

### Vault & dashboard

```bash
# dashboard aggregate powering the Command Center / Compliance screens
curl -s http://127.0.0.1:5000/api/v1/overview

# unified audit feed (all fourteen trails: license, settings, vault, discovery,
# jit, session, command, risk, bypass, break-glass, integration, vendor, cloud,
# broker - newest first, each row chain-linked with seq + hash)
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
  jit, sessions, command-control rule/incident/approval writes, risk
  evaluation)
  require the admin token in token mode (open mode stays open) and record who
  acted via `X-Actor`. The secret reveal (`GET /vault/items/<id>/secret`) is
  gated like a write route — it is never one of the public reads.

### Command control

```bash
# dry-run one command against the live policy (public, writes nothing)
curl -s -X POST http://127.0.0.1:5000/api/v1/command-control/evaluate \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -rf /var/log/audit", "target": ""}'
# -> {"result": {"decision": "block", "matched": true, "rule": {"id": 7, ...},
#                "terminate": false, "default": false}}

# partial edit of a live rule (only what changed)
curl -s -X PUT http://127.0.0.1:5000/api/v1/command-control/rules/9 \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{"enabled": false}'

# a command held by an approval rule resolves append-only on its session
curl -s -X POST http://127.0.0.1:5000/api/v1/sessions/1/events/2/approve \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice"
# -> {"event": {..., "decision": "approval"},
#     "resolution": {..., "decision": "approved", "allowed": true},
#     "message": "Command approved"}

# review an escalated incident (its evidence is already preserved)
curl -s -X POST http://127.0.0.1:5000/api/v1/command-control/incidents/1/close \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" -d '{"note": "block reviewed"}'
```

- **Command control** (architecture module 9) is a default-allow engine over
  `command_rules`: a match is a case-insensitive substring of the command plus
  an optional case-insensitive fnmatch glob on the target, and evaluation runs
  block → approval → allow with scoped rules first, then the longest pattern,
  then the lowest id. A rule either allows, holds the command for a human
  decision (the approval queue resolves through append-only `type=approval`
  rows that reference the hold — the hold is never edited), or blocks it; a
  scoped block with `terminate_on_match` ends the session through the normal
  release-and-rotate cascade and preserves the evidence as a
  `command_incidents` row (command, target, rule snapshot, session/seq,
  actor). The shipped §9 table seeds 15 rules once, into an empty table only,
  so an operator's deletion stays deleted; `engine_hash` is a content hash of
  the current policy, so any rule change is visible in the stats and on the
  screen. `session_events` grows `decision`/`rule_id`/`ref_seq` and
  `evaluate` is a pure dry-run: it never writes an event.

### Risk-based access (§7)

```bash
# score one access request (advisory - writes an evaluation, never a session)
curl -s -X POST http://127.0.0.1:5000/api/v1/risk/evaluate \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: alice" \
  -H "Content-Type: application/json" \
  -d '{"subject": "alice", "target": "10.77.0.9:5432",
       "device": "unmanaged-laptop", "source_ip": "8.8.8.8",
       "ticket": "fix-now", "command": "rm -rf /opt"}'
# -> {"evaluation": {"score": 70, "band": "high", "decision": "approval",
#     "result": "advisory", "context": "manual", "components": [ ...8... ]},
#     "message": "Scored 70/100 - high (approval)"}

# aggregates and the recorded evaluations
curl -s http://127.0.0.1:5000/api/v1/risk/stats
curl -s "http://127.0.0.1:5000/api/v1/risk/evaluations?band=critical&limit=5"
```

- **Risk-based access** (architecture module 7) scores every request over eight
  components that always come back with their measured-input detail, and the
  caps sum to exactly 100 so the score is the visible sum of its parts:
  `user` (≤10, 5 per prior critical evaluation in 24h), `device` (≤15, unknown
  to the discovered inventory), `asset` (≤30: `CRITICAL` 25 / `HIGH` 20 /
  `MEDIUM` 10 / `LOW` 0, +5 when the target is `unmanaged`), `time` (≤10 from
  the real local clock — off-hours or weekend), `location` (≤5 when the source
  address is global, via `ipaddress` — no geo feed is claimed), `behavior`
  (≤15: 10 for blocked commands + 5 for denied JIT requests in 24h),
  `ticket` (≤5 for a non-ITSM shape) and `command` (≤10 for a live
  `block` / ≤5 for `approval` under the §9 policy). Bands → decisions:
  ≤25 `allow`, ≤50 `mfa`, ≤75 `approval`, above that `block`.
- The console endpoint always advises (`result=advisory`); the **session-start
  gate** in `POST /sessions` runs the same scorer with `context=session_start`
  and commits its `RiskEvent` **before** it decides, so a refused start keeps
  its evaluation as SOC evidence in the ledger (`403` + `details.risk`):
  critical refuses outright, high proceeds only under an active JIT grant
  (approved by someone other than the requester), medium prescribes MFA, low
  allows. The `mfa` band is **enforced at start** when a TOTP factor is
  enrolled: the body must carry a valid `mfa_code` (missing/wrong → 403 with
  `details.mfa`; no factor enrolled → the start proceeds and says so), and
  every gate decision fans into the ledger as `mfa-gate` evidence.

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

### PAM bypass detection (§10)

```bash
# ingest a real auth-log bundle (OpenSSH lines take the bundle's target)
curl -s -X POST http://127.0.0.1:5000/api/v1/bypass/ingest \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: soc" \
  -H "Content-Type: application/json" \
  -d '{"origin": "auth.log", "target": "10.77.0.9",
       "content": "Oct  8 08:39:41 bastion sshd[4112]: Accepted publickey for admin01 from 10.10.5.20 port 50984"}'
# -> {"ingested": 1, "duplicates": 0, "skipped": 0, "total": N}

# correlate unscanned observed signals against inventory + recorded sessions
curl -s -X POST http://127.0.0.1:5000/api/v1/bypass/scans \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: soc"
# -> {"signals": {"scanned": 4, "candidates": 2, "covered": 1,
#     "out_of_scope": 1}, "incidents": 2, "rotations_forced": 2}

# the incidents, one incident's verbatim evidence, and aggregates
curl -s "http://127.0.0.1:5000/api/v1/bypass/incidents?status=open"
curl -s "http://127.0.0.1:5000/api/v1/bypass/incidents/byp-a6b82ade"
curl -s http://127.0.0.1:5000/api/v1/bypass/stats
```

- **PAM bypass detection** (architecture module 10): every raw log line is
  kept verbatim as evidence; correlation only ever opens an incident for a
  managed target outside any recorded session, the ACTION block reuses the
  real §5 rotation pipeline (failures recorded per credential, never
  fatal), `block_source` stays honestly `not connected`, and every
  ingest/scan/detect/close fans into the §19 chain as the ninth source
  `bypass`. Re-scans never duplicate incidents.

### Break-glass emergency path (§17)

```bash
# file an emergency request
curl -s -X POST http://127.0.0.1:5000/api/v1/break-glass/requests \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: oncall" \
  -H "Content-Type: application/json" \
  -d '{"target": "jump-edge.internal:22", "severity": "sev1",
       "protocol": "ssh",
       "reason": "PAM proxy tunnel down; recorded SSH needed to restore it."}'
# -> {"request": {"request_ref": "bg-3740f3d5", "status": "pending",
#     "approvals_required": 2, "mfa": "not configured", ...}}

# two DISTINCT approvers sign (self-approval -> 403, repeat signature -> 400)
curl -s -X POST http://127.0.0.1:5000/api/v1/break-glass/requests/1/approve \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: incident-commander"
curl -s -X POST http://127.0.0.1:5000/api/v1/break-glass/requests/1/approve \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: security-duty"
# -> {"request": {"status": "approved", ...}}

# open: dual approval first, then the §7 risk gate (critical -> 403,
# nothing released) and the §20 MFA gate (a factor enrolled -> a valid
# TOTP code is demanded: {"mfa_code": "123456"}; refusal -> 401
# {"error": "...", "details": {"field": "mfa_code", "mfa": "..."}});
# approved -> real vault checkout + recorded session
curl -s -X POST http://127.0.0.1:5000/api/v1/break-glass/requests/1/open \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: incident-commander" \
  -H "Content-Type: application/json" -d '{"mfa_code": "123456"}'
# -> {"session": {"id": 4, "session_ref": "sess-ccdcc3b9", ...}, ...}  (201)

# close: session stopped, credential force-rotated (trigger=break-glass),
# review note required - the rotation outcome is recorded on the request
curl -s -X POST http://127.0.0.1:5000/api/v1/break-glass/requests/1/close \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: incident-commander" \
  -H "Content-Type: application/json" \
  -d '{"review": "Tunnel restored; session recorded end to end; credential rotated."}'

# aggregates + the full list/detail
curl -s http://127.0.0.1:5000/api/v1/break-glass/stats
curl -s "http://127.0.0.1:5000/api/v1/break-glass/requests?limit=10"
```

- **Break-glass** (architecture module 17): `pending → approved → used →
  closed` (or `denied`); the requester cannot approve or deny their own
  emergency, both signatures come from distinct actors and are stored as
  append-only snapshots, and the risk gate runs **at open** — a critical
  evaluation refuses the release while staying committed as ledger
  evidence. Close forces the §5 rotation with `trigger=break-glass` and
  records the review; every request/approve/deny/open/close fans into the
  §19 chain as the tenth source `break-glass`.

### Immutable audit ledger (§19)

```bash
# aggregates: every module trail fanned into one append-only hash chain
curl -s http://127.0.0.1:5000/api/v1/audit/stats
# -> {"total": 67, "by_source": {"break-glass": 12, "bypass": 7,
#     "command": 7, "discovery": 4, "integration": 1, "jit": 1,
#     "license": 1, "risk": 9, "session": 8, "settings": 3,
#     "vault": 14}, "last_seq": 67,
#     "head_hash": "c4e1...", "trigger_protection": true, ...}

# walk every record and recompute every hash (what the console's
# "Verify Hash Chain" button runs on click)
curl -s http://127.0.0.1:5000/api/v1/audit/verify
# -> {"intact": true, "checked": 67, "total": 67, "last_seq": 67,
#     "head_hash": "c4e1...", "broken_at": null, "reason": null}

# the whole ledger as NDJSON in chain order, one record per line (SIEM ingest)
curl -s http://127.0.0.1:5000/api/v1/audit/export
# -> {"id":"license:1","seq":1,"event_ref":"license:1","source":"license",
#     "action":"imported", ...,"prev_hash":"000..0","event_hash":"..64 hex.."}
```

### Enterprise integrations (§20)

```bash
# enroll a TOTP factor (admin) - the secret is shown ONCE; the response
# also carries the otpauth:// URI for the authenticator app
curl -s -X POST http://127.0.0.1:5000/api/v1/mfa/enroll \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: sre-admin" \
  -H "Content-Type: application/json" -d '{}'
# -> {"factor": {"configured": true, "digits": 6, "period": 30,
#     "algorithm": "SHA1", "enrolled_for": "sre-admin",
#     "gate": "medium-risk (mfa-decision) session starts require a valid code",
#     ...}, "secret": "...", "otpauth_uri": "otpauth://totp/VY-PAM:...", ...}

# verify a code (6 digits, ±1 30s window; a wrong code -> 401 +
# `mfa-verify-failed` evidence on the integration trail - the code
# itself never lands anywhere)
curl -s -X POST http://127.0.0.1:5000/api/v1/mfa/verify \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "X-Actor: sre-admin" \
  -H "Content-Type: application/json" -d '{"code": "123456"}'

# verify an ITSM ticket over REST (itsm.base_url + api_token must be stored)
curl -s -X POST http://127.0.0.1:5000/api/v1/itsm/verify \
  -H "Content-Type: application/json" -d '{"ticket": "INC-001"}'

# LDAP bind login (ldap.server + ldap.user_bind_template must be stored;
# token mode answers a vypam-ldap1 ticket, open mode answers honestly)
curl -s -X POST http://127.0.0.1:5000/api/v1/auth/ldap \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "..."}'

# one aggregate for the Integrations cards + the console chips
curl -s http://127.0.0.1:5000/api/v1/integrations/status
# -> {"mfa": {...}, "itsm": {...}, "siem": {"state": "not connected", ...},
#     "ldap": {...}, "event_count": 1}
```

- **Integrations** (architecture module 20, **stdlib only** — no new
  dependencies): RFC-6238/4226 TOTP over `hmac`/`hashlib` (SHA-1/256/512,
  ±1 window; the deterministic time-window math is unit tested). The gate
  runs at session start on a `mfa` decision and at break-glass open. With no
  factor enrolled nothing is ever faked: the start proceeds and says
  `mfa: "not configured"`.
- ITSM verification queries the vendor REST path template with sealed
  credentials; every outcome (`verified`/`not_verified` plus the HTTP
  status) lands on the `integration` ledger source — never a fabricated pass.
- SIEM pushes committed ledger batches outbound as signed NDJSON
  (`sha256=` HMAC-SHA256) after commit; a failed push records exactly one
  `siem-push-failed` event and never breaks the write path.
- LDAP logins bind over a BER-encoded simple bind (stdlib socket) and issue
  `vypam-ldap1.<b64url>.<hmac>` tickets on `config.secret_key` in token
  mode. All four connectors report honestly through
  `GET /integrations/status`; every gate decision, enrollment, verification
  and login fans into the §19 chain as the `integration` source.

## Design notes

- **Revocation is server-side.** Phase 1 licenses are stateless; this server keeps
  the revocation list, so `POST /licenses/validate` is the authority for
  "is this license still good?".
- **Audit trail.** Every import/revoke/restore/usage report writes a
  `LicenseEvent` row, returned with `GET /licenses/<key>`.
- **The ledger is immutable (§19).** A `before_flush` listener fans every
  module trail — license, settings, vault, discovery, JIT, session lifecycle,
  command control (incidents and their closure included) and risk (every §7
  evaluation, refusals included) — into one
  `audit_events` chain: `seq` + `prev_hash` link each record to a sha256 over
  its canonical content, SQLite triggers refuse `UPDATE`/`DELETE` outright
  (`audit_events is append-only (architecture 19)`), first boot backfills any
  pre-existing history exactly once, and `/audit/verify` reports the first
  break instead of trusting the row count. Channel content stays in the
  session recording and secrets never enter the ledger: a reveal records
  who/what/when, never the plaintext.
- **Usage is reported, not simulated.** The screen renders
  `POST /licenses/<key>/usage` results only.
- **Settings are stored, not re-derived.** One `SettingGroup` row per group is
  upserted on write and merged with the built-in defaults on read, so a field
  that was never changed still shows its spec value; every write is mirrored
  into `SettingsEvent` for the changelog.
- **Naive local datetimes.** Expiry is compared in Python, not SQL, so results do
  not depend on the database's timezone handling.
- **Errors are JSON**: `{"error": "...", "details": {...}}` with 400/401/403/404/405/500.
