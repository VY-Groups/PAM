# VY-PAM — Technical Requirements & Design Document (TRD)

**Status:** as-built for Phase 4h
**Audience:** engineers extending or operating the system
**Companion docs:** `PRD.md`, `PAM_FLOW.md`, `BACKEND_SCHEMA.md`, `API_REFERENCE.md`

---

## 1. System context

```
                         ┌────────────────────────────────────────────┐
   Browser (admin)  ───► │ VY-PAM (shipped)                           │
   1920×1600 console      │  frontend/  static screens (file:// or HTTP)│
                          │  apis/      openapi.yaml (contract)        │
                          │  backend/   Flask runtime + SQLite         │
                          │    └ ipam_licensing (shared crypto engine) │
                          └────────────────────────────────────────────┘
                                     ▲ signed license envelope (.lic)
                                     │ (import endpoint; verification only)
                          ┌────────────────────────────────────────────┐
   VY-Groups operator ──► │ VY-PAM MASTER (pam_master/, NEVER SHIPPED) │
   port 5400, local only   │  issues/renews licenses, encrypted PII,    │
                          │  own sqlite + own OpenAPI contract         │
                          └────────────────────────────────────────────┘
```

Two processes, one crypto engine. **Shipped routes only ever verify** —
issuing lives exclusively in `pam_master/` (Phase 3a rule, stated verbatim in
`test_api.py`: *"tests play the vendor … the shipped server only ever
verifies"*). `licensing_bridge.get_generator()` can load a private key but is
invoked **only by tests** acting as the vendor stand-in. The trust root
(RSA/Ed25519 private keys) lives at the repo root, git-ignored, and is loaded
only when `pam_master` runs. Guards that exist today:
`test_no_private_key_material_in_tracked_files` (pam_master contract suite)
runs `git ls-files` and fails if **any tracked file** contains a
`-----BEGIN … PRIVATE KEY-----` block;
`test_master_source_never_references_the_pam_runtime` (no back-references to
the shipped runtime); key-custody tests (missing keys refused **without being
created**, keygen refuses overwrite); and the test suite keeps generated
Ed25519 keys inside `tmp_path` so no key material is ever written into the
repo.

## 2. Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3 (`python -X utf8`) | stdlib-first; no compiled deps |
| Web | Flask, blueprint `api` under `/api/v1` | app factory in `app.py`, `create_app()` |
| ORM | SQLAlchemy (Flask-SQLAlchemy) | declarative models, `db.create_all()` + additive `ensure_schema()` |
| Store | SQLite (`licenses.db`, git-ignored) | append-only enforced by triggers on `audit_events` |
| Crypto | `cryptography` lib | RSA-PSS-SHA256 (default) / Ed25519 envelopes; AES-256-GCM secrets |
| Frontend | Static HTML + Tailwind (CDN build) + vanilla JS | 10 sidebar screens, no bundler, works from `file://` |
| Tests | pytest | 440 backend + 46 pam_master |
| UI verification | Node + `playwright-core` (`shots_tool/`) | viewport 1920×1600, never `fullPage` |
| Vendor tool | Flask + raw `sqlite3` | `pam_master` package, `python -m pam_master` |

## 3. Runtime layering (shipped server)

```
routes.py          HTTP edge: validation, auth check, status codes, envelopes
   │
service.py         business logic; the ONLY layer that writes domain tables
   │                (one section per architecture module, in file order)
   ├── models.py   SQLAlchemy tables + ensure_schema() additive columns
   ├── audit.py    append_audit() → hash chain; ensure_audit_chain() backfill
   ├── risk.py     scoring helpers (clock anchored for tests via module patch)
   ├── rotation_scheduler.py  optional APScheduler-free polling loop
   └── keys.py / licensing_bridge.py   key material + shared engine bridge
```

Rules enforced by tests/conventions:

1. **Routes never touch `db.session` directly for domain writes** — they call
   `service.*`, so ledger emission happens in exactly one place per action.
2. **Every state change that matters calls `append_audit(source, action,
   …)`** inside the same transaction as the change → the chain can never
   disagree with the data.
3. **`X-Actor` is recorded verbatim** on audited writes; missing actor in
   token mode = 401, in open dev mode = explicit `"unknown (dev)"` honesty.

## 4. Module designs (as built)

### 4.1 Licensing (§2)
- **Import** (`POST /licenses/import`): accepts `.lic` file upload or raw
  envelope JSON → shared-engine verify → persist `licenses` row + `license`
  audit events. Revocation is a status flag with restore path (soft, both
  audited); usage endpoint computes real quota consumption from the row.
- **Validation** runs offline in three stages — signature check (fail-fast),
  structure check (required claims, schema), expiry/quota check. Order is
  deliberate: a bad signature never leaks whether a license *would* have
  expired.
- Quota/feature truth lives in the row (`features`, `usage_limits`,
  `quotas`, `modules` JSON); the entitlement screen renders it directly.

### 4.2 Settings (§2)
- Eight groups: `sso`, `hsm`, `zsp`, `worm` — **schema only**, no enforcement
  claimed (dashboard posture counts them honestly) — plus the §20 connector
  groups `mfa`, `itsm`, `siem`, `ldap` whose secrets seal AES-256-GCM
  (never echoed, `<set>`/`<cleared>` in the changelog) and whose
  `mfa.factor_*` rows are readonly (minted via `POST /mfa/enroll`).
- Every `PUT /settings/{group}` writes a `settings_events` row containing the
  per-field before/after diff → changelog on the Settings screen.

### 4.3 Vault (§4)
- Secrets encrypted **AES-256-GCM** with a data key derived from
  `VAULT_KEY_PATH` (auto-generated once if `VAULT_AUTOGENERATE_KEY`);
  each version row (`vault_secret_versions`) stores nonce + ciphertext +
  AAD bound to item id + version.
- Lifecycle: `available → checked_out → (revoke|rotate) → available`.
  Checkout is exclusive (one holder), audited; **reveal** returns plaintext
  once, is gated, and **never logs the secret** (log filter + test).
- Misspelled/missing vault key = fail-closed `503` with honest message.

### 4.4 Rotation (§5)
- Pipeline per item: **mint → seal → dependents → decrypt round-trip →
  audit**. The round-trip proves the new secret actually decrypts before the
  old one is retired; failure marks `failed` and is retryable.
- Triggers: `manual`, `bulk`, `session-end` (from session cascade),
  `scheduler` (`ROTATION_SCHEDULER=1`, interval
  `ROTATION_SCHEDULER_INTERVAL_SECONDS`).
- Version history is append-only; the previous version stays for dependent
  rollback but is never returned by reveal.

### 4.5 Discovery (§3)
- Real TCP connect scan: ≤256 hosts, ≤24 ports, single-flight per scan
  (concurrent start → 409). Classification from open port → service guess +
  banner read where the protocol allows.
- Persisted as `discovered_assets` / `discovered_accounts` with
  `BASE_RISK` mapping (port class → asset criticality); onboarding promotes
  an asset into managed inventory (drives §7 `asset`/`device` inputs).

### 4.6 JIT access (§6)
- Request carries duration, reason, ticket, target. Score inputs (all
  persisted on the row): asset tier (30/15/0), duration add-on (≤+20),
  off-hours (+20), repeat requester (+15), ticket ITSM-shape (+10),
  environment health (+10) → band.
- Band → approval matrix: `low ≤25` auto-approve; `medium ≤50` manager;
  `high ≤75` manager **+ security**; `critical >75` **deny-only** (no
  approve endpoint will accept it).
- Approvals are snapshots `{actor, at, role?}`; requester ≠ approver is
  enforced. Approved → time-boxed grant, consumed by starting a real
  session; expiry/close → **release + rotate** once.

### 4.7 Sessions (§8)
- Start against a vault credential (real checkout) **or** an active JIT
  grant (one live session per grant → 409). 13 protocols: ssh, rdp, telnet,
  vnc, http, https, sql, oracle, postgresql, mssql, mysql, sap, kubernetes.
- `session_events` is append-only (no update/delete endpoints exist); every
  event carries `seq`, actor, custody watermark. Controls are enforced at
  write time: `record=false` + typed content → 403; `keystroke_log=false` →
  content `null` + `withheld=true`; gated channels → `allowed=false` +
  reason stored **as kept evidence**.
- Terminate/complete cascade: close linked grant, release own checkout,
  rotate credential exactly once, report `cascade` in the response.

### 4.8 Command control (§9)
- **Default allow.** Rules: `pattern` (case-insensitive substring) + optional
  `target_pattern` (case-insensitive fnmatch glob) + `action`
  (`block` | `approval` | `allow`) + `terminate_on_match`.
- Evaluation order: **block → approval → allow**, scoped rules first, then
  longest pattern, then lowest id (deterministic, documented in OpenAPI).
- 15 architecture rules seed **once into an empty table** at boot
  (`ensure_command_rules()`); operator edits/deletes persist.
- Held commands → append-only `type=approval` rows referencing the hold id
  (the hold row itself is never mutated). Resolution emits a follow-up event;
  `terminate_on_match` block ends the session via the cascade and preserves
  evidence as incident `inc-<hex>`.

### 4.9 Risk engine (§7) — Phase 4f
- Eight components, caps sum to exactly **100**: `user` 10 (5 per prior
  critical evaluation in rolling 24h), `device` 15 (unknown to inventory),
  `asset` 30 (CRITICAL 25 / HIGH 20 / MEDIUM 10 / LOW 0, +5 `unmanaged`),
  `time` 10 (real clock: off-hours + weekend), `location` 5
  (`ipaddress.is_global` — no geo feed is claimed), `behavior` 15
  (10 blocked commands + 5 denied JITs / 24h), `ticket` 5 (non-ITSM),
  `command` 10 (`block`) / 5 (`approval`) via live `evaluate_command`.
- Bands: `≤25 low → allow`, `≤50 medium → mfa`, `≤75 high → approval`,
  `>75 critical → block`. Score = visible sum of components.
- Two consumers:
  1. `POST /risk/evaluate` (console) — always `advisory`, always persisted.
  2. **Session-start gate** inside `create_session`: evaluation is committed
     first (refusal must be SOC evidence), then `critical` → 403 refused;
     `high` → allowed only with an active JIT grant; else allowed. Refusal
     body: `details.risk` carries the full component breakdown.
- Every evaluation fans into the ledger as source `risk` (8th source).

### 4.10 Audit ledger (§19)
- Record: `{seq, source, action, entity, actor, detail, at, prev_hash,
  event_hash}`; `event_hash = sha256(canonical JSON incl. prev_hash)`,
  genesis prev = `0`×64.
- SQLite triggers `BEFORE UPDATE` / `BEFORE DELETE` → `RAISE(ABORT, …)`.
- First boot backfills any pre-chain history **exactly once** (flag row).
- `/audit/verify` recomputes the entire chain (reports first break index);
  `/audit/export` streams NDJSON in chain order (the SIEM seam).

### 4.11 PAM bypass detection (§10) — Phase 4g
- Ingest parses real bundles: OpenSSH `Accepted …` lines take the bundle's
  `target`; structured JSON records carry per-line `target`/`at`. Each raw
  line is kept as verbatim evidence (never rewritten); malformed or
  untargeted lines are counted, never invented; dedupe by
  origin+target+raw, including inside a batch.
- Correlation touches only unscanned `observed` signals: target not in the
  managed inventory → `out_of_scope`; a recorded session by the same actor
  on the same host covering `observed_at` → `covered`; otherwise
  `candidate` + a `bypass_incident` (`byp-` ref) whose ACTION block records
  `alert` (the ledger row), `rotation` (the §5 pipeline run per vault item
  on that target — `skipped` while checked out, `no_credential_on_file`
  when the vault has nothing, per-item failures caught so one broken
  credential never aborts the scan) and `block_source: not_connected`
  (honest until an enforcement connector exists).
- `BypassEvent` actions (`ingested`, `scanned`, `detected`, `closed`) fan
  into the §19 chain as the **ninth** source `bypass`; re-scans never
  duplicate incidents; stats and the compliance feed stay fully generic
  (no hardcoded source lists).

### 4.12 Break glass (§17) — Phase 4h
- Lifecycle `pending → approved → used → closed` (or `denied`): filing is
  cheap, the **risk gate runs at open** — dual approval is checked first,
  then the §7 evaluation; `critical` refuses the open (403 `details.risk`),
  nothing is released.
- Dual approval is enforced in code: the requester cannot approve their own
  emergency (403), a second signature from the same approver is rejected
  (400), and the two distinct approver rows are append-only snapshots.
- `open` performs a **real vault checkout** of the target's credential and
  starts a mandatory recorded session (`session_id` stored on the request);
  `close` ends the session, forces the credential rotation through the
  shared `_force_target_rotation` helper with `trigger=break-glass`, and
  requires a review note.
- `BreakGlassEvent` actions (`requested`, `approved`, `denied`, `opened`,
  `closed`) fan into the §19 chain as the **tenth** source `break-glass`
  (eleven since 4i added `integration`); `bg-` request refs, stats and the
  compliance feed stay generic. The emergency path runs the §20 MFA gate at
  open: a factor enrolled demands a `mfa_code` (401 `details.mfa`), no
  factor says so honestly.

### 4.13 Enterprise integrations (§20) — Phase 4i
- **TOTP (RFC 6238/4226)** over stdlib `hmac`/`hashlib` — SHA-1/256/512,
  ±1 window, 6 digits / 30 s; the secret shows once at enroll
  (`otpauth://` URI) and seals at rest like every other secret. The gate
  runs where the §7 scorer says `mfa`: session start (403 `details.mfa`)
  and break-glass open (401 `details.mfa`). No factor enrolled → the start
  proceeds and reports `mfa: "not configured"` — the product never
  simulates a challenge.
- **ITSM verification** is a real HTTP GET against the configured vendor's
  REST path template (ServiceNow/Jira shapes, sealed credentials), with a
  stdlib stub server in tests; outcomes land on the ledger with the HTTP
  status, and `itsm_verify_ticket` never raises (upstream trouble becomes
  `connection failed: …` / `request timed out after Ns` with
  `verified: false`, not a 500).
- **SIEM outbound** pushes committed ledger batches as signed NDJSON
  (`sha256=` HMAC-SHA256 over the body) *after* commit via a fresh
  post-commit session; one failed push = one `siem-push-failed` event, and
  the write path is never coupled to the webhook's availability.
- **LDAP bind** is a real RFC-4515-filtered search + BER-encoded simple
  bind over stdlib sockets; token mode mints `vypam-ldap1.<b64url>.<hmac>`
  tickets on `config.secret_key`, open mode answers honestly.
- `IntegrationEvent` folds into the §19 chain as the **eleventh** source
  `integration`; connector state aggregates at `GET /integrations/status`
  (Settings cards, Compliance SIEM chip, Break-Glass MFA field all read it).

### 4.14 UEBA behavior baselines + anomaly chain (§11) - Phase 4j
- **Baselines** (`behavior_baselines`) are learned only from real history
  rows - `risk_events`, `privileged_sessions`, `session_events` (type
  `command`) and `command_incidents` inside a 30-day rolling window - and
  store the principal's hours, devices, source IPs, targets, command and
  privilege verbs, protocols and session cadence with the sample counts
  behind them. Training is explicit (`POST /risk/baselines/train`, the
  Policy screen's Train button); an unseen principal gets no baseline, a
  truncated dimension (>128 distinct values) stops claiming deviation, and
  evaluations only ever diff against the stored profile.
- **Scoring**: the §7 `behavior` component keeps its local 24h counts and
  gains `RISK_ANOMALY_POINTS` (5) per named deviation - unusual
  time/device/IP/target/command/privilege, listed verbatim in the
  component's `reasons` - so behavior can reach 45 and the total clamps
  at 100 (the detail names the measured sum when it does). With no stored
  baseline nothing changes: byte-identical component details.
- **Response chain**: a CRITICAL refusal whose behavior component carries
  deviations runs block → rotate → alert → incident for real inside
  `create_session` - the start is refused (403, `details.risk`), every
  other active session of that principal ends through the
  release-and-rotate cascade, the credential the request sought is
  rotated through the §5 pipeline (`item_id`) or the target's items
  (`_force_target_rotation`), and an `AnomalyEvent` row commits with the
  reasons + actions (`details.anomaly`). It folds into the §19 ledger
  under the existing `risk` source (`anomaly-incident`, ref `anom:<id>`),
  so the source count stays 11; console evaluations stay advisory and
  never chain. Endpoints: `GET /risk/baselines`, `POST
  /risk/baselines/train` (admin), `GET /risk/anomalies`.

### 4.15 Dynamic watermark overlay (§12) - Phase 4k
- **Payload**: `GET /api/v1/sessions/{session_id}` gains an additive
  `watermark` object (`SessionWatermark` schema) assembled only from the
  session's own rows - `user` (actor), `session` (custody ref), `target`,
  `time` (`dd-Mon-yyyy HH:MM`, built locale-independently, of the latest
  recorded event so it moves when the session does and freezes when it
  ends), `ticket` (the linked JIT grant's ITSM reference, else null) and
  `source` (the address recorded at start - a nullable
  `privileged_sessions.source_ip` column added through `ensure_schema`, so
  pre-4k rows render an em dash, never a guess). `state` mirrors the
  session status that pause/resume/terminate move, `enabled` mirrors the
  watermark control, and `text` is the rendered six-line
  `USER/SESSION/TARGET/TIME/TICKET/SOURCE` overlay - null while the
  control is off, exactly like the per-event custody strings shipped in
  4c. The list view stays lean: the payload rides the detail response
  only.
- **Delivery**: the Live Session Hub detail pane renders the overlay from
  that real payload and reacts to pause/resume/terminate through the
  screen's existing load cycle; every recorded event row carries its
  custody watermark line. Protocol-level overlays (actual
  RDP/VNC/browser/DB/SSH/file-transfer pixels) stay gateway-dependent
  (§27) and the pane labels them `not connected` until that work lands.

## 5. API conventions

| Concern | Rule |
|---|---|
| Versioning | Everything under `/api/v1` (health/meta unversioned) |
| Auth | `LICENSE_ADMIN_TOKEN` set → `Authorization: Bearer …` or `X-Admin-Token` on the 49 admin operations; unset → explicit open dev mode (`X-Auth-Mode: open` response header) |
| Actor | `X-Actor` header recorded on every audited write |
| Errors | `{"error": {"code", "message", "details?"}}`; 400 validation, 401 auth, 403 policy refusal, 404, 409 conflict/state, 422 shape, 503 fail-closed dependency |
| Pagination | `limit` (max 200) + `offset`, newest first |
| Contract | `apis/openapi.yaml` is the source of truth; `test_openapi_contract.py` fails if routes ⇄ document ⇄ `ADMIN_OPERATIONS` ⇄ tests disagree |

## 6. Configuration (environment)

Shipped server (`backend/phase2_license_server`, `.env` supported):

| Variable | Default | Purpose |
|---|---|---|
| `LICENSE_DATABASE_URI` | `sqlite:///licenses.db` | DB location |
| `LICENSE_PRIVATE_KEY_PATH` / `LICENSE_PUBLIC_KEY_PATH` | repo-root PEMs | RSA-PSS envelope keys |
| `LICENSE_ED25519_PRIVATE_KEY_PATH` / `LICENSE_ED25519_PUBLIC_KEY_PATH` | repo-root PEMs | Ed25519 keys |
| `LICENSE_SECRET_KEY` | dev value + warning | Flask secret |
| `LICENSE_ADMIN_TOKEN` | unset (= open dev mode) | admin auth |
| `LICENSE_AUTOGENERATE_KEYS` | off | first-boot key creation |
| `LICENSE_DEFAULT_TRIAL_DAYS` | — | trial license default |
| `VAULT_KEY_PATH` | `vault.key` | AES-256-GCM master key |
| `VAULT_AUTOGENERATE_KEY` | off | create vault key once |
| `ROTATION_SCHEDULER` / `ROTATION_SCHEDULER_INTERVAL_SECONDS` | off / 3600 | background rotation |
| `LICENSE_SERVER_HOST` / `LICENSE_SERVER_PORT` / `LICENSE_SERVER_DEBUG` | `127.0.0.1` / `5000` / off | dev server |

Vendor tool (`pam_master`): `MASTER_DATABASE_URI`, `MASTER_RSA_PRIVATE_KEY_PATH`,
`MASTER_ED25519_PRIVATE_KEY_PATH`, `MASTER_CUSTOMER_KEY_PATH`,
`MASTER_CUSTOMER_KEY_B64`, `MASTER_SERVER_PORT` (5400), `MASTER_BIND`
(127.0.0.1).

## 7. Key trade-offs & constraints (accepted today)

1. **SQLite single-writer** — fine for one appliance node; §18 HA is out of
   scope. Journal mode + short transactions keep the ledger consistent.
2. **Naive datetimes stored local-time** — tests anchor the clock by patching
   module `datetime` in *both* the service and models modules (lesson from
   4f: column defaults bind their `datetime` at import).
3. **No geo-IP feed** — `location` component honestly uses `is_global` only.
4. **Settings are schema-only** — SSO/MFA/HSM not enforced; the posture
   widget counts them as not-active, never as "enabled".
5. **Frontend is static** — no framework build step; screens tolerate the
   backend being down (`file://` → disabled controls + `—`), which doubles as
   the honesty fallback.

## 8. Testing architecture

See `TESTING_QA_STRATEGY.md`. Design points that matter for implementation:
tests use `admin_token="test-admin-token"` + `X-Actor: tester`; fixtures
create real rows through service functions (no mocked domain data); contract
tests import the app and enumerate Flask routes to diff against OpenAPI.

## 9. Planned designs (pending modules — see `IMPLEMENTATION_PLAN.md`)

Target designs for the unbuilt sections; each becomes normative only when
its phase starts (plan > code > docs, in that order).

| Phase / section | Data additions | API additions | Runtime behavior |
|---|---|---|---|
| 5a §13 Vendor PAM | `vendor_accounts`, vendor scoping | vendor lifecycle endpoints over existing JIT | invite→MFA→NDA→ticket→approval→JIT→record→expiry |
| 5b §14 Cloud | `cloud_connectors` | connector CRUD + cloud discovery extension | real inventory/cloud grants only when credentials configured |
| 5c §15 DevSecOps | broker policy rows | `POST /broker/credentials` | time-boxed pipeline credentials (JIT semantics), no static CI secrets |
| 5d §16 AI-Agent | `agent_identities`, task scopes | agent request endpoints + task-scoped rule evaluation | identity → task → risk → JIT → restricted commands → expiry |
| 6a §18 HA | replication/failover topology | health/failover endpoints | multi-node; storage engine decision = core design item |
| 6b RBAC | `roles`, `role_bindings` | security schemes gain role requirements | attribute checks on the 49 admin ops + vault/target scoping |
| 6c SSO/HSM | SSO/HSM config state | SAML/OIDC login path, PKCS#11/KMS key ops | settings schema becomes enforcement; posture counts flip honestly |

Standing constraints that carry into all of these: ledger emission inside
the same transaction, contract lockstep in one commit, additive-only schema,
`file://` honest fallback, and **configured-or-`not connected`** for every
external dependency (no simulated integrations).
