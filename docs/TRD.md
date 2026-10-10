# VY-PAM — Technical Requirements & Design Document (TRD)

**Status:** as-built for Phase 6a
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
| Frontend | Static HTML + Tailwind (CDN build) + vanilla JS | 11 sidebar screens, no bundler, works from `file://` |
| Tests | pytest | 577 backend + 46 pam_master |
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
  (eleven with 4i's `integration`, twelve with 5a's `vendor`, thirteen with
  5b's `cloud`, fourteen with 5c's `broker`, fifteen with 5d's `agent`, sixteen with 6a's `cluster`);
  `bg-` request refs, stats and the
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

### 4.16 Third-party / vendor PAM (§13) — Phase 5a
- **Data**: `vendor_accounts` (unique `name`, status
  `invited|approved|denied|revoked|expired`, per-step timestamp columns for
  MFA/NDA/ticket/approval, `allowed_targets`/`denied_targets` JSON, nullable
  `window_start`/`window_end` daily window `HH:MM`, `recording`, lazy
  `expires_at`) + `vendor_events` (module log folded into the ledger as
  source `vendor`, the twelfth); `jit_requests` gains an indexed nullable
  `vendor_account_id` added through `ensure_schema`.
- **Chain**: invite seals a fresh TOTP seed (AES-256-GCM, AAD
  `vendor:{id}:mfa_secret`) and returns seed + otpauth URI exactly once;
  MFA verifies real RFC-6238 over it (a wrong code is refused + recorded,
  the code itself never lands); NDA records acceptance + timestamp; the
  ticket step is a real §20 ITSM HTTP GET (unconfigured → 409 honest
  refusal, never a simulated pass); approval refuses 409 with
  `details.missing` naming the outstanding steps — the chain cannot be
  short-cut. Deny/revoke are recorded verbatim, revoke closes every active
  grant through the normal JIT path (rotate + end sessions), and
  denied/revoked/expired names may be re-invited on the same row.
- **Access**: `POST /vendors/{id}/requests` delegates to
  `create_jit_request` after the scope gate — status must be `approved`,
  the target inside the allow list and outside the deny list (deny beats
  allow) and now inside the valid window; every refusal is 403
  `Vendor access refused` plus a `vendor` trail event, and the ITSM ticket
  defaults to the vendor's verified one. Vendor sessions start with
  `controls.record = true` regardless of caller flags; the lazy refresh
  marks past-`expires_at` rows `expired`.
- **Console**: the 11th sidebar screen
  `vendor_access_third_party_lifecycle` renders the section-13 dashboard
  (access/denied lists, `14:00–16:00`-style window, recording flag) from
  the account's own row, the 8-step chain with its actions, the invite
  modal with the one-time seed reveal, the vendor's JIT requests and
  lifecycle trail; Compliance gains the 13th chip (source `vendor`).

### 4.17 Cloud PAM (§14) — Phase 5b
- **Data**: `cloud_connectors` (unique `name`, provider
  `aws|azure|gcp|kubernetes`, `account_ref`/`endpoint`/`regions`/`services`,
  nullable `credential_item_id` pointing at the vault item — secret material
  never in the row, honest `status`, `last_test_at`/`last_test_detail`) +
  `cloud_events` (module log folded into the ledger as source `cloud`, the
  thirteenth); `jit_requests` gains an indexed nullable
  `cloud_connector_id` and a `cloud_binding` JSON column, both added through
  `ensure_schema`.
- **Chain**: connector status is honest state — `not connected` (no
  endpoint), `configured` (endpoint, never probed), `connected` (a real
  probe answered 2xx), `error` (probe failed, reason in
  `last_test_detail`); the endpoint must be `https` (`http` loopback-only
  for local development). The probe is a real GET carrying the vault
  credential (revealed per call, audited; the plaintext never appears in a
  response or event) and proves reachability plus the HTTP verdict only —
  never "credentials validated". Inventory requires endpoint + credential
  (409 honest refusal otherwise): the cloud's own API answers (`GET /` →
  `resources[]` for the clouds, `GET /api/v1/nodes` → `items[]` for
  Kubernetes), assets land as real `DiscoveryScan` rows under
  `source=cloud` with `method=CLOUD_METHODS[provider]`, and a failed or
  unrecognized answer records the honest reason and invents nothing.
- **Access**: the architecture's Kubernetes path *Kubernetes → RBAC → JIT →
  ephemeral privilege → audit* — `POST /cloud/connectors/{id}/rbac/requests`
  (kubernetes-only 409; role/namespace must be Kubernetes names; ticket
  required) delegates to the section-6 `create_jit_request` with risk
  scoring verbatim and tags `cloud_binding={namespace, role, binding:
  vypam-jit-<id>}`. Consuming the grant applies a real RoleBinding first
  (annotations `vypam.io/session-ref` / `vypam.io/expires-at`); a cluster
  refusal is 502 `Kubernetes refused the RBAC binding` + a
  `rbac-binding-failed` event with the request left `approved`; a checkout
  failure after the apply removes the binding again (`rbac-aborted`); close
  and lazy expiry remove the binding before ending the grant
  (`rbac-closed` / `rbac-expired`) and a failed removal is recorded, never
  hidden. Connectors refuse deletion (409) while open grants ride them; the
  trail stays after removal.
- **Console**: the Target Infrastructure screen gains the live Cloud PAM
  Connectors section (provider cards AWS/Azure/GCP/Kubernetes with honest
  states, connector table with probe / inventory / RBAC / add actions,
  `file://` falls back to dashes); Compliance gains the 14th chip (source
  `cloud`).

### 4.18 CI/CD credential broker (§15) — Phase 5c
- **Data**: `broker_policies` (unique `name`, `ci_system` from the §15
  surface `jenkins|gitlab|github|azure_devops|terraform|ansible|argocd|
  docker|other`, `approval_mode` `manual` (default) `|auto`,
  `max_ttl_minutes` 1–480 cap, `allowed_targets` JSON scope, `token_hash`
  sha256, honest `status`/`expires_at`/`last_used_at`/`use_count`) +
  `broker_credentials` (`policy_id` + `item_id`, reason/ticket/window,
  `build_ref`, `status pending|approved|released|denied|closed|expired`,
  `released_version`/`expires_at`/`session_ref broker-<id>`) +
  `broker_events` folded into the ledger as source `broker`, the
  **fourteenth**.
- **Identity**: the pipeline's API token is `vypam-ci1.<id>.<secret>`
  (`secrets.token_urlsafe(32)`), shown exactly once at creation and stored
  only as its sha256 hash; `verify_broker_token` compares in constant time
  and refuses revoked/expired identities honestly, recording the use on
  the policy. Pipeline routes (`POST /broker/credentials`, `…/{id}/release`,
  the pipeline side of `…/{id}/close`) authenticate with this token alone —
  the admin token never substitutes, open dev mode never waives it, and
  `X-Actor` is ignored (the actor on the trail is the policy name).
  `close` is dual-auth: `Authorization: Bearer vypam-ci1.…` or
  `X-Broker-Token` → pipeline (own rows only), otherwise the admin check.
- **Chain**: request → the policy decides (`auto` grants inline, `manual`
  queues for an admin approval) → release is a real vault checkout under
  the pipeline's name with the decrypted secret in that one response only
  → the window expires on the real clock (lazy refresh on every read), and
  close/expiry release the checkout and rotate the credential through the
  §5 pipeline (`session_end` trigger, `session_ref broker-<id>`), exactly
  like a JIT grant. Refusals are honest and evidenced: TTL above the
  policy cap → 400 `details.cap`, target outside `allowed_targets` → 403
  with a `refused` event on the trail, another pipeline's credential → 404,
  an `auto` release whose item is already checked out → 400 with the
  request left `approved`. Revoking a policy closes its open credentials
  first (released ones rotate), then the token stops authenticating.
- **Console**: the JIT Access screen gains the full-width Pipeline
  Credential Broker section (policy table with one-time token reveal at
  registration, credential queue with approve / deny / close, real stat
  tiles, `file://` falls back to dashes); Compliance gains the 15th chip
  (source `broker`).

### 4.19 AI-agent PAM (§16) — Phase 5d
- **Data**: `agent_identities` (unique `name`, `token_hash` sha256, honest
  `status active|disabled|revoked`, `max_ttl_minutes` 1–480 identity cap
  default 15, `last_used_at`/`use_count` — no standing expiry) +
  `agent_task_scopes` (per-agent unique `name`, `allowed_commands` JSON
  exhaustive allow-list of 1–32 literal substrings, `allowed_targets` exact
  scope with empty = any, `max_minutes` window cap default 5) +
  `agent_events` folded into the ledger as source `agent`, the
  **fifteenth**.
- **Identity**: the agent's API token is `vypam-agt1.<id>.<secret>`, shown
  exactly once at creation and stored only as its sha256 hash;
  `verify_agent_token` compares in constant time and refuses
  disabled/revoked identities honestly, recording the use on the identity.
  Agent routes (`POST /agent-access/requests`, `…/{id}/open`, the agent
  side of `…/{id}/close`) authenticate with this token alone
  (`X-Agent-Token` or Bearer) — the admin token never substitutes, open
  dev mode never waives it, and `X-Actor` is ignored (the actor on the
  trail is the agent's own name). `close` is dual-auth: the agent's own
  token or the admin check.
- **Chain**: request → identity verified → task verified (unknown task or
  target outside `allowed_targets` → 403 with the refusal on the trail;
  window above min(task, identity) cap → 400 `details.cap`) → §7 risk
  scoring (low lands `approved` with the `agent_binding`
  `{agent_id, agent_name, task_id, task}` snapshot, medium/high queue for
  their band's sign-offs on the normal §6 endpoints, critical lands
  `blocked` with `access-refused`) → `open` consumes the grant: a real
  vault checkout under the agent plus a **forced recorded session**, so
  every command is judged by the task's allow-list — §9 blocks still veto,
  an allow-listed command supersedes §9 approval holds (the declaration is
  the pre-authorization), anything outside the list → incident
  `agent task scope: <task>` + session terminated + `command-blocked`
  event + release and rotate. The window expires on the real clock like
  any JIT grant. Revoking an identity closes its open access first (active
  grants release and rotate), then the token stops authenticating (401); a
  revoked identity's settings and task scopes are frozen (409).
- **Console**: the JIT Access screen gains the full-width AI-Agent Access
  section (identity table with one-time token reveal at registration, task
  declaration modal, access queue wired to approve / deny / close, real
  stat tiles, `file://` falls back to dashes); Compliance gains the 16th
  chip (source `agent`) and its action labels.

### 4.20 HA / DC / DR (§18) - Phase 6a

- **Data**: `cluster_nodes` (registry: unique name, `dc`/`dr` site,
  `active`/`passive` role, base URL, honest `health`
  `unknown|healthy|degraded|unreachable`, last probe/error/failure count) +
  `cluster_events` (topology trail → ledger source `cluster`) +
  `cluster_audit_replicas` / `cluster_secret_replicas` /
  `cluster_session_replicas` (pulled evidence keyed per peer - never
  merged) + `cluster_backups` (verified copies). Tables **38→44**.
- **Self identity**: `PAM_NODE_NAME` / `PAM_SITE` name this node; startup
  registers the row once (no ledger event) and a restart never resets its
  role. `/health` answers with `node`/`site`/`role` so peers can identify
  each other.
- **Probes**: `POST /cluster/nodes/{id}/probe` performs a real
  `GET {base}/health` (5 s timeout): peer identity, latency, error
  verbatim; the trail records health **state changes** only. Registration
  implies nothing - health starts `unknown`.
- **Replication (pull)**: `POST /cluster/nodes/{id}/sync` pulls the peer's
  `/audit/export` NDJSON and re-hashes every record here (transitive trust
  through this node's own verified chain; a break stores the rest as
  `verified: false` and the response reports `first_break_seq`), its
  sealed vault ciphertext (`plaintext_here` only after a successful
  decrypt under this node's key), and session metadata. Replicas live
  under `node_id` as DR evidence; a sync from yourself is 400 and a
  transport failure is reported verbatim, keeping whatever kinds already
  applied.
- **Passive gate**: while `role=passive`, `_passive_node_gate` refuses
  every POST/PUT/PATCH/DELETE outside `/api/v1/cluster/*` and
  `/api/v1/auth/*` with 409 *before* auth runs (`details.promote` names
  the way back) - reads and cluster operations stay available for failback.
- **Failover**: `POST /cluster/failover {action: promote|demote}` flips
  the role (already there → 409) with `from`/`to` on the trail. The
  opt-in `CLUSTER_MONITOR` thread (and `POST /cluster/monitor/tick`)
  probes every registered active peer while passive and promotes only
  after **3** consecutive failures *and* all of them failed; an active
  node never auto-demotes - failback is an operator decision.
- **Backups**: `POST /cluster/backups` copies the live SQLite database
  through the online backup API into `CLUSTER_BACKUP_DIR`
  (`pam-backup-<ts>-seq<N>.db`), records sha256 + audit seq, then re-opens
  the copy read-only and re-walks its chain before answering 201; a
  non-SQLite engine answers 503 honestly.

## 5. API conventions

| Concern | Rule |
|---|---|
| Versioning | Everything under `/api/v1` (health/meta unversioned) |
| Auth | `LICENSE_ADMIN_TOKEN` set → `Authorization: Bearer …` or `X-Admin-Token: …` on the 101 admin operations; unset → explicit open dev mode (`X-Auth-Mode: open` response header); pipeline `/broker` operations require the broker API token and AI-agent `/agent-access` operations the agent API token — neither is ever waived |
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
| `PAM_NODE_NAME` / `PAM_SITE` | `pam-node-1` / `dc` | §18 self identity (`site` is `dc` or `dr`); the registry row is created at startup, its role never reset by a restart |
| `CLUSTER_MONITOR` / `CLUSTER_MONITOR_INTERVAL_SECONDS` | off / 60 | opt-in auto-failover monitor thread (tick interval, minimum 5 s) |
| `CLUSTER_BACKUP_DIR` | `backend/phase2_license_server/backups` | where `POST /api/v1/cluster/backups` writes its verified SQLite copies |
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
| 6b RBAC | `roles`, `role_bindings` | security schemes gain role requirements | attribute checks on the 101 admin ops + vault/target scoping |
| 6c SSO/HSM | SSO/HSM config state | SAML/OIDC login path, PKCS#11/KMS key ops | settings schema becomes enforcement; posture counts flip honestly |

Standing constraints that carry into all of these: ledger emission inside
the same transaction, contract lockstep in one commit, additive-only schema,
`file://` honest fallback, and **configured-or-`not connected`** for every
external dependency (no simulated integrations).
