# VY-PAM MASTER + VY-PAM — Product Split, Plan & Workflows

> Companion to `VY-PAM_Enterprise_PAM_Architecture.md` (which remains the
> authoritative requirements for the **PAM product itself** — the "last goal").
> This document defines the **commercial split**: two tools, one platform.

---

## 1. The two products

| | **VY-PAM MASTER** (vendor tool) | **VY-PAM** (shipped product) |
|---|---|---|
| Runs at | VY-Groups only, never shipped | Customer site (on-prem / hybrid / air-gapped) |
| Purpose | Run the business: customers, deals, **license generation**, entitlement catalog, renewals | Operate PAM: discovery → vault → rotation → JIT → sessions → command → audit |
| Data | Customer registry, contacts, quotes, issued-license archive, usage archives (encrypted at rest) | That customer's own assets/accounts/sessions/audit only |
| Keys | **Holds `license_private_key.pem`** — custody never leaves it | Only `license_public_key.pem` for offline verification |
| Issues licenses? | ✅ Yes — its only way to create them | ❌ Never |
| Validates licenses? | Creates + signs | ✅ Offline verify of its own license |
| Audience | Sales / ops staff (internal) | Security & infra teams (customers of every size) |

**Rule of thumb:** if a screen shows *other customers* or *issues a license*,
it belongs to PAM-MASTER. If it shows *infrastructure being protected*, it
belongs to VY-PAM.

---

## 2. Architecture — components & artifacts

```mermaid
flowchart LR
    subgraph VY["VY-Groups (vendor)"]
        subgraph MASTER["VY-PAM MASTER — internal tool, never shipped"]
            UI1["MASTER console<br/>(customers / licenses / renewals)"]
            CRM["Customer registry<br/>(encrypted PII)"]
            ENG["License engine<br/>(sign: RSA-PSS / Ed25519)"]
            KV["Key vault<br/>license_private_key.pem"]
            AUD["Issuance audit trail"]
        end
    end

    subgraph CUST["Customer site (any size, incl. air-gapped)"]
        subgraph PAM["VY-PAM — shipped product"]
            UI2["PAM console<br/>(10 modules)"]
            ENT["Entitlement screen<br/>(validate + quotas)"]
            RUN["PAM runtime<br/>Discovery→Vault→…→Audit"]
            PU["Local usage counters"]
        end
        PK["license_public_key.pem"]
        LIC["License artifact<br/>(file / JWS)"]
    end

    UI1 --> CRM --> ENG
    ENG --> KV
    ENG --> AUD
    ENG -->|"sign license"| LIC
    LIC -->|"delivered with package"| ENT
    PK --> ENT
    ENT -->|"gates modules / quotas"| RUN
    PU -->|"optional signed usage export"| ENG
```

Deliverable bundle to a customer = **package + license file + public key +
docs**. Nothing else crosses the boundary.

---

## 3. Vendor workflow — you as the sales/ops side (PAM-MASTER)

```mermaid
sequenceDiagram
    autonumber
    actor S as VY sales/ops
    participant M as VY-PAM MASTER
    participant K as Key vault
    actor C as Customer

    S->>M: Create customer (name, region, contact)
    M->>M: Store PII encrypted at rest
    S->>M: Choose deal: tier, modules, node/session quotas, validity
    M->>K: Sign license payload (private key never leaves vault)
    K-->>M: license_data + signature (JSON envelope or JWS)
    M->>M: Archive issued license + audit event
    M-->>S: Delivery bundle (license file, public key, checksums)
    S->>C: Hand over package + license
    Note over M,C: Renewal / upgrade = new signed license,<br/>same customer record, history kept
```

---

## 4. Customer journey — you as the customer (VY-PAM)

```mermaid
flowchart TD
    A["1. Buy / choose tier<br/>(all sizes: SMB → enterprise)"] --> B["2. Receive bundle:<br/>package + license + public key"]
    B --> C["3. Deploy on-prem or hybrid<br/>(file works fully air-gapped)"]
    C --> D["4. Activate license<br/>offline verify against public key"]
    D --> E["5. Entitlement screen shows<br/>real modules, quotas, expiry"]
    E --> F["6. Operators sign in (SSO/MFA)"]
    F --> G["7. Run the PAM loop ↓"]
    subgraph G [Daily PAM operation — from architecture doc]
        H["Discover → Classify → Risk"] --> I["Recommend policy → Onboard to Vault"]
        I --> J["Rotate credentials"]
        J --> K["JIT approvals & sessions"]
        K --> L["Record & watch sessions"]
        L --> M["Command Center + Compliance evidence"]
        M --> N["Immutable audit trail"]
    end
    G --> O["8. Watch local usage counters<br/>stay inside quotas"]
    O --> P{"Renewal / upgrade?"}
    P -->|yes| Q["Receive new license from VY<br/>swap file → continue, data intact"]
    P -->|no| R["Keep running until expiry"]
    Q --> E
```

**What the customer never sees:** license issuing, private keys, the customer
registry, or any other customer's data.

---

## 5. License activation & lifecycle (sequence)

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Customer admin
    participant P as VY-PAM console
    participant V as PAM verify module
    participant F as license file (offline)

    Admin->>P: Import license file (or JWS)
    P->>V: verify(license_data, signature, public key)
    alt signature / expiry / tamper invalid
        V-->>P: reject + honest error
        P-->>Admin: entitlements locked, modules gated off
    else valid
        V-->>P: tiers, modules, quotas, expiry
        P-->>Admin: Entitlement screen: what you own, what is used
    end
    Note over P,F: Fully offline — no callback to VY required.<br/>Usage counters stay local; optional signed export for VY.
```

---

## 6. PAM internal operating workflow (the shipped product = architecture doc)

```mermaid
flowchart LR
    subgraph core["VY-PAM module loop (VY-PAM_Enterprise_PAM_Architecture.md)"]
        D["3. Discovery Engine<br/>assets/accounts/risk"] --> V["4. Credential Vault"]
        V --> R["5. Rotation"]
        R --> J["6. JIT Access"]
        J --> S["8. Sessions & recording"]
        S --> C["9. Command Center"]
        C --> A["19. Audit / Compliance"]
        A -.->|"evidence & violations"| D
    end
    LIC["Entitlement (license)"] -.->|"gates modules & quotas"| core
```

---

## 7. Phase-wise plan (resumable — checkpoints survive interruptions)

**Working decisions (confirmed):** PAM-MASTER starts as `pam_master/` in this
repo (own app, own API spec, own tests), designed to extract into its own
repo later. Docker is **development-only** (local DB/test environments); the
shipped product installs directly on customer systems — no VM or Docker
required. `backend/ipam_licensing` stays the shared crypto engine (MASTER
signs with it, PAM verifies with it).

> **RESUME RULE:** after any interruption, read the checkpoint below, verify
> it with the listed command, and continue from the first ☐. Never redo a ✅
> phase; re-run its verification instead.

### Phase 1 — Discovery Engine (module 3 of the architecture doc)
- ☑ **1a** Backend: models (`discovered_assets/accounts/scans/events`), rules
  v1 (`BASE_RISK`, `RECOMMENDED_POLICY`, secret-type map, account taxonomy)
  in `backend/phase2_license_server/models.py`
- ☑ **1b** Service: real TCP-connect scanner + banner grab, classify, scope
  caps (256 hosts/24 ports, single-flight), onboard/adopt/patch/stats/lists,
  discovery events merged into `/api/v1/events` — `service.py`
- ☑ **1c** Routes + `apis/openapi.yaml` (8 operations, schemas, events enum,
  admin security) + contract test ADMIN_OPERATIONS — **verify:** `python -m pytest
  backend/phase2_license_server/tests/test_openapi_contract.py -q`
- ☑ **1d** Tests `tests/test_discovery.py` (19, incl. real listener scan) —
  **verify:** `python -m pytest backend -q` → 206 passed
- ☑ **1e** Live smoke (recreated) — **verify:** `python
  %LOCALAPPDATA%\Temp\opencode\smoke_restructure.py` → 17/17
- ☑ **1f** Plan doc `VY-PAM_MASTER_and_PAM_Workflow.md` (this file) +
  phase/checkpoint structure
- ☑ **1g** Wire screen `frontend/screens/target_infrastructure_connectors/`:
  honest static purge (tiles/pills/tabs/rows/probe-stream/mesh/discovery-panel)
  + real JS wiring (stats, assets, filters, search, pagination, scan modal,
  onboard modal, adopt/ignore, event feed) + honest toasts — plus suite-wide
  shared-chrome purge (sidebar ZSP card ×11, top header ×12: breadcrumb /
  attestation / audit-rate / notifications / identity, local logo asset ×11)
- ☑ **1h** Verify screen: `node --check` scripts, fake-data sweep HTTP +
  `file://` in `shots_tool/__verify_discovery.mjs` (58 checks: register,
  real scan, ignore/restore, adopt, probe, filters, feed) +
  `shots_tool/__verify_live.mjs` (28 checks across 4 API screens),
  screenshots recaptured via `shots_tool/__shots.mjs`, launcher badge → LIVE —
  **verify:** `python -m pytest backend -q` → 206 + smoke 17/17 + both node
  verifiers ALL CHECKS PASSED
- ☑ **1i** Commit + push (ephemeral token, verify not persisted) — `9f83bd3`
  pushed to `main`; no `ghp_` in git config, worktree, or history

### Phase 2 — VY-PAM MASTER (vendor tool, `pam_master/`)
- ☑ **2a** Skeleton: own Flask app + config (private key custody lives ONLY
  here), own test fixtures, dev Docker compose (dev-only) — **done:**
  `pam_master/` package (config, custody keys, licensing bridge, health,
  keygen CLI), 13-test suite (temp keys/db only), Dockerfile + compose,
  README with custody rules; live boot smoke honest (`rsa_key: present`,
  `ed25519_key: missing`, `ready: false` = this machine's real state)
  — **verify:** `python -m pytest pam_master -q` → 13 passed
- ☑ **2b** Customer registry: records with PII encrypted at rest, list/create/
  edit, issuance history — **done:** `registry.py` CRUD + validation,
  `crypto.py` AES-256-GCM bound to row `public_id`, `db.py` schema
  (customers + issuance_history), registry key custody (file/b64 env, honest
  503 without it), history write helper for 2c; README API table
  — **verify:** `python -m pytest pam_master -q` → 28 passed
- ☑ **2c** License generation: tier/modules/quotas/validity form → sign via
  `backend/ipam_licensing` → archive + audit trail + delivery bundle export
  (license file + public key + checksums); renewal/replace flow — **done:**
  `issuance.py` (options/issue/renew/list/get/bundle/audit), claims +
  signature via shared engine, encrypted archive (AAD = license_id),
  atomic license+history+audit write, renewal supersedes in-transaction,
  bundle verifies offline (SHA256SUMS + public key inside), shared
  `errors.py` failure types (400/404/409/500/503)
  — **verify:** `python -m pytest pam_master -q` → 40 passed
- ☑ **2d** Own `openapi.yaml` + contract tests; anti-mixing tests (no PAM
  runtime imports; private key absent from shipped surface) — **done:**
  `pam_master/openapi.yaml` (14 operations, strict request bodies, honest
  error-type enum, all response schemas), `tests/test_openapi_contract.py`
  (both-direction path coverage, live-shape checks, enums/ranges mirrored
  against code constants, git-tracked-file private-key scan), anti-mixing
  scan extended (`phase2_license_server` + `from backend.` / `import backend`)
  — **verify:** `python -m pytest pam_master -q` → 46 passed
- ☑ **2e** Docs + screenshots + commit/push — **done:** root README documents
  the two-product split (intro, tree entry, quick-start, custody bullet,
  test counts corrected to 206/46); `pam_master/README.md` complete
  (endpoints, custody rules, API contract). Screenshots: **none apply** —
  the MASTER is API-only, no UI exists in Phase 2 (console/screens
  screenshots return with the shipped side in 3c)
  — **verify (phase boundary):** `pytest backend` 206 + `pytest pam_master`
  46 + smoke 17/17 + both shots verifiers `ALL CHECKS PASSED`

### Phase 3 — Decouple the shipped PAM surface
- ☑ **3a** Self-issue removed from the shipped server: `POST /api/v1/licenses`
  is gone — the server only **verifies and records**, through the new
  `POST /api/v1/licenses/import` (admin token; 400 for malformed / foreign-key
  signed / expired / structurally invalid claims — the old issuing-form rules
  ported to claim-shape checks, claims stored byte-for-byte as signed, never
  normalised; 409 `Conflict` for an already-installed file). `service.issue_license`
  + its `_coerce_*` form helpers deleted, so **no shipped-server code touches a
  private key anymore**. Per decisions: revoke/restore + list/detail **stay** on
  PAM (local revocation-list authority for offline validation + the console's
  entitlement view); issuing/customer lookup live only in PAM-MASTER (2c).
  New `imported` event type (replaces `issued` in event assertions). Tests play
  the vendor: helpers sign with the shared engine then import.
- ☑ **3b** Re-scope `apis/openapi.yaml` + contract + tests — executed in
  lockstep with 3a (the two-directional contract test forbids an unserved
  documented route and an undocumented served one, so route removal, spec and
  test rewrites land together): POST `/licenses` → POST `/licenses/import`,
  `IssueLicenseRequest/Response` → `LicenseEnvelope` request +
  `ImportLicenseResponse`, new `Conflict` response, algorithm enums corrected
  to the real casing (`RSA-PSS-SHA256`/`Ed25519`), `ADMIN_OPERATIONS` updated;
  old form-validation tests rewritten as import rejection tests (+409, expired,
  foreign-signature, unusable-file cases), smoke reworked to sign vendor-side
  and import — **verify (phase boundary):** pytest backend **216** +
  pytest pam_master 46 + smoke 17/17 + both shots verifiers `ALL CHECKS PASSED`
- ☑ **3c** Docs/screens/launcher reflect the split — console rework: the
  `Renew / Upgrade Tier` issue form became `Import Vendor License` (file or
  paste → `POST /licenses/import`, signature verified, claims recorded as
  signed, re-download; `issue*` ids/JS renamed to `import*`); all issuing copy
  → import copy (subtitle, empty states, token note, account note, badge);
  launcher lines fixed; phase-2 server README re-scoped (intro, endpoint row,
  `### Issue` curl section → `### Import`, config notes, audit bullet, test
  counts 134/216); `apis/README` error list +409; frontend README checked —
  already accurate; license `screen.png` recaptured; stale :5000 dev server
  restarted on current code (`POST /licenses` → 405, `/licenses/import` → 400
  on empty body, discovery still honest); live UI check: modal opens, server
  refuses a malformed payload, dev registry untouched, no page errors —
  **verify (phase boundary):** pytest backend **216** + pytest pam_master
  **46** + smoke 17/17 + both shots verifiers `ALL CHECKS PASSED`

### Phase 4 — Continue `VY-PAM_Enterprise_PAM_Architecture.md` (the last goal)
- ☑ **4a** Rotation (5) → ☑ **4b** JIT (6) → ☑ **4c** Sessions (8) →
  ☑ **4d** Command Center hardening (9) → ☑ **4e** Audit (19) →
  ☑ **4f** Risk-Based Access Engine (7): `risk_events` scores every request
  over the eight components the doc names (user/device/asset/time/location/
  behavior/ticket/command — each read from a measured input: inventory
  lookup, live command policy, local clock, `ipaddress`, subject history,
  ITSM ticket shape), bands 0–25/26–50/51–75/76–100 drive
  allow/mfa/approval/block; `POST /risk/evaluate` + list + stats, joins the
  §19 ledger as the 8th source, session start is gated (HIGH needs an
  active JIT grant, CRITICAL is refused — 403 carries the breakdown), policy
  screen gains a Risk section → …
  module order per the architecture doc; each module = model + endpoints +
  openapi + tests + honest screen wiring, then commit/push.

### Checkpoint log (update at every phase boundary)
| Date | Stopped after | Resume from |
|---|---|---|
| 2026-10-06 | 1a–1f ✅ (206 tests, 17/17 smoke, plan doc) | **1g** (screen wiring) |
| 2026-10-06 | 1a–1h ✅ (206 tests, 17/17 smoke, 58+58 UI checks, 12 screenshots, launcher LIVE) | **1i** (commit + push) |
| 2026-10-06 | **Phase 1 complete ✅** (`9f83bd3` pushed: Discovery module + honest screen + chrome purge + shots_tool) | **Phase 2 / 2a** (`pam_master/` skeleton) |
| 2026-10-07 | **Phase 2a ✅** (`pam_master/` skeleton: 13 tests, live smoke honest; regression 206 + 17/17) | **2b** (customer registry, PII encrypted at rest) |
| 2026-10-07 | **Phase 2b ✅** (registry CRUD + PII AES-256-GCM at rest; 28 tests; live smoke: 201/list/PATCH/history + no plaintext in DB file) | **2c** (license generation + delivery bundle) |
| 2026-10-07 | **Phase 2c ✅** (issuance: signed claims, encrypted archive, renewal supersedes, offline-verifiable bundle, audit; 40 tests; live smoke: exact 90d/365d spans, sha256 match, tables 0→4) | **2d** (own `openapi.yaml` + contract/anti-mixing tests) |
| 2026-10-07 | **Phase 2d ✅** (own `openapi.yaml` + contract both ways + live shapes + enum mirrors + tracked-key scan + extended anti-mixing; 46 tests) | **2e** (docs + phase close + commit/push) |
| 2026-10-07 | **Phase 2 complete ✅** (PAM-MASTER vendor tool: key custody, PII-encrypted registry, signed issuance/renewal/bundle/audit, own contract — 46 tests; root README split docs; full boundary regression green) | **Phase 3** (decouple shipped PAM surface — **3a**) |
| 2026-10-07 | **Phase 3a+3b ✅** (self-issue removed → vendor-signed `POST /licenses/import`; form rules → claim-shape checks; no server code signs anymore; openapi/contract/tests/smoke lockstep; backend 216, pam_master 46, smoke 17/17, verifiers green) | **3c** (docs/screens/launcher reflect the split) |
| 2026-10-07 | **Phase 3 complete ✅** (console ISSUE → vendor-import flow; launcher + phase-2/apis docs honest; screen recaptured; dev server restarted on current code; backend **216**, pam_master **46**, smoke 17/17, verifiers green, live UI check: modal/error path + registry untouched) | **Phase 4 / 4a** (Rotation (5)) |
| 2026-10-07 | **Phase 4a ✅** (real encrypted secrets: AES-256-GCM at rest, AAD-bound, `vault_secret_versions` history, admin reveal, per-type generation; rotation pipeline in architecture order mint+seal → same-target dependents → decrypt round-trip validation → audit, triggers manual/bulk/session-end/scheduler, failed→retry, 503 key custody; openapi + contract + 30 new tests lockstep; vault screen reveal/copy/bulk/onboard wired honestly, screen recaptured; backend **246**, pam_master **46**, smoke 17/17, both verifiers `ALL CHECKS PASSED`, live UI 8/8) | **4b** (JIT (6)) |
| 2026-10-07 | **Phase 4b ✅** (JIT/JEA: `jit_requests`+`jit_events`, deterministic risk over tier/duration/off-hours/24h-repeat/ticket-shape/credential-health with visible factor points, bands low auto → medium manager → high +security → critical blocked, self-approval 403, grant = real checkout `session_ref=jit-<id>` with `expires_at`, expiry lazy on read + scheduler tick releases and rotates `trigger=session_end`; 8 endpoints + openapi/contract/ADMIN_OPERATIONS lockstep + 18 tests; JIT screen fully live — queue tabs, real stat cards, request modal, approve/deny/issue/close via API, detail pane (risk factors, quorum stepper, live state check) rebuilt from responses, fabricated footer/design values purged, verify_live sweeps 5 screens, screen recaptured; backend **264**, pam_master **46**, smoke 17/17, both verifiers `ALL CHECKS PASSED`, JIT live UI **49/49**) | **4c** (Sessions (8)) |
| 2026-10-07 | **Phase 4c ✅** (privileged sessions: `privileged_sessions` + append-only `session_events`, start against a vault credential (real checkout) or an active JIT grant (one live session per grant → 409), events carry `seq`/custody watermark/actor, controls gate for real — typed content while `record=false` → 403, gated channels store `allowed=false` + reason as kept evidence, `keystroke_log=false` stores null content + `withheld`; pause/lock refuse events (409) until resume, terminate/complete run the cascade — linked grant closes together, own checkout releases, credential rotates exactly once, lazy grant expiry ends sessions `grant_expired`; 12 endpoints + openapi (**49 paths**)/contract/ADMIN_OPERATIONS lockstep + 23 tests; session hub screen fully live — Start Session modal (13 protocols, credential select, control flags), real cards/tabs/stats, terminal replay with blocked boxes + withheld rows, Control Violations panel, governance (access source/quorum/flags), kill modal shows the real `sess-*` ref, archived filter; verify_live sweeps 6 screens with the 4c design-value FORBIDDEN set, screen recaptured 1920×1600; fixed a time-of-day-dependent ipam expiry test (fixed clock); backend **287**, pam_master **46**, smoke 17/17, both verifiers `ALL CHECKS PASSED`, session live UI **65/65**) | **4d** (Command Center hardening (9)) |
| 2026-10-07 | **Phase 4d ✅** (command control (9): `command_rules` + `command_incidents`, `session_events` gains `decision`/`rule_id`/`ref_seq`, default-allow engine — case-insensitive substring match + case-insensitive fnmatch target glob, evaluation order block → approval → allow (scoped first, longest pattern, lowest id), shipped §9 policy seeds 15 rules once into an empty table so a deletion sticks, held commands resolve append-only (`type=approval` rows referencing `ref_seq`, hold never edited), a scoped block with `terminate_on_match` ends the session through the release-and-rotate cascade and preserves the evidence as an `inc-<hex>` incident (close records who/when/note, second close 409); 12 endpoints / 10 path keys + openapi (**59 paths**)/contract/ADMIN_OPERATIONS (**36**) lockstep + 18 tests; policy screen fully live — header `POLICY: <n> rules · <engine_hash>`, real stat cards (enabled ratio, intercepts today, approvals, by-action split + sync provenance), 15 rule cards with create/edit/delete via modal, dry-run simulator (block/escalation/approval/default-allow verdicts naming the matched rule), approval queue resolve, incident lifecycle, sidebar ZSP chip follows live state, frozen design values purged; verify_live sweeps 7 screens with the 4d FORBIDDEN set, launcher cards honest (JIT/session-hub/policy now LIVE + header prose counts nine), screen recaptured 1920×1600; backend **305**, pam_master **46**, smoke 17/17, all verifiers `ALL CHECKS PASSED`, policy live UI **71/71**) | **4e** (Audit (19)) |
| 2026-10-08 | **Phase 4e ✅** (immutable audit ledger (19): `audit_events` hash chain — `seq`/`prev_hash`/`event_hash`, sha256 over the canonical record (genesis `0`×64), a SQLAlchemy `before_flush` listener fans all seven module trails in (license, settings, vault, discovery, JIT, session lifecycle, command — plus incident rows, explicit `incident-closed:` records, and reveals that log who/what/never the secret; channel content stays in the recording), SQLite triggers refuse `UPDATE`/`DELETE` (`audit_events is append-only (architecture 19)`), first boot backfills pre-existing history exactly once (idempotent), `/audit/verify` walks every record and reports the first break (sequence gap / content mismatch / re-link), `/audit/export` streams the chain as NDJSON; 3 endpoints / 3 path keys + openapi (**62 paths**)/contract/ADMIN_OPERATIONS (**36**) lockstep + 19 tests; overview `counters.total_events` now counts the ledger; compliance screen live — digest card (chain head SHA-256 + `seq` + depth, honest ISO-8601/hash-bound + append-only-SQLite rows, append-only badge), header button relabelled **Verify Hash Chain** and wired click-only to the real walk (records `Last Verify: 23/23 ok just now`), 7-source filter chips (click-to-fetch), probe rows carry `#seq` + truncated hash, CSV export rebuilt from the full ledger with chain columns, new NDJSON SIEM export button; verify_live 7 screens + discovery verifier `ALL CHECKS PASSED`, compliance live UI **36/36**, previews refreshed (compliance + policy recaptured 1920×1600); backend **324**, pam_master **46**, smoke 17/17; dev DB seeded only through the public API — **23** real records across all seven sources, chain verify 23/23 intact) | **4f** (next module per `VY-PAM_Enterprise_PAM_Architecture.md` — candidates: §7 risk engine, §10 bypass detection, §20 integrations) |
| 2026-10-08 | **Phase 4f ✅** (risk-based access engine (7): `risk_events` — the eight components the doc names, each with an honest detail and caps summing to exactly 100 (user ≤10 = 5 per prior critical in 24h, device ≤15 unknown to the discovered inventory, asset ≤30 `CRITICAL`25/`HIGH`20/`MEDIUM`10/`LOW`0 + 5 `unmanaged`, time ≤10 from the real local clock off-hours/weekend, location ≤5 when `ipaddress` says global — no geo feed claimed, behavior ≤15 = 10 blocked commands + 5 denied JITs in 24h, ticket ≤5 non-ITSM shape, command ≤10 `block`/≤5 `approval` via the live §9 engine); bands ≤25 allow / ≤50 mfa / ≤75 approval / else block; `POST /risk/evaluate` always advises and commits its row, the **session-start gate** in `POST /sessions` scores with `context=session_start` first (refusal kept as SOC evidence) then refuses critical outright / high without an active JIT grant → 403 + `details.risk`, `POST /sessions` response carries `risk` (+ optional `device` scored at start); 3 endpoints / 3 path keys + openapi (**65 paths**)/contract/ADMIN_OPERATIONS (**37**) lockstep + **19** tests; ledger joins the 8th source `risk` (`_map_risk_evaluation`: action = decision, ref `risk:<id>`, detail carries score/band/result/context/components), compliance filter chips 8→9 (8 sources incl. `risk`, labels + `speed` icon); policy screen gains the §7 section (4 stat tiles, score-on-click form → result + eight-component breakdown, spec band legend with caps, newest-first evaluations, enforcement note; file:// = dashes) wired by its own gated IIFE, compliance recaptured with the risk trail selected; test-fixture lesson recorded: history rows carry the bound real `datetime.now`, so the night-clock fixture must anchor **in the past** (Saturday 2026-09-26 15:00, weekend branch) for the 24h window to reach them; verify_live 7 screens + discovery verifier `ALL CHECKS PASSED`, risk live UI **43/43**; previews policy + compliance recaptured 1920×1600 no-fullPage; backend **343** (phase2 dir **261**), pam_master **46**, smoke 17/17; dev DB seeded only through the public API — **8** real evaluations across all four bands + 1 refused gate start (avg 50.6, refused 1), chain verify **35/35** intact across all eight sources) | **4g** (next module per `VY-PAM_Enterprise_PAM_Architecture.md` — candidates: §10 PAM Bypass Detection, §17 Break Glass, §20 Enterprise Integrations) |

---

## 8. Commercial fit — all customer types

- **SMB:** file license, defaults on, single site — same product, fewer nodes.
- **Enterprise:** quotas per node/session, SSO/HSM, multi-site.
- **Air-gapped / regulated:** everything offline by design (file license, no
  phone-home; optional signed usage export transferred manually).
- **Upgrades:** new signed license, same artifact format — no reinstall.
