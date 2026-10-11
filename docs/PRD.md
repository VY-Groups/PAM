# VY-PAM — Product Requirements Document (PRD)

**Status:** as-built for Phase 6a
**Source of truth:** `VY-PAM_Enterprise_PAM_Architecture.md` (requirements) and
`VY-PAM_MASTER_and_PAM_Workflow.md` (phase checkpoints)
**Companion docs:** `TRD.md`, `PAM_FLOW.md`, `UI_UX_DESIGN_BRIEF.md`,
`BACKEND_SCHEMA.md`, `API_REFERENCE.md`, `SECURITY_COMPLIANCE.md`,
`DEPLOYMENT_RUNBOOK.md`, `TESTING_QA_STRATEGY.md`

---

## 1. Product summary

VY-PAM is an enterprise **privileged identity & access management (PAM)**
platform: discovery of privileged targets, a credential vault with real
rotation, JIT access with approvals, recorded privileged sessions gated by a
risk engine, a zero-trust command-control policy, and an immutable audit
ledger — delivered as a web console + HTTP APIs that install directly on a
machine (no VM or container required; Docker exists only for development).

The repository carries **two deliverables**:

| Deliverable | Location | Ships to customers? |
|---|---|---|
| **VY-PAM** — console + APIs + PAM runtime | `frontend/`, `apis/`, `backend/` | Yes |
| **VY-PAM MASTER** — license-authority vendor tool | `pam_master/` | **Never** (VY-Groups internal) |

Both sides sign/verify through the same shared engine
(`backend/ipam_licensing`), so the vendor tool and the shipped server can
never drift apart.

## 2. Users & jobs to be done

| Persona | Job | Primary screens |
|---|---|---|
| PAM administrator | Onboard targets, store credentials, keep them rotating, configure policy | Command Center, Vault, Target Infrastructure, Settings, Policy |
| Security operator (SOC) | Approve/deny access and held commands, review incidents, watch sessions live | JIT, Live Session Hub, Policy, Compliance |
| Auditor / compliance officer | Prove what happened: chain-verified evidence, export for SIEM | Compliance, Audit endpoints |
| End user / engineer | Request time-boxed access and use it safely | JIT, (session usage via links) |
| Vendor (VY-Groups) | Issue/renew licenses, keep customer PII and archives encrypted | VY-PAM MASTER tool (internal) |

## 3. Product principles

1. **Honest data above all.** Every number on screen comes from the API at
   render time, or the UI shows `—` / "not connected". No sample rows, no
   placeholder metrics, no invented percentages. A verifier scans the live
   screens for legacy fabricated strings on every boundary.
2. **Real machine, real inputs.** Scans are real TCP connects, rotation really
   mints and validates secrets, the ledger really hashes, risk really reads
   the clock/inventory/policy. Simulated data is never acceptable.
3. **Evidence over assertions.** Anything a module claims (a decision, a
   refusal, a rotation) lands in the append-only §19 audit ledger with a hash
   chain a third party can re-verify.
4. **Contract-first HTTP.** `apis/openapi.yaml` is enforced in both directions
   by tests; no dark endpoints, no stale docs.
5. **Zero standing privilege.** Access is requested, risk-scored, approved by
   someone else, time-boxed, recorded, and revoked on expiry — by default.

## 4. Scope - built (as of Phase 4k)

| # | Architecture section | Requirement | Status | Evidence |
|---|---|---|---|---|
| 1 | §2 Core modules | Signed license lifecycle: vendor import, validation, revocation, usage/quota checks, feature/module catalog | Built | `POST /licenses/import`, 9 license+validation paths, `test_api.py` (59) |
| 2 | §2 Core modules | Platform settings groups (`sso`, `hsm`, `zsp`, `worm`) with per-field change diff + changelog | Built | `GET/PUT /settings/*`, `test_settings_and_ui.py` (32) |
| 3 | §3 Discovery Engine | Real TCP-connect scan (≤256 hosts, ≤24 ports), port/banner classification, asset risk from `BASE_RISK`, register/onboard/ignore | Built | `POST /discovery/scans`, `test_discovery.py` (19) |
| 4 | §4 Enterprise Vault | Credential inventory, per-type secret generation, AES-256-GCM at rest, admin reveal that never logs plaintext, checkouts | Built | `GET/POST /vault/*` (8 paths), `test_vault_dashboard.py` (19) |
| 5 | §5 Password Rotation Engine | Pipeline mint → seal → dependents → decrypt round-trip → audit; triggers manual/bulk/session-end/scheduler; failed → retry; version history | Built | `POST /rotation/run`, `test_rotation.py` (30) |
| 6 | §6 JIT / JEA Access | Requests scored from measured inputs, band-driven approvals (manager/security), time-boxed grants, real checkout, expiry → release + rotate | Built | `POST /jit/requests` (6 paths), `test_jit.py` (18) |
| 7 | §7 Risk-Based Access Engine | Eight-component scoring (visible sum, clamps at 100), bands → allow/mfa/approval/block, console evaluation + session-start gate with 403 evidence | Built | `POST /risk/evaluate` (3 paths), `test_risk.py` (19) |
| 8 | §8 Privileged Session Management | Start against credential or grant, append-only recorded events with custody watermarks, 7 control flags, pause/lock/resume, release-and-rotate cascade on end | Built | 12 session paths, `test_sessions.py` (23) |
| 9 | §9 Command Control | Default-allow engine, shipped §9 rules (15, seeded once), block → approval → allow, dry-run, approval queue, incidents with preserved evidence | Built | 8 command-control paths, `test_command_control.py` (18) |
| 10 | §10 PAM Bypass Detection | Real auth-log/JSON ingest → verbatim observations, correlation against managed inventory + recorded sessions, incidents with alert + forced rotation (real §5 pipeline) + honest `block_source` | Built | 7 bypass paths, `test_bypass.py` (19) |
| 11 | §17 Break Glass | Emergency request → dual approval (two distinct approvers, requester excluded) → recorded session releasing a real vault credential → forced rotation + required review at close, itself on the ledger | Built | 7 break-glass paths / 8 ops, `test_break_glass.py` (22) |
| 12 | §19 Immutable Audit Architecture | Hash-chained append-only ledger over 15 module trails, SQLite triggers, boot backfill, verify walk, NDJSON export | Built | 3 audit paths, `test_audit.py` (19) |
| 13 | §21 Admin Dashboard | Command Center overview (health, posture, counters, recent activity) + Compliance center (digest, verify, per-trail filter, export) | Built | `GET /overview`, `GET /events` |
| 14 | Product delivery | Console: 11-item sidebar, launcher, 11 screens live against real APIs, honest `file://` fallback | Built | `frontend/`, verifiers in `shots_tool/` |
| 15 | Vendor side | VY-PAM MASTER: encrypted customer registry, signed issuance/renewal, delivery bundles, own audit + own OpenAPI contract | Built | `pam_master/` (46 tests) |
| 16 | §20 Enterprise Integrations | RFC-6238 TOTP factor enrolling + enforced at session start / break-glass open, ITSM ticket verification over real HTTP, SIEM signed-NDJSON push after commit, LDAP bind login with HMAC tickets, connector status aggregate | Built | 5 integration paths / 5 ops, `test_integrations.py` (41) |
| 17 | §11 AI Security / UEBA | Per-principal behavior baselines learned from real history (hours/device/IP/target/verbs/cadence); named deviations on the behavior component (5 pts each); critical deviation → refuse start → release-and-rotate cascade → rotate sought credential → incident preserved on the `risk` ledger trail | Built | `GET/POST /risk/baselines*`, `GET /risk/anomalies` (3 paths / 3 ops), `test_ueba.py` (9) |
| 18 | §12 Dynamic Watermarking | Contextual overlay `USER/SESSION/TARGET/TIME/TICKET/SOURCE` assembled only from the session's own rows (actor, custody ref, target, latest-event clock, linked grant's ticket, source address recorded at start); moves with pause/resume/terminate; the watermark control gates the painted text (data stays, `—` for absent facts); console overlay in the Live Session Hub, protocol-level pixel overlays labelled `not connected` pending gateway work | Built | additive `watermark` field on `GET /api/v1/sessions/{session_id}` (`SessionWatermark` schema), `test_watermark.py` (6) |
| 19 | §13 Third-Party / Vendor PAM | Per-vendor TOTP (sealed at rest, shown once at invite), NDA, real ITSM ticket check, strict approval gate (refused 409 naming the missing steps), vendor-scoped JIT requests (scope + window checked pre-creation, deny beats allow), forced session recording, lazy account expiry, deny/revoke with the grant close cascade, re-invite on the same row; the vendor dashboard (access/denied lists, valid window, recording) renders the account's own row | Built | 9 vendor paths / 11 ops, `test_vendor_pam.py` (21) |
| 20 | §14 Cloud PAM | AWS/Azure/GCP/Kubernetes connectors with honest states (`not connected`/`configured`/`connected`/`error`, only a real probe moves them), credential federated into the vault (revealed per call, audited, never returned), real inventory from the cloud's own API under `source=cloud` (failed/unanswered runs record the honest reason and invent nothing), K8s *RBAC → JIT → ephemeral privilege → audit* (the grant applies a real RoleBinding, close/expiry removes it, deletion refused while grants are open) | Built | 6 cloud paths / 9 ops, `test_cloud.py` (27) |
| 21 | §15 DevSecOps PAM | CI/CD credential broker: pipeline identities (Jenkins/GitLab/GitHub/Azure DevOps/Terraform/Ansible/ArgoCD/Docker) authenticate with an API token shown once and stored as a sha256 hash — **no static secrets in pipelines**; `auto` policies release a time-boxed vault credential in one call, `manual` ones queue for admin approval; the grant is checked out under the pipeline, expires on the real clock and rotates through the §5 pipeline exactly like a JIT grant; scope (`allowed_targets`), TTL cap and revoke-close-cascade are enforced with evidence on the `broker` trail | Built | 9 broker paths / 13 ops, `test_broker.py` (24) |
| 22 | §16 AI-Agent PAM | Agent identities (API token `vypam-agt1.<id>.<secret>` shown once, sha256 at rest, constant-time verify, admin token never substitutes) declare **task scopes** — an exhaustive `allowed_commands` allow-list (1–32 literal substrings, default-deny), exact targets, a window cap; requests run identity → task → §7 risk (low auto-approves with the `agent_binding` snapshot, critical blocks), the grant is consumed as a **forced recorded session** whose every command is judged against the allow-list (§9 blocks still veto; out-of-scope → incident + session terminated + release/rotate), revoke closes open access before the token dies, evidence lands on the `agent` trail | Built | 9 agent paths / 15 ops, `test_agent.py` (29) |

## 5. Scope — explicitly NOT built yet (pending requirements)

Marked `—`/static in the UI where a screen exists; absent from the API
otherwise. Each row is a **planned requirement** — target behavior quoted
from the architecture doc, phase assigned in `IMPLEMENTATION_PLAN.md`:

| Arch. section | Pending requirement (target behavior) | Current state | Phase |
|---|---|---|---|
| §18 HA / DC / DR | Active-active/passive, load balancer, vault/audit/session replication, failover, health checks | **Shipped in 6a** (single-binary scope): node registry, real probes, pull replication, passive gate, failover + verified backups — external LB topology + multi-writer store remain | 6a |
| §20 Enterprise Integrations | IAM/MFA/ITSM/SIEM/SOAR/EDR connectors — real verification/push when configured, `not connected` otherwise | Shipped in 4i for TOTP-MFA, ITSM, SIEM and LDAP (each honest `not connected` until configured); SOAR/EDR only if ever configured | 4i |
| RBAC / ABAC | Multi-role model over the admin operations (single admin token today) | **Shipped in 6b**: five seeded roles over the 105 admin operations (policy in code), sha256-at-rest API tokens shown once, LDAP directory authenticates but the binding decides, ABAC target/vault-item scoping, `rbac` ledger source — `admin-token` remains the bootstrap superuser | 6b |
| SSO / MFA / HSM enforcement | Settings **schema** exists; enforcement not implemented | Settings store only — posture counts them honestly | 6c (SSO/HSM), 4i (MFA) |

## 6. Functional requirements detail (selected)

### FR-1 Risk-based access (§7)
- R1.1 Score every evaluation over 8 components — `user` ≤10 (5 per prior
  critical in 24h), `device` ≤15 (unknown to inventory), `asset` ≤30
  (CRITICAL 25 / HIGH 20 / MEDIUM 10 / LOW 0, +5 `unmanaged`), `time` ≤10
  (real clock, off-hours/weekend), `location` ≤5 (`ipaddress.is_global`; no
  geo feed claimed), `behavior` ≤15 local (10 blocked commands + 5 denied
  JITs / 24h) + 5 per named §11 baseline deviation (unusual time/device/
  IP/target/command/privilege, ≤45 with all six), `ticket` ≤5 (non-ITSM
  shape), `command` ≤10 (`block`) / ≤5 (`approval`) from the live §9
  policy. The measured sum is visible; the score clamps at 100.
- R1.2 Bands: `≤25 low → allow`, `≤50 medium → mfa`, `≤75 high → approval`,
  `>75 critical → block`.
- R1.3 Console evaluations are always advisory (`result=advisory`) and always
  persisted.
- R1.4 `POST /sessions` runs the same scorer with `context=session_start`
  **before** creating anything: the evaluation is committed first (refusals
  are SOC evidence), then critical → refused outright; high → only with an
  active JIT grant (approved by someone other than the requester); otherwise
  allowed. Refusal → `403` with `details.risk`.
- R1.5 Every evaluation fans into the §19 ledger as source `risk`.

### FR-2 Command control (§9)
- R2.1 Default-allow; rules match case-insensitive substring of the command
  plus optional case-insensitive fnmatch glob on target.
- R2.2 Evaluation order: block → approval → allow; scoped rules first, then
  longest pattern, then lowest id.
- R2.3 Shipped table seeds **15 rules once into an empty table** — an
  operator's deletion stays deleted.
- R2.4 Held commands resolve through append-only `type=approval` rows that
  reference the hold (the hold is never edited); `terminate_on_match` blocks
  end the session through the release-and-rotate cascade and preserve evidence
  as an `inc-<hex>` incident.

### FR-3 Audit ledger (§19)
- R3.1 One append-only `audit_events` chain: `seq`, `prev_hash`, `event_hash`
  (sha256 over the canonical record; genesis `0`×64).
- R3.2 Thirteen sources fan in: license, settings, vault, discovery, jit,
  session, command, risk, bypass, break-glass, integration, vendor, cloud.
- R3.3 SQLite triggers refuse `UPDATE`/`DELETE` outright.
- R3.4 `/audit/verify` recomputes every hash and reports the first break;
  `/audit/export` streams NDJSON in chain order; first boot backfills history
  exactly once.

### FR-4 Privileged sessions (§8)
- R4.1 Start against a vault credential (real checkout) or an active JIT
  grant (one live session per grant → 409).
- R4.2 Events are append-only with `seq`, actor and custody watermark;
  controls gate for real (typed content while `record=false` → 403; gated
  channels store `allowed=false` + reason as kept evidence; `keystroke_log=false`
  stores content `null` + `withheld=true`).
- R4.3 Terminate/complete cascade: linked grant closes, own checkout releases
  and the credential rotates exactly once (`cascade` reported).

### FR-5 PAM bypass detection (§10)
- R5.1 Ingest real platform logs (OpenSSH `Accepted …` lines with a bundle
  target; structured JSON records with per-line target/`at`) into verbatim
  observations; malformed or untargeted lines are counted, never invented.
- R5.2 Correlate `observed` signals: not a managed asset → `out_of_scope`;
  covered by a recorded session in its window → `covered`; otherwise a
  `candidate` opens an incident with the architecture's ACTION block —
  `alert` (the ledger record), `rotation` (the real §5 pipeline, per vault
  item, failures recorded not fatal), `block_source: not_connected`.
- R5.3 Re-scans never duplicate incidents; every ingest/scan/detect/close
  fans into the §19 ledger as source `bypass`.

## 7. Non-functional requirements

| NFR | Requirement | How it is met today |
|---|---|---|
| Data honesty | No fabricated values anywhere in the product | Live-data wiring + FORBIDDEN-string sweep (`shots_tool/__verify_live.mjs`, 9 screens × HTTP/file) |
| Portability | Installs directly on a machine | Pure Python deps; SQLite files; Docker only under `pam_master/` and `backend/phase2_license_server/` for development |
| Tamper evidence | Audit trail provable | sha256 chain + append-only triggers + `/audit/verify` |
| Least privilege | Admin actions authenticated, least-privilege roles | 105 admin operations require `Bearer`/`X-Admin-Token` when `LICENSE_ADMIN_TOKEN` is set; in token mode a bound principal (RBAC API token or LDAP ticket) may call only its role's operations and only its ABAC scope; open dev mode is explicit (`X-Auth-Mode: open`); pipeline `/broker` operations require the broker API token and AI-agent `/agent-access` operations the agent API token — neither is ever waived |
| Bounded resource use | Scans and lists bounded | Scan ≤256 hosts × ≤24 ports, single-flight; pagination `limit` max 200 |
| Contract stability | API evolution controlled | OpenAPI 3.1, both-direction contract test, `/api/v1` version segment |
| Testability | Every phase ships tests | 613 backend + 46 vendor-tool tests; UI verifiers; 17-step smoke |
| Offline crypto | Verification without network | Phase 1 validator verifies envelope/JWS offline (signature → structure → expiry) |

## 8. Success criteria (per release)

1. `python -m pytest backend -q` green (currently **613**) and
   `python -m pytest pam_master -q` green (**46**).
2. Contract test green: **102** documented paths both directions, **64**
   admin operations carrying security schemes.
3. Boundary verifiers green: smoke 17/17, `__verify_live.mjs`,
   `__verify_discovery.mjs`.
4. Screenshots recaptured at 1920×1600 viewport (no fullPage) for changed
   screens.
5. Docs (root + per-folder READMEs + this set) state only real counts.

## 9. Roadmap

The full phase-wise backlog (6c), scope, dependencies and
definition-of-done per phase live in **`docs/IMPLEMENTATION_PLAN.md`**;
execution checkpoints are logged in
`VY-PAM_MASTER_and_PAM_Workflow.md`. Next phase: **6c — SSO + HSM
enforcement** (Phases 4a–4k, 5a–5d and 6a/6b complete).

## 10. Target end-state (final output after full development)

When the plan completes, VY-PAM delivers — against the architecture doc's
Final Vision (*"discovers every privileged identity, evaluates every access
request, provides least-privilege JIT access, monitors every privileged
session, detects bypass and anomalous behavior, protects secrets, and
automatically responds to privileged threats across on-premises, cloud,
DevOps and AI environments"*):

| Dimension | Final output |
|---|---|
| **Modules** | All architecture sections §1–§21 built (the §4 table grows to full ✅; §5 table empties); §22 Feature Matrix matches reality line-for-line |
| **Console** | Every sidebar screen live — **zero `data-kind="static"` surfaces** (Break-Glass included); every widget renders real API data or honest `—`; `file://` fallback preserved |
| **Evidence** | One append-only hash-chained ledger covering every module source (12+), verified in CI, exported as NDJSON **and** pushed to a configured SIEM |
| **Access model** | Standing privilege eliminated everywhere: JIT for humans, task-scoped grants for agents/pipelines, MFA and SSO enforced, multi-role RBAC/ABAC over all admin operations |
| **Threat response** | Bypass detection, UEBA anomalies, and risk banding all drive the *real* response machinery — session cascade, forced rotation, incidents with preserved evidence |
| **Integrations** | IAM, MFA, ITSM, SIEM, SOAR, EDR, cloud and DevSecOps connectors — each either verified working against a real endpoint or explicitly `not connected` |
| **Scale** | §18 replicated deployment (load balancer, vault/audit replication, failover) with runbooks; single-node install remains Docker-free |
| **Contracts** | `apis/openapi.yaml` (135 paths today, `-` at completion) enforced both-ways; vendor tool contract likewise; zero dark endpoints |
| **Quality** | Backend suite (613 today) grows per phase with real counts recorded in READMEs; pam_master 46 stays green; smoke + both UI verifiers green at every boundary |
| **Honesty invariant** | Unchanged and non-negotiable: every displayed number comes from an API at render time — the product never fabricates, complete or not |
