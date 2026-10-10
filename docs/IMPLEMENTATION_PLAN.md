# VY-PAM — Implementation Plan (remaining architecture coverage)

**Status:** maintained through Phase 6a — remaining backlog starts at 6b
**Authoritative spec:** `VY-PAM_Enterprise_PAM_Architecture.md`
**Execution log:** `VY-PAM_MASTER_and_PAM_Workflow.md` (checkpoint rows — the
resumable source of truth while working)
**Companion docs:** the nine documents in `docs/` — this plan says what is
*pending*; they say what *exists*.

> **Honesty rule for this plan:** phases below describe intended scope and
> target behavior quoted from the architecture doc. No dates, no percentages,
> no test counts are asserted for unbuilt work — future counts are `—` until
> a phase lands and real numbers are collected.

---

## 1. Where the program stands

| Architecture section | Topic | Status | Phase |
|---|---|---|---|
| §2 Core modules | licensing, settings, dashboard | ✅ built | 1–3 |
| §3 Discovery Engine | scans, assets, onboarding | ✅ built | 1 |
| §4 Enterprise Vault | AES-256-GCM secrets, checkout/reveal | ✅ built | 4a |
| §5 Password Rotation | pipeline + 4 triggers | ✅ built | 4a |
| §6 JIT / JEA | scoring, approvals, time-boxed grants | ✅ built | 4b |
| §7 Risk-Based Access | 8-component engine + session gate | ✅ built | 4f |
| §8 Privileged Sessions | recording, controls, cascade | ✅ built | 4c |
| §9 Command Control | default-allow rules, holds, incidents | ✅ built | 4d |
| §19 Immutable Audit | hash chain, 16 sources, verify/export | ✅ built | 4e |
| §10 PAM Bypass Detection | direct-access detection | ✅ built | **4g** |
| §17 Break Glass | emergency protocol (dual approval → recorded session → rotation) | ✅ built | **4h** |
| §20 Enterprise Integrations | TOTP MFA gate, ITSM verify, SIEM push, LDAP bind | ✅ built | **4i** |
| §11 AI Security / UEBA | behavior baselines, anomaly response | ✅ built | **4j** |
| §12 Dynamic Watermarking | contextual session overlay | ✅ built | **4k** |
| §13 Third-Party / Vendor PAM | vendor invite → JIT flow, §13 dashboard | ✅ built | **5a** |
| §14 Cloud PAM | AWS/Azure/GCP/K8s connectors, K8s RBAC → JIT grants | ✅ built | **5b** |
| §15 DevSecOps PAM | CI/CD JIT credential broker | ✅ built | **5c** |
| §16 AI-Agent PAM | agent identity + task-scoped access | ✅ built | **5d** |
| §18 HA / DC / DR | multi-node, replication, failover | ✅ built | **6a** |
| RBAC / ABAC | multi-role model (single admin today) | ⛔ pending | **6b** |
| SSO / HSM enforcement | settings schema → real enforcement | ⛔ pending (schema only) | **6c** |
| §21 Admin Dashboard | all widgets live | 🟡 partial | closes per phase |

## 2. How every phase executes (the 13-step loop)

The loop proven in 4a–4f, unchanged:

```
1 model + service + endpoints → 2 openapi + ADMIN_OPERATIONS + contract
  lockstep → 3 tests green → 4 screen wiring (data-role, file:// dashes)
  → 5 restart dev server (python -X utf8 app.py) → 6 seed via PUBLIC API only
  → 7 recapture 1920×1600 no-fullPage → 8 docs (READMEs + docs/ counts)
  → 9 boundary regression (backend, pam_master, contract, smoke,
  __verify_live, __verify_discovery) → 10 temp-script cleanup →
  11 leak check (ghp_ on staged diff) → 12 commit → 13 push via fresh
  temp .ps1, delete it
```

Standing rules that apply to **every** phase below: real inputs only (no
sample rows), `—` for unavailable numbers, append-only + ledger emission
inside the same transaction, reveal-on-click + 30 s re-mask, frozen-HTML
discipline, contract lockstep in one commit.

---

## 3. Phase 4g — PAM Bypass Detection (§10)

**Goal (spec):** detect privileged access that **skips PAM** —
`User → Direct SSH → Production Server` instead of
`User → PAM → Gateway → Production Server` — and respond:
*Alert SOC · Block source · Create incident · Force credential rotation.*

**Scope:**
- Model `bypass_signals` + `bypass_incidents` (user, source, target,
  protocol, evidence pointer, status).
- **Detection inputs (real only):** (a) ingest endpoint for platform auth
  logs (Linux `auth.log` / Windows Event Log exports — file upload or
  watched directory configured in settings); (b) correlation against live
  inventory + `privileged_sessions`: a connection to a managed target from a
  known principal while **no active recorded session exists** ⇒ candidate
  bypass; (c) SSH/RDP telemetry surfaced by discovery scans' host state.
- Response path: incident row + ledger entry; *force credential rotation*
  reuses the real §5 pipeline (rotate the target's vault credential
  immediately); *block source* emits a connector action hook — implemented
  only where a real enforcement endpoint exists, otherwise the action is
  listed as `not connected` (never faked).
- Endpoints: `POST /bypass/scans` (correlate window), `GET /bypass/signals`,
  `GET /bypass/incidents`, `POST /bypass/incidents/{id}/close`.
- Ledger: new source **`bypass`** (9th) — lockstep: `AUDIT_SOURCES`,
  mapper-coverage test, compliance chip 9→10, stats assertions.
- Screen: new section on **Command Center** (alert feed) + incident rows in
  Compliance chips.

**Depends on:** 4e (ledger), 4c (sessions), §3 (inventory).
**Tests:** `test_bypass.py` — **19** (as built).
**Done when:** a real direct-connection log line produces a real incident with
forced rotation of the affected credential, chain intact, all boundary
suites green.

**As built (4g):** 3 models (`bypass_signals`, `bypass_incidents`,
`bypass_events`) / 22 tables; 7 endpoints (ingest, signals, scans,
incidents ×3, stats — 3 admin); ledger source `bypass` (9th) via
`_map_bypass`; compliance chips 9→10; Command Center bypass section
(click-only, `file://` dashes); contract 72 paths / 80 ops / 12 tags / 40
admin; `test_bypass.py` 19 + full backend **362**; dev-only Docker image
(`backend/phase2_license_server/Dockerfile`) ran the suite green inside
the container (280/280) plus a 41/41 fresh-database HTTP E2E.

## 4. Phase 4h — Break Glass (§17)

**Goal (spec):** *BREAK GLASS → emergency authentication → MFA → dual
approval → emergency credential → session recorded → automatic alert →
credential rotation → post-incident review* — and **the break-glass process
itself is auditable**.

**Scope:**
- Model `break_glass_requests` (reason, severity, target, status
  `pending → approved|denied → used → closed`, approval snapshots) +
  `break_glass_approvals` (two distinct approvers required — dual approval).
- Flow: request → two approvals → **emergency credential** released via real
  vault checkout → mandatory recorded session (`record=true` regardless of
  user prefs) → on close: forced rotation + post-incident review note →
  every step to the ledger (new source **`break-glass`**, the 10th — 4g
  landed `bypass` as the 9th).
- MFA step: executed only when a factor exists (4i); until then the request
  records `mfa: not configured` **honestly** — never a fake challenge.
- Endpoints: `POST|GET /break-glass/requests`, `/{id}/approve` (×2), deny,
  open (checkout + session), close (rotate + review).
- Screen: **`break_glass_emergency_protocol` goes from
  `data-kind="static"` → live** (header Break-Glass button wires to request
  modal); static placeholders purged.

**Depends on:** 4a (vault/rotation), 4c (sessions), 4e (ledger).
**Tests:** `test_break_glass.py` — **22** (as built).
**Done when:** an emergency request walks the full path on real data, both
approvals enforced (self/second-approver rules), rotation fires, screen is
live, verifiers green.

**As built (4h):** 3 models (`break_glass_requests`, `break_glass_approvals`,
`break_glass_events`) / 25 tables; 8 endpoints across 7 path keys (create,
list, detail, approve, deny, open, close, stats — 5 admin); dual approval
enforced in code (requester self-approval 403, repeat signature 400,
append-only snapshots); risk gate enforced **at open** (403 `details.risk`
refuses `critical` — nothing released); `open` = real vault checkout +
mandatory recorded session (201), `close` = session end + forced rotation
through the shared `_force_target_rotation` helper (`trigger=break-glass`)
+ required review note; ledger source `break-glass` (10th) via
`_map_break_glass`; compliance chips 10→11; Break-Glass screen fully live
(`data-kind="live"` — request modal with `EMERGENCY-AUTHORIZE` confirm,
per-status actions, honest footer, `file://` dashes); contract 79 paths /
88 ops / 13 tags / 45 admin; `test_break_glass.py` 22 + full backend
**384**; MFA honestly `not configured` until 4i.

## 5. Phase 4i — Enterprise Integrations foundation (§20)

**Goal (spec):** integration surface — *IAM (AD/LDAP/Entra/Okta…), MFA
(RADIUS/TOTP/FIDO2/WebAuthn/Duo), ITSM (ServiceNow/Jira/BMC/Freshservice),
SIEM (Splunk/Sentinel/QRadar/Elastic/Wazuh/ArcSight), SOAR, EDR.*

**Scope (foundation slice — every connector either works for real or shows
`not connected`):**
- **MFA — TOTP (RFC 6238):** real authenticator enrol + verify (stdlib
  `hmac`/`hashlib` — no new deps). Makes the risk engine's `mfa` band
  decision *actionable*: medium band start requires a verified code.
  FIDO2/WebAuthn = later slice, out of this phase.
- **ITSM:** connector config (settings group) + real HTTP verification of
  ticket keys against ServiceNow/Jira REST when configured → upgrades the
  §7 `ticket` component from *shape-only* to *verified* (score gains a
  verified flag; unconfigured stays shape-only, labelled honestly).
- **SIEM outbound:** signed NDJSON batch POST on ledger append when a webhook
  is configured (built on `/audit/export` data); unconfigured → chip
  `not connected`. SOAR/EDR inbound webhooks = later slice.
- **LDAP/AD bind** as an optional auth backend for admin login (real bind
  when configured; token mode remains default).
- Settings groups `mfa`, `itsm`, `siem`, `ldap` (schema + changelog, same
  pattern as `sso/hsm/zsp/worm`).
- Screen: Settings gains Integrations cards; Compliance gains SIEM push
  status.

**Depends on:** 4e (ledger export seam), 4f (risk `mfa`/`ticket` consumers).
**Tests:** `test_integrations.py` — **41** (external calls tested against
local stub servers, never mocked domain behavior).
**Done when:** a configured TOTP factor actually gates a medium-band session
start, a configured ITSM key is really verified, and SIEM push moves real
ledger records — with every unconfigured path rendering `not connected`.

**As built (4i):** 1 model (`integration_events`) / **26** tables; 5
endpoints across 5 path keys (`mfa/enroll`, `mfa/verify`, `itsm/verify`,
`auth/ldap`, `integrations/status` — 3 admin) under the new `integrations`
tag; RFC-6238 TOTP over stdlib `hmac`/`hashlib` (±1 window, SHA-1/256/512,
deterministic window math unit-tested) enforces the `mfa` decision at
session start (`mfa_code`, refusal 403 `details.mfa`) and at break-glass
open (refusal 401 `details.mfa`) — **no factor → honest pass**
(`mfa: "not configured"`, never a fake challenge); ITSM verified over real
HTTP against local stub servers (verified/not_verified + status on the
ledger, `itsm_verify_ticket` never raises); SIEM signed NDJSON (`sha256=`
HMAC) pushed **after commit** — a failed push records exactly one
`siem-push-failed` event via a fresh post-commit session (SQLAlchemy 2.x
refuses SQL on the committed session inside `after_commit`); LDAP BER bind
+ `vypam-ldap1.<b64url>.<hmac>` tickets on `config.secret_key` (open mode
answers honestly); settings groups `mfa`/`itsm`/`siem`/`ldap` (8 total —
secrets sealed AES-256-GCM AAD `settings:{group}:{field}` with
`<set>`/`<cleared>` changelog values, `mfa.factor_*` readonly → 400 with
`POST /mfa/enroll` hint, plain-`http` connector URLs rejected unless
`allow_http`); `Unauthorized` now carries `details` (3× 500s fixed); ledger
source `integration` (**11th**) via `_map_integration`; Settings screen §20
cards + 4 live chips + one-time secret reveal, Compliance 11→12 chips +
`integration` trail + SIEM header chip, Break-Glass open modal with the MFA
field gated on `GET /integrations/status`; contract **84 paths / 93 ops /
14 tags / 48 admin**; `test_integrations.py` **41** + full backend
**425**; MFA footnote retired — the gate is live.

## 6. Phase 4j — AI Security / UEBA (§11)

**Goal (spec):** *PAM Security Intelligence Engine* — learns normal behavior
per principal (hours, device, IP, target set, command class, privilege
cadence), then flags deviations:
*unusual time/device/IP/target/command/privilege → BLOCK SESSION → ROTATE
CREDENTIAL → SOC ALERT → CREATE INCIDENT → PRESERVE EVIDENCE.*

**Scope:**
- Baselines learned **from the product's own history** (`risk_events`,
  `session_events`, `command_incidents` — real rows, no synthetic users),
  stored as `behavior_baselines` (rolling windows per actor).
- New/extended scoring: anomaly factor joining the §7 `behavior` component
  (currently local 24h counts → baseline deviation), with per-reason
  breakdown identical to the spec's "Reasons:" list.
- Response chain reuses real machinery: session end (existing cascade),
  rotation pipeline, incident rows, ledger.
- Screen: Policy §7 section gains an "Anomalies" subsection; Compliance
  chips unchanged unless a new source is introduced (lockstep if so).

**Depends on:** 4f (risk), 4c/4d (session/command history depth), 4i (MFA
for step-up).
**Tests:** `test_ueba.py` — **9**.
**Done when:** an actor deviating from their own recorded baseline produces a
critical evaluation with named reasons, a real block/cascade, and preserved
evidence — all from real history rows.

**As built (4j):** 2 models (`behavior_baselines`, `anomaly_incidents`) /
**28** tables; 3 endpoints across 3 path keys (`risk/baselines` GET public,
`risk/baselines/train` POST admin, `risk/anomalies` GET public) under the
existing `risk` tag. Baselines learn a 30-day rolling profile (hours,
devices, source IPs, targets, command/privilege verbs, protocols, cadence)
**only from real rows** (`risk_events`, `privileged_sessions`,
`session_events` type `command`, `command_incidents`) — trained explicitly
(endpoint / Policy-screen button), an unseen principal gets no baseline, and
a truncated dimension (>128 distinct values) stops claiming deviation. The
§7 `behavior` component keeps its local 24h counts and gains **5 points per
named deviation** (unusual time/device/IP/target/command/privilege, listed
verbatim in `reasons`; behavior ≤45, total **clamps at 100** with the
measured sum named in the detail); with no stored baseline the component
stays byte-identical. A CRITICAL refusal carrying deviations runs the chain
inside `create_session`: refuse the start (403 `details.risk`) → end every
other active session of that principal through the release-and-rotate
cascade → rotate the credential the request sought (`item_id` →
`rotate_vault_item`, else `_force_target_rotation` on the target's items) →
commit the `AnomalyEvent` with reasons + actions (failures reported, never
hidden) → `details.anomaly` back to the caller; the incident fans into the
ledger under the existing `risk` source (`anomaly-incident`, ref
`anom:<id>`) so sources stay **11**/chips 12. Console evaluations stay
advisory. Drift guard auto-covers `AnomalyEvent` (class named `*Event` on
purpose). Policy screen §7 gains the Anomalies subsection (baselines list,
per-reason chips, Train button, honest empty states); caps legend now reads
"score clamps at 100". Contract **87 paths / 96 ops / 14 tags / 49 admin**;
`test_ueba.py` **9** + full backend **434**.

## 7. Phase 4k — Dynamic Watermarking (§12)

**Goal (spec):** contextual watermark overlaid on RDP/VNC/browser/DB/SSH/
file-transfer views —
`USER / SESSION / TARGET / TIME / TICKET / SOURCE` — changing with session
state.

**Scope:**
- Watermark payload assembled from **real session rows** (actor,
  `session_ref`, target, started_at, linked ticket, source IP).
- Delivery: console session-inspection pane renders the live overlay (DOM,
  `data-role`), plus a watermark string appended to recorded event views;
  protocol-level overlays (actual RDP/VNC pixels) are gateway-dependent —
  gated behind §27 gateway work and honestly labelled `not connected` until
  then.
- Screen: Live Session Hub detail pane + event stream.

**Depends on:** 4c (sessions), §21 dashboard conventions.
**Tests:** `test_watermark.py` — `—`.
**Done when:** opening a live session shows an overlay whose fields all come
from that session's real row and change on pause/resume/terminate.

**As built (4k):** additive `watermark` object (`SessionWatermark` schema)
on `GET /api/v1/sessions/{session_id}`, assembled only from the session's
own rows — actor, custody ref, target, the clock of the latest recorded
event (`dd-Mon-yyyy HH:MM`, locale-independent; moves with the session,
freezes at its end), the linked grant's ticket, and the source address
recorded at start (new nullable `privileged_sessions.source_ip` column
added through `ensure_schema`, so pre-4k rows render `—`). `state` moves
with pause/resume/terminate, `enabled` mirrors the watermark control, and
`text` is the rendered six-line overlay (null while off — the per-event
custody strings are gated by the same control). The Live Session Hub
renders the pane from that payload, every recorded event row carries its
custody line, and protocol-level pixel overlays are labelled
`not connected` pending §27 gateway work; screenshot recaptured at
1920×1600. Contract **87 paths / 96 ops / 14 tags / 49 admin**;
`test_watermark.py` **6** + full backend **440**.

---

## 8. Phase 5 — enterprise expansion

### 5a — Third-Party / Vendor PAM (§13)
Vendor lifecycle *Invite → MFA → NDA/Agreement → Ticket → Approval → JIT →
Recording → Automatic expiry* on top of existing JIT/vault/session machinery;
`vendor_accounts` model + vendor-scoped dashboard (access/denied lists, time
window, recording state per spec example). Reuses 4i MFA and ITSM ticket
verification for the real gate.

**As built (5a):** `vendor_accounts` + `vendor_events` (tables **28→30**) and
an indexed `jit_requests.vendor_account_id`. Invite seals a fresh per-vendor
TOTP seed (AES-256-GCM, AAD `vendor:{id}:mfa_secret`) returned exactly once;
MFA/NDA/ticket/approve each store their timestamp, approval refuses **409**
with `details.missing` while any step is outstanding, the ticket step is the
real §20 ITSM HTTP check (unconfigured → honest 409), deny/revoke record
verbatim (revoke closes active grants through the normal JIT path — rotate +
end sessions), and denied/revoked/expired names re-invite on the same row.
`POST /vendors/{id}/requests` gates on `approved` status + allow/deny lists
(deny beats allow) + the daily window before delegating to
`create_jit_request`; vendor sessions force `controls.record = true`; lazy
expiry marks past-`expires_at` rows `expired`. New **11th** sidebar screen
`vendor_access_third_party_lifecycle` renders the §13 dashboard (chain dots
M N T A, one-time seed reveal modal, requests + trail) from the account's
own row; ledger source `vendor` (**11→12**), Compliance chips **12→13**,
launcher card live, `__verify_live.mjs` **8→9** screens. Contract
**96 paths / 107 ops / 15 tags / 58 admin**; `test_vendor_pam.py` **21** +
full backend **461** (in-container **379**).

### 5b — Cloud PAM (§14)
Connector model (`cloud_connectors` per AWS/Azure/GCP/K8s) with credential
federation into the vault; discovery extension inventories cloud assets for
real when credentials are configured; K8s path issues ephemeral RBAC grants
through the existing JIT (spec: *Kubernetes → RBAC → JIT → ephemeral
privilege → audit*). Unconfigured clouds render `not connected`.

**As built (5b):** `cloud_connectors` + `cloud_events` (tables **30→32**)
and indexed `jit_requests.cloud_connector_id` + `cloud_binding` JSON (both
added through `ensure_schema`). Connector status is honest state —
`not connected` / `configured` / `connected` / `error` — and only a real
probe moves it: endpoint must be `https` (`http` loopback-only for local
dev), the probe is a real GET (vault credential revealed per call, audited;
2xx → `connected`, failure → `error` + reason, never "credentials
validated"). Inventory requires endpoint + vault credential (409 honest
otherwise); the cloud's own API answers (`GET /` → `resources[]` for the
clouds, `GET /api/v1/nodes` → `items[]` for Kubernetes), assets land under
`source=cloud` with `method=CLOUD_METHODS[provider]` as real
`DiscoveryScan` rows, and an unrecognized/failed response records an honest
failure and invents nothing. The architecture's Kubernetes path
*Kubernetes → RBAC → JIT → ephemeral privilege → audit* files a section-6
JIT request (`risk` scoring verbatim) with `cloud_binding`; consuming the
grant applies a real RoleBinding `vypam-jit-<id>` (refusal → 502 +
`rbac-binding-failed`, request stays approved), close/expiry removes it
first (`rbac-closed`/`rbac-expired`), a failed checkout after apply removes
the binding again (`rbac-aborted`), and connectors refuse deletion (409)
while grants ride them. Ledger source `cloud` (**12→13**, 13th mapper
`_map_cloud`), Compliance chips **13→14**, Target Infrastructure screen
gains the live Cloud PAM Connectors section (provider cards, table,
probe/inventory/RBAC/add actions; `file://` → dashes). Contract
**102 paths / 116 ops / 16 tags / 64 admin / 178 schemas**;
`test_cloud.py` **27** + full backend **488** (in-container **406**).

### 5c — DevSecOps PAM (§15) — ✅ shipped
CI/CD credential broker: pipeline identities (Jenkins/GitLab/GitHub/Azure
DevOps/Terraform/Ansible/ArgoCD/Docker) authenticate with an API token
`vypam-ci1.<id>.<secret>` shown once and stored as a sha256 hash;
**no static secrets in CI** — an `auto` policy releases the time-boxed
vault credential in the same call (secret exactly once), a `manual` one
queues the request for an admin approval the pipeline then releases with
its own token. The grant is checked out under the pipeline, expires on the
real clock and rotates through the §5 pipeline exactly like a JIT grant;
`allowed_targets` scope (403 + `refused` on the trail), TTL cap (400
`details.cap`), another pipeline's row → 404, revoke closes open
credentials (released ones rotate) before the token stops authenticating.
Ledger source `broker` (**13→14**, 14th mapper `_map_broker`), Compliance
chips **14→15**, JIT Access screen gains the Pipeline Credential Broker
section (policy table with one-time token reveal, credential queue with
approve/deny/close, real stat tiles). Contract
**111 paths / 129 ops / 17 tags / 74 admin / 197 schemas**;
`test_broker.py` **24** + full backend **512** (in-container **430**).

### 5d — AI-Agent PAM (§16) — ✅ shipped
Agent identities: the agent is a first-class principal — API token
`vypam-agt1.<id>.<secret>` shown once and stored as a sha256 hash,
constant-time verify; the admin token never substitutes and open dev
mode never waives it (`X-Actor` ignored, the actor on the trail is the
agent's own name). Admins declare **task scopes**: the exhaustive
`allowed_commands` allow-list (1–32 literal substrings, case-insensitive,
default-deny), optional exact `allowed_targets`, `max_minutes` cap. The
chain runs the spec's sequence — identity verification → task
verification (unknown task or target outside `allowed_targets` → 403
with the refusal recorded; window above min(task, identity) cap → 400
`details.cap`) → §7 risk evaluation (low lands `approved` with the
`agent_binding` snapshot, medium/high queue for their band's sign-offs
on the normal §6 endpoints, critical lands `blocked` with
`access-refused`) → consume = real vault checkout under the agent +
**forced recorded session** (no secret ever returned — the session *is*
the access) → the command channel enforces the task allow-list (§9
blocks still veto; an allow-listed command supersedes §9 approval holds
— the declaration is the pre-authorization, so `systemctl restart
postgresql` runs per the spec example; anything out-of-scope → incident
`agent task scope: <task>` + session terminated + `command-blocked` on
the agent trail + release and rotate) → real-clock expiry like any JIT
grant. Revoke closes open access first (active grants release and
rotate), then the token stops authenticating (401); a revoked identity's
settings and task scopes are frozen (409); deleting a task first ends
the access riding it. `jit_requests` gains `agent_id` + `agent_binding`
JSON snapshot; tables **35→38** (`agent_identities`, `agent_task_scopes`,
`agent_events`). 15 operations / 9 path keys + openapi (**120 paths /
144 ops / 18 tags / 86 admin / 218 schemas** — `agentToken` security
scheme, ADMIN_OPERATIONS 74→86) lockstep. Ledger source `agent`
(**14→15**, 15th mapper `_map_agent`), Compliance chips **15→16**, JIT
Access screen gains the AI-Agent Access section (identity table with
one-time token reveal at registration, task declaration modal, access
queue wired to approve/deny/close, real stat tiles, `file://` falls back
to dashes). `test_agent.py` **29** + full backend **541** (in-container
**459**).

---

## 9. Phase 6 — platform & scale

### 6a - HA / DC / DR (§18) - ✅ shipped
Honest single-binary HA/DC/DR: a multi-node registry where each node is
active or passive (`PAM_NODE_NAME`/`PAM_SITE`, self seeded at startup
without a trail row), real `GET {base}/health` probes against every
registered peer (https unless loopback, errors verbatim on the trail,
events only on state change), pull replication that re-hashes the peer's
chain record-by-record (`intact`/`verified`/`unverified`/
`first_break_seq` — vault ciphertext stays sealed unless this node's key
opens it → `decryptable_here`, replicas held as evidence and never
merged, self sync → 400), `_passive_node_gate` refusing every write
outside `/cluster/*` + `/auth/*` with 409 *before* auth while passive
(promote re-enables writes immediately), promote/demote failover
carrying `from`/`to` on the trail, opt-in `CLUSTER_MONITOR` where the
monitor thread runs the same tick as `POST /cluster/monitor/tick`: while
passive it probes every registered active peer and promotes this node
once all of them reached 3 consecutive real failures
(`detail.automatic` + the failing probes recorded; an active node never
auto-demotes — failback is an operator decision, a quiet clock produces
no events), and SQLite online backups copied then verified from the copy
(`chain intact over N records`, non-SQLite → 503). `/health` gained
`node`/`site`/`role`. Tables **38→44** (`cluster_nodes`,
`cluster_events`, `cluster_audit_replicas`, `cluster_secret_replicas`,
`cluster_session_replicas`, `cluster_backups`). 15 operations / 11 path
keys + openapi (**131 paths / 159 ops / 19 tags / 101 admin / 238
schemas** — ADMIN_OPERATIONS 86→101) lockstep. Ledger source `cluster`
(**15→16**, 16th mapper `_map_cluster`), Compliance chips **16→17**,
Platform Settings gains the HA / DC / DR section (registry +
register/probe/sync/remove, promote/demote, replica posture, backup
ledger, all live over `/api/v1/cluster/*`) with the gate at **33**
checks (live register → probe → sync → remove against an unreachable
peer asserting verbatim failures); runbooks in
`docs/DEPLOYMENT_RUNBOOK.md` §7. `test_cluster.py` **36** + full backend
**577** (in-container **495**).

### 6b — RBAC / ABAC
Multi-role model (today: single admin token + open dev mode): roles
(admin / approver / operator / auditor / auditor-read-only), policy bindings
on the 101 admin operations, attribute rules on vault items and targets.
Contract lockstep: security schemes gain role requirements.

### 6c — SSO + HSM enforcement
Settings schema (`sso`, `hsm`) becomes enforcement: SAML/OIDC login path and
HSM/KMS-backed key operations (PKCS#11 or cloud KMS), replacing file-based
keys where configured. Posture widget then counts them honestly as active.

---

## 10. Suggested execution order & rationale

```
4k §12 ✓ (Phase 4 complete)
        → 5a §13 ✓ → 5b §14 ✓ → 5c §15 ✓ → 5d §16 ✓   (expansion)
        → 6a §18 ✓ → 6b RBAC → 6c SSO/HSM          (scale)
```

- **4i next:** UEBA step-up responses and vendor flows both consume MFA/
  ITSM/SIEM primitives; integrations are the multiplier.
- Dashboard (§21) and docs close **inside each phase** — never a separate
  afterthought (lockstep rule).

## 11. Final product output (definition of "program complete")

The end state, measured against the architecture doc — **all values will be
real numbers collected at that time, `—` until then**:

1. **Every architecture section §1–§21 has a built, tested implementation**
   (the §1 status table above fully ✅), and §22 Feature Matrix rows match
   reality line-for-line.
2. **Console:** all 11 sidebar screens live (including Break-Glass), zero
   `data-kind="static"` surfaces, zero FORBIDDEN strings, `file://` fallback
   intact.
3. **Evidence:** one append-only ledger covering every module source (16
   sources), chain verified in CI, NDJSON + webhook export flowing to a real
   SIEM when configured.
4. **Contracts:** `apis/openapi.yaml` (path count `-`, today 131) and the
   vendor tool contract both enforced both-ways; zero dark endpoints.
5. **Quality gates:** backend suite (today **577**) grows per phase with real
   counts recorded in the READMEs; pam_master stays green (**46**); smoke,
   both UI verifiers, leak check all green at every boundary.
6. **Operations:** single-node install stays Docker-free; §18 adds replicated
   deployment with runbooks; backup/restore verified by drill.
7. **Honesty invariant (non-negotiable):** every displayed number comes from
   an API at render time — complete or not, the product never fabricates.

## 12. Change control

- New phases are appended to the master plan's checkpoint log at start and
  closed with a ☑ row + real numbers at the boundary (pattern of 4a–4f).
- Scope discovered mid-phase that doesn't fit → new phase entry here first,
  then code (plan and reality never drift).
- This document updates only at phase boundaries, alongside `docs/` README
  count refreshes, in the same commit.
