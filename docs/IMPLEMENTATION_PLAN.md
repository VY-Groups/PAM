# VY-PAM — Implementation Plan (remaining architecture coverage)

**Status:** maintained through Phase 4h — remaining backlog starts at 4i
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
| §19 Immutable Audit | hash chain, 10 sources, verify/export | ✅ built | 4e |
| §10 PAM Bypass Detection | direct-access detection | ✅ built | **4g** |
| §17 Break Glass | emergency protocol (dual approval → recorded session → rotation) | ✅ built | **4h** |
| §20 Enterprise Integrations | IAM/MFA/ITSM/SIEM/SOAR/EDR | ⛔ pending (export seam only) | **4i** |
| §11 AI Security / UEBA | behavior baselines, anomaly response | ⛔ pending | **4j** |
| §12 Dynamic Watermarking | contextual session overlay | ⛔ pending (custody string only) | **4k** |
| §13 Third-Party / Vendor PAM | vendor invite → JIT flow | ⛔ pending | **5a** |
| §14 Cloud PAM | AWS/Azure/GCP/K8s connectors | ⛔ pending | **5b** |
| §15 DevSecOps PAM | CI/CD JIT credential broker | ⛔ pending | **5c** |
| §16 AI-Agent PAM | agent identity + task-scoped access | ⛔ pending | **5d** |
| §18 HA / DC / DR | multi-node, replication, failover | ⛔ pending | **6a** |
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
**Tests:** `test_integrations.py` — `—` (external calls tested against
local stub servers, never mocked domain behavior).
**Done when:** a configured TOTP factor actually gates a medium-band session
start, a configured ITSM key is really verified, and SIEM push moves real
ledger records — with every unconfigured path rendering `not connected`.

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
**Tests:** `test_ueba.py` — `—`.
**Done when:** an actor deviating from their own recorded baseline produces a
critical evaluation with named reasons, a real block/cascade, and preserved
evidence — all from real history rows.

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

---

## 8. Phase 5 — enterprise expansion

### 5a — Third-Party / Vendor PAM (§13)
Vendor lifecycle *Invite → MFA → NDA/Agreement → Ticket → Approval → JIT →
Recording → Automatic expiry* on top of existing JIT/vault/session machinery;
`vendor_accounts` model + vendor-scoped dashboard (access/denied lists, time
window, recording state per spec example). Reuses 4i MFA and ITSM ticket
verification for the real gate.

### 5b — Cloud PAM (§14)
Connector model (`cloud_connectors` per AWS/Azure/GCP/K8s) with credential
federation into the vault; discovery extension inventories cloud assets for
real when credentials are configured; K8s path issues ephemeral RBAC grants
through the existing JIT (spec: *Kubernetes → RBAC → JIT → ephemeral
privilege → audit*). Unconfigured clouds render `not connected`.

### 5c — DevSecOps PAM (§15)
JIT credential broker for pipelines: CI systems (Jenkins/GitLab/GitHub/
Azure DevOps) request short-lived credentials via API token + approval policy;
**no static secrets in CI** — response is a time-boxed credential that
expires like any JIT grant; Terraform/Ansible/ArgoCD use the same broker.

### 5d — AI-Agent PAM (§16)
Agent identities (`agent_identities`), task-scoped requests:
*agent identity verification → task verification → risk evaluation → JIT
credential → command restrictions → monitoring → expiry.* Command-control
gains task scope (allowed command list per agent task), producing exactly the
spec's example (`systemctl restart postgresql` ALLOW / `DROP DATABASE`
BLOCK).

---

## 9. Phase 6 — platform & scale

### 6a — HA / DC / DR (§18)
Active-active/passive nodes behind a load balancer, vault cluster with
encrypted replication, audit/session replication to immutable storage,
automatic failover + health checks. Storage engine decision (SQLite
single-node → replicated store) is the core design item; backup/restore
procedures in `docs/DEPLOYMENT_RUNBOOK.md` extend to replication runbooks.

### 6b — RBAC / ABAC
Multi-role model (today: single admin token + open dev mode): roles
(admin / approver / operator / auditor / auditor-read-only), policy bindings
on the 45 admin operations, attribute rules on vault items and targets.
Contract lockstep: security schemes gain role requirements.

### 6c — SSO + HSM enforcement
Settings schema (`sso`, `hsm`) becomes enforcement: SAML/OIDC login path and
HSM/KMS-backed key operations (PKCS#11 or cloud KMS), replacing file-based
keys where configured. Posture widget then counts them honestly as active.

---

## 10. Suggested execution order & rationale

```
4i §20 → 4j §11 → 4k §12                                (Phase 4 completion)
        → 5a §13 → 5b §14 → 5c §15 → 5d §16     (expansion)
        → 6a §18 → 6b RBAC → 6c SSO/HSM          (scale)
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
2. **Console:** all 10 sidebar screens live (including Break-Glass), zero
   `data-kind="static"` surfaces, zero FORBIDDEN strings, `file://` fallback
   intact.
3. **Evidence:** one append-only ledger covering every module source (10+
   sources), chain verified in CI, NDJSON + webhook export flowing to a real
   SIEM when configured.
4. **Contracts:** `apis/openapi.yaml` (path count `—`, today 79) and the
   vendor tool contract both enforced both-ways; zero dark endpoints.
5. **Quality gates:** backend suite (today **384**) grows per phase with real
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
