# ADR-0021: Role-based console — role journeys, navigation and permission contract

Status: **APPROVED FOR IMPLEMENTATION — owner sign-off 2026-10-21**, verbatim:
"do all as i was instructed vibe coading not allowed" (after "do all"). The brief's
step-2 human-review step was waived by that owner instruction; Amendment 1 records
exactly what the waiver covers and what must still be re-validated with real
approver/operator/auditor users before the requester phase. No role-program UI code
existed when this record was approved (step 1 evidence + spec only), per the rule
"no UI code before the spec exists". Every proposal here is anchored to
evidence; anything unproven is an explicit open question, not a guess.

## Context — step-1 role audit (evidence, pasted)

Audited on a disposable rig (`vypam-rigaudit`, token mode, own DB): one real console user per seeded
role, each through the real first-sign-in ladder (forced change → TOTP enrolment → session mint), then
every page's primary load API probed with that role's session. Raw captures kept outside the repo tree
(`Temp/role-audit-raw.log`, `Temp/role-audit.md`, script `Temp/audit-roles.ps1`); the essentials are
pasted inline here so the record is self-contained.

Seeded roles (verbatim `RBAC_SEED_ROLES`, `models.py:2663-2669`): `admin`, `approver`, `operator`,
`auditor`, `auditor-read-only`. **Requester and vendor do not exist** (`models.py:2656-2662`).

### Load matrix (65 probes; route → primary load API, status per role)

| Role | ops | cc | vault | jit | sess | infra | policy | comp | lic | b/g | vend | users | sec | set |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| admin | 145 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 |
| operator | 48 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | **403** | 200 | 200 |
| approver | 13 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | **403** | 200 | 200 |
| auditor | 34 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 |
| auditor-ro | 31 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 |

Route → load API: `/command-center`→`/api/v1/overview`, `/vault`→`/api/v1/vault/items`,
`/jit`→`/api/v1/jit/requests`, `/sessions`→`/api/v1/sessions`, `/infrastructure`→`/api/v1/discovery/assets`,
`/policy`→`/api/v1/command-control/rules`, `/compliance`→`/api/v1/audit/stats`, `/licensing`→`/api/v1/licenses`,
`/break-glass`→`/api/v1/break-glass/requests`, `/vendor-access`→`/api/v1/vendors`, `/users`→`/api/v1/users`,
`/security`→`/api/v1/auth/mfa/factors`, `/settings`→`/api/v1/settings`. `/topology` is static client data.

The only screen returning 403 on load for any role: **`/users` for operator and approver**. Verbatim:

```json
{"details":{"operation":"get /api/v1/users","role":"operator"},"error":"Role 'operator' may not call GET /api/v1/users"}
```

### whoami already carries the permission contract per session

Verbatim shapes (audit): `{"kind":"user","mode":"token","principal":"aud-approver","role":"approver",
"operations":["post /api/v1/jit/requests/{request_id}/approve", …13 decision ops…],
"operations_count":13,"scope":{}}`. Counts: admin 145 (= `ADMIN_OPERATIONS`), operator 48, approver 13,
auditor 34, auditor-read-only 31 (the 3-op diff is exactly `cluster/export/sessions`, `cluster/export/vault`,
`licenses/{license_key}/file` — matches the seed descriptions). `operations` is computed server-side from
`ROLE_OPERATIONS`, which CI pins to the OpenAPI document (`tests/test_openapi_contract.py:133-148`).

### Navigation today

No role filtering exists: `Sidebar.tsx:39-45` filters `NAV_ITEMS` by label text only; the role badge is
displayed (`Sidebar.tsx:189`) but filters nothing. All five roles see all 14 routes and the same landing
page (`/command-center` → `/api/v1/overview`, 200 for everyone).

### Key finding

Only operations present in `ROLE_OPERATIONS` are enforced. Page-load reads that are not role operations
(`/vault/items`, `/settings`, `/audit/stats`, …) succeed for any signed-in role — which is why the
approver loads nearly everything. Enforcement is the real control; visibility must follow the contract.

## Scope of this record

The five seeded roles now; the requester/end-user role and the vendor view are open questions (below).
Backend `ROLE_OPERATIONS` stays the enforcement source of truth — this record only governs what each
role's console *shows*, and how actions are gated and explained.

## Role journeys (proposal for review — jobs taken from the brief's own role table, not invented)

### approver — landing: Approvals inbox (new, step 5)
1. Review JIT access requests (risk, requester, ticket context) — `post /api/v1/jit/requests/{request_id}/approve|deny`
2. Review break-glass requests — `post /api/v1/break-glass/requests/{request_id}/approve|deny`
3. Review vendor access windows — `post /api/v1/vendors/{vendor_id}/approve|deny`
4. Review brokered credentials — `post /api/v1/broker/credentials/{credential_id}/approve|deny`
5. Decide session command-control events — `post /api/v1/sessions/{session_id}/events/{seq}/approve|deny`
Also held: emergency grants, factor-recovery, gateway node approvals (13 ops total).
Visible pages (proposal): Command Center, Approvals inbox. Everything else hidden — **open question 3**.

### operator — landing: vault/targets view (step 5)
1. Check out vault credentials — `post /api/v1/vault/items/{item_id}/checkout` (+ rotate/revoke)
2. Run and control sessions — pause/lock/resume/terminate/complete (`post /api/v1/sessions/…`)
3. Discovery and onboarding — `post /api/v1/discovery/scans`, `…/assets/{asset_id}/onboard`
4. Gateway/cluster day-2 — drain, backups, failover, monitor tick
5. File break-glass and close incidents — `post /api/v1/break-glass/requests`, `…/close`
Visible pages (proposal): Command Center, Vault, Sessions, Infrastructure, Break-glass.
Hidden: Identity(/users), Security(/security), Licensing, Settings, Compliance(evidence), Policy — **open question 5**.

### auditor — landing: evidence view (step 5)
1. Verify the audit chain — `/compliance` (read)
2. Export evidence — `get /api/v1/cluster/export/sessions|vault`, `get /api/v1/licenses/{license_key}/file`
3. Read-only views of every surface (34 read ops incl. `/users`, `/roles`, `/role-bindings`)
4. Gateway recordings and playback — `get /api/v1/gateway/sessions/{id}/recording…`
5. Reports — `get /api/v1/auth/report`, `/auth/deliveries`
Visible pages: all read surfaces; writes hidden with a stated reason (step 6 pattern).

### auditor-read-only — same as auditor, minus exports
Same journeys; the 3 export ops are absent (evidence: `operations_count` 31 vs 34). Export affordances
must render disabled with a reason, never silently absent.

### admin — everything, grouped by job
All 145 admin operations; landing keeps Command Center ("needs attention" first). No hidden pages.

### requester / end-user, vendor (external) — open questions 1–2, not designed here

## Navigation grouping (proposal)

Groups by job, not module: **Access** (Vault, JIT, Break-glass, Vendor-access, future My-Access),
**Approvals** (inbox, new), **Sessions** (Sessions), **Evidence** (Compliance, later Recordings/Reports),
**Platform** (Users, Security, Settings, Licensing, Infrastructure, Policy, Topology).
Command Center remains the landing, outside the groups.

## Decisions proposed (to be confirmed in review)

- **D1 — permission map**: do **not** add a CI-generated `can()` file. Nav items declare required
  operation strings; the shell filters against `whoami.operations` (already contract-derived and
  CI-pinned). Zero hand-written role lists, zero drift, zero extra artifacts. This meets the intent of
  the instruction ("frontend holds no hand-written role lists"); flag for explicit sign-off since the
  instruction literally said "generate a map in CI".
- **D2 — guard scope**: server-side role-guards stay as they are (`get /api/v1/users` pattern) unless
  review names a concrete read that must become guarded. Visibility is enforced client-side by D1;
  every API still fails closed with a verbatim 403.
- **D3 — action gating**: disabled controls render a reason ("requires approver role"); server 403s
  always surface verbatim (existing `expectOk` pattern).
- **D4 — scope display**: whoami's `scope` field is displayed on the profile ("scoped to N targets")
  when non-empty; today it is `{}` for all audited roles.
- **D5 — matrix tests**: per role — visible nav set, landing, one allowed action, one denied action's
  verbatim 403; plus "hidden route renders a friendly not-available-for-your-role page" (new route
  gate). Backend enforcement remains the real control.
- **D6 — docs**: the UI brief navigation section and PAM_FLOW describe navigation per role, generated
  from the OpenAPI operation↔role table by a CI script (topology.mjs pattern) so counts cannot drift.

## Open questions for the human reviewers (do not answer by guessing)

1. Add the requester/end-user role now (recommended: yes — My Access and the vendor view depend on it),
   or after the assignment model (safes/groups) lands?
2. Vendor external view: same decision, tied to assignment model.
3. Approver visibility: inbox-only, or also read access to the request lists inside JIT/Break-glass/
   Vendor pages for context?
4. Multi-role bindings: whoami reports a singular `role`; confirm nav must filter on the union of
   `operations` if a principal holds several bindings (backend behaviour to verify in review).
5. Operator on `/policy` and `/compliance`: confirm both hidden per the brief's role table.
6. Landing pages for operator/admin: confirm the proposal above before step-5 build order
   (approvals inbox + auditor evidence view first, per the brief).

## Amendment 1 — owner sign-off resolutions (2026-10-21)

- **D1–D6 CONFIRMED** as proposed.
- **D2 amended (partly superseded):** the brief's "backend enforcement stays the real
  control" plus "generate permissions from the contract" require the read contract to
  be completed. The step-1 audit proved page-load reads are self-service today
  (approver `GET /api/v1/vault/items` = 200), so `whoami.operations`, the nav filter
  and the server 403s cannot yet tell one story. Scheduled as batch **12.RB** (read
  grants in `ROLE_OPERATIONS` + `apis/openapi.yaml` security scopes + docs-count
  lockstep + rig re-audit), sequenced after 11.11 lands — recorded, not silently
  skipped. Until 12.RB, nav visibility below is narrower than the brief's
  read-only-views row for the auditors (and for pages where no job read op exists).
- **Q3 resolved (brief-literal):** approver nav = `/approvals` only — "Should not see:
  Everything else". Recorded deviation, single waived-review open item: `/command-center`
  and `/topology` declare no required operations (always visible for everyone), so an
  approver can reach those two read-only surfaces; hiding them would need an artificial
  admin-only marker operation.
- **Q4 dissolved:** the shell filters on exactly what `whoami` returns
  (`operations: string[] | 'all'`); there is no client-side role arithmetic to reason
  about, and multi-binding union semantics remain the server's business.
- **Q5 resolved by the table below:** it supersedes the draft's per-role "Visible
  pages" lists. Visibility = declared job operations only; the brief's own job tables
  and not-see lists decided which operations each item declares.
- **Requester role + vendor console view:** later phase, dependent on the assignment
  model (safes/groups) — the brief's own suggested order, not skipped silently.

### Approved navigation contract — `NAV_JOB_OPS` (any-of; strings verbatim from the
step-1 whoami captures; admin holds all; open mode `'all'` shows all)

| path | declared operations (any-of) | admin | operator | approver | auditor | aud.-r.o. |
|---|---|---|---|---|---|---|
| /command-center | *(none — always visible)* | ✓ | ✓ | ✓dev | ✓ | ✓ |
| /approvals | `post /api/v1/jit/requests/{request_id}/approve` ∨ `post /api/v1/break-glass/requests/{request_id}/approve` ∨ `post /api/v1/vendors/{vendor_id}/approve` ∨ `post /api/v1/broker/credentials/{credential_id}/approve` ∨ `post /api/v1/sessions/{session_id}/events/{seq}/approve` | ✓ | ✗ | ✓ | ✗ | ✗ |
| /vault | `post /api/v1/vault/items/{item_id}/checkout` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /jit | `post /api/v1/jit/requests` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /break-glass | `post /api/v1/break-glass/requests` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /vendor-access | `post /api/v1/vendors/{vendor_id}/requests` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /sessions | `post /api/v1/sessions` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /infrastructure | `post /api/v1/discovery/assets` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /policy | `post /api/v1/command-control/rules` ∨ `post /api/v1/command-control/incidents/{incident_id}/close` | ✓ | ✓ | ✗ | ✗ | ✗ |
| /compliance | `get /api/v1/auth/report` ∨ `get /api/v1/cluster/export/sessions` ∨ `get /api/v1/cluster/export/vault` | ✓ | ✗ | ✗ | ✓ | ✓ |
| /users | `get /api/v1/users` | ✓ | ✗ | ✗ | ✓ | ✓ |
| /security | `get /api/v1/auth/sso/sessions` | ✓ | ✗ | ✗ | ✓ | ✓ |
| /licensing | `get /api/v1/licenses/{license_key}/file` | ✓ | ✗ | ✗ | ✓ | ✗ |
| /settings | `put /api/v1/settings/{group}` | ✓ | ✗ | ✗ | ✗ | ✗ |
| /topology | *(none — always visible)* | ✓ | ✓ | ✓dev | ✓ | ✓ |

`✓dev` = the recorded deviation above. Operator's not-see list (Identity/RBAC, HSM,
SSO, licensing, settings) maps 1:1 to the ✗ column; operator's extra ✗ on
/compliance is the "no job read op exists" narrowing resolved by 12.RB.

### Landing pages (ordered operations rule — no role names anywhere)

1. holds `put /api/v1/setup/profile` → `/command-center` (admin-only op in the captures)
2. else holds any `/approvals` declared op → `/approvals`
3. else holds `get /api/v1/auth/report` → `/compliance` (both auditors)
4. else holds `post /api/v1/sessions` → `/sessions` (operator: "Targets and live sessions")
5. else → `/command-center`

### Navigation grouping — the brief's five job groups replace ADR-0020 Decision 3's
six module groups (amends ADR-0020 by reference): **Access** (/vault, /jit,
/break-glass, /vendor-access), **Approvals** (/approvals), **Sessions** (/sessions),
**Evidence** (/compliance), **Platform** (/command-center, /infrastructure, /policy,
/users, /security, /settings, /licensing, /topology).

## Sequencing (per the governing instruction)

1. ✅ Step 1 role audit (this record's context).
2. 🔄 Step 2 this record — draft done; **blocked on real reviewers**.
3. Steps 3–4 D1 filtered navigation (small, safe) after review.
4. Step 5 landings: approvals inbox, auditor evidence, then operator/admin.
5. Steps 6–9 gating, scope display, matrix tests, honest states — folded into each of the above.
6. Step 10 docs generated in the same change as each step.

## Amendment 2 — step-6/D6 build record (12.RC, 2026-10-21)

Implementation notes against the approved contract; no decision changes.

- **D3 as built:** `ACTION_OPS` (`RoleGate.tsx`) maps 37 named actions to
  their contract operation; `canOperate(op, whoami)` mirrors the route gate
  (`'all'` → true, unresolved whoami → fail open, otherwise membership).
  Call sites use the house disabled+reason pattern (`disabled` plus `title`
  from `roleReasons.*` in `en.json` — exactly two strings exist: "requires
  approver role" and "requires administrator role", no per-role reason
  zoo). Every `ACTION_OPS` value is pinned to `API_OPERATIONS` by
  `RoleGate.test.tsx` — the same drift rule as `NAV_JOB_OPS`.
- **`RequireRole.tsx` deleted:** the hand-written role allow-list component
  was dead code and the D1 anti-pattern; its friendly-page coverage lives
  in `RoleGate.test.tsx` now, and the orphaned `errors.roleForbidden*`
  i18n keys were removed with it.
- **Four operations deliberately not client-gated:** `get
  /api/v1/audit/export`, `get /api/v1/audit/verify`, `post
  /api/v1/licenses/validate`, `post /api/v1/command-control/evaluate`
  appear in no `whoami` list (admin included), so gating on them would
  disable buttons the server may allow. They stay enabled and any server
  refusal surfaces verbatim — D3's second half. Batch **12.RB**'s read
  grants make them gate-able.
- **D6 as built:** `docs/architecture/role-console.md` is generated by
  `topology.mjs` from `nav.ts` (NAV_GROUPS/NAV_JOB_OPS) and
  `apis/openapi.yaml` security scopes (rbacToken/ldapTicket lists =
  `ROLE_OPERATIONS`, pinned by `tests/test_openapi_contract.py`); the
  navigation sections of the UI brief (§1.3) and PAM_FLOW (§1.1) describe
  the same contract in job terms and link the generated matrix.

## Amendment 3 — batch 12.RB contract, queued (2026-10-22)

The read half of D2: make `whoami.operations`, the nav filter and the
server's own 403s tell **one** story, so the console can gate what the
server would refuse. Scope fixed by Amendment 1 (D2): read grants in
`ROLE_OPERATIONS` + `apis/openapi.yaml` security scopes + docs-count
lockstep + rig re-audit. Every fact below was read in the tree at
`c754851`; nothing is estimated.

| Fact | Evidence |
|---|---|
| `whoami` reports only **admin operations** a role may call; the admin role holds all of them | service.py:11423-11433 (`operations_for_role`), :11139 (`ADMIN_OPERATIONS`) |
| the role grants are built rule-wise: every admin GET goes to `auditor` + `auditor-read-only`, **except** the secret reveal (nobody) and the evidence exports (`auditor` only — which is why the read-only auditor does not hold `/licensing`); `approver`/`operator` get only their explicit sets, so their lists carry **no read op at all** | service.py:11386-11408 (`_build_role_operations`), :11376-11383 (the two exception sets) |
| the vault **list** read is not an admin operation at all (`get .../secret` is; `get /api/v1/vault/items` is not) and its route carries **no guard** → it is self-service: any authenticated session answers 200 and no role grant can ever describe it | service.py:11147-11151; routes.py:876 (no `@require_admin`); the step-1 audit's approver `GET /api/v1/vault/items` = 200 |
| the openapi scope lists (`rbacToken`/`ldapTicket`) are the `ROLE_OPERATIONS` mirror, enforced **both ways** — every admin operation's scopes must equal its role set | tests/test_openapi_contract.py:133-147 |
| promoting a read to an admin operation changes the document: the documented admin operations must equal `ADMIN_OPERATIONS` (+ whoami), so its `security` gains the admin header | tests/test_openapi_contract.py:120-130; openapi.yaml:192, :4735 (`rbacToken: []` = admin-only) |
| the four operations no role holds (admin included) are why their buttons stay ungated | Amendment 2 above (:239-245) |
| the approved nav contract and the one recorded narrowing (operator's `/compliance` — "no job read op exists") | Amendment 1: the table :178-194, the note :196-198 |
| 12.RC's shipped baseline to re-run and widen | `Temp/role-403-12rc.md` (ops 145/48/13/34/31, verbatim 403s), `Temp/captures-12rc-summary.md` (per-role nav sets, gate strings, disabled-with-reason) |

**The read matrix, as the brief's row and the shipped role data imply**
(brief §1.3 per role; `service.ROLE_OPERATIONS` / `service.ADMIN_OPERATIONS`
read straight out of the shipped module, cross-checked against the nav sets
12.RC captured live):

| role (the brief's row) | route it keeps | the read that route needs | state in the shipped tree |
|---|---|---|---|
| operator (Access group, Sessions, Infrastructure, Policy) | /vault | `get /api/v1/vault/items` | not an admin operation — self-service |
| | /jit | `get /api/v1/jit/requests` | not an admin operation — self-service |
| | /break-glass | `get /api/v1/break-glass/requests` | not an admin operation — self-service |
| | /vendor-access | `get /api/v1/vendors` | not an admin operation — self-service |
| | /sessions | `get /api/v1/sessions` | not an admin operation — self-service |
| | /infrastructure | `get /api/v1/discovery/assets` | not an admin operation — self-service |
| | /policy | `get /api/v1/command-control/rules` | not an admin operation — self-service |
| approver (the Approvals inbox) | /approvals | `get /api/v1/jit/requests`, `get /api/v1/break-glass/requests`, `get /api/v1/vendors` | not admin operations — self-service |
| | /approvals | `get /api/v1/broker/credentials` | **an admin operation granted to `auditor`/`auditor-read-only` only — the approver is refused (403)**, and 12.RC's inbox reads exactly this queue (frontend/app/src/features/approvals/queries.ts:95). Observed live on the rig: `GET /api/v1/broker/credentials` -> **403** `{"details":{"operation":"get /api/v1/broker/credentials","role":"approver"},"error":"Role 'approver' may not call GET /api/v1/broker/credentials"}`, while the inbox's other three queues answer 200 — and the approver's whoami carries 13 operations, **all of them writes, no read at all** (Temp/inbox-approver-12rc.md) |
| auditor (Evidence, Users, Security, Licensing) | /compliance, /users, /security, /licensing | `get /api/v1/auth/report`, `get /api/v1/users`, `get /api/v1/auth/sso/sessions`, `get /api/v1/licenses/{license_key}/file` | all four already admin operations, and the grants already match the brief (the licence file is an evidence export → `auditor` only — which is why the read-only auditor does not see /licensing) |
| auditor-read-only (Evidence, Users, Security) | /compliance, /users, /security | the same three, minus the licence file | already granted |

**The reads, taken from the pages themselves.** The reads a surface
needs are not a guess: they are what that page's own query hooks call
(`frontend/app/src/features/<page>/queries.ts`), read out of the shipped
tree. Per the brief's rows:

| surface (the role that keeps it) | the reads its page calls |
|---|---|
| /vault, /jit, /break-glass, /vendor-access (operator) | `get /api/v1/vault/items` + `/vault/items/{id}` + `/vault/stats` + `/vault/events`, `/jit/requests` + `/jit/requests/{id}` + `/jit/stats`, `/break-glass/requests` + `/break-glass/requests/{id}` + `/break-glass/stats`, `/vendors` + `/vendors/{id}`, `/agents` + `/agents/{id}` + `/agent-access/requests` + `/agent-access/stats`, `/broker/policies` + `/broker/stats` + `/broker/credentials` |
| /sessions (operator) | `/sessions` + `/sessions/{id}` + `/sessions/{id}/events` + `/sessions/stats` |
| /infrastructure (operator) | `/discovery/assets` + `/discovery/accounts` + `/discovery/scans` + `/discovery/stats`, `/cloud/connectors` + `/cloud/stats` |
| /policy (operator) | `/command-control/rules` + `/command-control/incidents` + `/command-control/stats` + `/command-control/approvals`, `/risk/anomalies` + `/risk/baselines` + `/risk/evaluations` + `/risk/stats` |
| /approvals (approver) | `/jit/requests`, `/break-glass/requests`, `/vendors`, `/broker/credentials` |
| /compliance, /users, /security, /licensing (auditors) | `/audit/export` + `/audit/verify` + `/audit/stats`, `/users`, `/auth/mfa/factors`, `/licenses` + `/licenses/{key}` + `/licenses/{key}/file` |
| /settings (admin only) | `/settings` + `/settings/audit`, `/roles` + `/role-bindings`, `/cluster` + `/cluster/backups`, `/hsm/status`, `/auth/emergency` + `/auth/sso/status` |

**What is excluded, and why** — the decisions that keep the promotion
honest:

- **The passive three stay open**: `GET /health`, `GET /api/v1/cluster`,
  `GET /api/v1/integrations/status` are the shipped passive reads (the
  shell reads them before a session exists); they are not admin
  operations by design and this batch does not touch them.
- **The secret reveal stays admin-only**: `get
  /api/v1/vault/items/{id}/secret` is in neither the operator's nor the
  approver's set (the house rule: the reveal is never a day-2 read).
- **The evidence exports keep their rule**: `get
  /api/v1/licenses/{key}/file` and the cluster exports stay the
  auditor's, never the read-only auditor's (service.py:11374-11383).
- **The four operations no role holds** (Amendment 2) are promoted with
  the role their own page needs: `get /api/v1/audit/export` → the
  auditor (the export rule), `get /api/v1/audit/verify` → both
  auditors, `post /api/v1/licenses/validate` → the auditor and the
  admin (the licensing page the auditor keeps), `post
  /api/v1/command-control/evaluate` → the operator and the admin (the
  session console the operator keeps). After that all four become
  client-gate-able — which is what Amendment 2 said 12.RB would do.

So the batch's backend delta is **the reads behind the operator's and the
approver's own screens** — the seven list reads named above plus the
detail reads behind them (`/vault/items/<id>` routes.py:897,
`/jit/requests/<id>` :1022, `/sessions/<id>` :1127 and its events :1133,
`/vendors/<id>` :1907, `/break-glass/requests/<id>` :1773 - all of them
unguarded too) — **plus one missing grant** (the approver on the broker
list, which is the one queue its own inbox cannot read today); the
auditors need nothing new. The exact list is settled in the batch's own
contract record before any code is written, because the count moves
every printed number. The admin-only surfaces' own reads
(`/settings` routes.py:514, `/settings/audit` :522) are in the same
class — unguarded reads of a surface no other role keeps.
The four operations no role holds (Amendment 2) get the same treatment:
each is given the role its own page needs, by the same brief-row method.

**Decided shape (smallest complete):**

- **One grant rule, no arithmetic in the client:** each nav route's
  declared read operation is granted to exactly the roles the brief's
  read-only-views row lists (Amendment 1:169-171), and the same list
  lands in that operation's `rbacToken`/`ldapTicket` scopes — the
  contract test enforces the mirror, so the two cannot drift.
- **A read behind an admin surface is promoted into
  `ADMIN_OPERATIONS`** with its documented security, which makes it
  **guarded, not self-service**. The guard is a decorator, so the
  promotion is three things together, not one: the route carries
  `@require_admin` (routes.py:234, the gate at :198-204), the
  (method, path) joins `ADMIN_OPERATIONS` (the policy, and the count),
  and the operation's `rbacToken`/`ldapTicket` scopes list the roles
  that may read it - the document's security entries and the runtime
  guards are the same set, enforced both ways
  (tests/test_openapi_contract.py:120-130, :133-147). Today the reads
  behind the operator's and the approver's screens have **no guard at
  all** - `get /api/v1/vault/items` (routes.py:876),
  `/jit/requests` (:993), `/sessions` (:1074), `/command-control/rules`
  (:1252), `/discovery/assets` (:1395), `/break-glass/requests` (:1755),
  `/vendors` (:1886) - so any authenticated session reads them; the
  one inbox read that *is* guarded, `/broker/credentials` (:2276), is
  the one the approver is refused on. That moves the admin-operation
  count and every per-role count, so every number that prints them
  (PRD, the READMEs, the generated `role-console.md`) updates in the
  same commit — the docs-count lockstep of the batch scope. The places
  that print them, for the lockstep list: `tests/test_sso.py:858,860`
  (asserts 145), `docs/SECURITY_COMPLIANCE.md:82,88,239` (the
  admin/operator/auditor/auditor-read-only/approver counts),
  `docs/PRD.md:176,187`, `docs/TRD.md:780`, `docs/API_REFERENCE.md:18`,
  `docs/BACKEND_SCHEMA.md:656`, `docs/TESTING_QA_STRATEGY.md:55`, the
  generated `docs/architecture/role-console.md` and
  `docs/architecture/api-surface.md`, and the frontend's own pins
  (`nav.test.ts` against `API_OPERATIONS`, `RoleGate.test.tsx`'s role
  matrix).
- **The nav contract widens, the drift rules do not:** `NAV_JOB_OPS`'s
  any-of lists gain the read operations the widened grants carry; the
  existing drift tests (`nav.test.ts`, `RoleGate.test.tsx` against
  `API_OPERATIONS`) must pass unchanged, and no role name appears in
  either file.
- **Evidence bar:** backend contract tests (the two openapi contract
  tests plus a per-role whoami/403 matrix), the rig re-audit (fresh
  five-role whoami + 403 probe, and REA captures of the widened nav sets
  and the newly gate-able buttons), and the docs-count lockstep check.

**Open item (one, and it is a text conflict, not a guess):** the per-role
read matrix is the brief's read-only-views row, read column by column —
but two in-repo texts disagree on one cell. The brief (§1.3) lists the
operator as keeping "the Access group, Sessions, Infrastructure and
Policy" and does **not** list Compliance, while this ADR's own note
(:196-198) calls the operator's ✗ on `/compliance` "the 'no job read op
exists' narrowing resolved by 12.RB". **This record's reading:** the
brief's row governs — it is the owner's per-role statement, it matches
the contract this ADR's Amendment 2 built and pinned (the nav table at
:178-194, the matrix tests, and the 12.RC live capture, where the
operator's nav has no Compliance), so Amendment 1's forward-looking
note is superseded and **12.RB grants the operator no compliance read**.
If the owner says otherwise, that is one grant plus the `/compliance`
cell of the nav contract — it does not touch anything else in the
batch, so 12.RB proceeds on the rest of the matrix meanwhile.
