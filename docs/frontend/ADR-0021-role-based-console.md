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
