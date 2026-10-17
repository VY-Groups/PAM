# VY-PAM Console (frontend rebuild, `frontend/app/`)

The React + TypeScript rewrite of the console — the strangler app described
by the plan in the repo root and the ADRs in `../../docs/frontend/`.

- Stack (locked): React 19 + TS strict + Vite + Tailwind 4 (CSS-first
  tokens) + Vitest/Testing Library + Storybook. See ADR-0001..0012.
- Tokens: `src/styles/tokens.css` — **generated** from the as-built legacy
  config; regenerate via the documented extractor, never hand-edit values
  (ADR-0002).
- Components: `src/components/` (F2 design system) — KPI card, chip,
  status dot, button, table, modal (Radix), section header, tabs (Radix)
  and the honest-state patterns (`Value` → em-dash, `NotConnected` chip).
  Each module ships a `.stories.tsx` and a `.test.tsx` whose suite ends
  with an axe-core check (`src/test/axe.ts`, ADR-0008).
- Shell + auth + API client (F3, plan §3): `src/app/` holds the single
  AppShell (as-built sidebar/topbar classes, ADR-0005 route table under
  the `/app` basename), `RequireAuth`/`RequireRole` guards, honest
  error/404/backend-down states; `src/api/` holds the orval client
  **generated from `../../apis/openapi.yaml`** (`pnpm openapi`, never
  hand-edited — CI regenerates and fails on drift, ADR-0004), the shared
  `http.ts` wrapper (auth headers, timeouts, `{error, details}` shape,
  single backend-down signal) and session storage; `src/i18n/en.json` is
  the single string catalogue (ADR-0010); `src/features/auth/` is the
  contract-shaped login (RHF + Zod, ADR-0006). Pending feature screens
  render the honest F4-pending state with their live legacy links until
  their replacement ships (plan §8).
- Command Center (F4 screen 1, plan §4 line 105):
  `src/features/command-center/` renders the posture KPI quad, health
  strip, control-posture evidence table, activity feed and
  bypass-detection section **from live contract data only**
  (`getApiV1Overview`, `getHealth`, `getApiV1Events`,
  `getApiV1BypassStats`, `getApiV1BypassIncidents` through generated
  hooks in `queries.ts`) — honest loading / section-error (verbatim
  server message) / empty / `not connected` / shared backend-down states,
  i18n strings only, no hard-coded sample rows. The legacy
  `../screens/pam_command_center_threat_dashboard/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012) — the
  strangler keeps both reachable.
- Credential Vault (F4 screen 2, plan §4 line 106):
  `src/features/vault/` renders the vault-posture KPI quad, the
  credential inventory with its per-row lifecycle actions (check out /
  revoke / rotate-or-retry, disabled `Locked` while rotating), the
  audited one-shot **secret reveal** modal and the per-credential
  **version history** modal, plus the vault audit feed — **from live
  contract data only** (`getApiV1VaultStats`, `getApiV1VaultItems`,
  `getApiV1VaultEvents`, `getApiV1VaultItemsItemId`,
  `getApiV1VaultItemsItemIdSecret`, `postApiV1VaultItemsItemId{Checkout,
Revoke,Rotate}` through generated hooks in `queries.ts`). Actions send
  the real session principal as the contract's `X-Actor` header and
  invalidate the `['vault']` key prefix so rows re-render from server
  truth; the reveal is deliberately a **mutation** (plaintext never
  enters the query cache, cleared on modal close). Honest loading /
  section-error (verbatim server message) / empty / `not connected` /
  shared backend-down states, i18n strings only, no hard-coded sample
  rows; test fixtures are verbatim rig payloads. The legacy
  `../screens/credential_vault_secrets_inventory/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- JIT Access (F4 screen 3, plan §4 line 107):
  `src/features/jit/` renders the queue-posture KPI quad, the filterable
  request queue, the **file-a-request** modal (RHF + Zod, ADR-0006), the
  request **detail modal** (risk factors, the audit trail, quorum read
  from the server's `requested` event - never re-derived client-side -
  and the approve / deny / grant / close actions), the **Pipeline
  Credential Broker** section (identity register with its one-time token
  panel, revoke, credential approve / deny / close; `release` is
  deliberately absent - the contract authenticates it with the
  pipeline's own token) and the **AI-Agent Access** section (identities
  with enable / disable / revoke, task declare, one-time register token;
  `open` is deliberately absent - agent-token authenticated) — **from
  live contract data only** (`getApiV1Jit*`, `postApiV1JitRequests*`,
  `getApiV1Broker*` / `postApiV1Broker*` / `deleteApiV1BrokerPolicies*`,
  `getApiV1Agents*` / `postApiV1Agents*` / `patch|deleteApiV1Agents*`
  through generated hooks in `queries.ts`). Actions send the real session
  principal as `X-Actor` and invalidate the `['jit']` key prefix; grants
  bound to an agent close through the agent-access endpoint so the §16
  trail event is written, and an approved agent's grant is opened by the
  agent's own token, not by the console. Honest loading / section-error
  (verbatim server message) / empty / `not connected` / shared
  backend-down states, i18n strings only, no hard-coded sample rows;
  test fixtures are verbatim rig captures generated from
  `Temp/opencode/fixtures/*.json` (generator not committed; rig-issued
  secrets never enter the repo - synthetic token fixtures only). The
  legacy `../screens/jit_access_ephemeral_approvals/code.html` stays
  served until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- Live Session Hub (F4 screen 4, plan §4 line 108):
  `src/features/sessions/` renders the session-posture KPI quad over
  `GET /api/v1/sessions/stats`, the Live / Ended session tabs (client
  split of the limit=200 list, honest per-tab empty states, selection
  derived during render so the detail pane always mirrors a server row),
  the selected session's **event stream** (the legacy hub's duplicate
  terminal-mirror and timeline merged into one sequence-ordered tape:
  command prompts from the real actor/host, blocked actions kept as
  visible red evidence with the server's reason, withheld input said
  out loud, custody watermark sub-lines), the supervisor **toolbar**
  (pause / resume / lock / terminate gated by session state with honest
  disabled reasons and the server's verbatim message; the terminate
  outcome reports the real release-and-rotate cascade from
  `SessionEndResponse.cascade`), the seven interactive **control
  flags** (`POST /sessions/{id}/controls`, every change re-read from
  server truth - no optimistic state), the **watermark card** with the
  server-assembled payload and the section-27/8a protocol-overlay line
  in all four gateway branches (awaiting / not brokered / connected
  with the injection fact and sealed segments / ended with reason and
  node), the **governance panel** (JIT-linked vs direct, quorum from
  the server's audit trail - recorded approvals vs the `requested`
  event's `required_approvals`, never client-derived), and the
  **start** / **terminate** dialogs (RHF + Zod, ADR-0006; vault
  credential picker from `/vault/items`; submit disabled in-flight;
  success shows the server's message and risk band). The contract
  gained the nullable `SessionGateway` schema documenting the shipped
  gateway half (`apis/openapi.yaml`, client regenerated - zero backend
  behavior change). Live pixel playback stays out of scope (plan:
  "live player later") and the `complete` action plus per-event
  approve/deny have no legacy UI - API-only stays API. The legacy
  `../screens/live_session_recording_inspection_hub/code.html` stays
  served until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- Policy & Zero Trust (F4 screen 5, plan §4 line 110):
  `src/features/policy/` renders the policy KPI quad over
  `GET /api/v1/command-control/stats`, the three-tab catalog (rules /
  held-command approvals / SOC incidents) with the evaluation-order
  filter lines, rule cards over `GET /command-control/rules` and the
  create/edit dialog (RHF + Zod, ADR-0006; full contract payload, the
  terminate-requires-block rule mirrored in the UX with the server's 400
  still authoritative; DELETE carries no `X-Actor` per contract),
  approve/deny on the held commands and incident close with the
  signed-in principal as `X-Actor` (append-only resolution rows), the
  click-only **decision simulator** (`POST /command-control/evaluate` —
  GET never evaluates; default-allow and block+terminate branches
  rendered verbatim from the engine's own rule match), the §7 **risk
  engine** section (score form posting `/risk/evaluate` on click with
  the advisory-only contract note, the eight-component breakdown table
  with verbatim measured inputs, the spec band legend, the
  recent-evaluations trail) and the §11 **UEBA section** (trained
  baselines with per-dimension detail, honest empty anomalies, Train
  showing the server's own message). Every number is a live contract
  count (no hard-coded sample data), the honest states follow DoD 2
  (section error verbatim, `not connected` chips, BackendDownNotice,
  per-list empty messages), and the policy JSON export reports the real
  loaded rule count. The contract needed no fix this screen. The legacy
  `../screens/policy_zero_trust_rules_engine/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- Compliance & SOC2 (F4 screen 6, plan §4 line 111):
  `src/features/compliance/` renders the digest KPI quad over
  `GET /api/v1/audit/stats` (records with the oldest→newest window,
  chain position with the head-hash footer, sources reporting out of
  the 21 zero-filled keys, append-only triggers installed), the
  hash-chain digest card (full head SHA-256, seq chip, window, the
  `by_source` chip cloud) with the on-demand **verify walk**
  (`GET /audit/verify` on click only — idle until run; the intact
  verdict and a broken chain both render the server's own numbers,
  `broken_at` and reason verbatim), the measured **connector chips**
  from `GET /api/v1/integrations/status` (MFA / ITSM / SIEM / LDAP
  with the contract's own detail strings and the SIEM `last_push`
  line, `never` before the first batch), and the **unified trail** over
  `GET /api/v1/events?source=&limit=` (twelve source-filter chips with
  `aria-pressed`, rows carrying `#seq`, the source chip,
  action/subject/actor, relative time and the event hash, honest empty
  line; the contract's `all` state is the absent parameter). The CSV
  **export** pulls the whole ledger from `GET /audit/export`
  (`application/x-ndjson` — `http.ts` now keeps non-JSON 2xx bodies
  verbatim instead of dropping them, aligning the shared wrapper with
  the generated `string` type; test added) and reports the real record
  count. This screen has zero writes (the ledger is append-only server
  side, no `X-Actor`) and no form, so ADR-0006 has nothing to gate.
  Honest states follow DoD 2 (section error verbatim including the
  stats-backed digest, `not connected` chips, BackendDownNotice,
  em-dash KPIs). Fixtures in `src/test/complianceFixtures.ts` are
  verbatim rig captures with two clearly-labelled synthetic schema
  states (broken chain, empty trail). The legacy
  `../screens/compliance_soc_2_audit_center/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- Target Infrastructure (F4 screen 7, plan §4 line 109):
  `src/features/infrastructure/` renders the discovery KPI quad over
  `GET /api/v1/discovery/stats` + `GET /api/v1/cloud/stats` (targets
  with the PAM-status split, privileged accounts, scans run with the
  last-scan footer, connectors with the status split and error
  accent), the **real scan trigger** (`POST /discovery/scans` — a
  synchronous TCP-connect probe of the operator's scope; the dialog
  cannot invent a default scope, and an empty ports CSV keeps the
  contract parameter absent so the server uses its management-plane
  default set) with the captured **scan history** (scope, method and
  status chips, ports or the honest default-set line, probed/open/
  services counters, trigger provenance, started→finished, errors
  verbatim), the **target inventory** whose PAM-status chips, type
  chips and search drive real contract parameters (`pam_status`,
  `type`, `q` — refetched server truth, never a client re-filter),
  with asset cards (type/risk/status/source chips, ports with
  proto+service labels, vault-count linkage, the advisory
  `recommended_policy` line) offering **Ignore/Restore**
  (`PATCH pam_status` flips) and **Onboard to Vault Now**
  (`POST /discovery/assets/{id}/onboard`) — every result renders the
  server's own message — plus the **privileged-accounts panel** over
  `GET /discovery/accounts`; the **cloud connector fleet** (provider/
  status chips as contract filters, account/endpoint/registered-by
  lines, the captured last-probe detail verbatim) with **Probe**
  (`POST .../test`), **Discover** (`POST .../discover` — the server's
  409 credential refusal renders verbatim) and **Remove** behind a
  confirmation modal (`DELETE .../{id}`), all carrying the signed-in
  principal as `X-Actor` per contract, while the discovery writes
  carry none (the contract documents only `rbac:operator`); the
  **discovery event tape** over `GET /api/v1/events?source=discovery`.
  ADR-0006 gates all four forms (scan, onboard, adopt, connector):
  contract limits mirrored in Zod with the 400 still authoritative,
  including the endpoint https/loopback rule as a UX guard. Honest
  states follow DoD 2 (section error verbatim including a dedicated
  stats-failure alert over the KPIs, `not connected` chips,
  BackendDownNotice, em-dash KPIs, honest empty lines). Fixtures in
  `src/test/infrastructureFixtures.ts` are verbatim rig captures (a
  real loopback probe, real register/ignore/restore/adopt and
  connector create/probe/409-refusal/deletion round-trips, all against
  synthetic `vypam-` strings) plus two clearly-labelled synthetics
  (empty list, unmanaged-state replay for the adopt path). The legacy
  `../screens/target_infrastructure_connectors/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012); its
  "Connector Mesh Health" and connector Inventory/RBAC tabs are out of
  plan scope (the gateway mesh has its own contract surface).
- Vendor Access (F4 screen 8, plan §4 line 114):
  `src/features/vendor/` renders the registry KPI quad over
  `GET /api/v1/vendors` (accounts = the server's total, while
  invited/approved/closed count the loaded page and say so), the
  **vendor registry** whose status chips and search send real contract
  parameters (`status`, `q` — refetched server truth over name _and_
  contact, never a client re-filter), each row carrying the four
  lifecycle-step chips, activity/allowed-targets/expiry lines and the
  server's denied reason, with **Open** and **Reinvite** actions; the
  **selected-vendor dashboard** over `GET /api/v1/vendors/{id}` shows
  the chain steps with verbatim server timestamps, the captured ITSM
  check line (`INC-23892 · HTTP 200`), the NDA reference, the approval
  provenance, the access scope (allowed/denied target chips, window,
  recording, expiry), the real scoped grant (`item 1 · risk low · 30
min`) and the 20-event lifecycle trail with verbatim detail
  previews; **actions are gated on the account's state** — an invited
  account gets Verify MFA / Record NDA / Verify ITSM Ticket / Approve /
  Deny, an approved one gets Revoke / File Access Request, and a denied
  or revoked one gets none; the **invite** (`POST /api/v1/vendors`)
  mirrors the contract's name/contact/target-lines/window-pair rules in
  Zod (ADR-0006, the 400 still authoritative) and renders the
  **one-time MFA seed card** — secret and otpauth URI shown once, Hide
  drops it for good; the **scoped request** picks a real item from
  `GET /api/v1/vault/items` and keeps an empty minutes field
  contract-absent; every lifecycle write carries the signed-in
  principal as `X-Actor` per contract, and every captured refusal
  renders verbatim: the 401 bad-TOTP, the 409 ITSM-unconfigured (with
  the honest `not connected - set itsm.base_url` hint from
  `GET /api/v1/integrations/status`), the 409 missing-chain-steps, the
  403 access refusal with the server's own reason line, and the
  invite-name conflict. Honest states follow DoD 2 (section-error
  verbatim after the retry budget, honest empty lines, em-dash KPIs,
  and the shared BackendDownNotice gated on the transport error — its
  unconditional rendering on screens 3/5/7 was a real bug this screen's
  section-error test surfaced; all four pages now gate it). Fixtures in
  `src/test/vendorFixtures.ts` are verbatim rig captures of the whole
  lifecycle (invite → MFA → NDA → ticket → approve → request → revoke,
  plus the invited/denied detail states and every write refusal) with
  the one-time TOTP seeds sanitized to synthetic base32 — real one-time
  secrets never enter the repo. The legacy
  `../screens/vendor_access_third_party_lifecycle/code.html` stays
  served until the Flask app mounts `dist/` under `/app/` (ADR-0012);
  `PATCH /api/v1/vendors/{id}` stays unimplemented (no legacy surface
  needs it).
- **Screen 9 — Emergency Break-Glass** (`/break-glass`, plan line 113
  "Filing, dual approval, recorded session"):
  `src/features/break-glass/` renders the request KPI quad over
  `GET /api/v1/break-glass/stats` (total on record, awaiting approval
  with the outstanding-signatures footer, open emergencies with the
  error accent, last unseal as the raw captured ISO), the legacy
  critical banner and header chip carrying the **live factor line**
  from `GET /api/v1/integrations/status` (`not configured - the mfa
band stays advisory` on the capture rig) and the singular/plural
  open-emergency chip, the **dual-approval registry** over
  `GET /api/v1/break-glass/requests` (limit 200; the status chips send
  the contract's `status` parameter and refetch server truth, never a
  client re-filter; DataTable with the legacy columns Request/Target/
  Requested/Approvals/Status/Session/Actions; actions gated on the
  request's state — pending gets Approve/Deny posted directly with `{}`
  exactly like the legacy console, approved gets Open (unseal), used
  gets Close + review, terminals get none, and every row Inspects), the
  read-only **selected-request record** over
  `GET /api/v1/break-glass/requests/{id}` (verbatim reason,
  severity/status/mfa chips, both signatures with their notes, the
  denial block, the recorded-session card with `recording: forced`, the
  closed block with its review note — rotation is shown only from the
  close response's own `rotation` field, never fabricated), the **file
  dialog** (Zod mirrors the contract's target/reason limits and keeps
  the legacy EMERGENCY-AUTHORIZE typing guard client-only — never
  posted), the **release dialog** (legacy parity for the enrolled-factor
  path; the capture rig reports none, so the unseal posts directly and
  no code is ever faked), and the **close dialog** that always demands
  the contract-required review note; every lifecycle write carries the
  acting identity as `X-Actor` (the editable legacy input, seeded with
  the signed-in principal — the server's own rules judge it), and every
  captured refusal renders verbatim: the 403 `Requesters cannot approve
their own emergency request`, the 400 duplicate signer, the 400
  no-vault-credential. Honest states follow DoD 2 (section-error
  verbatim, em-dash KPIs, the honest no-selection placeholder, the
  shared BackendDownNotice gated on the transport error). Fixtures in
  `src/test/breakGlassFixtures.ts` are verbatim rig captures of the
  whole lifecycle (filed → 1/2 → 2/2 → opened to the used state with
  its live session → closed with the review note and the server's
  rotation answer) plus every refusal arm and the empty-registry
  baselines; no secret ever transited (the rig's global factor is not
  configured and enrolling one is irreversible app-wide, so the
  positive MFA-release path is documented in the fixtures header, not
  claimed). The legacy
  `../screens/break_glass_emergency_protocol/code.html` stays served
  until the Flask app mounts `dist/` under `/app/` (ADR-0012).
- **Screen 10 — Enterprise Licensing** (`/licensing`, replaces the nav
  target `enterprise_licensing_tier_entitlements_node_quotas` per the
  recorded decision; `license_entitlement_center` stays a separate live
  surface): `src/features/licensing/` renders the KPI quad over
  `GET /api/v1/overview`'s captured `licenses` block (total/active/
  expiring-soon/revoked with the by-tier chips; loading and failure both
  read the honest em-dash, never a zeroed quad), the contract catalog
  rail over `GET /api/v1/meta` (tiers, license types, algorithms,
  formats, the 8-module count) with the live offline air-gap ingestion
  process, the **license registry** over `GET /api/v1/licenses`
  (limit 200; the status chips, tier/type selects and free-text search
  send the contract's `status`/`tier`/`license_type`/`q` parameters and
  refetch server truth — semantics pinned by live rig probes: `status`
  matches record OR effective status, `q` is a case-insensitive
  substring over key/ID/issued-to/tier and NOT classification; DataTable
  with the legacy columns and every row Inspects), the read-only
  **license inspector** over `GET /api/v1/licenses/{key}` (identity and
  raw-vs-effective status verbatim, the 8-module entitlement grid with
  the server's per-module entitled state, the quota meters reading the
  captured consumed/quota/headroom/utilization with over-quota rows
  flagged not clamped, the four pool rows by environment with their
  enforcement levels, the payload-signature block algorithm/format/
  fingerprint, and the activity timeline from the record's own events),
  the **import dialog** (ADR-0006 Zod guards only that the paste is a
  JSON envelope with `license_data`+`signature` — signature
  verification, the duplicate 409 and every other refusal are the
  server's judgement, rendered verbatim), the **validate dialog**
  (offline-parity verdict from the pasted envelope or raw JWT, rendered
  structurally: valid/signature/registered/revoked/expired/match plus
  the entitled count), the **signed-file viewer** (json envelope and
  the raw `text/plain` jwt verbatim, dispatched by format), and the
  **revoke/restore lifecycle** (the destructive confirm records the
  reason; the server's own `License revoked`/`License restored` message
  lands on the status line and one `['licensing', ...]` key root
  refreshes every view). Honest states follow DoD 2 (section-error
  verbatim, em-dash KPIs, the honest no-selection placeholder, the
  shared BackendDownNotice + NotConnected rail on transport errors).
  Fixtures in `src/test/licensingFixtures.ts` are verbatim rig captures:
  the read side of both captured licenses plus a real write lifecycle
  minted through the product's own `LicenseGenerator` with the rig's
  bind-mounted signing key (import 201 → duplicate 409 → validate for
  each license → revoke → restore → revoke terminal; both raw jwt file
  answers; rig hygiene: the scratch license ends revoked, the demo
  license untouched). The legacy
  `../screens/enterprise_licensing_tier_entitlements_node_quotas/code.html`
  stays served until the Flask app mounts `dist/` under `/app/`
  (ADR-0012).
- **System & Workflow Maps** (`/topology`, ADR-0013 - the user-ordered
  live diagrams, contract-first): `src/features/topology/` renders five
  views, every figure derived from a real source. **Frontend**: the
  console route table extracted from `src/app/layout/nav.ts` +
  `src/app/router.tsx` with each route's ADR-0012 strangler state, the
  pending routes honestly linked to their live legacy screens, and each
  live route's `src/api/generated` client functions resolved to the
  contract operations they call. **Backend**: the three python trees
  walked on disk (`pam_master`, `phase2_license_server`,
  `ipam_licensing`; tests/conftest excluded) with per-file size and the
  drawn intra-package import edges. **API**: the `apis/openapi.yaml`
  surface grouped by the contract's own first tag, with real
  path/operation/method counts. **Network** (live): `GET /health`,
  `GET /api/v1/cluster` and `GET /api/v1/integrations/status` through
  the generated client (`expectOk`), rendered as three honest
  this-node/cluster/integrations cards - loading, `not connected` on
  transport failure, verbatim data otherwise (the capture's own texts,
  e.g. `not configured - the mfa band stays advisory`, render raw).
  **Application**: five curated workflows (license lifecycle, emergency
  break-glass, auth & RBAC, vendor onboarding, JIT access) where every
  step is a contract operation and every step's proof names a real
  fixture/test/gate marker. `src/features/topology/topology.generated.ts`
  is produced by `pnpm topology` (`scripts/topology.mjs`, never
  hand-edited): CI regenerates and fails on drift right after the orval
  step, `topology.generated.test.ts` re-parses nav, router, the contract
  and the backend trees independently and pins every workflow's
  operation and evidence file on disk, and the extractor itself refuses
  any endpoint not in the contract. The same run emits the Mermaid
  diagram docs under `docs/architecture/` (frontend-map, backend-map,
  api-surface, network-posture, workflows - rendered natively by
  GitHub) from the same extraction, so the readable architecture
  diagrams share the drift gate; the cross-check suite pins every
  doc's routes, files, operations, edges and workflow steps.
  `src/test/topologyFixtures.ts`
  holds verbatim rig captures (2026-10-16) backing the test double; the
  page itself only ever shows live answers. `yaml` is a dev-only
  dependency for the extractor/test; no diagramming dependency -
  design-system primitives only.
- During migration the legacy `../screens/` pages stay reachable and the
  standing gate (`../../shots_tool/__verify_*.mjs`) stays authoritative
  until F5 (ADR-0008).

## Commands (all proven locally on node 24 / pnpm 12.11.2)

```
pnpm install --frozen-lockfile     # deps from the committed lockfile
pnpm exec playwright install chromium  # once, for the Storybook browser tests
pnpm openapi                       # regenerate src/api/generated from the contract
pnpm topology                      # regenerate src/features/topology/topology.generated.ts
pnpm format:check                  # prettier --check
pnpm lint                          # eslint flat config (strict TS)
pnpm typecheck                     # tsc --noEmit
pnpm test                          # vitest: jsdom project + Storybook browser project (stories + axe)
pnpm build                         # production bundle into dist/
pnpm build-storybook               # static Storybook into storybook-static/
pnpm storybook                     # dev server on :6006 (component work)
```

CI runs the same commands in the `frontend-rebuild` job.

Notes:

- The Storybook browser project needs a chromium binary
  (`pnpm exec playwright install chromium`); CI runs it with
  `--with-deps` on the ubuntu runner.
- axe's `color-contrast` rule is disabled in jsdom (no layout engine
  there); contrast is checked interactively in Storybook's a11y panel and
  in the F6 accessibility pass.
