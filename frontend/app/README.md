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
- During migration the legacy `../screens/` pages stay reachable and the
  standing gate (`../../shots_tool/__verify_*.mjs`) stays authoritative
  until F5 (ADR-0008).

## Commands (all proven locally on node 24 / pnpm 12.11.2)

```
pnpm install --frozen-lockfile     # deps from the committed lockfile
pnpm exec playwright install chromium  # once, for the Storybook browser tests
pnpm openapi                       # regenerate src/api/generated from the contract
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
