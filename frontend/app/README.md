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
