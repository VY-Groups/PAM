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
- During migration the legacy `../screens/` pages stay reachable and the
  standing gate (`../../shots_tool/__verify_*.mjs`) stays authoritative
  until F5 (ADR-0008).

## Commands (all proven locally on node 24 / pnpm 12.11.2)

```
pnpm install --frozen-lockfile     # deps from the committed lockfile
pnpm exec playwright install chromium  # once, for the Storybook browser tests
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
