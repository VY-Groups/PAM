# VY-PAM Console (frontend rebuild, `frontend/app/`)

The React + TypeScript rewrite of the console — the strangler app described
by the plan in the repo root and the ADRs in `../../docs/frontend/`.

- Stack (locked): React 19 + TS strict + Vite + Tailwind 4 (CSS-first
  tokens) + Vitest/Testing Library. See ADR-0001..0012.
- Tokens: `src/styles/tokens.css` — **generated** from the as-built legacy
  config; regenerate via the documented extractor, never hand-edit values
  (ADR-0002).
- During migration the legacy `../screens/` pages stay reachable and the
  standing gate (`../../shots_tool/__verify_*.mjs`) stays authoritative
  until F5 (ADR-0008).

## Commands (all proven locally on node 24 / pnpm 12.11.2)

```
pnpm install --frozen-lockfile   # deps from the committed lockfile
pnpm lint                        # eslint flat config (strict TS)
pnpm typecheck                   # tsc --noEmit
pnpm test                        # vitest (jsdom + Testing Library)
pnpm build                       # production bundle into dist/
```

CI runs the same five commands in the `frontend-rebuild` job.
