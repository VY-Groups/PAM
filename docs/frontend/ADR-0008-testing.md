# ADR-0008 — Testing: Vitest + Testing Library + fetchMock + Playwright + axe; Storybook from F2

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2, §8, §9.M/§9.O

## Decision

- Unit/component: **Vitest** + Testing Library; network mocked with the
  app's own typed **fetchMock** layer (verbatim rig-capture fixtures;
  *amended 2026-10-16*: MSW was never adopted — the custom layer in
  `src/test/fetchMock.ts` ships and is this ADR's real decision).
- E2E: **Playwright** (already used by `shots_tool/` — same engine,
  Microsoft Edge channel via `GATE_BROWSER_CHANNEL` locally and on CI).
- Accessibility: **axe-core** in CI per component/screen; axe alone is
  never claimed as compliance (manual keyboard/screen-reader passes on
  login, approval, reveal, session flows — checklist M).
- **Storybook lands with F2** (component stories + a11y checks), not F1:
  the F1 exit criteria are build + lint + typecheck green in CI.
- The custom `__verify_*.mjs` gate scripts **stay authoritative for the
  legacy screens until F5** (they are this repo's standing gate; plan F5
  retires them only when the legacy pages are gone). Playwright e2e
  defers to the F6 harness (*amended 2026-10-16*: no e2e suite exists yet —
  the F4 screen PRs documented the deferral each time).

## Consequences

- Two verification systems coexist during migration — documented here so
  nobody "cleans up" the gate early; standing rule: gate green in both
  modes before any frontend-area commit.
