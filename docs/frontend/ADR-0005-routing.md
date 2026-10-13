# ADR-0005 — Routing: React Router, short stable routes, /app basename during migration

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §4 (screen mapping), §7 (build/serving)

## Decision

- React Router with the plan's §4 route table: `/command-center`,
  `/vault`, `/jit`, `/sessions`, `/infrastructure`, `/policy`,
  `/compliance`, `/licensing`, `/break-glass`, `/vendor-access`,
  `/settings` (plus planned `auth`, `users-roles`, `change-control`,
  `gateways`). Long export slugs are retired with their screens.
- During the strangler migration the router runs with
  `basename: "/app"` while Flask serves the bundle under `/app/`
  (ADR-0012); legacy URLs stay untouched. At F5 the basename collapses
  to `/` in one config line.
- Deep links and refresh must work (checklist K); unknown client routes
  render a real 404 page; unknown assets return a real 404 (never
  index.html).

## Consequences

- Gate/verify scripts assert legacy URLs until each screen's F4 PR;
  new Playwright e2e covers `/app/*` from F3 on.
