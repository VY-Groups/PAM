# ADR-0004 — Data layer: TanStack Query + generated OpenAPI client

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2, §3 layer rules

## Decision

- **orval** reads the contract at `apis/openapi.yaml` (repo root `apis/`,
  verified — the plan's guessed path did not exist) and generates the
  typed client into `frontend/app/src/api/generated/`. Generated code is
  never edited by hand.
- **TanStack Query** wraps every call; components never call `fetch`
  directly (layer rule 3). Query keys live in `src/api/queryKeys.ts`.
- Revealed secrets use a **mutation**, never a cached query: nothing
  sensitive enters the cache, localStorage, the URL or logs; state clears
  on remask/navigation (plan §6).
- **SSE for live session streams and audit counters is deferred** until the
  gateway lands (plan §2) — the design reserves a `live/` module for it.

## Consequences

- Contract-first backend discipline pays off directly in typed UI code.
- A contract change regenerates the client in CI; drift fails the build.
- Backend-down state is implemented once in the shared API wrapper
  (plan §5) so every screen degrades identically.
