# ADR-0001 — Framework: React 19.3 + TypeScript (strict) + Vite

**Status:** Accepted 2026-10-13 (locked by Yash Kumar Dubey, rebuild plan §11)
**Amended 2026-10-13:** React **19.3** (current stable) instead of 18 — user
re-confirmed the §2 wording "React 18 (or the current stable)" against the
registry (React 18 is two majors behind; all current tooling targets 19).
**Plan ref:** Front-End Rebuild Plan §2, §3

## Decision

The new VY-PAM console is a React 19.3 application written in strict
TypeScript and built with Vite. Source lives in `frontend/app/`
(see ADR-0012 for the location rationale).

## Alternatives considered

- **Flask/Jinja + HTMX** — smaller attack surface, no second build chain,
  stays inside the existing Flask app. Rejected: the plan warns (and the
  roadmap's live session views, playback and gateway streams confirm) that
  server-rendered partials will outgrow the pattern; typed client code from
  the OpenAPI contract is a first-class goal.
- **Keeping the current vanilla/inline-script pages** — they are the legacy
  being strangled (frozen-HTML discipline does not scale, inline scripts
  block the strict CSP).

## Consequences

- Build-time dependency on Node (already present: CI uses windows-latest,
  node 24) — runtime stays air-gapped: `vite build` output is static.
- Strict CSP becomes achievable (no inline scripts) once legacy pages are
  retired (ADR-0012, F5).
- Every screen replacement ships with tests and deletes its legacy page
  (plan §8 per-screen DoD).
