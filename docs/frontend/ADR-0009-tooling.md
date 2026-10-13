# ADR-0009 — Tooling: pnpm + lockfile, ESLint flat config, Prettier, strict TS

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2 (package manager), §10 (rules 4-5)

## Decision

- **pnpm** with a committed `pnpm-lock.yaml` (installed locally:
  pnpm 12.11.2 via `npm i -g pnpm`; CI installs the pinned version).
  npm fallback is documented if CI ever blocks pnpm, but the lockfile
  format stays pnpm.
- ESLint (flat config) + Prettier; `eslint-plugin-boundaries` (or
  dependency-cruiser) enforces the layer rules of plan §3 in CI.
- TypeScript `strict: true`, no implicit any; lint rules ban
  `dangerouslySetInnerHTML` and hard-coded sample numbers (plan §5).
- CI additions (rebuild F1 skeleton): `pnpm install --frozen-lockfile`,
  `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`, later
  `pnpm audit` (plan §10 rule 4).

## Consequences

- `frontend/app/node_modules/` and `frontend/app/dist/` are gitignored;
  lockfile is tracked.
