# ADR-0006 — Forms: React Hook Form + Zod

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2

## Decision

- All forms use React Hook Form with Zod schemas as resolver; schemas
  are shared with the generated types where the contract allows.
- Validation runs client-side for UX and **server-side always** — the
  client rules are never the security boundary (checklist D/F).
- Duplicate-submission protection: submit buttons disable in-flight;
  approval/rotation endpoints stay idempotent server-side.

## Consequences

- One place per endpoint for field limits that mirror the backend
  schema (`max_length` in the settings registry, etc.).
