# ADR-0002 — Styling: Tailwind compiled at build time, one tokens file, single theme v1

**Status:** Accepted 2026-10-13 (single-theme choice locked by the user, §11)
**Plan ref:** Front-End Rebuild Plan §2, §5; `docs/UI_UX_DESIGN_BRIEF.md` §1.1

## Decision

- Tailwind is compiled at build time from one tokens file. The Tailwind
  CDN runtime script (used by the legacy pages) is forbidden in the new app.
- The tokens are transcribed from the as-built brief
  `docs/UI_UX_DESIGN_BRIEF.md` §1.1 (Material-3-style semantic palette,
  `#004ac6` primary, Geist/JetBrains Mono type scale, space/radius scale).
- **One theme for v1.** The tokens file keeps a reserved dark-palette slot
  so F6 hardening can add dark mode without component rework; v1 ships the
  light theme matching the current console.
- No component hard-codes a color; everything reads a token.

## Alternatives considered

- Dark mode in the first release (rejected: contrast work across every
  component doubles the F6 pass; decision deferred to F6 with no rework).
- Keeping the legacy inline `tailwind.config` blocks (rejected: runtime
  compiler, duplicated 13×, incompatible with a bundled app).

## Consequences

- Deviations live in one file; CI can lint that feature code uses only
  token classes (F6 rule).
- The legacy pages keep their own inline Tailwind config until deleted
  per screen (F4).
