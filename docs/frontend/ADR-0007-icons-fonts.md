# ADR-0007 — Icons and fonts: self-hosted Material Symbols, Geist + JetBrains Mono via fontsource

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2; brief §1.1

## Decision

- Icons: **Material Symbols Outlined**, self-hosted (matches the 11-item
  sidebar and every existing screen; no CDN at runtime).
- Fonts: **Geist** (UI) and **JetBrains Mono** (code/badges), self-hosted
  via `@fontsource` packages bundled by Vite. Both are open source.
- The legacy `frontend/vendor/` fonts stay for the legacy pages; the new
  app bundles its own copies (same visual result, build-hashed).

## Consequences

- The build works fully offline (plan §7); no external URL appears in
  any page (existing `__verify_live.mjs` external-URL assertion keeps
  passing for legacy, applies to the bundle by CI).
