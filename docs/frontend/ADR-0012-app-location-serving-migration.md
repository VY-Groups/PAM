# ADR-0012 — App location, serving and strangler coexistence

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §3 (structure), §7 (build/serving), §8 (migration)

## Decision

- The new app lives in **`frontend/app/`** (package.json, `src/`,
  `e2e/`, `.storybook/`, `vite.config.ts`). The plan's §3 tree applies
  rooted there. Rationale: Vite's default entry is `<root>/index.html`,
  which collides with the existing launcher `frontend/index.html`; a
  subdirectory keeps the strangler clean and matches the note already in
  `frontend/README.md` ("drop a built app alongside e.g. frontend/app/").
  The plan author explicitly had not seen the repo and asked to verify.
- **Serving:**
  - During migration: Flask serves `frontend/app/dist` under **`/app/`**
    with SPA fallback for valid client routes (*not yet mounted — pending;
    today Flask serves only the legacy suite*, amended 2026-10-16);
    unknown asset paths → real
    404; `/api/*` keeps JSON `{error, details}` errors; legacy URLs
    (`/index.html`, `/login.html`, `/screens/*`, `/`, `/license`,
    `/settings`) are untouched.
  - At **F5** (legacy retired): the bundle moves to `/`, `/index.html`
    redirects to `/`, `/screens/*` return 404. One-line router basename
    change (`/app` → `/`).
- Hashed assets long-cache; `index.html` no-cache (plan §7). Fonts/icons
  bundled; build fully offline.
- **`file://` operation applies only to legacy screens** (honest dashes /
  disabled controls, brief §3.2). The React app is served exclusively by
  Flask and has a real backend by construction.
- **Strict CSP (`script-src 'self'`, no inline) ships at F6** — the
  legacy pages are built from inline scripts and IIFEs, so CSP can only
  go strict after F5 removes them (or via a temporary relaxed interim;
  not worth it — F5→F6 is days).
- During migration the legacy screenshots
  (`frontend/screens/<slug>/screen.png`) are **runtime UI assets** (the
  launcher renders them, backend tests assert them), not documentation
  screenshots — they stay in the repo, recaptured by
  `shots_tool/__shots.mjs`. This is a deliberate deviation from plan F0's
  "remove screenshots" (the plan asked to verify against the repo; the
  intent — no review-artifact clutter — holds: there are none outside
  `screens/` and the deleted Stitch reference).
