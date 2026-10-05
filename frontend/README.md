# VY-PAM Frontend

The web console for VY-PAM (product requirements:
`../VY-PAM_Enterprise_PAM_Architecture.md`).

This is the **product frontend**, served by the license server at
`http://127.0.0.1:5000`. It started as a copy of the design reference in
`../stitch_pam_suite_dashboard_ui/` — that folder stays frozen as the
visual reference; **screens evolve here**.

## Layout

```
frontend/
├── index.html          # launcher: every screen, LIVE / STATIC / SPEC badges, filters
├── screens/
│   ├── <screen-name>/
│   │   ├── code.html   # one self-contained screen (markup + styles + scripts)
│   │   └── screen.png  # preview capture shown by the launcher
│   └── zero_trust_sentinel/DESIGN.md   # design tokens + system spec
└── README.md
```

## How the server serves it

| URL | Screen |
| --- | --- |
| `GET /index.html` | launcher |
| `GET /` · `GET /license` | **live** Licensing screen (talks to `/api/v1/licenses*`) |
| `GET /settings` | **live** Platform Settings screen (talks to `/api/v1/settings*`) |
| `GET /screens/<name>/code.html` | any other screen |
| `GET /screens/<name>/screen.png` | preview image |

Screens are **siblings** under `screens/`, which is exactly what makes the
shared sidebar's `../<screen>/code.html` links resolve — keep new screens at
that level.

## Adding a screen (the contract)

1. Create `screens/<snake_case_name>/code.html` — self-contained; Tailwind
   CDN + Google Fonts are the only externals, there is no build step.
2. Keep the canonical 10-item sidebar (`<nav>` with `data-path="…"` slugs and
   `../<screen>/code.html` hrefs) and exactly one `aria-current="page"`.
3. Add a launcher card to `index.html` (both `href` and preview `img` under
   `screens/`).
4. Register the folder in
   `../backend/phase2_license_server/tests/test_settings_and_ui.py`
   (`OWN_INDEX`, plus `CANONICAL_NAV` when it joins the sidebar) — the nav
   and launcher tests fail on drift.
5. Capture `screens/<name>/screen.png` at the screen's viewport size.

## Future

Room is reserved for a bundled app (React / Next.js — the direction in the
architecture doc): keep `index.html` + `screens/` as the static reference and
drop a built app alongside (e.g. `frontend/app/`), then point a launcher card
at it. Nothing outside `frontend/` needs to move.
