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
| `GET /screens/pam_command_center_threat_dashboard/code.html` | **live** Command Center (talks to `/api/v1/overview` + `/api/v1/events`, plus the §10 bypass section over `/api/v1/bypass/*` — ingest/scan/incidents posted on click only) |
| `GET /screens/credential_vault_secrets_inventory/code.html` | **live** Credential Vault (talks to `/api/v1/vault/*`) |
| `GET /screens/compliance_soc_2_audit_center/code.html` | **live** Compliance (talks to `/api/v1/overview`, `/api/v1/events` — a 9-source trail filter, one fetch per source on click — and the immutable `/api/v1/audit/*` ledger) |
| `GET /screens/target_infrastructure_connectors/code.html` | **live** Target Infrastructure (talks to `/api/v1/discovery/*`) |
| `GET /screens/jit_access_ephemeral_approvals/code.html` | **live** JIT access (talks to `/api/v1/jit/*`) |
| `GET /screens/live_session_recording_inspection_hub/code.html` | **live** Live Session hub (talks to `/api/v1/sessions/*`) |
| `GET /screens/policy_zero_trust_rules_engine/code.html` | **live** Zero-trust policy console (talks to `/api/v1/command-control/*` + `/api/v1/risk/*` — the §7 eight-component scorer, posted on click only) |
| `GET /screens/<name>/code.html` | any other screen |
| `GET /screens/<name>/screen.png` | preview image |

Screens are **siblings** under `screens/`, which is exactly what makes the
shared sidebar's `../<screen>/code.html` links resolve — keep new screens at
that level.

Live screens fetch on load and fall back to **honest placeholders** — never
invented values. Opened as `file://` or with the API unreachable, `—` and
"not connected" markers stay on screen; sections without a backing module say
so instead of showing numbers; when data does load, every figure comes from the
API response (the seven API-driven screens are scanned for legacy fake strings in
`../shots_tool/__verify_live.mjs`, HTTP and `file://` modes; the discovery
screen additionally runs a full UI end-to-end in
`../shots_tool/__verify_discovery.mjs` — real register, scan, ignore/restore,
adopt and filter actions against a throwaway server, and
`../shots_tool/__shots.mjs` recaptures every `screen.png`).

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
6. **No fake data, ever**: static markup, JS render paths, failure toasts and
   empty states must show only real, computed, or honestly-empty values
   (`—` / "module not connected") in every load mode (live, `file://`, API down).

## Future

Room is reserved for a bundled app (React / Next.js — the direction in the
architecture doc): keep `index.html` + `screens/` as the static reference and
drop a built app alongside (e.g. `frontend/app/`), then point a launcher card
at it. Nothing outside `frontend/` needs to move.
