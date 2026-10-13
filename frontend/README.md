# VY-PAM Frontend

The web console for VY-PAM (product requirements:
`../VY-PAM_Enterprise_PAM_Architecture.md`).

This is the **product frontend**, served by the license server at
`http://127.0.0.1:5000`. It started as a copy of the Stitch design
reference (removed in the frontend-rebuild F0, `../docs/frontend/ADR-0011`);
**screens evolve here**. The VY-PAM React rebuild lives in **`app/`**
(decisions: `../docs/frontend/ADR-*.md`).

## Layout

```
frontend/
├── index.html          # launcher: every screen, LIVE / SPEC badges, filters
├── login.html          # console login: /auth/login (+ MFA step when
│                       # challenged), session stored in sessionStorage,
│                       # redirect to the launcher
├── vendor/             # offline assets: tailwind.min.js + font CSS/woff2
│                       # (no CDN, no external URLs)
├── app/                # VY-PAM React rebuild (strangler app, F3 shell done,
│                       #   F4 screen 1 Command Center live; see app/README.md)
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
| `GET /login.html` | **live** console login (POST `/api/v1/auth/login`; honest MFA step on a `mfa_required` challenge, honest enrolment-required message otherwise; stores the session bearer + CSRF twin in `sessionStorage`, then redirects to the launcher) |
| `GET /` · `GET /license` | **live** Licensing screen (talks to `/api/v1/licenses*`) |
| `GET /settings` | **live** Platform Settings screen (talks to `/api/v1/settings*`, plus the §18 HA/DC/DR section over `/api/v1/cluster*` — registry, probe/sync, promote/demote, backups, the §10 RBAC/ABAC section over `/api/v1/roles`, `/api/v1/role-bindings*`, `/api/v1/auth/whoami` — role directory, bindings, grant form, one-time token — and the 6c SSO + HSM enforcement lines over `/api/v1/auth/sso/status` + `/api/v1/hsm/status`, and the 7 Identity & Login Security section over `/api/v1/settings/auth|webauthn|smtp|sms|radius|scim` + `/api/v1/users*` + `/api/v1/auth/deliveries` + `/api/v1/auth/emergency` + `/api/v1/settings/scim/rotate` - group cards with exact schema fields, the users table, measured OTP deliveries, and the sealed emergency-admin card with its dual-control open request) |
| `GET /screens/pam_command_center_threat_dashboard/code.html` | **live** Command Center (talks to `/api/v1/overview` + `/api/v1/events`, plus the §10 bypass section over `/api/v1/bypass/*` — ingest/scan/incidents posted on click only) |
| `GET /screens/credential_vault_secrets_inventory/code.html` | **live** Credential Vault (talks to `/api/v1/vault/*`) |
| `GET /screens/compliance_soc_2_audit_center/code.html` | **live** Compliance (talks to `/api/v1/overview`, `/api/v1/events` - a 22-chip trail filter (All + 21 sources incl. the 8a `gateway` trail), one fetch per source on click - and the immutable `/api/v1/audit/*` ledger, plus the §20 SIEM push chip over `/api/v1/integrations/status`) |
| `GET /screens/target_infrastructure_connectors/code.html` | **live** Target Infrastructure (talks to `/api/v1/discovery/*` + the §14 cloud connectors over `/api/v1/cloud/*` — honest connector states, probe/inventory/RBAC actions posted on click only, `file://` fallback shows dashes) |
| `GET /screens/jit_access_ephemeral_approvals/code.html` | **live** JIT access (talks to `/api/v1/jit/*`, plus the §15 Pipeline Credential Broker over `/api/v1/broker/*` and the §16 AI-Agent Access section over `/api/v1/agents*` + `/api/v1/agent-access/*`) |
| `GET /screens/live_session_recording_inspection_hub/code.html` | **live** Live Session hub (talks to `/api/v1/sessions/*`; 8a: the watermark card's protocol-overlay line is wired to the detail's gateway half - connected/ended/ honest not-connected naming the reason - exported as `window.hubLive.gateway` for the gate) |
| `GET /screens/policy_zero_trust_rules_engine/code.html` | **live** Zero-trust policy console (talks to `/api/v1/command-control/*` + `/api/v1/risk/*` — the §7 eight-component scorer, posted on click only, with the §11 UEBA layer: the Anomalies subsection - trained baselines, per-reason deviation chips and the incident chain, fed by `/api/v1/risk/baselines` + `/risk/anomalies`) |
| `GET /screens/break_glass_emergency_protocol/code.html` | **live** Emergency Break-Glass (talks to `/api/v1/break-glass/*` — file/approve/deny/open/close posted on click only - the open action demands a TOTP `mfa_code` when a factor is enrolled) |
| `GET /screens/<name>/code.html` | any other screen |
| `GET /screens/<name>/screen.png` | preview image |

Screens are **siblings** under `screens/`, which is exactly what makes the
shared sidebar's `../<screen>/code.html` links resolve — keep new screens at
that level.

Live screens fetch on load and fall back to **honest placeholders** — never
invented values. Opened as `file://` or with the API unreachable, `—` and
"not connected" markers stay on screen; sections without a backing module say
so instead of showing numbers; when data does load, every figure comes from the
API response (the twelve API-driven screens are scanned for legacy fake strings in
`../shots_tool/__verify_live.mjs`, HTTP and `file://` modes, which also
asserts that no screen references an external URL; the discovery
screen additionally runs a full UI end-to-end in
`../shots_tool/__verify_discovery.mjs` — real register, scan, ignore/restore,
adopt and filter actions against a throwaway server, and
`../shots_tool/__shots.mjs` recaptures every `screen.png`).

## Console login & demo data

`login.html` is the console's front door: the shipped auth policy is
fail-closed (`auth.mfa_required=True`), so a password-only login only works
once a factor is enrolled or an admin has relaxed the policy. For local
demo/CI rigs, `../tools/demo_seed.py` fills a fresh rig **through the public
API only**: it relaxes `mfa_required` via the audited
`PUT /api/v1/settings/auth`, creates the demo users + local RBAC bindings
(one-shot tokens printed once), and imports an enterprise license signed
offline with the rig's own keypair. Idempotent; `--admin-token` for a
token-mode rig, `--private-key` when the rig trusts an ephemeral keypair
(the CI job does exactly this). Real deployments keep MFA required.

## Adding a screen (the contract)

1. Create `screens/<snake_case_name>/code.html` — self-contained; the
   vendored Tailwind + fonts under `../vendor/` are the only style sources
   (no externals, no build step).
2. Keep the canonical 11-item sidebar (`<nav>` with `data-path="…"` slugs and
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

## Future — the VY-PAM rebuild (supersedes this note)

The Front-End Rebuild Plan (repo root) replaces these pages with a
React + TypeScript app in **`app/`** (F1 scaffolded 2026-10-13; F4 screen 1
— Command Center — replaced its route the same day, legacy page still
served until the `/app/` mount lands, ADR-0012); every
decision is an ADR in `../docs/frontend/`. Strangler rules: legacy URLs
stay reachable until each screen's replacement ships (F4),
`../shots_tool/__verify_*.mjs` remains the standing gate until F5, and
the bundle is served under `/app/` until the legacy pages are gone
(`ADR-0012`). Nothing outside `frontend/` needs to move.
