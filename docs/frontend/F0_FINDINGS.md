# Frontend rebuild F0 — findings and cleanup record

**Plan ref:** `VY-PAM — Front-End Rebuild Plan and PAM-Adapted Quality Checklist.md`
§9.A (inventory + prioritised findings), F0 (decisions and cleanup).
**Date:** 2026-10-13 · Decisions: ADR-0001..0012 in this directory.

## What was audited (real commands, real output)

- Repo-wide brand scan: `AegisPAM|STITCH SCREENS|aegispam_enterprise_security_logo`
  across `frontend/`, `(?i)aegis|stitch` across the repo, `cdn.tailwindcss.com`,
  `AB6AX|vendor/img`, `screen.png` references, gate/backend/doc assertions on
  every string that was a rename candidate (grep of `shots_tool/` + `backend/`).
- Result: **no gate check and no backend test asserted any user-visible brand
  string** — the only hard assertions on brand-adjacent text were the ones listed
  under P1/P3 below.

## Prioritised findings

### P1 — removed in this F0 commit (live, always-visible surfaces)

| # | Finding | Location | Fix | Verification |
|---|---|---|---|---|
| 1 | Sample brand in launcher chrome: `<title>`, h1, "STITCH SCREENS" kicker, footer | `frontend/index.html` | VY-PAM strings, kicker → "ZERO-TRUST PRIVILEGED ACCESS" | exact-count byte replacements, count asserted per literal; gate open+token modes green after |
| 2 | Sample brand in login: title, h1, file-note | `frontend/login.html` | "VY-PAM Console" | as above |
| 3 | Sample brand in all 13 screen sidebars: Stitch-generated logo image (`aegispam_enterprise_security_logo/screen.png`) + `AegisPAM` wordmark | `frontend/screens/*/code.html` | new neutral shield mark `frontend/vendor/img/vy-pam-mark.svg` (same glyph as the inline shield, no letterform, no fabricated logo art — ADR-0011) + `VY-<span class="text-primary">PAM</span>`; license screen keeps its inline shield, aria-label renamed | recapture 13/13, previews visually checked (sidebar renders mark + VY-PAM, no broken image) |
| 4 | Sample brand in screen `<title>` and hero/prose copy | settings title; licensing copy ×2; vault prose; infrastructure copy ("Aegis Connector…AegisPAM gateway mesh") | renamed to VY-PAM wording | exact-count replacements; verify_live (112) green after |
| 5 | Stitch design reference suite committed in repo (14 Stitch screenshots, sample names, headshot image) | `stitch_pam_suite_dashboard_ui/` (root) | `git rm -r`; docs references updated in same commit | repo-wide grep afterwards: no `stitch` outside docs history notes; no test/gate referenced it (verified by grep before delete) |
| 6 | Orphan logo spec folder (Stitch wordmark SVG source + png used as sidebar logo) | `frontend/screens/aegispam_enterprise_security_logo/` | `git rm -r`; `__shots.mjs` SKIP entry removed (stale) | `aegispam_enterprise_security_logo` grep → 0 refs in `frontend/`; `WIRED_SCREENS` never included it (tests unaffected, `test_settings_and_ui` 33 passed) |

### P2 — tracked, dies with the legacy screens (F4/F5), not touched now

| # | Finding | Why deferred |
|---|---|---|
| 7 | Decorative Stitch-generated jpgs (`frontend/vendor/img/AB6AX*`) still rendered by legacy screens (settings/infra headers, JIT avatars) | Removing them is per-screen surgery on pages that F4 deletes anyway; each such screen's own PR is the honest place (per-screen DoD #6). The new React app never adopts them — goal "no generated images" holds for all new code from F1. |
| 8 | Runtime-purged design blocks contain sample brand ("Aegis Guard kernel hook…", `[AEGIS SENTINEL DETECTED]`, `aegis-quarantine`, `[AEGIS-POLICY] …marcus.brody`) | These phrases are in `__verify_live.mjs`'s FORBIDDEN list — proof they never render live (purged by the wiring, hidden in `file://` mode). Editing inside purge-matched blocks risks breaking the wiring; they are deleted with their screen at F4. |
| 9 | Legacy inline `tailwind.config` + inline scripts (13× duplication, blocks strict CSP) | Retired per screen (F4); strict CSP lands at F6 after F5 removes inline scripts (ADR-0012). |

### P3 — accepted deliberately (see ADR-0011), not oversights

| # | Finding | Rationale |
|---|---|---|
| 10 | sessionStorage keys `aegispam_admin_token` / `aegispam_admin_csrf` / `aegispam_current_license` | Internal identifiers, not branding. The standing gate writes them via `addInitScript` and every screen reads them; renaming before the legacy login dies (F5) buys nothing and risks the gate. |
| 11 | License-id format `LIC-####-AEGIS-SEC-*`, issuer default `licensing.aegispam.internal` | Embedded in signed licenses and asserted by `test_license_spec.py`/`test_api.py` — a backend compatibility decision, not UI. |
| 12 | Settings placeholder values in static markup (`aegis-corp.okta.com`, `hsm-cluster-k10-east.prod.aegis.internal`, `aegispam-immutable-worm-audit-prod-01`) | Runtime-replaced by API values (ids present); mirror backend schema defaults that tests assert. Backend defaults are a separate contract decision. |
| 13 | `identity.py` password-denylist entry `aegispam` | Security control (denylist); harmless and useful. |

### Open items for the user (plan §11)

- **Final logo/wordmark** (interim: neutral shield mark, ADR-0011) and the
  trademark/licence check on anything a generator produces.
- Remaining §11 decisions already locked 2026-10-13: framework (React 18+TS+Vite),
  single theme v1, English-first i18n.

## Deviation recorded (ADR-0012)

Plan F0 says "remove screenshots from the repo (keep them as CI artifacts)".
The per-screen `frontend/screens/<slug>/screen.png` files are **runtime UI
assets** — the launcher renders them as preview cards and
`backend/.../tests/test_settings_and_ui.py::test_launcher_links_every_screen`
asserts their presence. They stay in the repo, recaptured by
`shots_tool/__shots.mjs`. No review-artifact screenshots exist elsewhere in the
repo (the only other committed pngs were the deleted Stitch suite's).

## Verification evidence (step 9, run 2026-10-13)

| Check | Result |
|---|---|
| `node shots_tool/__verify_agent.mjs` (open mode, :5000) | ALL CHECKS PASSED (83) |
| gate token mode (BASE=:5001, `GATE_ADMIN_TOKEN`) | ALL CHECKS PASSED (90, incl. RBAC flow) |
| `node shots_tool/__verify_live.mjs` | ALL CHECKS PASSED (112, HTTP + file://) |
| `node shots_tool/__verify_discovery.mjs` | ALL CHECKS PASSED (58) |
| `node shots_tool/__shots.mjs` | 13 captured, 0 failed |
| `pytest backend … test_settings_and_ui.py -q` | 33 passed |
| `pytest backend … test_openapi_contract.py -q` | 9 passed |
| `pytest pam_master -q` | 46 passed |
| boundary smoke (`Temp\opencode\smoke_restructure.py`, recreated) | 17/17 |
| `python tools/demo_seed.py` (idempotency on :5000) | 0 created, all "already exists" |
| `pytest backend -q` (full, 794 baseline) | 794 passed in 1:02:35 |

## Pre-existing red found by this boundary (fixed here)

`test_api.py::test_license_screen_served_at_root_and_license` asserted
`"cdn.tailwindcss.com" in html` — stale since the vendor-offline work of the
frontend-completion phase: the served screen references
`../../vendor/tailwind.min.js` and the literal `cdn.tailwindcss.com` existed
nowhere in the file at `HEAD` (proven with `git show HEAD:…`), so the test was
red at `f3ac3c0`, independent of F0 changes. Fixed to assert
`"vendor/tailwind.min.js" in html` (the honest, vendored reality; the no-CDN
property itself is enforced by `__verify_live.mjs`'s external-URL assertion).
