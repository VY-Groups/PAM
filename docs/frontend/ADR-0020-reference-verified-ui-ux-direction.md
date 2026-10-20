# ADR-0020: Reference-verified UI/UX direction (Teleport + OpenBao + legacy IA)

|             |                                                                                         |
|-------------|-----------------------------------------------------------------------------------------|
| Status      | Accepted (user-directed pivot, 2026-10-20)                                              |
| Decision    | Redesign the console as a **mix of three references** — shipped Teleport web UI patterns, OpenBao/Vault shell patterns, and VY-PAM's own legacy screen IA — "so that it will look like a new tool": distinctive VY-PAM identity, reference-informed structure. |
| Supersedes   | — (direction only; ADR-0001..0012 framework/design decisions still hold)               |
| Evidence    | `Temp/teleport-ui-carve/` extraction logs + `_all_literals.txt`/`_ui_study.txt`; HTTP probes of `:5000` in session log; `Temp/openbao-src/ui/` (read-only) |

## Why (user report, 2026-10-19/20)

The user tried to access the frontend from **two paths** (their answer, verbatim):
`docker compose up` and `http://127.0.0.1:5000 (README)` — and saw "code.html failing",
"a big failure", and a Stitch-generated UI they judge "very bad". Verified state:

| Fact | Evidence |
|------|----------|
| No containers survived the Docker Desktop restart (compose leg = total failure) | `docker ps` → only `vypam-pg119`; compose maps **5010:5000** (`backend/phase2_license_server/docker-compose.yml`), so the compose entry is `:5010` |
| Entry page `/` (license screen) serves fine but its **relative sidebar links 404 in browser context** (`../<screen>/code.html` clamps to root) | literal probe `GET /break_glass_emergency_protocol/code.html` → **404**; contract pins `/` itself to 200 + license content (`tests/test_api.py:163-175`, `tests/test_settings_and_ui.py:417-421`) |
| React console serving is healthy | `/settings` → 302 → `/app/settings`; shell 407 B; `index-CodazOre.js` **1,160,515 B** 200; CSS 51,046 B 200 (literal-URL probes) |
| Two legacy folders have no `code.html` (HTTP 404) | `platform_settings_center` (strangled by 11.5/ADR-0015 — only `screen.png` remains) and `zero_trust_sentinel` (only `DESIGN.md` — *intent to verify in the fix batch*) |

Note: an earlier probe wave falsely reported "everything 116059 bytes" — a `.NET Uri`
relative-resolution quirk collapsed `../` probes onto `/` (werkzeug log: 11× `GET /`).
Corrected with literal URLs only.

## Reference 1 — Teleport v18.10.0 web UI (REA shipped-artifact extraction)

**Artifact**: `Temp/rea-evidence/teleport-dist/teleport/teleport`, ELF x86_64,
sha256 `3f3cc3ea0b0feed8fe786dec2ceda125b3059a3e4d53b96ea37633886deb5e31`
(pinned by `rea.open_binary`). The release tarball ships **no separate web dir**
(`tar -tzf` filter: only helm/terraform examples) — the UI is embedded.

**REA provider diagnostics (verbatim summary)**: `search_strings` on this target is
blocked on win32 — hopper `unsupported_host` (macOS-only), ghidra `not_configured`
+ `target_format_unsupported` (Windows Ghidra P0 accepts PE only), ida/kuna
`not_configured`. With the artifact identity pinned by REA, assets were therefore
**carved locally** (stdlib ELF section parse → Go `embed` pointer table
`{name ptr,len,data ptr,len}` in `.rodata` → brotli). Scripts: `Temp/carve_teleport_ui.py`,
`Temp/map_teleport_ui.py`, `Temp/extract_teleport_assets.py`, `Temp/study_teleport_ui.py`.

**Extracted (verified)**:

| Asset | Result |
|-------|--------|
| `index.html` shell | verbatim in `_carve_log.txt`: `<script type="module" crossorigin src="/web/app/app.js">`, `<link … href="/web/app/index.css">`, `<div id="app">`, light+dark favicons via `prefers-color-scheme` |
| `app.js.br` → brotli | 928,008 B → **4,188,263 B** JS (minified ESM; starts `var e=Object.create,…`) |
| `index.css` | 14,042 B (opens with the Ubuntu `@font-face` ladder 300/400/500/700) |
| `favicon-light.png` | 1,093 B, valid PNG |
| asset manifest | **385** embedded names: 310 SVG icons (many light/dark pairs incl. vendor logos), 37 `.br`, 24 fonts, 13 PNG |

**UX signals mined from the bundle** (full lists in `Temp/teleport-ui-carve/_ui_study.txt`,
`_all_literals.txt` = 19,234 literals):

- **IA / route map — 75 `/web/...` routes**: resource-first cluster scoping
  (`nodes, apps, databases, desktops, kubernetes, sessions, recordings, audit,
  console, resources, discover`), governance (`accessrequest, requests, roles,
  users, sso, locks, trust, devices, mfa, account/*`), automation (`bots,
  integrations/*, managedupdates, instances`), platform (`clusters, tokens,
  settings, support, downloads`).
- **UI vocabulary — 1,491 multi-word labels**: unified empty states
  (`No Nodes Found`, `No Recordings Found`, `You have not pinned any resources`),
  action verbs (`Enroll…`, `Create…`, `Add…`, `Manage…`), toolbar language
  (`Filter by resource type`, `Sort by`, `Newest first`), status pattern
  (`Status: Healthy|Initializing|Unhealthy`), form hints (`Type a role name and press Enter`).
- **Semantic token layer**: `text.main|primary|secondary|muted|slightlyMuted|
  disabled|primaryInverse`, `primary`, `secondary`, `error(.main|.hover)`,
  `success(.main|.active)`, `warning(.main|.active)`, `info`.
- **Palette evidence**: navy/slate ramp (`#010B1C #0C143D #1F2549 #222C59 #2F3659
  #344179 #4C516E #546E7A`) with teal/cyan accents (`#2EFFD5 #66D9CA #74EEFF #00D3F0`).
- **Layout vocabulary**: flex/typography value set (`column row wrap flex-start
  space-between sticky ellipsis uppercase …`).

## Reference 2 — OpenBao web UI (local source, read-only)

**Policy compliance**: `Temp/openbao-src/AGENTS.md` rejects AI-generated contributions
to the OpenBao project while allowing conversational/read analysis of the codebase.
This reference is used **for reading only**: patterns are re-implemented in our own
React/Tailwind code; **no OpenBao source file is copied into VY-PAM** (which also keeps
us outside the MPL-2.0 file-level copyleft), and no issue/PR is ever filed there.

**Shell pattern** (`ui/app/components/sidebar/frame.hbs`):

- `Hds::AppFrame` with sidebar; responsive `Hds::SideNav` structured as
  **header** (home link logo + actions: console toggle button, user menu) /
  **body** (portal target that screens register nav links into) /
  **footer** (namespace picker = context switcher).
- `Frame.Main#app-main-content` doubles as the **skip-link a11y refocus target**
  (`@a11yRefocusSkipTo`), contains a modal wormhole, and a **slide-in console
  drawer** (`main--console-open` + `Console::UiPanel`) — an always-available
  terminal panel beside page content.
- Design-token naming pattern `--token-side-nav-color-surface-*`; 14 px bold menu
  labels; `data-test-*` hooks on every structural node.

## Reference 3 — VY-PAM legacy IA (scope that stays)

The 14 `frontend/screens/*` domains remain the functional scope (break-glass,
compliance, credential vault, enterprise/licensing, JIT, license entitlement,
session recording, command center, infrastructure connectors, zero-trust policy,
vendor access, sentinel, platform settings/idp-hsm) — `platform_settings_center`
already strangled to `/app/settings` (ADR-0015); `zero_trust_sentinel` served-set
status to verify. The React app already mirrors these domains as 15 feature areas
(`frontend/app/src/features/*`).

## Decision — the synthesis (what gets built)

1. **Shell**: app frame with persistent left side nav — OpenBao frame *mechanics*
   (header/body/footer regions, responsive collapse, skip-link refocus, slide-in
   drawer), Teleport-style *IA depth*. Header = VY-PAM mark (ADR-0011) + global
   search/actions; footer = node/cluster context switcher + user menu.
2. **Console drawer**: adapt the slide-in drawer as the **live session terminal /
   recording inspector** — the PAM-native analogue of Vault's console panel.
3. **Navigation IA**: map VY-PAM's domains into resource-first groups
   (Access & Sessions · Infrastructure · Identity & Access · Policy & Compliance ·
   Vault & Secrets · Platform) instead of the legacy 14-isolated-pages model;
   every legacy domain keeps a route (strangler rule, ADR-0005/0015).
4. **Copy vocabulary**: adopt the reference patterns for empty states
   (`No <thing> Found`), filter/sort toolbars, and `Status: …` chips — as new i18n
   keys (ADR-0010), English-first.
5. **Tokens**: extend the F2 design system with the semantic naming layer
   (`text.muted`, `surface.*`, state colors) **using the VY-PAM brand palette**
   — Teleport's navy/teal and Vault's greens are evidence of how leaders structure
   tokens, not colors to copy. Distinct identity per the user: "a new tool".
6. **P0 defect fixes before the redesign lands** (contract-pinned, separate batch):
   - Entry `/` dead links: serve the screens at root-relative URLs via a
     root-mirror route (`/<folder>/<path>` → `UI_ROOT/screens/<folder>/<path>`,
     API-refusal guard like `suite_files`) **or** absolute hrefs — decided at
     implementation with the two `/`-200 contract tests updated in the same commit.
   - Compose leg: rebuild/rerun guidance (`docker compose up --build`, entry `:5010`).
   - Verify no sidebar still links the two 404 screens.

### P0 batch contract — verification + decided approach (2026-10-20, pre-implementation)

All three P0 items were checked read-only against the tree while the 11.9
in-container battery still runs (house rule: no source edits mid-battery):

| Item | Result | Evidence |
|------|--------|----------|
| Compose rebuild/rerun guidance | **already lands inside the 11.9 batch** | `backend/phase2_license_server/README.md:201-208` (staged): `docker compose up --build` → host **5010**, plus the same-image in-container suite line |
| Sidebars linking the two 404 screens | **clean — zero references** | literal scan of every `frontend/screens/**/*.html`: no mention of `platform_settings_center` or `zero_trust_sentinel`; launcher exclusion pinned by `tests/test_settings_and_ui.py:402`, sentinel's served-set status pinned by `:466` (`/screens/zero_trust_sentinel/DESIGN.md` only) |
| Entry `/` dead relative links | **open — fix decided** | the license screen served at `/` carries `../<folder>/code.html` hrefs; in browser context at root these clamp to `/<folder>/code.html` → 404, because only `/screens/<folder>/…` is served (`app.py:202-221`) |

**Decided fix: root-mirror route, not absolute hrefs.** Add
`GET /<folder>/<path:screen_path>` serving
`UI_ROOT/screens/<folder>/<screen_path>` (the literal folder `screens` maps to
the same root the existing route serves), reusing `suite_files`' exact
API/health refusal and `resolve()` + `relative_to()` traversal guard.
Absolute hrefs were rejected: they rewrite 14 sidebars and silently drop the
on-disk sidebar-target assertion (`tests/test_settings_and_ui.py:379-382`
skips absolute hrefs). New contract tests in the same commit: every wired
screen folder answers 200 at its root-mirror URL, and `/api/…` + `/health/…`
still refuse as 404. Both `/`-200 contract tests (`tests/test_api.py:163-175`)
stay unchanged. Implementation was pulled forward ahead of the 11.9 commit at
the user's direction ("complete this project ASAP"); it lands as its own batch
immediately after 11.9, staged path-by-path so nothing leaks into the 11.9
commit (app.py edits are unstaged; the test file carries 11.9-staged content
plus unstaged P0 additions until the P0 batch stages them).

### Shell/IA batch contract — pre-implementation (2026-10-20)

The shell/IA redesign (Decisions 1–3) lands as its own unnumbered batch
immediately after the P0 batch (11.10/11.11/12.0 are contractually pinned by
ADR-0017/0018 and were not renumbered for it). Every input below was read
from the tree before any code was written.

**Decision 1 — shell frame (mechanics pinned):**

| Region | Content | Honest data source |
|--------|---------|--------------------|
| Sidebar header | VY-PAM mark (unchanged) + filter input | Client-side nav filter over the 14 routes — the contract has **no `/search` endpoint**, so the input filters sidebar links only and is labelled "Filter navigation" (never "global search") |
| Sidebar body | The six groups below, one `<nav aria-label>` wrapping all of them | `NAV_GROUPS` in `nav.ts` (see Decision 3) |
| Sidebar footer | Node/cluster context + user menu (principal, role, sign-out) | `GET /api/v1/cluster` `self` (name/role/site) + existing `whoami` — moved out of the TopBar verbatim |
| Skip link | "Skip to content" → focuses `<main>` (id + tabIndex −1 + refocus on click) | OpenBao `@a11yRefocusSkipTo` pattern, re-implemented |
| Responsive collapse | Sidebar hidden below `lg`, hamburger in TopBar opens it as drawer; breakpoint classes only (jsdom renders through them) | — |
| Console drawer | Slide-in right panel, toggled from TopBar; **live session / recording inspector** (Decision 2) | see below |

**Decision 2 — console drawer, honest scope:** no PTY/websocket/exec operation
exists in `apis/openapi.yaml` (literal scan), so an interactive terminal would
be fabricated. The drawer is the **recording inspector**: session list from
`GET /api/v1/sessions` (existing `useSessionList` hook, 15 s poll, mounted only
while open) → selecting one loads `GET /api/v1/sessions/{id}/events`
(`useSessionEvents`) with the Teleport empty-state vocabulary (`No Sessions
Found`). Interactive terminal is deferred until the contract adds an endpoint
(`shortcut:` comment in code).

**Decision 3 — navigation IA, the six groups (mapping pinned):**

| Group (i18n key `nav.group.*`) | Routes |
|--------------------------------|--------|
| Access & Sessions | `/sessions`, `/jit`, `/break-glass`, `/vendor-access` |
| Infrastructure | `/infrastructure`, `/topology` |
| Identity & Access | `/users`, `/security` |
| Policy & Compliance | `/policy`, `/compliance` |
| Vault & Secrets | `/vault` |
| Platform | `/command-center`, `/licensing`, `/settings` |

All 14 `NAV_ITEMS` paths appear in exactly one group (contract test: coverage +
no duplicates). Group membership is a **separate `NAV_GROUPS` export**, not a
field inside the item literals: the topology extractor parses each item with a
closing-brace-anchored regex (`scripts/topology.mjs:54-57`), so an added field
would silently drop nav rows. Consequence: `topology.generated.ts`, the mermaid
maps and the architecture explorer need **no regeneration** for this batch.
Routes, hrefs, labels, icons and the strangler fallbacks are untouched
(ADR-0005/0015 rules hold).

**Test contract:** `AppShell.test.tsx` updated (groups render under one
navigation landmark, identity chip + sign-out still present in the footer,
skip link focuses main, filter narrows links); new `ConsoleDrawer.test.tsx`
(list renders from the verbatim fixture, empty state, honest error state);
axe clean as before. New i18n keys (English-first, ADR-0010): the six group
labels, filter/skip/drawer labels, `shell.drawer.noSessions`. The unused
`app.sectionLabel` ("Privileged Controls") is removed with the flat list.

**Out of this batch (next):** Decision 4 copy vocabulary and Decision 5 token
layer ship with the screen-by-screen polish batches — the shell reuses the
existing F2 tokens unchanged so no screen restyles here.

## Consequences

- Frontend work becomes a tracked workstream ordered: **11.9 commit (pending PG
  battery) → P0 serving fixes → shell/IA redesign → screen-by-screen polish**.
- Extraction evidence lives in `Temp/` (never staged) and is re-runnable via the
  four cited scripts; the REA provider gap is documented rather than worked around
  silently.
- OpenBao stays read-only reference; attribution + policy note travel with this ADR.
