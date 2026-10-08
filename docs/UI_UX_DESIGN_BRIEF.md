# VY-PAM — UI/UX Design Brief

**Status:** as-built for Phase 4h
**Source design:** `stitch_pam_suite_dashboard_ui/` (frozen reference — never
modified; screens live under `frontend/screens/<slug>/code.html`).
This brief documents the design system as implemented, so new screens match
without re-deriving tokens.

---

## 1. Design foundation

### 1.1 Tokens (Tailwind runtime config, `id="tailwind-config"`)

**Color** — Material-3-style semantic tokens (light theme today; `darkMode:
"class"` reserved):

| Token | Value | Use |
|---|---|---|
| `primary` | `#004ac6` | accents, active icons, links |
| `primary-container` | `#2563eb` | active nav pill, primary buttons |
| `surface` / `background` | `#f8f9ff` | page background |
| `surface-container-lowest` | `#ffffff` | cards, sidebar, header |
| `surface-container-low` / `-container` / `-high` / `-highest` | `#eff4ff` / `#e5eeff` / `#dce9ff` / `#d3e4fe` | nested panels, chips, hovers |
| `on-surface` / `on-surface-variant` | `#0b1c30` / `#434655` | body / secondary text |
| `outline` / `outline-variant` | `#737686` / `#c3c6d7` | dividers, borders (`/30` opacity typical) |
| `error` | `#ba1a1a` | destructive actions, break-glass |
| `tertiary` | `#006242` (+ containers) | healthy/positive states |

**Type** — Geist (UI) + JetBrains Mono (code/badges), both `100..900`,
loaded from Google Fonts; Material Symbols Outlined for icons.

| Role | Family | Size/Line |
|---|---|---|
| `headline-xl` | Geist 600 | 32/40, `-0.02em` |
| `headline-lg` | Geist 600 | 24/32 |
| `headline-md` | Geist 600 | 20/28 |
| `headline-sm` | Geist 600 | 16/24 |
| `body-lg/md/sm` | Geist 400 | 15/24 · 14/20 · 12/18 |
| `label-md` | Geist 500 | 12/16 |
| `label-badge` | JetBrains Mono 600 | 11/14 |
| `code-md/sm` | JetBrains Mono 500 | 13/20 · 11/16 |

**Space** — `space-xs .25rem → sm .5 → md .75 → lg 1 → xl 1.5`, plus
`gutter(1rem)`, `gutter-lg(1.5rem)`, `margin(1rem)`, `margin-md(1.5rem)`,
`margin-lg(2rem)`.
**Radius** — `DEFAULT .125rem`, `lg .25rem`, `xl .5rem`, `full .75rem`
(cards = `rounded-xl`).

### 1.2 Shell layout (identical on all 10 screens)

```
<aside> fixed, w-64, bg-surface-container-lowest, border-r outline-variant/30
  ├─ h-16 brand row: logo (../aegispam_enterprise_security_logo/screen.png),
  │   "AegisPAM" + "ZERO-TRUST CORE" code kicker, verified_user icon
  ├─ nav (data-path slugs, Material icon + label, active =
  │   bg-primary-container text-on-primary-container)  ← 10 items
  └─ footer widget: module status (e.g. "ZSP Policy — not connected")
<header> fixed top, left-64, h-16, backdrop-blur, z-40
  ├─ deployment/attestation chip · Cmd+K search (readonly) · audit-stream
  │   counter · Break-Glass button (bg-error, uppercase) · bell · profile
<main> pl-64, pt-16, px-space-xl, pb-12, vertical gap-space-xl sections
```

## 2. Components

| Component | Pattern |
|---|---|
| **KPI card** | `rounded-xl bg-surface-container-lowest p-space-lg shadow-sm hover:shadow-md`, 4px accent bar `absolute top-0 h-1 bg-primary(-container)`, label `font-label-md`, value `font-headline-xl`, footer row `body-sm` |
| **Chip / badge** | `rounded font-label-badge` or `font-code-sm`, uppercase, `tracking-wider`, `bg-surface-container text-primary` (info) / `text-outline` (inactive) |
| **Status dot** | `w-1.5 h-1.5 rounded-full` + `animate-pulse` for live; flat for static |
| **Buttons** | primary = `bg-surface-container hover:bg-surface-container-high` + leading icon; destructive = `bg-error text-on-error`; all `rounded-lg`, `font-label-md` |
| **Table** | header row `font-label-badge uppercase text-outline`, rows `body-sm`, zebra via `bg-surface-container-low/40`, actions as icon buttons |
| **Modal** | centered card `rounded-xl bg-surface-container-lowest`, dark scrim, close × |
| **Section header** | `headline-lg` + `body-md text-on-surface-variant` subtitle + right-aligned action cluster |
| **Tabs** | pill group; active = `bg-surface-container-high font-semibold` |

## 3. Interaction rules

1. **Reveal on click, auto re-mask 30 s.** Sensitive payloads (secret reveal,
   audit record inspect, source drill-downs) fetch **only on user click**;
   a 30 s timer re-masks. Nothing sensitive renders on page load or hover.
2. **Honest states first.**
   - No data → `—` (em-dash) in the value slot — never a sample number.
   - Module not wired → explicit chip `not connected` / `NOT CONNECTED` with
     a one-line explanation in the footer widget.
   - `file://` or backend down → controls render **disabled**, values `—`;
     the screen stays navigable.
   - Profile shows `no user session`, auth chip `auth: -` when unauthenticated.
3. **No fabricated strings.** A verifier (`shots_tool/__verify_live.mjs`)
   scans the rendered DOM for legacy placeholder phrases (e.g. fabricated
   pagination pairs) across all live screens in both HTTP and `file://`
   modes. Feature-descriptor prose is allowed; fake *data* is not.
4. **Frozen-HTML discipline.** Never add `id=` attributes to frozen markup;
   use structural lookups or JS-created `data-role` hooks. New sections are
   appended in their own gated IIFE so a missing backend can't break the page.
5. **Data flows one direction:** `fetch → state object → render()`. Partial
   failures degrade individual widgets to `—` + error chip, never a blank
   page.

## 4. Screen inventory (what each shows)

| Screen | Primary content | Live since |
|---|---|---|
| Command Center | posture KPIs, health strip, recent activity feed, **§10 bypass detection section** (ingest → scan → incidents) | 2a/4g |
| Credential Vault | inventory grid, checkout/reveal/rotate, version history | 4a |
| JIT Access | request list, score breakdown, approvals, grants | 4b |
| Live Session Hub | active sessions, controls, event stream, terminate cascade | 4c |
| Target Infrastructure | scans, discovered assets/accounts, register/ignore | 2d/3c |
| Policy & Zero Trust | command rules table, evaluate, approval queue, incidents, **§7 risk section** | 4d/4f |
| Compliance & SOC2 | ledger digest, verify walk, 11-source chips, export, record modal, SIEM header chip | 4e/4f/4g/4h/4i |
| Licensing | entitlements, quota usage, import/validate/revoke | 3a |
| Break-Glass | request filing, dual-approval signatures, recorded emergency session, close + review — **§17 live** | 4h |
| Settings | group forms + per-field changelog | 2b |

## 5. Responsive & accessibility

- Grids collapse via Tailwind `md:`/`lg:`/`xl:` columns; header items hide
  progressively (`hidden xl:flex` for the audit-stream counter).
- Icons always paired with text labels in nav; icon-only buttons carry
  `aria-label`.
- Focus rings: `focus:outline-none focus:border-primary-container
  focus:ring-1` on inputs.
- Contrast: `on-surface #0b1c30` on `#f8f9ff` (AA+); muted text reserved for
  secondary lines.

## 6. Screenshot & verification convention

- Viewport **1920×1600**, `fullPage: false` — always. Tall sections are
  captured with `element.scrollIntoView({block:'start'})` first, never by
  growing the viewport height.
- Recapture only screens whose code changed; diff review before commit.
- Filename: `frontend/screens/<slug>/screenshot.png` (per-screen).

## 7. Pending UI work (planned — see `IMPLEMENTATION_PLAN.md`)

| Screen / surface | Pending work | Phase |
|---|---|---|
| Policy & Zero Trust (§7 section) | "Anomalies" subsection — baseline deviations with per-reason chips (UEBA) | 4j |
| Live Session Hub | Dynamic watermark overlay pane (USER/SESSION/TARGET/TIME/TICKET/SOURCE) that reacts to pause/resume/terminate; protocol-level overlays remain `not connected` until gateway work | 4k |
| Target Infrastructure | Cloud connector cards (AWS/Azure/GCP/K8s) — `not connected` until configured | 5b |
| New nav entries | Vendor/agent surfaces (5a/5d) require sidebar growth — **decision point**: extend the canonical 10-item nav (and the nav-consistency test) or nest under existing screens; decided at phase start, not earlier | 5a/5d |

Constraints that carry into all pending UI: frozen-HTML rules (no new `id=`,
`data-role` hooks only), reveal-on-click + 30 s re-mask, honest
`file://`/backend-down dashes, and every value sourced from a real API
response at render time.
