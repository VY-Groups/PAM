---
name: Zero-Trust Sentinel
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#434655'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#737686'
  outline-variant: '#c3c6d7'
  surface-tint: '#0053db'
  primary: '#004ac6'
  on-primary: '#ffffff'
  primary-container: '#2563eb'
  on-primary-container: '#eeefff'
  inverse-primary: '#b4c5ff'
  secondary: '#565e74'
  on-secondary: '#ffffff'
  secondary-container: '#dae2fd'
  on-secondary-container: '#5c647a'
  tertiary: '#006242'
  on-tertiary: '#ffffff'
  tertiary-container: '#007d55'
  on-tertiary-container: '#bdffdb'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dbe1ff'
  primary-fixed-dim: '#b4c5ff'
  on-primary-fixed: '#00174b'
  on-primary-fixed-variant: '#003ea8'
  secondary-fixed: '#dae2fd'
  secondary-fixed-dim: '#bec6e0'
  on-secondary-fixed: '#131b2e'
  on-secondary-fixed-variant: '#3f465c'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Geist
    fontSize: 26px
    fontWeight: '600'
    lineHeight: 34px
    letterSpacing: -0.015em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.005em
  body-lg:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
  label-md:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.01em
  label-badge:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.02em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-lg: 1.5rem
  margin: 1rem
  margin-md: 1.5rem
  margin-lg: 2rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system targets SecOps engineers, identity architects, and enterprise CISO teams managing privileged credentials and zero-trust perimeter access. The brand personality projects architectural authority, absolute precision, clinical transparency, and unflinching reliability. It rejects frivolous visual ornament in favor of high-signal utility: every pixel either conveys system status, enforces an access boundary, or guides critical remediation.

The aesthetic fuses **Corporate / Modern Enterprise** clarity with **Technical Precision Minimalist** discipline. It relies on crisp slate neutrals, high-density informational hierarchy, structural division lines, and deliberate semantically loaded accents (Cobalt, Emerald, Amber, Rose) that communicate state instantly without cognitive friction.

## Colors

The palette operates on strict functional roles:
- **Base Canvas & Surfaces**: The default canvas sits on Slate-50 (`#F8FAFC`). Primary cards and containers use pure white (`#FFFFFF`) with distinct borders (`#E2E8F0`). Secondary panels, such as persistent navigation rails and command bars, draw from deep Slate/Navy-900 (`#0F172A`) to ground the application chrome.
- **Primary Accent (`#2563EB`)**: Cobalt Blue drives interactive focus, selected navigation items, primary elevation actions, and interactive links. Hover states step to `#1D4ED8`.
- **Secondary Chrome (`#0F172A`)**: Deep Navy grounds high-security context, structural sidebars, and critical modal headers.
- **Safe / Verified (`#10B981`)**: Precision Emerald validates active zero-trust verification, healthy agent heartbeats, and rotated keys. Muted surface tint: `#ECFDF5`.
- **Elevation / Warning (`#F59E0B`)**: Industrial Amber signals time-limited session escalations, pending approvals, and approaching lease expirations. Muted surface tint: `#FFFBEB`.
- **Threat / Kill-Switch (`#EF4444`)**: Crisp Rose denotes privilege revocation, anomalies, active breach containment triggers, and immediate session termination. Muted surface tint: `#FEF2F2`.
- **Monochrome & Text**: Text hierarchy utilizes Slate-900 (`#0F172A`) for primary headings, Slate-700 (`#334155`) for standard body text, Slate-500 (`#64748B`) for secondary metadata and table captions, and Slate-200 (`#E2E8F0`) for borders and dividers.

## Typography

The typography pairings divide duty strictly between human-centric enterprise interface copy and machine-centric security telemetry:
- **UI & Structural Copy (`Geist`)**: Used across all headings, body narrative, form fields, and navigation items. Tight tracking on headers produces a clean, calibrated, contemporary tech aesthetic.
- **Security Artifacts (`JetBrains Mono`)**: Mandatory for all raw IP addresses, CIDR blocks, SHA-256 signatures, SSH commands, policy enforcement strings, and audit log tables. Status badges also utilize JetBrains Mono to clearly separate machine-verified statuses from descriptive layout labels.
- Tabular figures (`font-variant-numeric: tabular-nums`) must be active across all tables and real-time session counters to eliminate visual jitter during live security refreshes.

## Layout & Spacing

The layout model emphasizes high information density and strict spatial discipline:
- **Layout Model**: A 12-column fluid grid system with fixed left-hand rail navigation (collapsed at 64px, standard at 240px). Section containers fit a maximum boundary of `1600px` for wide-monitor control rooms, scaling gracefully down to full fluid width on sub-desktop screens.
- **Breakpoints**:
  - `Desktop Wide (>= 1440px)`: 24px margins, 24px gutters, persistent contextual right-hand audit drawer.
  - `Desktop (1024px - 1439px)`: 24px margins, 16px gutters, collapsible secondary inspectors.
  - `Tablet (768px - 1023px)`: 16px margins, 16px gutters; navigation collapses into icon rail.
  - `Mobile (< 768px)`: 16px margins, 12px gutters; tables scroll horizontally with frozen ID/action columns; drawer components convert to full-screen overlays.
- **Density Control**: Padding within data grids conforms to compact (32px row height) or standard (44px row height) toggles to suit intensive monitoring workflows.

## Elevation & Depth

Visual hierarchy relies on structural planes and subtle, razor-thin outlines rather than heavy atmospheric shadows:
- **Surface Elevation**:
  - **Level 0 (Canvas)**: Slate-50 (`#F8FAFC`), entirely flat.
  - **Level 1 (Cards, Tables, Panels)**: Surface White (`#FFFFFF`) with a 1px solid structural border (`#E2E8F0`). Shadow is minimal: `0 1px 2px 0 rgba(15, 23, 42, 0.05)`.
  - **Level 2 (Popovers, Dropdowns, Hovered Cards)**: Surface White with a 1px border (`#CBD5E1`) and a directional drop shadow: `0 4px 6px -1px rgba(15, 23, 42, 0.08), 0 2px 4px -2px rgba(15, 23, 42, 0.04)`.
  - **Level 3 (Modal Dialogs, Policy Editors, Kill-Switch Confirmation)**: Elevated white surface with a dark perimeter stroke (`#94A3B8`), supported by a strong layered shadow: `0 20px 25px -5px rgba(15, 23, 42, 0.12), 0 8px 10px -6px rgba(15, 23, 42, 0.08)`. Backdrops feature a solid 40% Navy overlay (`#0F172A66`) with a 2px backdrop blur.
- **Active Boundary Glows**: Critical active states apply an inner micro-ring (e.g., focused security inputs utilize `box-shadow: 0 0 0 2px #FFFFFF, 0 0 0 4px #2563EB`).

## Shapes

The design system maintains a **Soft (Level 1)** geometric standard. Enterprise security software requires precise, predictable layouts; round elements can compromise visual structure in data-dense tables.

- Standard buttons, form fields, and dropdown targets: `4px` (`0.25rem`).
- Cards, table wrappers, panels, and metric displays: `8px` (`0.5rem`).
- Modals, large slide-out drawers, and alert banners: `8px` (`0.5rem`).
- Status indicator pills and terminal tags: `3px` or `4px` subtle caps, explicitly avoiding circular pill-shaped extremes (`rounded-full` is reserved exclusively for user identity avatars and live connection status dots).

## Components

- **Buttons**:
  - *Primary*: `#2563EB` solid fill, white text, 4px radius, medium weight. Focused with 2px offset ring.
  - *Secondary / Outline*: White surface, 1px `#CBD5E1` border, `#0F172A` text. Hover: `#F1F5F9`.
  - *Destructive / Kill-Switch*: Crimson `#EF4444` solid or bordered state. Used for credential revocation and session termination.
  - *Terminal / Secret*: Monospaced command triggers featuring inline copy icons and micro-tooltips.
- **Status Badges & Chips**:
  - Designed with an ultra-light tint background, 1px border, and high-contrast text using `label-badge` (`JetBrains Mono`).
  - *Verified / Active*: `#ECFDF5` background, `#10B981` border, `#065F46` text with a 6px pulsating green dot.
  - *Elevated / Ephemeral*: `#FFFBEB` background, `#F59E0B` border, `#92400E` text.
  - *Revoked / High-Risk*: `#FEF2F2` background, `#EF4444` border, `#991B1B` text.
- **Enterprise Data Tables**:
  - Built with compact vertical padding (`8px 12px`), zebra or hover highlighting (`#F8FAFC`), and sticky column headers.
  - Includes quick-filter row controls, inline privilege level meters, and one-click SSH connection launch links.
- **Security Status Gauges & Metric Cards**:
  - Top metric cards feature an upper 2px accent line denoting category (Cobalt for activity, Emerald for posture, Rose for vulnerabilities).
  - Radials and zero-trust health meters use sharp vector tracks with contrasting percentage indicators in tabular typography.
- **Input Fields & Secret Vault Pickers**:
  - Clean white inputs with a 1px `#CBD5E1` border, placeholder text in `#94A3B8`, and absolute-positioned visibility toggles for masked secret strings (`••••••••`).
  - Audit log viewers embed inside a customized terminal component with a dark `#0F172A` background, `#38BDF8` syntax highlights, and line-numbered gutters.