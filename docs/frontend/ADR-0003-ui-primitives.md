# ADR-0003 — Accessible primitives: Radix UI

**Status:** Accepted 2026-10-13
**Plan ref:** Front-End Rebuild Plan §2 ("Radix UI or React Aria")

## Decision

Dialogs, tabs, menus, tooltips, popovers and focus management use
**Radix UI** primitives (unstyled, headless) styled with the Tailwind
tokens. Icon-only controls keep `aria-label` (brief §5).

## Alternatives considered

- **React Aria (Adobe)** — equally correct a11y hooks; rejected for now
  because Radix's component set maps 1:1 onto the console's needs
  (modal, tabs, dropdown, tooltip) with less composition glue.
- Hand-rolled dialogs/menus — rejected: focus traps and keyboard support
  are exactly where hand-rolling fails reviews (checklist M).

## Consequences

- New dependency family in the lockfile (MIT, no runtime CDN).
- Storybook stories (F2) must include keyboard-only walkthroughs.
