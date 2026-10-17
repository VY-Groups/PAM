# ADR-0013 - Live system & workflow maps (`/topology`)

**Status:** Accepted 2026-10-16
**Ref:** User order 2026-10-16 - "workflow diagrams (frontend, backend,
api, network, application) ... a live diagram and no vibe coding
allowed"; form recorded that day: *live console page + drift gate*,
first batch = *all five workflows*.

## Context

No diagram surface exists in the F4 app. The legacy console carries
only placeholder map buttons (`View STS Map`, `View Posture Matrix`)
that the standing gate verifies render honestly-offline under
`file://`. A diagram is a claim: every box, edge and number on it must
come from a pinned source of truth, and something must fail loudly the
moment reality moves away from the picture. "No vibe coding" for
diagrams therefore means: **extracted, not drawn; verified, not
trusted.**

## Decision

### Surface

- New F4-native route **`/topology`** (feature `src/features/topology/`),
  sidebar item `nav.topology` ("System Maps"). There is no legacy
  screen to strangle, so `NavItem.legacyHref` becomes **optional**,
  with the invariant: *a nav item without a `legacyHref` must be an
  implemented route* - the pending-screen fallback only accepts items
  that carry a legacy URL (type predicate in `router.tsx`), and the
  tests assert the invariant from both directions.

### The five views (one design-system `Tabs`, one source per view)

| View | Source of truth | Mode |
| --- | --- | --- |
| Frontend | `src/app/layout/nav.ts` + `src/app/router.tsx` + the per-feature imports of the generated client | extracted (committed, drift-gated) |
| Backend | the file trees of `pam_master/`, `backend/phase2_license_server/`, `backend/ipam_licensing/` and their intra-package `import` edges | extracted (committed, drift-gated) |
| API | `apis/openapi.yaml` - paths, methods, tags, summaries verbatim | extracted (committed, drift-gated) |
| Network | `GET /health`, `GET /api/v1/cluster`, `GET /api/v1/integrations/status` | **live** (generated client + `expectOk`, honest loading/error states) |
| Application | the five workflows (license, break-glass, auth & RBAC, vendor, JIT): ordered steps, each a contract operation plus an evidence reference | curated, contract-validated by test |

Diagrams render from design-system primitives (`Tabs`, `Chip`,
`StatusDot`, `SectionHeader`, `NotConnected`, `Value`) and semantic
HTML/CSS - no diagramming dependency, per the offline-build rule
(ADR-0012) and the DoD's components-only clause.

### Extraction and the three verification layers

- `pnpm topology` runs `scripts/topology.mjs` (Node 24, new
  **dev-only** dependency `yaml` to read the contract) and writes the
  committed `src/features/topology/topology.generated.ts`; the script
  regenerates prettier-formatted output so a rerun is byte-stable.
- **Layer 1 - CI drift step** (mirrors the existing orval step in
  `ci.yml`): `pnpm topology && git diff --exit-code` fails the build
  when nav, routes, backend trees, feature imports or the contract
  change without regeneration.
- **Layer 2 - independent cross-check tests**: vitest re-parses
  `nav.ts`, `router.tsx`, `apis/openapi.yaml` and the backend trees
  with its own readers and asserts equality against the generated
  module - the generator cannot lie unnoticed.
- **Layer 3 - workflow contract validation**: every workflow step's
  `METHOD /path` must exist in the independently parsed contract, and
  every evidence file must exist on disk with its stated marker text.

Network fixtures for tests are verbatim rig captures (2026-10-16,
`Temp/opencode/cap-topo/`) - never invented bodies.

## Consequences

- `nav.ts`: `legacyHref?: string`; `AppShell.test.tsx` gains the 12th
  label; `router.tsx` pending fallback switches to an explicit live-set
  plus a `legacyHref` type predicate (behaviour unchanged: `/settings`
  stays the only pending screen).
- `ci.yml` gains one drift step in the frontend job; the local
  pre-commit battery runs the same regenerate + diff.
- One new devDependency (`yaml`, dev-only, audit-clean); one new pnpm
  script (`topology`); no runtime dependency is added to the bundle -
  the generated module is plain TS.
- Backend map entries go stale when files move: layer 1 fails until
  regeneration, which is the point.
