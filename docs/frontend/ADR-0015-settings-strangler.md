# ADR-0015: Platform Settings screen — strangle `platform_settings_center`, phased

Date: 2026-10-17
Status: Accepted (user decision, 2026-10-17: strangle target + phased slicing)

## Context — which legacy page does /settings strangle?

Two legacy pages exist and only one is the real settings screen:

| Evidence | Fact |
|---|---|
| `backend/phase2_license_server/app.py:43` | `SETTINGS_SCREEN = UI_ROOT / "screens" / "platform_settings_center" / "code.html"` — the server serves this page |
| `backend/phase2_license_server/README.md:120` | "`GET /settings` serves Platform Settings (`platform_settings_center/`), **built from the spec screen `platform_settings_idp_hsm_configuration/`** and wired to the settings API" — the idp_hsm page is the design spec, center is the wired implementation |
| Legacy sidebar (every screen) | links `data-path="platform-settings-center"` → `../platform_settings_center/code.html` |
| Standing gate `__verify_agent.mjs:342` | Settings checks navigate to `platform_settings_center/code.html` |
| React `nav.ts:91` (F4 slip) | `legacyHref` points at the SPEC screen — assembled from the 13 spec-screen names before center existed in nav |
| Plan doc F4 | Settings is the last F4 screen; "each screen ships with tests and **its old `code.html` deleted**" |

**Decision 1**: the React `/settings` route strangles **`platform_settings_center`**.
The nav `legacyHref` is corrected to `/screens/platform_settings_center/code.html`
(evidence above); topology regenerates from the edited nav.

## Scope inventory — from the real page + live captures (not from memory)

The legacy page (142 KB) calls: `GET /settings` (+`/settings/audit`,
`PUT /settings/{group}`, `POST /settings/smtp/test`, `POST /settings/scim/rotate`),
`GET /cluster` (+ nodes/replicas/backups/failover/sync ops), `GET /integrations/status`
(+ MFA enroll/verify, ITSM verify, LDAP auth), `GET /auth/sso/status`,
`GET /hsm/status`, `GET /auth/emergency`, `GET /roles`, `GET /role-bindings`
(+ create/delete), `GET /auth/whoami`.

`GET /api/v1/settings` returns **`schema` + `settings` for exactly 15 groups**:
`auth, gateway, hsm, itsm, ldap, mfa, radius, scim, siem, sms, smtp, sso,
webauthn, worm, zsp` — field descriptors carry `type` (str/int/bool/…),
`default`, `min`/`max`, `max_length`, `allow_empty`. Changelog:
`GET /settings/audit` → `{events[{id, group, action, actor, changes{field:{old,new}}, created_at}], total}`.
Verbatim rig captures (2026-10-17, open rig :5100) back every shape claimed here;
honest-state facts to preserve: `peers`/`backups` are **absent** (not empty) on a
pristine node, `sealed` secrets render as sealed `not set` boxes, roles seed five
(`admin, approver, auditor, auditor-read-only, operator`).

## Decision 2 — phased slices, pending until the flip

`/settings` stays **pending** (nav keeps its `legacyHref`) through 11.1–11.4, so the
F4 invariant *no-legacyHref ⇒ implemented route* holds at every commit and topology
never claims a half-built screen. The route goes live only in 11.5.

| Batch | Content | Verified by |
|---|---|---|
| **11.0** | This contract + inventory + rig captures (reviewed, untracked until staged with 11.1) | user review |
| **11.1** | Feature shell (`features/settings/`) + read-only live sections: server-state header, HA/DC/DR cluster posture, SSO + HSM live lines/chips, Enterprise Integrations chips; nav legacyHref correction; verbatim fixtures | vitest + axe in jsdom (page not routed yet) |
| **11.2** | RBAC/ABAC: role directory, bindings table, create-binding form + one-time token box (hidden until 201) | vitest + axe |
| **11.3** | The 15 schema groups as RHF+Zod forms (zod derived from the API schema: type/min/max/allow_empty), dirty tracking, save through `X-Admin-Token`, changelog view; `smtp/test` + `scim/rotate` actions | vitest + axe |
| **11.4** | Identity addendum specials: emergency-admin card (`/auth/emergency`), MFA enroll (secret shown once), ITSM verify, LDAP auth, gateway card; `settingsLive`-style exports for the future gate re-point | vitest + axe |
| **11.5** | **Flip**: router live + nav `legacyHref` removed, topology regenerates (settings tag becomes route-wired), gate Settings block re-pointed to the React page (same honest-state regexes, `data-role` selectors, no `id=`), `platform_settings_center/code.html` deleted per the plan, full boundary regression | full battery + gate both modes + e2e |

## Cross-cutting rules

1. **Copy**: every string through i18n keys (ADR-0010), en.json grows per batch.
2. **Auth model**: admin writes send `X-Admin-Token` from `sessionStorage
   aegispam_admin_token` — the existing pattern; token-mode rigs seed it via
   `addInitScript` already.
3. **Honest states**: absent `peers`/`backups` → honest zeros/"not connected"; no
   `loading...` after settle; secrets sealed until acted on; changelog empty →
   honest empty state; verbatim server errors on failures.
4. **Interim test story**: while unrouted, screen-level checks are Vitest +
   axe in jsdom against the committed verbatim fixtures - the same
   harness every landed screen uses (Storybook stays a design-system
   surface). Real-browser e2e and the gate's own Settings block join at
   the flip. No test claims the route works before it does.
5. **Gate**: `__verify_agent.mjs` keeps verifying the legacy page until 11.5 (the
   strangled page must stay green while it is still the served one).

## Consequences

- The nav legacyHref for settings is corrected (topology/frontend-map/explorer
  regenerate; the explorer's `settings` tag stays `w=0` until screens actually
  call it).
- `platform_settings_idp_hsm_configuration` (spec screen) loses its last link;
  deleting it belongs to F5 legacy retirement, not to this screen.
- Screen 11 ships as five reviewed commits, each battery-green and CI-green.
