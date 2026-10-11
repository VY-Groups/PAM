# VY-PAM — Testing & QA Strategy

**Status:** as-built for Phase 6a
Every number below was collected from the real suite at this commit.

---

## 1. Suite inventory (real collect counts)

| Suite | File | Tests |
|---|---|---|
| **Backend total** | `python -m pytest backend -q` | **613** |
| ├ licensing core | `backend/ipam_licensing/test_license_core.py` | 46 |
| ├ licensing spec | `backend/ipam_licensing/test_license_spec.py` | 35 |
| ├ licensing bridge | `backend/ipam_licensing/test_licensing.py` | 1 |
| ├ API & licenses | `…/tests/test_api.py` | 59 |
| ├ settings + UI structure | `…/tests/test_settings_and_ui.py` | 33 |
| ├ vault | `…/tests/test_vault_dashboard.py` | 19 |
| ├ rotation | `…/tests/test_rotation.py` | 30 |
| ├ discovery | `…/tests/test_discovery.py` | 19 |
| ├ JIT | `…/tests/test_jit.py` | 18 |
| ├ sessions | `…/tests/test_sessions.py` | 23 |
| ├ command control | `…/tests/test_command_control.py` | 18 |
| ├ audit ledger | `…/tests/test_audit.py` | 19 |
| ├ risk engine (4f) | `…/tests/test_risk.py` | 19 |
| ├ bypass detection (4g) | `…/tests/test_bypass.py` | 19 |
| ├ break-glass (4h) | `…/tests/test_break_glass.py` | 22 |
| ├ integrations (4i) | `…/tests/test_integrations.py` | 41 |
| ├ UEBA (4j) | `…/tests/test_ueba.py` | 9 |
| ├ watermark (4k) | `…/tests/test_watermark.py` | 6 |
| ├ vendor PAM (5a) | `…/tests/test_vendor_pam.py` | 21 |
| ├ cloud PAM (5b) | `…/tests/test_cloud.py` | 27 |
| ├ broker (5c) | `…/tests/test_broker.py` | 24 |
| ├ agent PAM (5d) | `…/tests/test_agent.py` | 29 |
| ├ HA/DC/DR (6a) | `…/tests/test_cluster.py` | 36 |
| ├ RBAC/ABAC (6b) | `…/tests/test_rbac.py` | 31 |
| └ OpenAPI contract | `…/tests/test_openapi_contract.py` | 9 |
| **Vendor tool total** | `python -m pytest pam_master -q` | **46** |
| ├ registry (encrypted PII) | `pam_master/tests/test_registry.py` | 15 |
| ├ skeleton/custody/health | `pam_master/tests/test_skeleton.py` | 13 |
| ├ issuance + delivery | `pam_master/tests/test_issuance.py` | 12 |
| └ vendor OpenAPI contract | `pam_master/tests/test_openapi_contract.py` | 6 |

Contract test asserts (9): valid OpenAPI 3.1, documented ⇄ implemented
routes both directions, security schemes on **105** admin operations, the
documented admin set ⇄ runtime (`service.ADMIN_OPERATIONS` ∪ `whoami`),
per-op role lists ⇄ `ROLE_OPERATIONS`, the `rbacToken`/`ldapTicket`
schemes + `/auth/whoami` documenting every credential, enums ⇄ code
constants, required `info`/tags (20), and live response shapes ⇄ schemas —
currently **135 paths / 164 operations**.

## 2. Test design rules

1. **Real behavior, no mocks of the domain.** Fixtures create rows through
   service functions and real HTTP calls; crypto runs for real (tests act as
   the vendor by signing with the shared engine — the shipped server only
   verifies).
2. **Auth fixture:** `admin_token="test-admin-token"` +
   `{"X-Actor": "tester", "Authorization": "Bearer test-admin-token"}`.
3. **Every audited action is asserted twice** — domain effect *and* the
   ledger row (source, action, chain still intact).
4. **Tamper tests prove detection, not repair** — forged rows must be
   *reported* by `/audit/verify`.
5. **Append-only is tested by attempt** — `UPDATE`/`DELETE` on
   `audit_events` must raise; no endpoint may mutate `session_events`.

### Fixture lessons worth repeating (from 4f)

- History rows carry the `datetime.now` **bound at import** — patching
  `service.datetime` alone doesn't move column defaults. Night-clock fixtures
  must patch **both** `service_module.datetime` and `models_module.datetime`,
  and anchor in the past (a weekend anchor like Saturday 15:00 lands on the
  weekend branch reliably).
- Risk `user` component = 5 per prior critical → seed **two** prior criticals
  to reach cap 10.
- Assert `set(state["by_source"]) == set(audit.AUDIT_SOURCES)` after any
  feature adds a source (4f added `risk` as the 8th, 4g added `bypass` as
  the 9th, 4h added `break-glass` as the 10th).
- Asset registration (`POST /discovery/assets`) ingests the admin
  credential **in the same call** — a managed target always has a vault
  item, so §10 rotation assertions expect `rotated`; hit `skipped` by
  checking the credential out first (and `no_credential_on_file` only by
  removing the item at model level).

### Fixture lessons worth repeating (from 4h)

- Error responses serialize as `{"error": …, "details": …}` — assert
  `["error"]`, never `["message"]`.
- `from flask import request` shadows the service's `request` variable in
  route handlers — use a local name (`req`) when both are needed.
- YAML flow mappings (`{…}`) reject an unquoted `": "` inside a plain
  scalar — quote any description containing a colon.

## 3. UI verification (`shots_tool/`)

| Script | What it proves |
|---|---|
| `__verify_live.mjs` | **9 live screens** render with real API data over HTTP **and** honest `file://` fallback; sweeps the DOM for FORBIDDEN fabricated strings (exact pairs like `'Showing 5 of 2,875'`; a bare `'Showing 5 of'` is *not* forbidden — live pagination may honestly show `Showing 5 of 5 items`) |
| `__verify_discovery.mjs` | discovery screen flows (scan/adopt/filter against a throwaway server) |
| `__verify_agent.mjs` | **6a+6b standing gate - 50 checks, ALL PASSED**: §16 AI-Agent Access section on the JIT screen (below the broker block, zero `id=`, live `/agents*` + `/agent-access/*`, honest zero-state `0 agents · 0 open grants · 0 agent events`, numeric tiles, one-time token reveal modal, `window.jitLive.agent`), the Compliance screen's 18 source chips (`rbac` appended last), the §18 HA / DC / DR section on Platform Settings (summary shape, role badge vs the Promote/Demote label, numeric THIS NODE/PEERS/REPLICATION/BACKUPS tiles, node + replica + backup rows, zero `id=`, `window.settingsLive.cluster`) plus a live register → probe → sync → remove flow against an unreachable peer asserting the verbatim probe/sync errors and the registry returning to its baseline, and the §10 RBAC / ABAC section on Platform Settings (summary, five seeded roles, bindings table, hidden one-time token box, zero `id=`, `window.settingsLive.rbac`) plus — under `GATE_ADMIN_TOKEN` against a token-mode rig — a live grant → 403 verbatim → allowed op → scope 403 → revoke → 401 flow; in open dev mode it says so and skips honestly |
| `__shots.mjs` / `__debug_screen.mjs` | pre-existing capture/debug helpers (kept) |

Screenshots: **1920×1600 viewport, `fullPage: false` always**; tall pages use
`element.scrollIntoView({block:'start'})` before capture. Never recapture via
a fullPage path.

## 4. Boundary regression (run before every commit)

```powershell
python -X utf8 -m pytest backend -q          # 613
python -X utf8 -m pytest pam_master -q       # 46
python -X utf8 -m pytest backend\phase2_license_server\tests\test_openapi_contract.py -q   # 9
# boundary smoke (Temp\opencode\smoke_restructure.py): 17/17
node shots_tool/__verify_live.mjs            # ALL CHECKS PASSED
node shots_tool/__verify_discovery.mjs       # ALL CHECKS PASSED
node shots_tool/__verify_agent.mjs           # ALL CHECKS PASSED
```

Then, for the working tree:

1. **Secret leak check** on the staged diff: `ghp_[A-Za-z0-9]{20,}` (and
   never stage `*.pem`, `*.key`, `*.db`, `.env` — git-ignored).
2. **Root README counts** must match real collect output (per-file rows too).
3. **Temp scripts deleted** — only `__verify_live.mjs`,
   `__verify_discovery.mjs`, `__verify_agent.mjs`, `__shots.mjs`,
   `__debug_screen.mjs` survive in `shots_tool/`.

## 5. The lockstep rule (contract-first)

Any API change requires **four** edits in the same commit:

```
backend routes  ⇄  apis/openapi.yaml  ⇄  ADMIN_OPERATIONS (security)  ⇄  tests
```

`test_openapi_contract.py` fails on any drift — undocumented route,
documented-but-missing route, admin op without security scheme, enum
mismatch, response-shape mismatch. Docs (READMEs + `docs/`) update in the
same commit with **real** counts.

## 6. Per-phase workflow (established in 4a–4f)

1. Model + service + endpoints → 2. openapi + contract lockstep →
3. tests (green) → 4. screen wiring (`data-role`, gated IIFE, file:// dashes)
→ 5. restart dev server (`python -X utf8 app.py` in
`backend/phase2_license_server`) → 6. **seed via public API only** →
7. recapture changed screens (1920×1600, no fullPage) → 8. docs →
9. boundary regression → 10. temp cleanup → 11. leak check → 12. commit →
13. push via fresh temp `.ps1` (token ephemeral, base64 auth, delete after).

## 7. What we deliberately don't claim

- No coverage percentage is reported (not measured honestly today).
- No browser-matrix or performance benchmarks are asserted — none exist.
- Load/scalability: single-node SQLite by design; HA is §18, not built.

## 8. Planned suites (see `IMPLEMENTATION_PLAN.md`)

Each pending phase adds a test file and grows the contract — **counts are
`—` until the phase lands and real collection is recorded**:

| Phase | New suite | Contract impact |
|---|---|---|
| 5a-5d | `test_vendor_pam.py`, `test_cloud.py`, `test_broker.py`, `test_agent.py` | per-phase path additions |
| 6a §18 | `test_cluster.py` (36) | 15 cluster paths + the `Health` node-identity fields |
| 6b | `test_rbac.py` (31) | 4 rbac paths + role scope lists on the 74 role-declaring admin ops + `rbacToken`/`ldapTicket` schemes |
| 6c | `test_sso_hsm.py` | SSO/HSM endpoints + settings enforcement |

Standing expectations for every future phase: the 4-way lockstep
(routes ⇄ openapi ⇄ ADMIN ⇄ tests), mapper-coverage test keeps all event
models wired to a ledger source, UI verifiers extend to any new screen
section, and the boundary checklist (§4) runs unchanged before each commit.
Root README per-file counts update in the same commit as the suite that
changes them.
