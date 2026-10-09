# VY-PAM — API Reference

**Status:** as-built for Phase 4i
**Contract:** `apis/openapi.yaml` (OpenAPI 3.1) - **87 paths / 96
operations**, enforced in both directions by
`backend/phase2_license_server/tests/test_openapi_contract.py`. If this page
and the YAML ever disagree, the YAML wins.

---

## 1. Conventions

| Concern | Rule |
|---|---|
| Base URL (dev) | `http://127.0.0.1:5000` (`LICENSE_SERVER_HOST`/`LICENSE_SERVER_PORT`) |
| Version | `/api/v1/…` (`/health`, `/api/v1/meta` unversioned) |
| Content type | `application/json` (license import also accepts multipart upload / raw body) |
| Auth | When `LICENSE_ADMIN_TOKEN` is set: `Authorization: Bearer <token>` **or** `X-Admin-Token: <token>` on the **49 admin operations**. When unset: open dev mode - responses carry `X-Auth-Mode: open` (explicit, never silent). |
| Actor | `X-Actor: <name>` recorded verbatim in the audit ledger on every audited write |
| Errors | `{"error":{"code","message","details?"}}` — 400 validation · 401 auth · 403 policy refusal (risk gate) · 404 · 409 conflict/state · 422 unprocessable shape · 503 fail-closed dependency |
| Pagination | `limit` (≤200) + `offset`, newest first |
| Ordering | Ledger/session streams ascending `seq`; listings newest-first |

## 2. Operations by tag (14 tags)

### `ops` — unversioned
| Method | Path | Summary |
|---|---|---|
| GET | `/health` | liveness + real DB ping |
| GET | `/api/v1/meta` | build/feature metadata |

### `licenses` + `validation` — entitlement lifecycle
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/licenses` | list imported licenses (filters: `status`, `q`, `limit`, `offset`) |
| POST | `/api/v1/licenses/import` | import signed `.lic`/envelope → verify → persist |
| GET | `/api/v1/licenses/{license_key}` | one license row |
| GET | `/api/v1/licenses/{license_key}/file` | download original `.lic` |
| POST | `/api/v1/licenses/{license_key}/revoke` | soft revoke (body: reason) |
| POST | `/api/v1/licenses/{license_key}/restore` | restore revoked |
| POST | `/api/v1/licenses/{license_key}/usage` | report/refresh usage counters |
| POST | `/api/v1/licenses/validate` | offline verify: signature → structure → expiry |
| POST | `/api/v1/licenses/{license_key}/check` | single-key validation check |

### `settings` — configuration groups
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/settings` | all groups (`sso`, `hsm`, `zsp`, `worm`, `mfa`, `itsm`, `siem`, `ldap`) |
| PUT | `/api/v1/settings/{group}` | upsert group; writes per-field diff event (secrets sealed, readonly `mfa.*` rejected) |
| GET | `/api/v1/settings/audit` | changelog (group filter) |

### `integrations` — Enterprise Integrations (§20)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/integrations/status` | real state of every connector + last SIEM push + `event_count` |
| POST | `/api/v1/mfa/enroll` | mint this operator's RFC-6238 TOTP factor (secret shown once) |
| POST | `/api/v1/mfa/verify` | check a 6-digit code (401 invalid with ledger evidence, 409 no-factor, 400 missing) |
| POST | `/api/v1/itsm/verify` | verify a ticket against the configured ITSM instance (real HTTP) |
| POST | `/api/v1/auth/ldap` | real LDAP bind; token mode mints `vypam-ldap1.*`, open mode says so |

### Dashboard feeds (untagged but public in spec)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/overview` | Command Center posture (real counters) |
| GET | `/api/v1/events` | unified recent-activity feed (source/type filters) |

### `vault` — credentials (AES-256-GCM at rest)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/vault/stats` | inventory counters |
| GET | `/api/v1/vault/items` | list items |
| POST | `/api/v1/vault/items` | create + generate secret (version 1) |
| GET | `/api/v1/vault/items/{item_id}` | item detail (metadata only) |
| GET | `/api/v1/vault/items/{item_id}/secret` | **click-gated reveal** (admin; never logged) |
| POST | `/api/v1/vault/items/{item_id}/checkout` | exclusive checkout |
| POST | `/api/v1/vault/items/{item_id}/revoke` | release checkout |
| POST | `/api/v1/vault/items/{item_id}/rotate` | rotate now (pipeline) |
| GET | `/api/v1/vault/events` | item action log |

### `rotation` — §5 engine
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/rotation/run` | manual/bulk rotation (ids or all) |
| POST | `/api/v1/rotation/session-end` | rotation triggered by session cascade |

### `jit` — §6 ephemeral access
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/jit/stats` | queue/band counters |
| GET | `/api/v1/jit/requests` | list (status/requester filters) |
| POST | `/api/v1/jit/requests` | request + score + band (auto-approve if `low`) |
| GET | `/api/v1/jit/requests/{request_id}` | detail incl. `risk_factors` |
| POST | `/api/v1/jit/requests/{request_id}/approve` | manager (and security on `high`); requester ≠ approver |
| POST | `/api/v1/jit/requests/{request_id}/deny` | deny with reason |
| POST | `/api/v1/jit/requests/{request_id}/consume` | bind to a session (409 if one live) |
| POST | `/api/v1/jit/requests/{request_id}/close` | end grant → release + rotate once |

### `sessions` — §8 privileged sessions (12 paths)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/sessions/stats` | live counters |
| GET | `/api/v1/sessions` | list (status/actor filters) |
| POST | `/api/v1/sessions` | start — **§7 risk gate runs first** (403 `details.risk` when refused); a `mfa` decision also demands `mfa_code` when a factor is enrolled (403 `details.mfa`) |
| GET | `/api/v1/sessions/{session_id}` | detail + §12 watermark payload (`SessionWatermark`) |
| GET | `/api/v1/sessions/{session_id}/events` | recorded stream (`after` cursor) |
| POST | `/api/v1/sessions/{session_id}/events` | append event (controls enforced) |
| POST | `/api/v1/sessions/{session_id}/controls` | update control flags |
| POST | `/api/v1/sessions/{session_id}/pause` / `lock` / `resume` | custody states |
| POST | `/api/v1/sessions/{session_id}/terminate` / `complete` | end → cascade (close grant, release checkout, rotate once) |
| POST | `/api/v1/sessions/{session_id}/events/{seq}/approve` / `deny` | resolve held command (append-only approval) |

### `command-control` — §9 policy (8 paths)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/command-control/stats` | rules/incidents/approval counters |
| GET | `/api/v1/command-control/rules` | list (enabled filter) |
| POST | `/api/v1/command-control/rules` | create rule |
| PUT | `/api/v1/command-control/rules/{rule_id}` | update rule |
| DELETE | `/api/v1/command-control/rules/{rule_id}` | delete rule (seeds never return) |
| POST | `/api/v1/command-control/evaluate` | dry-run: `block` \| `approval` \| `allow` (+ matched rule) |
| GET | `/api/v1/command-control/approvals` | pending held commands |
| GET | `/api/v1/command-control/incidents` | incidents (status filter) |
| GET | `/api/v1/command-control/incidents/{incident_id}` | evidence detail |
| POST | `/api/v1/command-control/incidents/{incident_id}/close` | resolve (note + actor, audited) |

### `discovery` — §3 targets
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/discovery/stats` | asset/account/scan counters |
| GET | `/api/v1/discovery/assets` | list (risk/pam_status filters) |
| POST | `/api/v1/discovery/assets` | manual register |
| PATCH | `/api/v1/discovery/assets/{asset_id}` | edit notes/status/ignore |
| POST | `/api/v1/discovery/assets/{asset_id}/onboard` | promote to managed |
| GET | `/api/v1/discovery/accounts` | discovered accounts (kind filter) |
| GET | `/api/v1/discovery/scans` | scan history |
| POST | `/api/v1/discovery/scans` | start scan (≤256 hosts × ≤24 ports; 409 if running) |

### `risk` — §7 engine (Phase 4f)
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/risk/evaluate` | advisory evaluation (8 components → band/decision; always persisted; with a trained baseline the behavior component carries named `reasons`) |
| GET | `/api/v1/risk/evaluations` | history (band/context filters) |
| GET | `/api/v1/risk/stats` | band distribution + averages (real) |
| GET | `/api/v1/risk/baselines` | UEBA baselines (§11): hours/devices/IPs/targets/verbs/cadence per principal, learned from real history rows |
| POST | `/api/v1/risk/baselines/train` | **admin** - learn or refresh baselines (optional `subject`; no history, no baseline) |
| GET | `/api/v1/risk/anomalies` | UEBA incidents (§11), newest first: the refused evaluation, named deviations, response chain; also on the ledger `risk` trail |

### `bypass` — §10 detection (Phase 4g)
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/bypass/ingest` | parse a real log bundle into connection observations (admin) |
| GET | `/api/v1/bypass/signals` | parsed observations, newest first (status/protocol filters) |
| POST | `/api/v1/bypass/scans` | correlate unobserved/observed signals → incidents + forced rotation (admin) |
| GET | `/api/v1/bypass/incidents` | direct-access incidents, newest first (status filter) |
| GET | `/api/v1/bypass/incidents/{incident_id}` | one incident with its parsed log-line evidence |
| POST | `/api/v1/bypass/incidents/{incident_id}/close` | analyst closure (note optional, recorded with who/when; admin) |
| GET | `/api/v1/bypass/stats` | signal states, incident and forced-rotation aggregates |

### `break-glass` — §17 emergency access (Phase 4h, 7 paths / 8 operations)
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/break-glass/requests` | file an emergency request (risk gate runs at open, not at filing) |
| GET | `/api/v1/break-glass/requests` | list, newest first (status/severity filters) |
| GET | `/api/v1/break-glass/requests/{request_id}` | detail with approval snapshots + recorded session |
| POST | `/api/v1/break-glass/requests/{request_id}/approve` | record one signature — requester excluded, two distinct approvers required |
| POST | `/api/v1/break-glass/requests/{request_id}/deny` | refuse a pending request with a note (any actor may; 400 once decided) |
| POST | `/api/v1/break-glass/requests/{request_id}/open` | release the approved credential — dual approval + §7 risk gate + the §20 MFA gate (`mfa_code`, refusal 401 `details.mfa`) enforced, 201 with the recorded session |
| POST | `/api/v1/break-glass/requests/{request_id}/close` | end session, forced credential rotation, review note required |
| GET | `/api/v1/break-glass/stats` | request statuses, approval signatures, action counts, last unseal |

### Ledger (Compliance feeds)
| Method | Path | Summary |
|---|---|---|
| GET | `/api/v1/audit/stats` | digest: totals, per-source, chain state |
| GET | `/api/v1/audit/verify` | recompute chain → `intact` or first break seq |
| GET | `/api/v1/audit/export` | NDJSON stream in chain order (`source` filter) |

## 3. Semantics worth knowing

- **Command evaluation order** (`/command-control/evaluate`): block →
  approval → allow; scoped rules first, then longest pattern, then lowest id.
  Default = allow when nothing matches.
- **Risk gate** (`POST /sessions`): evaluation committed *before* the
  decision; `critical` always refused; `high` allowed only with an active
  JIT grant; refusal = `403` + full `details.risk`.
- **Cascade on session end**: linked grant → `closed`, own checkout →
  released, credential → rotated once; response reports `cascade`.
- **Reveal endpoints are click-gated in the UI** (30 s re-mask) and never
  write plaintext to logs.
- **Bypass correlation** (`POST /bypass/scans`): only unscanned `observed`
  signals are considered; unmanaged targets → `out_of_scope`, a managed
  target covered by a session in its window → `covered`, otherwise an
  incident opens with alert + forced rotation (real §5 pipeline) and
  `block_source: not_connected`. Re-scanning never duplicates an incident.
- **`X-Auth-Mode: open`** on responses when no admin token is configured —
  development-only by construction.

## 4. Vendor tool API (separate contract, `pam_master`, port 5400)

Own `openapi.yaml` + contract test; **never shipped**. Highlights:

| Method | Path | Summary |
|---|---|---|
| GET/POST | `/api/v1/customers` | list (limit 1–200) / create (`name`+`region` → 201 + `Location`) |
| GET/PATCH | `/api/v1/customers/{id}` | read / partial edit (`null` clears) |
| GET | `/api/v1/customers/{id}/issuance-history` | newest first |
| POST | `/api/v1/licenses` | issue signed license (+ delivery bundle) |
| GET | `/api/v1/licenses` | list / filter by customer |
| POST | `/api/v1/licenses/{id}/renew` | supersede + re-sign |
| … | see `pam_master/openapi.yaml` | options, bundle, audit, health |

Auth on the vendor side: local bind by default (`127.0.0.1:5400`);
keys only via `python -m pam_master.keygen`.

## 5. Planned endpoints (NOT in the contract — see `IMPLEMENTATION_PLAN.md`)

These do **not** exist today; the contract's **87 paths / 96 operations**
are the complete current surface. Each lands in `openapi.yaml` + ADMIN
security + tests in the same commit when its phase starts (counts `—`):

| Phase | Planned additions |
|---|---|
| 5a §13 | vendor account CRUD + vendor-scoped lifecycle endpoints |
| 5b §14 | `POST|GET /api/v1/cloud/connectors`, cloud discovery extension |
| 5c §15 | `POST /api/v1/broker/credentials` (+ list/revoke) |
| 5d §16 | agent identity CRUD + task-scoped request endpoints |
| 6b | security schemes gain role requirements across existing admin ops |
