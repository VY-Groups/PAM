# VY-PAM — API Reference

**Status:** as-built for Phase 4f (`110909f`)
**Contract:** `apis/openapi.yaml` (OpenAPI 3.1) — **65 paths / 73
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
| Auth | When `LICENSE_ADMIN_TOKEN` is set: `Authorization: Bearer <token>` **or** `X-Admin-Token: <token>` on the **37 admin operations**. When unset: open dev mode — responses carry `X-Auth-Mode: open` (explicit, never silent). |
| Actor | `X-Actor: <name>` recorded verbatim in the audit ledger on every audited write |
| Errors | `{"error":{"code","message","details?"}}` — 400 validation · 401 auth · 403 policy refusal (risk gate) · 404 · 409 conflict/state · 422 unprocessable shape · 503 fail-closed dependency |
| Pagination | `limit` (≤200) + `offset`, newest first |
| Ordering | Ledger/session streams ascending `seq`; listings newest-first |

## 2. Operations by tag (11 tags)

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
| GET | `/api/v1/settings` | all groups (`sso`, `hsm`, `zsp`, `worm`) |
| PUT | `/api/v1/settings/{group}` | upsert group; writes per-field diff event |
| GET | `/api/v1/settings/audit` | changelog (group filter) |

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
| POST | `/api/v1/sessions` | start — **§7 risk gate runs first** (403 `details.risk` when refused) |
| GET | `/api/v1/sessions/{session_id}` | detail |
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
| POST | `/api/v1/risk/evaluate` | advisory evaluation (8 components → band/decision; always persisted) |
| GET | `/api/v1/risk/evaluations` | history (band/context filters) |
| GET | `/api/v1/risk/stats` | band distribution + averages (real) |

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
