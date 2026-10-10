# VY-PAM — API Reference

**Status:** as-built for Phase 5d
**Contract:** `apis/openapi.yaml` (OpenAPI 3.1) - **120 paths / 144
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
| Auth | When `LICENSE_ADMIN_TOKEN` is set: `Authorization: Bearer <token>` **or** `X-Admin-Token: <token>` on the **86 admin operations**. When unset: open dev mode - responses carry `X-Auth-Mode: open` (explicit, never silent). Pipeline `/broker` operations require the broker API token and AI-agent `/agent-access` operations require the agent API token — neither is ever waived, even in open dev mode. |
| Actor | `X-Actor: <name>` recorded verbatim in the audit ledger on every audited write |
| Errors | `{"error": "<message>", "details"?: {…}}` — 400 validation · 401 auth · 403 policy refusal (risk gate) · 404 · 409 conflict/state · 422 unprocessable shape · 503 fail-closed dependency |
| Pagination | `limit` (≤200) + `offset`, newest first |
| Ordering | Ledger/session streams ascending `seq`; listings newest-first |

## 2. Operations by tag (18 tags)

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

### `vendors` — §13 third-party PAM (Phase 5a, 9 paths / 11 operations)
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/vendors` | invite a vendor (201): the per-vendor TOTP seed + otpauth URI come back once, here — never again |
| GET | `/api/v1/vendors` | list accounts, newest first (`status` filter, `q` search, paging) |
| GET | `/api/v1/vendors/{vendor_id}` | dashboard payload: chain steps, access/denied lists, valid window, recording, requests, trail |
| PATCH | `/api/v1/vendors/{vendor_id}` | edit contact + access scope (allowed/denied targets, window, recording, expiry) on an invited/approved account |
| POST | `/api/v1/vendors/{vendor_id}/mfa` | step 1 — verify the vendor's TOTP code (real RFC-6238; a wrong code is 401 + recorded, the code itself never lands) |
| POST | `/api/v1/vendors/{vendor_id}/nda` | step 2 — record the NDA/agreement acceptance (reference optional, timestamp not) |
| POST | `/api/v1/vendors/{vendor_id}/ticket` | step 3 — real §20 ITSM check (unconfigured → 409 honest refusal; upstream's own answer on a failed check) |
| POST | `/api/v1/vendors/{vendor_id}/approve` | step 4 — approve; refused 409 with the exact steps still missing (the chain cannot be short-cut) |
| POST | `/api/v1/vendors/{vendor_id}/deny` | refuse the invite outright (reason recorded; the name may be re-invited later) |
| POST | `/api/v1/vendors/{vendor_id}/revoke` | withdraw an approved vendor: active grants close through the JIT path (rotate + end sessions), account turns `revoked` |
| POST | `/api/v1/vendors/{vendor_id}/requests` | the vendor files a scoped JIT request — status must be `approved`, scope + window checked pre-creation (403 `Vendor access refused` is evidence on the trail), ticket defaults to the verified one |

### `cloud` — §14 cloud PAM (Phase 5b, 6 paths / 9 operations)
| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/cloud/connectors` | register AWS/Azure/GCP/Kubernetes (201): credential stays in the vault, row starts honest (`not connected` without endpoint, `configured` with one) |
| GET | `/api/v1/cloud/connectors` | list, newest first (`provider`/`status` filters, `q` search, paging) |
| GET | `/api/v1/cloud/connectors/{connector_id}` | console payload: connector, recent §14 trail, RBAC grants raised through it, last inventory run |
| PATCH | `/api/v1/cloud/connectors/{connector_id}` | edit config; changing the endpoint drops the row back to `configured` (the old probe described the old endpoint), clearing it → `not connected` |
| DELETE | `/api/v1/cloud/connectors/{connector_id}` | remove the connector (409 while open RBAC grants ride it; the trail stays) |
| POST | `/api/v1/cloud/connectors/{connector_id}/test` | real reachability probe (GET with the vault credential; 2xx → `connected`, failure → `error` + reason; no endpoint → 409) |
| POST | `/api/v1/cloud/connectors/{connector_id}/discover` | real inventory (cloud API answers; assets land under `source=cloud`; failed/unrecognized answer records the honest reason and invents nothing) |
| POST | `/api/v1/cloud/connectors/{connector_id}/rbac/requests` | Kubernetes path (201): files a section-6 JIT request with `cloud_binding`; the grant applies a real RoleBinding `vypam-jit-<id>`, close/expiry removes it |
| GET | `/api/v1/cloud/stats` | aggregates: connectors by provider/state, §14 trail size, RBAC grants, cloud-discovered assets |

### `broker` — §15 CI/CD credential broker (Phase 5c, 9 paths / 13 operations)

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/broker/policies` | register a pipeline identity (201): the API token `vypam-ci1.<id>.<secret>` is shown exactly once and stored as a sha256 hash |
| GET | `/api/v1/broker/policies` | list identities (`ci_system`/`status` filters, `q` search, paging) |
| GET | `/api/v1/broker/policies/{policy_id}` | console payload: policy, open credential count, latest §15 trail |
| PATCH | `/api/v1/broker/policies/{policy_id}` | edit approval mode / TTL cap / allowed targets / contact / expiry (never name, CI system or token; revoked → 409 frozen) |
| DELETE | `/api/v1/broker/policies/{policy_id}` | revoke: open credentials are closed first (released ones rotate like a JIT expiry), then the token stops authenticating |
| POST | `/api/v1/broker/credentials` | **pipeline token** (201): request a short-lived credential; an `auto` policy releases the secret in this same response (once), a `manual` policy lands it in the approval queue; a target outside `allowed_targets` → 403 + `refused` on the trail |
| GET | `/api/v1/broker/credentials` | list every pipeline credential (`status`/`policy_id` filters, paging; never the secret — only the `secret_released` flag) |
| GET | `/api/v1/broker/credentials/{credential_id}` | console payload: credential, its policy, full §15 trail |
| POST | `/api/v1/broker/credentials/{credential_id}/approve` | admin sign-off (only `pending`); the pipeline then releases with its own token |
| POST | `/api/v1/broker/credentials/{credential_id}/deny` | refuse a queued request (reason recorded; nothing released) |
| POST | `/api/v1/broker/credentials/{credential_id}/release` | **pipeline token**: a real vault checkout under the pipeline's name; the secret appears exactly once and expires at the returned timestamp |
| POST | `/api/v1/broker/credentials/{credential_id}/close` | dual auth (own pipeline token or admin): ends the grant early; a released credential releases its checkout and rotates |
| GET | `/api/v1/broker/stats` | aggregates: policies by state/CI system, credentials by state, §15 trail size |

### `agent` — §16 AI-agent PAM (Phase 5d, 9 paths / 15 operations)

| Method | Path | Summary |
|---|---|---|
| POST | `/api/v1/agents` | register an agent identity (201): the API token `vypam-agt1.<id>.<secret>` is shown exactly once and stored as a sha256 hash |
| GET | `/api/v1/agents` | list identities (`status`/`q` filters, paging) |
| GET | `/api/v1/agents/{agent_id}` | console payload: identity, declared task scopes, open-grant count, latest §16 trail |
| PATCH | `/api/v1/agents/{agent_id}` | edit description / contact / window cap / active-disabled (never the name or token; revoked → 409 frozen) |
| DELETE | `/api/v1/agents/{agent_id}` | revoke: open access ends first (active grants release and rotate), then the token stops authenticating |
| GET | `/api/v1/agents/{agent_id}/tasks` | list the identity's declared task scopes |
| POST | `/api/v1/agents/{agent_id}/tasks` | declare one task: the exhaustive `allowed_commands` allow-list (1–32 literal substrings, case-insensitive), optional exact `allowed_targets`, `max_minutes` cap |
| PATCH | `/api/v1/agents/{agent_id}/tasks/{task_id}` | edit the allow-list / targets / window cap / description (never the name; revoked identity → 409) |
| DELETE | `/api/v1/agents/{agent_id}/tasks/{task_id}` | withdraw a task: access riding it ends first (release + rotate), then the scope goes |
| POST | `/api/v1/agent-access/requests` | **agent token** (201): identity verified → task verified (unknown task or target outside `allowed_targets` → 403 with the refusal recorded; window above min(task, identity) cap → 400) → §7 risk scoring (low auto-approves with the binding snapshot, medium/high queue for their band's sign-offs, critical → `blocked` + `access-refused`) |
| GET | `/api/v1/agent-access/requests` | list agent-raised requests (`status`/`agent_id` filters, paging; human JIT requests stay in their own queue) |
| GET | `/api/v1/agent-access/requests/{request_id}` | console payload: request, its identity, §16 trail (never a secret — only the outcome) |
| POST | `/api/v1/agent-access/requests/{request_id}/open` | **agent token** (201): consume the grant — real vault checkout under the agent + forced recorded session; a §7 gate refusal releases + rotates again and lands on the trail |
| POST | `/api/v1/agent-access/requests/{request_id}/close` | dual auth (own agent token or admin): ends the grant early — checkout released, credential rotated, any session riding it ends |
| GET | `/api/v1/agent-access/stats` | aggregates: identities by state, declared tasks, requests by state, §16 trail size |

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
- **Pipeline auth** (`POST /broker/credentials`, `…/{id}/release` and the
  pipeline side of `…/{id}/close`): the broker API token is the only
  credential — the admin token never substitutes for it and open dev mode
  does not waive it; `X-Actor` is ignored and the actor on the trail is
  the policy name.
- **Agent auth** (`POST /agent-access/requests`, `…/{id}/open` and the
  agent side of `…/{id}/close`): the agent API token (`X-Agent-Token` or
  Bearer) is the only credential — the admin token never substitutes and
  open dev mode does not waive it; `X-Actor` is ignored and the actor on
  the trail is the agent's own name.

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

These do **not** exist today; the contract's **120 paths / 144 operations**
are the complete current surface. Each lands in `openapi.yaml` + ADMIN
security + tests in the same commit when its phase starts (counts `—`):

| Phase | Planned additions |
|---|---|
| 5d §16 | agent identity CRUD + task-scoped request endpoints |
| 6b | security schemes gain role requirements across existing admin ops |
