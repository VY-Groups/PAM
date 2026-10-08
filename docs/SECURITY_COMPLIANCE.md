# VY-PAM — Security & Compliance Overview

**Status:** as-built for Phase 4f (`110909f`)
States what the platform **actually enforces today** — implemented controls
are described with their evidence; gaps are named plainly.

---

## 1. Trust model

```
[Trust root]  RSA + Ed25519 private keys (repo root, git-ignored)
      │  signing only
      ▼
[VY-PAM MASTER]  vendor tool, 127.0.0.1:5400, never shipped
      │  signed .lic envelope handed to the customer out of band
      ▼
[VY-PAM runtime]  verify-only: signature → structure → expiry/quota
      │  (shipped routes never sign; tests play the vendor)
      ▼
[Console]  click-gated reveals, 30 s re-mask, every action → ledger
```

Boundaries: (a) vendor↔customer (signed artifact), (b) console↔API (admin
token or explicit open dev mode), (c) runtime↔disk (encrypted secrets),
(d) everything↔audit (hash chain).

## 2. Key custody

| Key | Where | Protection |
|---|---|---|
| License RSA private (`license_private_key.pem`) | repo root, **git-ignored** | `pam_master` only; refusals are fail-closed |
| License Ed25519 private (`license_ed25519_private.pem`) | repo root, **git-ignored** | same |
| Vault AES key (`*.key`) | server directory, **git-ignored** (`*.key`) | `VAULT_KEY_PATH`; auto-gen only if `VAULT_AUTOGENERATE_KEY` |
| Customer registry key (`customer_registry.key` / `MASTER_CUSTOMER_KEY_B64`) | pam_master dir / env secret | encrypts PII blobs at rest |
| Admin token (`LICENSE_ADMIN_TOKEN`) | env / `.env` (git-ignored) | dev default = unset → open mode, made explicit via `X-Auth-Mode: open` |

**Enforced guards (real tests):**
- `test_no_private_key_material_in_tracked_files` — runs `git ls-files`,
  fails if any **tracked** file contains `-----BEGIN … PRIVATE KEY-----`
  (pam_master contract suite).
- `test_master_source_never_references_the_pam_runtime` — the vendor tool has
  zero back-references into the shipped runtime (one-way dependency).
- `test_custody_refuses_missing_keys_without_creating_them` /
  `test_key_generation_refuses_overwrite` — custody never silently mints or
  replaces trust-root keys.
- Test suites keep generated keys in `tmp_path`; nothing writes key material
  into the repo.
- Shipped routes never call the generator — issuing is PAM-MASTER's job
  (Phase 3a rule, encoded in `test_api.py` docstrings and usage).

## 3. Secrets at rest & in use

- **Vault secrets:** AES-256-GCM per version row (nonce + ciphertext + tag),
  AAD binds ciphertext to item id + version — cross-item splice is rejected.
- **Reveal discipline:** plaintext returns once on explicit admin reveal;
  it is **never written to logs or audit** (audit records who/what/when —
  `test_list_and_detail_never_expose_the_secret` + reveal-never-logged
  assertions). Rotation pipeline proves decryptability with a round-trip
  **before** retiring the old version.
- **Vendor PII:** customer records and license archives stored as
  `data_ct` / `archive_ct` ciphertext; the registry key never travels with
  the database.
- **Ephemeral channel content:** `keystroke_log=false` stores
  `content: null, withheld: true` — evidence of withholding, not the data.

## 4. Authentication & accountability

- **37 admin operations** carry security schemes in `openapi.yaml`
  (contract-tested) — they require `Bearer`/`X-Admin-Token` whenever
  `LICENSE_ADMIN_TOKEN` is set.
- **Open dev mode is loud, never silent:** responses carry
  `X-Auth-Mode: open`, the console profile shows `no user session` /
  `auth: -`, and the security posture checklist records it as the single
  known violation (`admin_auth "open dev mode"` — development posture score
  **87.5**, one violation, honestly reported).
- **Actor capture:** `X-Actor` is recorded verbatim on every audited write;
  in token mode a missing actor is a 401, in open mode it degrades to an
  explicitly labelled value rather than a fake identity.
- **Separation of duties:** JIT requester ≠ approver (enforced in code);
  `high` band requires manager **and** security approvals; held commands are
  resolved through append-only approval rows by another actor.

## 5. Tamper evidence (architecture §19)

| Property | Implementation | Test evidence |
|---|---|---|
| Ordered | `seq` unique, ascending | `test_audit.py` chain walk |
| Chained | `prev_hash` → `event_hash = sha256(canonical record)`, genesis `0`×64 | verify endpoint recompute |
| Append-only | SQLite triggers abort `UPDATE`/`DELETE` with `'audit_events is append-only (architecture 19)'` | trigger tests |
| Complete coverage | 8 sources (`license settings vault discovery jit session command risk`); mapper-coverage test fails if any event model lacks a mapper | `MAPPERS` ⇄ models ⇄ `by_source` assertions |
| Detect, don't repair | tampering is **reported** (`first break` index), never silently fixed | forged-insert test |
| Portable evidence | `/audit/verify`, `/audit/export` NDJSON in chain order | contract + audit tests |

Session recordings are append-only by API surface (no mutating endpoints)
with per-event `seq` and custody watermarks.

## 6. Session custody & evidence preservation

- Every session event carries actor + `watermark` custody string; controls
  (`record`, `keystroke_log`, `watermark`, `clipboard_allowed`,
  `upload_allowed`, `download_allowed`, `screenshot_allowed`) are enforced at
  write time — violations become kept evidence (`allowed=false` + reason), not
  silent drops.
- Terminating a session cascades (close grant → release checkout → rotate
  once) **and keeps the event trail**; `terminate_on_match` blocks mint an
  incident (`inc-<hex>`) pointing at the exact event `seq` + rule used.

## 7. SOC 2-oriented control mapping (honest scope)

| Control theme | Status | Where |
|---|---|---|
| Logical access — least privilege on admin APIs | ✅ (token mode) | 37 secured operations, contract-tested |
| Logical access — dev-mode transparency | ✅ explicit | `X-Auth-Mode: open`, posture violation logged |
| Encryption of secrets at rest | ✅ | AES-256-GCM vault versions |
| Change management — config change log | ✅ | `settings_events` per-field diffs |
| Audit logging — immutable, reviewable | ✅ | hash chain + triggers + verify/export |
| Segregation of duties | ✅ for JIT/commands | requester ≠ approver; approval rows |
| Key management — custody + rotation | ✅ partial | vault key rotation; license key = manual reissue (no HSM) |
| Incident response evidence | ✅ | incidents + preserved session events |
| SSO / MFA / HSM integration | ⛔ schema only | settings store; not enforced — posture says so |
| Geo-IP / UEBA behavioral analytics | ⛔ | `location` = `is_global` only; `behavior` = local events only |
| TLS in transit | ⛔ at app layer | terminate at reverse proxy (see runbook) |
| HA / DR | ⛔ | single-node SQLite |
| Break-glass emergency workflow | ⛔ | §17 static screen |
| SIEM streaming | ⚠️ seam only | NDJSON export (pull), no live webhook (§20) |

## 8. Gap closure plan (target posture — see `IMPLEMENTATION_PLAN.md`)

Every ⛔/⚠️ in §7 has an assigned phase; until it lands, the control is
reported as missing — never as partial-good.

| Gap today | Closes in | Target state |
|---|---|---|
| No bypass detection (§10) | 4g | Direct-access signals ingested from real auth logs/telemetry; incidents + forced rotation; ledger source `bypass` |
| Break-glass not implemented (§17) | 4h | Dual-approval emergency path, forced recording, forced rotation, auditable end-to-end (screen static → live) |
| MFA not enforced (`mfa` band advisory only) | 4i | RFC-6238 TOTP verified for real; medium-risk starts require a valid code |
| ITSM tickets shape-only (§7 `ticket`) | 4i | Real ServiceNow/Jira verification when configured; verified flag in the score |
| SIEM = pull-only NDJSON seam (§20) | 4i | Outbound signed webhook push when configured; `not connected` otherwise |
| No UEBA baselines (§11) | 4j | Per-actor baselines from real history; deviations drive block→rotate→incident |
| Watermark = custody string only (§12) | 4k | Live contextual overlay from real session data; protocol-level overlays pending gateway work |
| Single admin role (RBAC/ABAC claimed in matrix) | 6b | Roles + attribute bindings over all admin operations and vault/target scoping |
| SSO/HSM schema-only | 6c | SAML/OIDC login enforced; HSM/KMS-backed keys where configured |
| TLS not terminated by the app | runbook §5 (now) | Reverse-proxy TLS — documented and checklisted; app stays plain HTTP by design |
| No HA/DR (§18) | 6a | Replicated multi-node deployment with failover drill + runbooks |
| Geo-IP/UEBA-lite (`location` = `is_global`) | 4j/4i | Baseline device/IP context; a real geo feed only if one is ever configured — otherwise the honest label stays |

**Target posture (after plan completion):** admin auth enforced (token/SSO),
MFA on elevated paths, integrations verified or explicitly `not connected`,
bypass + UEBA feeding the incident pipeline, break-glass auditable, evidence
exportable to SIEM — with the posture checklist scoring honestly from
measured controls at that time (no claimed score until measured).
