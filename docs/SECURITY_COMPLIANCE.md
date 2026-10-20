# VY-PAM — Security & Compliance Overview

**Status:** as-built for Phase 8a
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
| Master-key wrap (`<vault_key>.wrap`) | next to `VAULT_KEY_PATH`, mode 0600 | base64 provider ciphertext only (an envelope over the same master key) — key material never on disk; `hsm.enforcement=enforced` refuses the file key entirely |
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
- **HSM/KMS custody (6c):** with `hsm.enforcement=enforced` the master
  key is unwrapped only through the configured provider (Vault transit,
  AWS KMS, Azure Key Vault, optional PKCS#11) and there is **no** file
  fallback — an unreachable provider seals the vault (the monitor tick
  honors `seal_delay_seconds`), and unseal without the provider token
  stays sealed (honest 503). `test_hsm.py` plus the both-rig E2E prove
  the whole cycle against a real HTTP transit stub; rotation is an
  envelope re-wrap, so every existing ciphertext stays valid.

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
- **Per-vendor TOTP seeds:** each §13 vendor's RFC-6238 seed is sealed
  AES-256-GCM with AAD `vendor:{id}:mfa_secret` and returned exactly once,
  at invite; a wrong code is refused 401 and recorded without the code ever
  landing in the ledger.

## 4. Authentication & accountability

- **144 admin operations** carry security schemes in `openapi.yaml`
  (contract-tested) — they require `Bearer`/`X-Admin-Token` whenever
  `LICENSE_ADMIN_TOKEN` is set.
- **Least-privilege roles (6b):** in token mode the `admin-token` may call
  everything; every other credential is a *binding* — five seeded roles
  (admin / approver / operator / auditor / auditor-read-only) over the
  admin operations (policy in code, approver∩operator = ∅, reveal
  operator-only, evidence exports auditor-only), API tokens sha256 at
  rest and shown once, ABAC `scope` limiting targets / vault items. An
  LDAP directory authenticates but never authorizes: a valid ticket with
  no binding reaches no admin route (403 verbatim). A denial records
  `rbac` ledger evidence; revocation stops tokens immediately (401).
- **SSO login (6c):** SAML 2.0 / OIDC logins verify the IdP's signature
  (the metadata document itself, then the assertion / `id_token` RS256
  via JWKS), bind each flow single-use (`InResponseTo` / `state` + nonce
  + PKCE, 120 s clock skew, replay refused), and require the MFA
  assertion fail-closed (`require_mfa` → 403 + `sso.login.mfa_failed`,
  nothing minted). Sessions are server-side (`vypam-sso1.…`, sha256 at
  rest, TTL, revoke 401s immediately); a login grants **existence only**
  — admin access still needs a `kind=sso` binding, so privilege never
  rides the assertion.
- **Local identity & login security (7):** scrypt (N=2**14) local login
  with NIST policy (length over complexity, breached-password and
  username-containment refusals, generated passwords shown once + forced
  change); server-side console sessions (`vypam-ui1.…` bearer sha256 at
  rest + HttpOnly `vypam_session` cookie, `X-CSRF-Token` double-submit on
  cookie-authenticated mutations, idle + absolute expiry, revoke /
  logout / logout-all). `mfa_required` is **fail-closed**: no factor ⇒ a
  single-use `vypam-enr1` enrolment ticket (never a session, never a
  cookie), an unproven factor ⇒ a single-use `vypam-mfa1` challenge (300
  s; a wrong assertion survives it, a reused TOTP time step does not);
  step-up for sensitive routes with hashed single-use backup codes;
  per-account / per-IP rate limits, progressive delay, spray detection
  and doubling lockout with admin unlock (the password path stays
  MFA-fail-closed after unlock). E-mail OTP is HMAC-hashed, TTL'd,
  attempt-capped and answers identically for known and unknown accounts
  (no enumeration; suppressed deliveries are measured with the honest
  reason and never a code); WebAuthn options are 202 for existing **and**
  non-existing handles; the RADIUS factor fails closed 503 on an
  unreachable server; SCIM 2.0 drives the joiner/mover/leaver lifecycle
  over its own shown-once bearer (SCIM-managed logins get the uniform
  401, the true `scim-managed` reason only on the ledger). The sealed
  emergency admin has no usable password and opens only on a reason ≥ 8
  chars plus two distinct approvers (never the requester), in a
  time-boxed window; its login is single-use and rotates the seal.
- **Gateway credential & recording custody (8a):** the user never sees
  the injected target password — connect-args are **one-shot** and issued
  only to the node's own `vypam-gwn1` token (the admin bearer is refused
  403 by name, a second fetch is 409), and the ledger never contains
  credentials or key material (proven by test). Recordings are sealed
  per segment under a per-recording data key wrapped by the master key —
  **crypto-shreddable**: destroying the key turns playback into a 410
  while the rows remain as evidence; each segment's SHA-256 is verified
  before decrypt (tamper ⇒ 500). Dispatch fails closed (no healthy node
  in the target's zone ⇒ 503, the create rolled back), node registration
  is maker-checker (self-approval 403), and `gateway` is the **21st**
  ledger trail (node registration/approval, brokering,
  credential-injection facts, segment seals, playback reads,
  retention-expired). Retention never prunes sessions linked to command
  incidents (derived legal hold).
- **Open dev mode is loud, never silent:** responses carry
  `X-Auth-Mode: open`, the console profile shows `no user session` /
  `auth: -`, and the security posture checklist records it as the single
  known violation (`admin_auth "open dev mode"` — development posture score
  **87.5**, one violation, honestly reported).
- **Actor capture:** `X-Actor` is recorded verbatim on every audited write;
  in token mode a missing actor is a 401, in open mode it degrades to an
  explicitly labelled value rather than a fake identity. For **console
  sessions `X-Actor` is ignored** — the actor is the authenticated
  principal, which is what makes requester ≠ approver and dual approval
  real controls instead of header conventions — and the admin token
  alone holds no console session.
- **Separation of duties:** JIT requester ≠ approver (enforced in code);
  `high` band requires manager **and** security approvals; held commands are
  resolved through append-only approval rows by another actor.
- **Vendor chain cannot be short-cut (§13):** approval is refused 409 while
  MFA/NDA/ticket are outstanding (the refusal names the steps), the ticket
  step is a real §20 ITSM HTTP check (unconfigured → honest 409, never a
  simulated pass), vendor access requests are scope- and window-checked
  before the JIT request exists, and every refusal lands on the `vendor`
  ledger trail.
- **Pipeline identity cannot be short-cut (§15):** the broker API token is
  the only credential on pipeline routes — the admin token never
  substitutes, open dev mode never waives it, and `X-Actor` is ignored
  (the actor is the policy name). The token is shown once and stored as a
  sha256 hash (constant-time compare); revoked/expired identities are
  honest 401s, scope misses are 403 with a `refused` event, and the
  released secret exists only in the single release response.
- **AI-agent identity cannot be short-cut (§16):** the agent API token is
  the only credential on agent request/open/close routes — the admin token
  never substitutes, open dev mode never waives it, and `X-Actor` is
  ignored (the actor is the agent's own name). The token is shown once and
  stored as a sha256 hash (constant-time compare); disabled/revoked
  identities are honest 401s, unknown tasks and target-scope misses are
  403 with an `access-refused` event on the `agent` trail, a window above
  the task's cap is 400 `details.cap`, and the decrypted secret is never
  returned — access is a forced recorded session whose every command is
  judged against the declared allow-list (blocks still veto; an
  out-of-scope command opens an incident, terminates the session and ends
  the grant).

## 5. Tamper evidence (architecture §19)

| Property | Implementation | Test evidence |
|---|---|---|
| Ordered | `seq` unique, ascending | `test_audit.py` chain walk |
| Chained | `prev_hash` → `event_hash = sha256(canonical record)`, genesis `0`×64 | verify endpoint recompute |
| Append-only | PostgreSQL triggers abort `UPDATE`/`DELETE` with `'audit_events is append-only (architecture 19)'` | trigger tests |
| Complete coverage | 21 sources (`license settings vault discovery jit session command risk bypass break-glass integration vendor cloud broker agent cluster rbac sso hsm auth gateway`); mapper-coverage test fails if any event model lacks a mapper | `MAPPERS` ⇄ models ⇄ `by_source` assertions |
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
| Logical access — least privilege on admin APIs | ✅ (token mode) | 144 secured operations, contract-tested |
| Logical access — dev-mode transparency | ✅ explicit | `X-Auth-Mode: open`, posture violation logged |
| Encryption of secrets at rest | ✅ | AES-256-GCM vault versions |
| Change management — config change log | ✅ | `settings_events` per-field diffs |
| Audit logging — immutable, reviewable | ✅ | hash chain + triggers + verify/export |
| Segregation of duties | ✅ for JIT/commands/break-glass | requester ≠ approver; approval rows; two distinct break-glass signatures |
| Key management — custody + rotation | ✅ partial | vault key rotation; license key = manual reissue (no HSM) |
| Incident response evidence | ✅ | incidents + preserved session events |
| PAM bypass detection (§10) | ✅ | verbatim auth-log evidence → correlation vs inventory + sessions → incident with forced rotation; ledger `bypass` |
| Logical access — MFA at login for local users | ✅ fail-closed | `mfa_required` (default on): no factor ⇒ single-use enrolment ticket, unproven factor ⇒ single-use challenge; TOTP replay guard, step-up + backup codes, lockout doubling; e-mail OTP / WebAuthn / RADIUS factors; sealed emergency admin opens only on dual approval (§7 phase 7, `identity` tag) |
| SSO / MFA / HSM integration | ✅ | SAML 2.0 / OIDC login with signature-verified IdP metadata + assertion / `id_token`, single-use flows, fail-closed MFA assertion, JIT subjects + server-side sessions + `kind=sso` bindings (6c); HSM/KMS providers envelope-wrap the master key — `enforcement=enforced` refuses file fallback and seals on provider failure; posture counts real evidence, never settings booleans |
| Geo-IP / UEBA behavioral analytics | ⚠️ UEBA built, no geo feed | §11 baselines from real history + named deviations (unusual time/device/IP/target/command/privilege) driving the block→rotate→incident chain; `location` stays `is_global` (no geo feed claimed) |
| TLS in transit | ⛔ at app layer | terminate at reverse proxy (see runbook) |
| HA / DR | ✅ | multi-node registry + real `/health` probes, hash-verified pull replication (audit/vault/sessions), passive write gate, manual failover + opt-in auto-promote, verified logical backup bundles — runbooks in the deployment runbook §7 |
| Break-glass emergency workflow (§17) | ✅ | dual approval (requester excluded) → recorded session → forced rotation at close; ledger `break-glass` |
| Gateway data plane & credential injection (8a) | ✅ | brokered rdp/ssh/vnc/telnet through maker-checked nodes over zones/pools (self-approval 403, fail-closed 503 dispatch with the create rolled back); one-shot connect-args per node token — the user never sees the injected password and the admin bearer is refused 403 by name; per-segment AES-256-GCM recordings under a master-key-wrapped envelope key (SHA-256 verified before decrypt, tamper ⇒ 500, destroyed key ⇒ 410 with rows kept); retention legal hold for incident-linked sessions; ledger `gateway` (21st source) |
| Third-party / vendor access (§13) | ✅ | per-vendor TOTP (sealed, shown once) + NDA + real ITSM ticket → strict approval gate → scope/window-checked JIT request with forced session recording + lazy expiry; refusals recorded; ledger `vendor` |
| SIEM streaming | ✅ push + pull | live webhook push on state change (`siem.webhook_url`, §20 — shipped in 4i) plus the NDJSON export (pull) |
| Dynamic watermark overlay (§12) | ✅ | six-line `USER/SESSION/TARGET/TIME/TICKET/SOURCE` payload assembled from the session's own rows (grant ticket + recorded source address), console overlay reacting to pause/resume/terminate, per-event custody lines; protocol-level pixel overlays labelled `not connected` pending gateway (§27) |

## 8. Gap closure plan (target posture — see `IMPLEMENTATION_PLAN.md`)

Every ⛔/⚠️ in §7 has an assigned phase; until it lands, the control is
reported as missing — never as partial-good.

| Gap today | Closes in | Target state |
|---|---|---|
| ~~Single admin role~~ — **✅ closed in 6b** | 6b | Five seeded roles over all admin operations (admin 144 / operator 48 / auditor 34 / auditor-read-only 31 / approver 13), sha256-at-rest tokens shown once, LDAP binding-required (the directory authenticates, the binding decides), ABAC target / vault-item scoping; `admin-token` stays the bootstrap superuser and open dev mode remains an explicit, posture-recorded violation |
| ~~SSO/HSM schema-only~~ — **✅ closed in 6c** | 6c | SAML 2.0 + OIDC login with verified signatures, single-use flows and fail-closed MFA; JIT subjects + server-side sessions; `kind=sso` bindings on the 6b model (the IdP authenticates, the binding decides). HSM/KMS providers wrap the master key (envelope — same key, ciphertexts stay valid); `enforcement=enforced` refuses any file fallback and seals on provider failure — `sso_mfa`/`hsm_backed` posture now count real evidence, never settings booleans |
| ~~No real identity behind logins~~ — **✅ closed in 7** | 7 | scrypt local users, fail-closed MFA at login, CSRF-bound server-side console sessions, actor bound to the authenticated principal (`X-Actor` ignored for sessions), lockout + spray detection, e-mail OTP / WebAuthn / RADIUS / SCIM lifecycle, and the sealed emergency admin with dual-approved, time-boxed, single-use open — Addendum C in full; `auth` is the 20th ledger source |
| ~~No gateway data plane~~ — **✅ closed in 8a** | 8a | zones/pools + maker-checker node registration (Addendum A), guacd-first brokering of rdp/ssh/vnc/telnet with fail-closed dispatch (no healthy node in zone ⇒ 503, create rolled back), one-shot credential injection the user never sees (ledger holds the fact, never the secret), per-segment sealed recordings with verified playback and crypto-shreddable retention (incident-linked sessions are legal hold) — `gateway` is the 21st ledger source |
| TLS not terminated by the app | runbook §5 (now) | Reverse-proxy TLS - documented and checklisted; app stays plain HTTP by design |
| Geo-IP feed (`location` = `is_global`) | 4i | Device/IP context now sits in the trained §11 baselines; a real geo feed only if one is ever configured - otherwise the honest label stays |

**Target posture (after plan completion):** admin auth enforced (token/SSO),
MFA on elevated paths, integrations verified or explicitly `not connected`,
bypass + UEBA feeding the incident pipeline, break-glass auditable, evidence
exportable to SIEM — with the posture checklist scoring honestly from
measured controls at that time (no claimed score until measured).
