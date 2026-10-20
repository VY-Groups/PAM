# VY-PAM — Deployment & Operations Runbook

**Status:** as-built for Phase 8a
Docker exists **only** for development and runtime testing (vendor tool +
license server). The shipped product
installs directly on a machine — no VM, no container.

---

## 1. Prerequisites

- Python **3.10+** (tested on the versions running this repo's suite), `pip`
- Node.js **18+** — *screenshots/verification tooling only* (not runtime)
- No outbound network required — the console ships fully vendored (Tailwind
  runtime, fonts and icons under `frontend/vendor/`); air-gapped installs
  need nothing extra
- Disk: PostgreSQL keeps the DB server-side (back it up per §6) — this
  install carries only a handful of PEM/`*.key` files

## 2. Install — shipped product (VY-PAM)

```powershell
# 1) API + console runtime
cd backend\phase2_license_server
pip install -r requirements.txt        # Flask, Flask-SQLAlchemy, cryptography, python-dotenv, pytest, PyYAML

# 2) configure (optional — sensible dev defaults exist)
copy .env.example .env                 # if present; else create .env by hand (see §4)
#    minimum for real auth: LICENSE_ADMIN_TOKEN=<long random>

# 3) run
python app.py                          # dev: http://127.0.0.1:5000  (console at /)
#    or, for a production-ish WSGI server:
pip install waitress
waitress-serve --port 5000 wsgi:app
```

First boot, automatically: creates the schema on the configured PostgreSQL
server, generates missing keys **only
if** `LICENSE_AUTOGENERATE_KEYS=1`, backfills the audit chain once, seeds the
15 §9 rules into an empty table, and (if enabled) starts the rotation
scheduler.

**Verify:** `GET /health` → 200 with a real DB ping; open
`http://127.0.0.1:5000/` → the 11-item console with live numbers.

Development alternative (**runtime/real-time testing only**, never a
shipping instruction): `backend/phase2_license_server/docker-compose.yml`
builds a **dev-only** image from the repo root
(`docker build -f backend/phase2_license_server/Dockerfile -t vypam-license-server:dev .`),
maps **5010 → 5000** (the host dev server usually owns 5000), starts a real
`postgres:16` service (`shm_size: 1g`, named volume, `service_healthy`) and
points the server at it via `LICENSE_DATABASE_URI` (ADR-0019 D7: one
production-shape compose), gives every `up` a fresh database (`down -v`
starts over), and bakes throwaway signing keys per build — `.dockerignore`
keeps `*.pem`/`*.key`/`.env`/`*.db` out of every build context. The same
image runs the suite in its Linux runtime against the same service:
`docker compose run --rm license-server python -m pytest tests -q`.

## 3. Install — vendor tool (VY-PAM MASTER, internal only)

```powershell
# one-time trust-root keys (refuses to overwrite — by design)
cd pam_master
python -m pam_master.keygen             # writes license_private_key.pem etc. at repo root
# note: the repo tracks license_public_key.pem (the verification half that
# ships to clients). keygen never touches it, and the server refuses a
# mismatched pair by design — after regenerating, delete the old public
# file; the first server boot re-derives it from the new private key.

# run (default http://127.0.0.1:5400)
$env:MASTER_BIND="127.0.0.1"; $env:MASTER_SERVER_PORT="5400"
python -m pam_master
```

Development alternative: `pam_master/docker-compose.yml` (binds 0.0.0.0
**inside the container**, mounts `/keys` and `/data`) — **dev-only**; never a
shipping instruction.

## 4. Configuration reference (shipped)

| Variable | Default | Notes |
|---|---|---|
| `LICENSE_DATABASE_URI` | **required — no default** | PostgreSQL is the only storage engine (ADR-0019): `postgresql+psycopg://user:pass@host:5432/db` — the psycopg `[binary]` wheel in `requirements.txt` bundles libpq, no system client libraries needed. Unset, or a non-PostgreSQL scheme (e.g. a stale `sqlite:///` line), refuses to boot with an honest error naming this ADR. |
| `LICENSE_SERVER_HOST` / `LICENSE_SERVER_PORT` / `LICENSE_SERVER_DEBUG` | `127.0.0.1` / `5000` / off | bind to localhost behind a proxy |
| `LICENSE_ADMIN_TOKEN` | **unset = open dev mode** | **set this in production**; unset ⇒ `X-Auth-Mode: open` |
| `LICENSE_PRIVATE_KEY_PATH` / `LICENSE_PUBLIC_KEY_PATH` | repo-root PEMs | verification keys |
| `LICENSE_ED25519_PRIVATE_KEY_PATH` / `LICENSE_ED25519_PUBLIC_KEY_PATH` | repo-root PEMs | |
| `LICENSE_SECRET_KEY` | dev fallback + warning | set explicitly |
| `LICENSE_AUTOGENERATE_KEYS` | off | key creation on boot |
| `LICENSE_DEFAULT_TRIAL_DAYS` | 30 | trial issuance default |
| `VAULT_KEY_PATH` / `VAULT_AUTOGENERATE_KEY` | `vault.key` / off | **back this up — losing it loses the secrets** |
| `ROTATION_SCHEDULER` / `ROTATION_SCHEDULER_INTERVAL_SECONDS` | off / 3600 | background rotation |
| `PAM_NODE_NAME` / `PAM_SITE` | `pam-node-1` / `dc` | §18 self identity per node (`site` ∈ `dc`,`dr`) |
| `CLUSTER_MONITOR` / `CLUSTER_MONITOR_INTERVAL_SECONDS` | off / 60 | opt-in auto-failover monitor thread |
| `CLUSTER_BACKUP_DIR` | `backend/phase2_license_server/backups` | destination of verified `POST /cluster/backups` copies |
| `RECORDING_STORAGE_DIR` | `SERVER_DIR/recordings` | gateway recording storage root (§27) — deployment config, not settings policy |

`.env` next to `config.py` is loaded automatically and is git-ignored.

## 5. Production hardening checklist

1. ✅ Set `LICENSE_ADMIN_TOKEN` (long, random) — verify a request **without**
   it returns 401 and responses no longer carry `X-Auth-Mode: open`.
2. ✅ Run under `waitress-serve` (or another WSGI server), not `python app.py`.
3. ✅ Terminate **TLS at a reverse proxy** (nginx/Caddy/IIS) and forward to
   `127.0.0.1:5000`; the app itself speaks plain HTTP by design.
4. ✅ Filesystem permissions: DB, `*.key`, `*.pem` readable only by the service
   account.
5. ✅ Bind `127.0.0.1`; expose only the proxy.
6. ✅ Schedule backups (§6) and a nightly `GET /api/v1/audit/verify`.
7. ✅ Leave `LICENSE_SERVER_DEBUG` unset; dev mode is a development thing.

## 6. Backup / restore / upgrade

**Backup** (the engine's own files while stopped, or copy-consistent):
```
PostgreSQL data / pg_dump  # domain data + audit chain (ADR-0019 engine)
vault.key            # VAULT_KEY_PATH — secrets are unrecoverable without it
license_*.pem        # verification keys (trust root stays in PAM-MASTER)
.env                 # config (contains secrets — store accordingly)
```
Verified logical backups (§7) run without stopping the service:
`POST /api/v1/cluster/backups` streams a logical NDJSON bundle of every
table into `CLUSTER_BACKUP_DIR`, hashes it, then re-parses it and re-walks
its embedded audit chain before answering (`verified: true`) — copy the
bundle off-host with your normal job. The operations-grade physical lane
remains `pg_dump`/WAL archiving. The chain verifies afterwards either way
via `GET /api/v1/audit/verify`.

**Restore:** stop service → put files back with original permissions →
start → `GET /health` + `GET /api/v1/audit/verify` (chain must report intact
across the restored history).

**Upgrade:** stop → back up → replace code → `pip install -r requirements.txt`
→ start. Schema changes are additive and applied at boot by
`ensure_schema()`; the one-time chain backfill and rule seeding never repeat.
Run the boundary suites before exposing it: `python -m pytest backend -q`
(expect **834** — the suite requires `PAM_TEST_DATABASE_URI`, §2) and
`python -m pytest pam_master -q` (**46**).

## 7. HA / DC / DR runbooks (§18)

Every node runs the same binary with its own identity: set
`PAM_NODE_NAME` and `PAM_SITE` (`dc`|`dr`) per node. Decide the vault-key
story deliberately — a **shared** `vault.key` is what lets the DR node
actually open pulled ciphertext (`decryptable_here: true`); separate
keys keep replicas sealed (`decryptable_here: false`), an equally valid
posture. Add `-H "X-Admin-Token: <token>"` (or `Authorization: Bearer
<token>`) to the calls below when `LICENSE_ADMIN_TOKEN` is set.

**Register a peer** (once, on the node that should pull):

```bash
PAM=http://127.0.0.1:5000/api/v1
curl -s -X POST $PAM/cluster/nodes \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -d '{"name":"pam-dr-2","site":"dr","role":"passive","base_url":"https://dr.example/pam"}'
```

Health starts `unknown` — registration probes nothing. This node's own
row registers itself at boot from `PAM_NODE_NAME`; never add it here.

**Verify topology:** `GET /api/v1/cluster` (registry, peers by health,
replica totals, backup counts) or console → Platform Settings →
*HA / DC / DR Cluster*. Measure and pull on demand:

```bash
curl -s -X POST $PAM/cluster/nodes/2/probe -H "X-Actor: runbook" \
  -H "Content-Type: application/json" -d '{}'
curl -s -X POST $PAM/cluster/nodes/2/sync -H "X-Actor: runbook" \
  -H "Content-Type: application/json" \
  -d '{"peer_token":"<the peer admin token, if it runs with one>"}'
```

- a dead peer answers verbatim (`"error": "connection failed: ..."`) and
  turns `unreachable` — the trail records the state change, not each try
- a tampered chain lands with `verified: false` + `first_break_seq`:
  investigate the peer before trusting that DR node
- a failed pull reports the transport error with whatever kinds already
  applied kept (listed in the trail event, never rolled back silently)

**Failover (manual — recommended):** on the passive node

```bash
curl -s -X POST $PAM/cluster/failover -H "X-Actor: runbook" \
  -H "Content-Type: application/json" \
  -d '{"action":"promote","reason":"dc-1 down"}'
```

`GET /health` then reports `role: passive` on the demoted node. While
passive it refuses product writes with 409 (cluster + auth endpoints
excepted), so failback is the same call in reverse
(`{"action":"demote"}`) from whichever node should lead.

**Failover (automatic — opt-in):** set `CLUSTER_MONITOR=1` on the
passive node. Each tick (default 60 s) it probes every registered active
peer and promotes itself only after **3** consecutive failures *and* all
active peers failed. An active node never auto-demotes — failback is
always an operator decision.

**Scheduled backups** (per node): `POST /api/v1/cluster/backups` streams
the live store into a logical NDJSON bundle under `CLUSTER_BACKUP_DIR` and
re-walks the chain from the bundle before answering (`verified: true`);
copy the bundle off-host with your normal job. Restore is §6 (restore the
engine from `pg_dump`/volume → `GET /health` + `GET /api/v1/audit/verify`).

**DR drill:** on a spare node set `PAM_SITE=dr`, register the production
peers, run `sync`, then confirm `GET /api/v1/audit/verify` is intact and
`GET /api/v1/cluster/replicas` shows exactly what was pulled. Replicas
are evidence, never merged — the spare still serves only its own ledger.

## 8. Monitoring

| Signal | Source | Healthy looks like |
|---|---|---|
| Liveness | `GET /health` | 200, real DB ping |
| Chain integrity | `GET /api/v1/audit/verify` | `intact` (alert on first break) |
| Rotation | `/api/v1/vault/stats` | `last_rotated_at` advancing for due items |
| Session/control load | `/api/v1/sessions/stats` | as capacity requires |
| Failed admin auth | proxy/app logs | spikes ⇒ token probing |
| Peer health | `GET /api/v1/cluster` | registered peers `healthy`, `consecutive_failures` 0 (§7) |

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 401 on admin routes | `LICENSE_ADMIN_TOKEN` set, client missing header | send `Authorization: Bearer …` or `X-Admin-Token` |
| Admin routes work without auth | open dev mode | **expected only in dev**; set the token (posture violation `admin_auth "open dev mode"` disappears when set) |
| Boot fails: "Private key not found" / key load error | missing/corrupt PEM | restore from backup; or `LICENSE_AUTOGENERATE_KEYS=1` for a **fresh trust root** (invalidates previously issued licenses) |
| Vault endpoint 503 | `vault.key` missing/unreadable | restore `vault.key`; never regenerate over an existing DB (old ciphertext undecryptable) |
| `/audit/verify` reports first break | DB tampering/corruption | **do not repair silently** — export NDJSON evidence, restore from last good backup, investigate |
| Writes answer 409 `role: passive` | this node was demoted (or is the DR standby) | intended §18 gate — promote it (`POST /api/v1/cluster/failover`) if it should lead |
| Peer stuck `unreachable` | network/TLS/DNS to `base_url` | the row's `last_error` is verbatim — fix reachability, then re-probe (§7) |
| `cluster/replicas` shows `unverified` | peer chain broke (tampering or version skew) | treat as evidence, not mirror: verify the peer before trusting it |
| Scan 409 | a scan is already running | single-flight by design; wait or check `/discovery/scans` |
| Console shows `—` everywhere | API unreachable or `file://` | correct: honest fallback; fix base URL / serve via HTTP |
| Fonts/icons missing offline | n/a — assets are vendored (`frontend/vendor/`), no CDN | ship `frontend/vendor/` with the console; no outbound font/CDN fetch exists |

## 10. Uninstall

Stop the process; delete the install directory **after** securely destroying
`vault.key`, the PEMs, the PostgreSQL data and its dumps, and `.env` (they
contain secrets, credentials, and audit history).

## 11. Target deployment (after planned work — see `IMPLEMENTATION_PLAN.md`)

Status per item — recorded so operations planning isn't surprising:

- **§18 HA/DC/DR (phase 6a — shipped, single-binary scope):** node
  registry, real `/health` probes, hash-verified pull replication
  (audit/vault/sessions), the passive write gate, manual failover + opt-in
  automatic promotion, and verified logical backup bundles run today —
  runbooks in §7. Still ahead of the full spec picture: external
  load-balancer topology guidance and a replicated store for multi-writer
  nodes.
- **Phase 4i connectors:** SIEM outbound push and LDAP/SSO auth paths add
  egress/firewall expectations (outbound webhook + LDAP port) to this
  checklist when configured.
- **Kubernetes deployment (§31 item 22):** containerized deployment of the
  *shipped* product remains optional and off the default path — the
  install-directly guarantee stands for single-node editions.
- Uninstall at scale: decommission order (drain nodes → final audit export →
  destroy keys per §10 on every node).

## 12. RBAC / ABAC operations (§10, phase 6b)

With `LICENSE_ADMIN_TOKEN` set, that token (kind `admin`) keeps calling
everything as before — it is the bootstrap superuser. Every *other*
credential is a **role binding**; the five seeded roles and their
operation counts are at `GET /api/v1/roles` (also console → Platform
Settings → *RBAC / ABAC*):

```bash
PAM=http://127.0.0.1:5000/api/v1
curl -s -H "X-Admin-Token: <admin token>" $PAM/roles
```

**Grant a role** (the token is returned **once** — sha256 at rest,
never retrievable again):

```bash
curl -s -X POST $PAM/role-bindings \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -H "X-Admin-Token: <admin token>" \
  -d '{"principal":"ops-1","role":"operator"}'
# -> {"id":1,"token":"vypam-rbac1.<id>.<secret>", ...}
```

- `admin` 127 ops · `operator` 45 (day-2 work, never approvals) ·
  `auditor` 27 (reads incl. evidence exports) · `auditor-read-only` 24
  · `approver` 12 (decisions only) - approver ∩ operator = ∅ by design.
- optional ABAC `scope`: `{"targets":["db-prod-*"],
  "vault_items":[3,7]}` — fnmatch on session targets, explicit vault
  item ids; empty scope = the role governs everywhere. Out-of-scope →
  403 with `details.target`.
- Verify as the principal: `GET /api/v1/auth/whoami` with
  `Authorization: Bearer <the minted token>` reports mode, principal,
  role and its operation count; a denial is 403 verbatim
  (`Role 'operator' may not call GET /api/v1/roles`).

**LDAP migration note (the directory authenticates, the binding
decides):** before 6b, any valid LDAP login ticket reached admin
routes. From 6b a ticket alone reaches nothing — each directory user
needs a binding with `"kind":"ldap"` (no token is minted; the signed
ticket is the credential):

```bash
curl -s -X POST $PAM/role-bindings \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -H "X-Admin-Token: <admin token>" \
  -d '{"principal":"alice","role":"operator","kind":"ldap"}'
```

**Revoke:** `DELETE /api/v1/role-bindings/<id>` — the principal's
tokens 401 immediately; the row stays as evidence. Grants, revocations
and refusals land on the §19 ledger under source `rbac`; open dev mode
(no admin token set) waives all of it and says so (`mode: open`).

## 13. SSO + HSM operations (phase 6c)

**Point the SP at your IdP** (Platform Settings → `sso`, or the API):

```bash
PAM=http://127.0.0.1:5000/api/v1
# SAML: the IdP metadata URL (https unless loopback) + our entity id
curl -s -X PUT $PAM/settings/sso \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -H "X-Admin-Token: <admin token>" \
  -d '{"protocol":"saml2","primary_metadata_url":"https://idp.example.com/metadata",
       "primary_entity_id":"urn:aegispam.internal:sp:primary","require_mfa":true}'
```

- The SP downloads and **signature-verifies** the IdP metadata (cached
  3600 s); a later login re-fetches on signature failure, so IdP
  certificate rotation heals itself on the next login.
- `require_mfa` is fail-closed: an assertion without an MFA authn
  context / `amr` entry is refused 403 and recorded
  `sso.login.mfa_failed` — nothing is minted.
- OIDC: `"protocol":"oidc"` + the discovery URL in
  `secondary_metadata_url`/`primary_metadata_url`; PKCE and nonce are
  enforced and `id_token`s are RS256-verified against the JWKS.
- **Provisioning stays two-step**: a successful login creates the
  *subject* only (`jit_provisioning`); admin access needs a role
  binding of kind `sso` (principal = the subject) — the IdP
  authenticates, the binding decides (§12's rule, unchanged):

```bash
curl -s -X POST $PAM/role-bindings \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -H "X-Admin-Token: <admin token>" \
  -d '{"principal":"alice@example.com","role":"operator","kind":"sso"}'
```

- Sessions: `GET /api/v1/auth/sso/sessions`; revoke with
  `POST /api/v1/auth/sso/sessions/<id>/revoke` (the bearer 401s
  immediately); TTL is `sso.session_ttl_minutes`.

**HSM/KMS custody** (Platform Settings → `hsm`):

```bash
# move the master key under provider custody (advisory keeps the file key)
curl -s -X PUT $PAM/settings/hsm \
  -H "Content-Type: application/json" -H "X-Actor: runbook" \
  -H "X-Admin-Token: <admin token>" \
  -d '{"provider":"hashicorp-vault","kms_endpoint":"https://vault.example.com:8200",
       "master_key_label":"pam-root","enforcement":"enforced"}'
curl -s -X POST $PAM/hsm/keys/rotate -H "X-Admin-Token: <admin token>"
curl -s -X POST $PAM/hsm/seal      -H "X-Admin-Token: <admin token>"   # manual seal
curl -s -X POST $PAM/hsm/unseal    -H "X-Admin-Token: <admin token>"   # reload the key
```

- Providers: `hashicorp-vault` (transit; `PAM_HSM_VAULT_TOKEN`),
  `aws-kms` (region + SigV4 credentials), `azure-keyvault` (OAuth),
  `pkcs11` (optional binding). `GET /api/v1/hsm/status` shows mode,
  provider, `key_in_use` (`file`/`provider`), sealed state and the wrap
  record; an unconfigured provider is reported honestly, never
  simulated.
- Rotation is an **envelope re-wrap** — the same master key, so every
  existing ciphertext stays valid. `<vault_key>.wrap` holds base64
  provider ciphertext only; deleting it while `enforcement=enforced` is
  set leaves the vault sealed until the provider can unwrap again
  (honest 503, never a file fallback).
- `enforcement=enforced` + an unreachable provider seals the vault (the
  monitor tick honors `hsm.seal_delay_seconds`); unseal then needs the
  provider. `advisory` keeps the file key and says so.
- The custody trail lands on the §19 ledger under source `hsm`;
  posture `hsm_backed` passes only on enforced + a reachable provider
  (real health probe).

## 14. Identity & login security operations (phase 7)

**Users & console sessions** (the `auth` settings group holds policy —
`mfa_required`, `lockout_threshold`/`lockout_minutes`,
`rate_limit_per_account`/`rate_limit_per_ip`, `spray_threshold`,
`progressive_delay`, `session_idle_minutes`, `stepup_ttl_minutes`,
`emergency_window_minutes`):

```bash
# create a user - no password given => a generated one is shown ONCE
curl -s -X POST $PAM/users -H "Content-Type: application/json" \
  -H "X-Actor: runbook" -H "X-Admin-Token: <admin token>" \
  -d '{"username":"alice"}'
# -> {"user":{...,"must_change_password":true},"generated_password":"..."}

# alice logs in; with mfa_required (default) and no factor yet she gets a
# fail-closed 403 + a one-time enrolment ticket - never a session:
#   {"status":"enrolment_required","enrol_ticket":"vypam-enr1.…"}
curl -s -X POST $PAM/auth/mfa/enroll/totp \
  -H "Content-Type: application/json" \
  -d '{"enrol_ticket":"<from the 403>"}'          # -> secret shown ONCE
curl -s -X POST $PAM/auth/mfa/enroll/totp/verify \
  -H "Content-Type: application/json" \
  -d '{"enrol_ticket":"<same ticket>","code":"<live TOTP>"}'
# -> session_token vypam-ui1.… + csrf_token + HttpOnly vypam_session cookie
```

- A console session is **not** an admin token: mutations authenticated by
  the cookie must send `X-CSRF-Token: <csrf_token>` (credential headers
  skip CSRF by design); the admin token alone holds no console session.
- Lockout doubles on further failures; unlock with
  `POST /api/v1/users/<id>/unlock` — the password path stays MFA-fail-
  closed after unlock. `POST /api/v1/auth/logout-all` revokes every
  session but the caller's.
- Actor is bound to the authenticated principal: for console sessions
  `X-Actor` is ignored (what makes requester ≠ approver real).

**E-mail OTP** (sealed `smtp` group — `enabled`/`host`/`port`/`username`/
`password`/`from_address`/`use_tls`; SMS is settings+DLT only, a
documented gap):

```bash
curl -s -X PUT $PAM/settings/smtp -H "Content-Type: application/json" \
  -H "X-Actor: runbook" -H "X-Admin-Token: <admin token>" \
  -d '{"enabled":true,"host":"smtp.example.com","port":587,"username":"pam@example.com",
       "password":"<smtp password>","from_address":"pam@example.com","use_tls":true}'
```

- With SMTP unconfigured the OTP path **still creates a real challenge**
  and records a *suppressed* delivery with the honest reason
  (`GET /api/v1/auth/deliveries`, admin) — it never fakes a send and
  never returns a code. Start answers identically for known and unknown
  accounts (no enumeration).

**SCIM lifecycle** (own bearer, rotated via the sealed `scim` group):

```bash
curl -s -X POST $PAM/settings/scim/rotate -H "X-Admin-Token: <admin token>"
# -> {"token":"vypam-scim1.…"}   shown ONCE - configure it on the IdP now
curl -s $PAM/scim/v2/Users -H "Authorization: Bearer <the scim token>"
```

- The IdP owns joiner/mover/leaver; SCIM users land in `users` with
  `source=scim` and their logins answer the same uniform 401 as a wrong
  password (true `scim-managed` reason only on the ledger). DELETE keeps
  the row as evidence (`active=false`), never a hard erase. Local console
  users stay invisible to the `/scim/v2/Users` surface.

**RADIUS factor** (`radius` group: `enabled`, `host`, `port`, `secret`,
`timeout_seconds`): point it at your RFC 2865 server, then a user enrols
with `POST /api/v1/auth/mfa/enroll/radius` (session + CSRF). A factor
whose server is unreachable **fails closed** (honest 503, recorded
`auth.mfa.radius-unreachable`) — never a silent pass.

**Sealed emergency admin** (`emergency-admin`): seeded at first boot with
**no usable password** (sealed; the seeding runs under the vault key). If
the vault key is absent at boot, seeding is skipped with a warning and
the server still boots — the account simply doesn't exist yet; it is
never created with an invented password. Opening it is dual-controlled:

```bash
curl -s $PAM/auth/emergency -H "X-Admin-Token: <admin token>"
# -> {"username":"emergency-admin","grants":[...]}
curl -s -X POST $PAM/auth/emergency/open -H "Content-Type: application/json" \
  -H "X-Actor: alice" -H "X-Admin-Token: <admin token>" \
  -d '{"reason":"dc fire drill","ticket":"CHG-1234"}'   # reason >= 8 chars
# then two DISTINCT approvers (never the requester):
curl -s -X POST $PAM/auth/emergency/grants/<id>/approve \
  -H "X-Actor: bob" -H "X-Admin-Token: <admin token>" -d '{"decision":"approve"}'
```

- The window is time-boxed by `auth.emergency_window_minutes`; the login
  (`POST /api/v1/auth/emergency/login`) still demands the sealed
  password, is single-use, and rotates the seal after use. Every step
  lands on the ledger under source `auth`.

## 15. Gateway data-plane operations (phase 8a)

The `gateway` settings group (12 fields) holds policy — `enabled`,
`require_zone`, `guacd_host`, `guacd_port`, `segment_seconds`,
`recording_failure_policy`, the spool alert / full thresholds,
`spool_max_bytes`, `retention_default_days`, `retention_overrides`,
`node_heartbeat_ttl_seconds`.

**Point at guacd:** `guacd_host`/`guacd_port` (default `127.0.0.1:4822`)
is the guacd on the gateway host. Brokered protocols are
rdp/ssh/vnc/telnet (default ports 22/3389/5900/23); the target's zone
comes from its discovered-asset zone binding. Dispatch is **fail-closed:
no healthy node in the target's zone ⇒ 503** and the privileged-session
create rolls back; `require_zone` refuses unmapped targets with an
explicit 503, and a brokered session always requires a vault credential
(503 otherwise). With the gateway disabled, plain sessions keep their
previous behavior and report `gateway: null`.

**Register a node — maker-checker.** Registration lands `pending` and
needs a separate approver to approve it (self-approval is 403). The node
token `vypam-gwn1.<node_id>.<secret>` is shown **once** at registration,
stored sha256 (constant-time compare), and never echoed again; revoke
rotates it off and terminates the node's live gateway sessions.
Heartbeats carry capacity/version; offline is **derived** from a stale
heartbeat (`node_heartbeat_ttl_seconds`, default 90) — never stored —
and drain stops dispatch to the node.

**Run the node daemon** on the gateway host (stdlib only, no extra
package):

```powershell
python gateway_daemon.py --api <server-url> `
  --token <the vypam-gwn1.… token from registration> `
  --storage <recording dir> --poll <seconds>
```

- The daemon heartbeats and polls for work **outbound** — pause and
  terminate control directives arrive on that same poll, so a node needs
  **no inbound port**. Pause stops the daemon reading/acking, so TCP
  backpressure stalls guacd.
- `--storage` is where the daemon seals and writes segments
  (`<storage>/gws-<id>/seg-<seq>.json`); the server-side storage root is
  `RECORDING_STORAGE_DIR` (§4). DB rows hold pointer + size + SHA-256
  only — the API never discloses the path or key material.

**Spool pressure:** spool usage is measured against `spool_max_bytes`
(default 10 GiB) with an alert threshold at 70% and a full threshold at
85%; `recording_failure_policy` decides whether a recording failure
blocks the session or flags it and carries on.

**Retention** (`retention_default_days`, default 90, plus per-protocol
overrides) is run **manually** via the retention endpoint — dry-run
first, then real: it deletes the segment files, destroys the recording
keys and emits `retention-expired` ledger events. Sessions linked to a
command incident are **never** pruned (derived legal hold), and the DB
rows remain as evidence either way; a destroyed key turns later playback
into an honest 410.
