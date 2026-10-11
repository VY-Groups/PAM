# VY-PAM — Deployment & Operations Runbook

**Status:** as-built for Phase 6b
Docker exists **only** for development and runtime testing (vendor tool +
license server). The shipped product
installs directly on a machine — no VM, no container.

---

## 1. Prerequisites

- Python **3.10+** (tested on the versions running this repo's suite), `pip`
- Node.js **18+** — *screenshots/verification tooling only* (not runtime)
- Outbound network only for first-run font/CDN assets (Tailwind CDN, Google
  Fonts); air-gapped deployments should vendor those two assets locally
- Disk: the DB is one SQLite file; keys are a handful of PEM/`*.key` files

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

First boot, automatically: creates `licenses.db`, generates missing keys **only
if** `LICENSE_AUTOGENERATE_KEYS=1`, backfills the audit chain once, seeds the
15 §9 rules into an empty table, and (if enabled) starts the rotation
scheduler.

**Verify:** `GET /health` → 200 with a real DB ping; open
`http://127.0.0.1:5000/` → the 11-item console with live numbers.

Development alternative (**runtime/real-time testing only**, never a
shipping instruction): `backend/phase2_license_server/docker-compose.yml`
builds a **dev-only** image from the repo root
(`docker build -f backend/phase2_license_server/Dockerfile -t vypam-license-server:dev .`),
maps **5010 → 5000** (the host dev server usually owns 5000), gives every
`up` a fresh in-container database, and bakes throwaway signing keys per
build — `.dockerignore` keeps `*.pem`/`*.key`/`.env`/`*.db` out of every
build context. The same image runs the suite in its Linux runtime:
`docker run --rm vypam-license-server:dev python -m pytest tests -q`.

## 3. Install — vendor tool (VY-PAM MASTER, internal only)

```powershell
# one-time trust-root keys (refuses to overwrite — by design)
cd pam_master
python -m pam_master.keygen             # writes license_private_key.pem etc. at repo root

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
| `LICENSE_DATABASE_URI` | `sqlite:///licenses.db` | keep on local disk |
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

**Backup** (while the service is stopped, or copy-consistent):
```
licenses.db          # domain data + audit chain
vault.key            # VAULT_KEY_PATH — secrets are unrecoverable without it
license_*.pem        # verification keys (trust root stays in PAM-MASTER)
.env                 # config (contains secrets — store accordingly)
```

**Restore:** stop service → put files back with original permissions →
start → `GET /health` + `GET /api/v1/audit/verify` (chain must report intact
across the restored history).

**Upgrade:** stop → back up → replace code → `pip install -r requirements.txt`
→ start. Schema changes are additive and applied at boot by
`ensure_schema()`; the one-time chain backfill and rule seeding never repeat.
Run the boundary suites before exposing it: `python -m pytest backend -q`
(expect **613**) and `python -m pytest pam_master -q` (**46**).

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

**Scheduled backups** (per node): `POST /api/v1/cluster/backups` copies
the live SQLite file into `CLUSTER_BACKUP_DIR` and re-walks the chain
from the copy before answering (`verified: true`); copy the file
off-host with your normal job. Restore is §6 (file put-back →
`GET /health` + `GET /api/v1/audit/verify`).

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
| Fonts/icons missing offline | CDN blocked | vendor Tailwind CDN + Google Fonts locally |

## 10. Uninstall

Stop the process; delete the install directory **after** securely destroying
`vault.key`, the PEMs, `licenses.db`, and `.env` (they contain secrets,
credentials, and audit history).

## 11. Target deployment (after planned work — see `IMPLEMENTATION_PLAN.md`)

Status per item — recorded so operations planning isn't surprising:

- **§18 HA/DC/DR (phase 6a — shipped, single-binary scope):** node
  registry, real `/health` probes, hash-verified pull replication
  (audit/vault/sessions), the passive write gate, manual failover + opt-in
  automatic promotion, and verified SQLite backups run today — runbooks in
  §7. Still ahead of the full spec picture: external load-balancer
  topology guidance and a replicated store replacing single-file SQLite
  for multi-writer nodes.
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

- `admin` 105 ops · `operator` 45 (day-2 work, never approvals) ·
  `auditor` 19 (reads incl. evidence exports) · `auditor-read-only` 16
  · `approver` 10 (decisions only) — approver ∩ operator = ∅ by design.
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
