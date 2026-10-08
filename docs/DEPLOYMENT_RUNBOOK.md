# VY-PAM — Deployment & Operations Runbook

**Status:** as-built for Phase 4f (`110909f`)
Docker exists **only** for developing the vendor tool. The shipped product
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
`http://127.0.0.1:5000/` → the 10-item console with live numbers.

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
(expect **343**) and `python -m pytest pam_master -q` (**46**).

## 7. Monitoring

| Signal | Source | Healthy looks like |
|---|---|---|
| Liveness | `GET /health` | 200, real DB ping |
| Chain integrity | `GET /api/v1/audit/verify` | `intact` (alert on first break) |
| Rotation | `/api/v1/vault/stats` | `last_rotated_at` advancing for due items |
| Session/control load | `/api/v1/sessions/stats` | as capacity requires |
| Failed admin auth | proxy/app logs | spikes ⇒ token probing |

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 401 on admin routes | `LICENSE_ADMIN_TOKEN` set, client missing header | send `Authorization: Bearer …` or `X-Admin-Token` |
| Admin routes work without auth | open dev mode | **expected only in dev**; set the token (posture violation `admin_auth "open dev mode"` disappears when set) |
| Boot fails: "Private key not found" / key load error | missing/corrupt PEM | restore from backup; or `LICENSE_AUTOGENERATE_KEYS=1` for a **fresh trust root** (invalidates previously issued licenses) |
| Vault endpoint 503 | `vault.key` missing/unreadable | restore `vault.key`; never regenerate over an existing DB (old ciphertext undecryptable) |
| `/audit/verify` reports first break | DB tampering/corruption | **do not repair silently** — export NDJSON evidence, restore from last good backup, investigate |
| Scan 409 | a scan is already running | single-flight by design; wait or check `/discovery/scans` |
| Console shows `—` everywhere | API unreachable or `file://` | correct: honest fallback; fix base URL / serve via HTTP |
| Fonts/icons missing offline | CDN blocked | vendor Tailwind CDN + Google Fonts locally |

## 9. Uninstall

Stop the process; delete the install directory **after** securely destroying
`vault.key`, the PEMs, `licenses.db`, and `.env` (they contain secrets,
credentials, and audit history).
