# VY-PAM MASTER — vendor license authority

> **Internal tool. Never shipped to customers.** VY-PAM MASTER runs only at
> VY-Groups and runs the business: customer registry, deals, **license
> generation**, entitlements, renewals. The shipped product is **VY-PAM**
> (customer site) — it *verifies* licenses offline with the public key and
> never creates one. The two-product split is specified in
> `../VY-PAM_MASTER_and_PAM_Workflow.md`.

## What is implemented

Phase 2a (skeleton):

| Piece | State |
| --- | --- |
| Config (`MASTER_*` env, sqlite only) | ✅ `pam_master/config.py` |
| Key custody (presence-only health, **no implicit key creation**) | ✅ `pam_master/keys.py` |
| Signing via shared crypto engine (`backend/ipam_licensing`) | ✅ `pam_master/licensing.py` |
| Endpoints: `GET /`, `GET /health` (real DB state + key presence) | ✅ `pam_master/routes.py` |
| Key generator: `python -m pam_master.keygen` | ✅ `pam_master/keygen.py` |
| Test suite (temp keys/db only — never real custody keys) | ✅ `tests/` |
| Dev-only Docker | ✅ `Dockerfile` + `docker-compose.yml` |
| Customer registry (PII encrypted at rest) | ☐ next (2b) |
| License issuance API + delivery bundle | ☐ (2c) |
| Own `openapi.yaml` + contract/anti-mixing tests | ☐ (2d) |

## Run (development)

```bash
cd pam_master
python -m pam_master            # http://127.0.0.1:5400
python -m pam_master.keygen     # create signing keys (only way they appear)
```

Settings (all optional, defaults shown):

| Variable | Default |
| --- | --- |
| `MASTER_DATABASE_URI` | `sqlite:///` → `pam_master/master.db` (git-ignored) |
| `MASTER_RSA_PRIVATE_KEY_PATH` | `<repo>/license_private_key.pem` |
| `MASTER_ED25519_PRIVATE_KEY_PATH` | `<repo>/license_ed25519_private.pem` |
| `MASTER_SERVER_PORT` | `5400` |
| `MASTER_BIND` | `127.0.0.1` |

## Key custody rules

1. The MASTER holds the **only** copy of the license private keys; the
   shipped VY-PAM receives public keys only.
2. **Keys are never created implicitly.** The shared engine would happily
   mint a key on an empty path — that is correct for customer installs and
   forbidden here: a silently-created trust root signs licenses nothing
   trusts. Keys exist only after an explicit `python -m pam_master.keygen`,
   which never overwrites an existing key.
3. Endpoints report key **presence** (`present` / `missing`) only — key
   material never crosses the process boundary.
4. Keys are git-ignored (repo root and `.keys/`), and generated per test run
   under pytest's temp dirs.

## Tests

```bash
# from the repo root
python -m pytest pam_master -q
```

## Docker (development only)

Docker is a **convenience for local development** — neither product deploys
through containers; VY-PAM installs directly on customer systems and the
MASTER installs directly at VY-Groups.

```bash
cd pam_master
docker compose run --rm pam-master python -m pam_master.keygen   # explicit key creation
docker compose up                                                # http://127.0.0.1:5400/health
```

## Extraction note

This folder is deliberately self-contained (own app, own config, own tests,
own Docker): it imports the **shared crypto engine**
(`../backend/ipam_licensing`) and nothing from the PAM runtime — a test
enforces that. To extract, move `pam_master/` into its own repository and
vendor or submodule `backend/ipam_licensing` beside it; the bridge computes
paths from its own location, so only `licensing.py`'s repo-root assumption
needs revisiting.
