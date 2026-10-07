# VY-PAM MASTER — vendor license authority

> **Internal tool. Never shipped to customers.** VY-PAM MASTER runs only at
> VY-Groups and runs the business: customer registry, deals, **license
> generation**, entitlements, renewals. The shipped product is **VY-PAM**
> (customer site) — it *verifies* licenses offline with the public key and
> never creates one. The two-product split is specified in
> `../VY-PAM_MASTER_and_PAM_Workflow.md`.

## What is implemented

Phase 2 (complete: skeleton + registry + issuance + API contract):

| Piece | State |
| --- | --- |
| Config (`MASTER_*` env, sqlite only) | ✅ `pam_master/config.py` |
| Key custody (presence-only health, **no implicit key creation**) | ✅ `pam_master/keys.py` |
| Signing via shared crypto engine (`backend/ipam_licensing`) | ✅ `pam_master/licensing.py` |
| Endpoints: `GET /`, `GET /health` (real DB state + key presence) + customer API | ✅ `pam_master/routes.py` |
| Key generator: `python -m pam_master.keygen` (RSA / Ed25519 / registry) | ✅ `pam_master/keygen.py` |
| Test suite (temp keys/db only — never real custody keys) | ✅ `tests/` |
| Dev-only Docker | ✅ `Dockerfile` + `docker-compose.yml` |
| Customer registry: list/create/get/edit + issuance history, **PII AES-256-GCM at rest** | ✅ `registry.py` + `crypto.py` + `db.py` |
| License issuance: sign via shared engine, encrypted archive, renewal, audit, offline-verifiable delivery bundle | ✅ `issuance.py` + `errors.py` |
| Own `openapi.yaml` + contract/anti-mixing tests | ✅ `openapi.yaml` + `tests/test_openapi_contract.py` |

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
| `MASTER_CUSTOMER_KEY_PATH` | `pam_master/customer_registry.key` (git-ignored) |
| `MASTER_CUSTOMER_KEY_B64` | unset — when set, base64 of 32 bytes wins over the file (orchestration secrets) |
| `MASTER_SERVER_PORT` | `5400` |
| `MASTER_BIND` | `127.0.0.1` |

## Customer registry API

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/customers` | list — `limit` 1–200 (default 50), `offset`; newest first |
| `POST` | `/api/v1/customers` | create — `name` + `region` required → `201` + `Location` |
| `GET` | `/api/v1/customers/<id>` | one record (32-hex `public_id`) |
| `PATCH` | `/api/v1/customers/<id>` | partial edit; `null` clears an optional field |
| `GET` | `/api/v1/customers/<id>/issuance-history` | newest first; entries are written by the issuance flow (2c) |

* All six fields (`name`, `region`, `contact_name`, `contact_email`,
  `contact_phone`, `notes`) are stored **encrypted** (AES-256-GCM, bound to
  the row's `public_id`); the database file never contains plaintext — a test
  reads the raw file and proves it.
* No hard deletes on purpose: issued licenses must keep resolving their
  customer (list/create/edit only, per plan).
* **No auth layer yet** — the server binds `127.0.0.1` by default; expose
  deliberately.
* Honest failures: validation → `400`, unknown customer → `404`,
  missing/invalid registry key → `503 registry_unavailable`, corrupt row →
  `500 registry_data_corrupt`. Nothing is guessed.

## License issuance API

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/license-options` | tiers/modules/algorithms/defaults — asserted against the shared engine's catalog in tests |
| `POST` | `/api/v1/customers/<id>/licenses` | issue — `license_type` required; `validity_days`, `modules`, `quotas`, `algorithm`, `environment` optional → `201` |
| `GET` | `/api/v1/licenses` | list — `customer`, `status` (`active`/`superseded`), `limit`, `offset` |
| `GET` | `/api/v1/licenses/<id>` | metadata (no decryption needed — the customer name lives only in the encrypted archive) |
| `POST` | `/api/v1/licenses/<id>/renew` | new signed license for the same customer; previous row marked `superseded` in the same transaction |
| `GET` | `/api/v1/licenses/<id>/bundle` | delivery zip: `<id>.lic` + `license_public_key.pem` + `README.txt` + `SHA256SUMS.txt` |
| `GET` | `/api/v1/audit` | master-side audit trail: `license_issued`, `license_renewed`, `license_bundle_exported` |

* Claims, tier/plan/module/quota defaults and signing come from
  `backend/ipam_licensing` (one engine on both sides); the issuance tests
  assert the API's advertised defaults against the engine's actual behavior.
* The signed envelope carries the licensee's name — as any real license
  file does — so the **archive is encrypted** with the registry key
  (AAD = license id). A test reads the raw database file and proves the
  name is not in plaintext.
* The bundle verifies offline: `sha256sum -c SHA256SUMS.txt`, then verify
  the `.lic` envelope with the included `license_public_key.pem`.
* No auth layer yet (same as the registry): binds `127.0.0.1` by default.

## API contract

`pam_master/openapi.yaml` is this product's own OpenAPI 3 contract (the
shipped product's contract lives separately in `apis/openapi.yaml`).
`tests/test_openapi_contract.py` enforces it **both ways** (documented
operations ↔ served routes), compares live response shapes against the
documented schemas, mirrors documented enums/ranges against the code
constants they claim to describe — and, as a shipped-surface invariant,
fails if any git-tracked file contains a private-key block. The anti-mixing
scan additionally forbids `phase2_license_server` and `backend.` package
imports in the MASTER's package sources (tests excluded — they name the
forbidden tokens deliberately).

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
4. Keys are git-ignored (repo root and `.keys/`), the registry key lives in
   `pam_master/customer_registry.key`, and tests generate every key fresh
   under pytest's temp dirs.
5. **Customer PII is encrypted at rest** with its own AES-256-GCM key
   (registry key) — never the signing keys; data confidentiality and signing
   trust stay separate.

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
