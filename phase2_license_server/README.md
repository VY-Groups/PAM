# IPAM License Server (Phase 2)

Flask service that issues, stores, revokes and validates IPAM licenses.

It does **not** re-implement cryptography: signing and verification come
straight from the Phase 1 library in `../ipam_licensing` (RSA-PSS-SHA256),
imported through `licensing_bridge.py`. A license produced by this server is
byte-for-byte compatible with the Phase 1 `license_validator` CLI.

## Layout

| File | Responsibility |
| --- | --- |
| `app.py` | Flask app factory, error handlers, `/health`, `python app.py` entrypoint |
| `config.py` | Environment-driven configuration (`.env` supported) |
| `routes.py` | HTTP layer: parsing, auth, status codes |
| `service.py` | Business logic: issue, list, revoke, restore, validate, checks |
| `models.py` | `LicenseRecord` (signed license) + `LicenseEvent` (audit trail) |
| `keys.py` | Startup key checks (fail fast, public/private must match) |
| `licensing_bridge.py` | Path bootstrap + cached Phase 1 `LicenseGenerator`/`LicenseValidator` |
| `tests/test_api.py` | End-to-end API tests |

## Quick start

```bash
cd phase2_license_server
pip install -r requirements.txt

python app.py                 # http://127.0.0.1:5000  -> web UI at /
# or
flask --app app run
# production:
waitress-serve --port 5000 wsgi:app     # pip install waitress
```

## Web UI

`GET /` (alias `/license`) serves the **License & Entitlement Center** screen,
a live page in the suite's design system that drives the API below:

- registry table with status/type/search filters, metrics, audit trail
- issue modal (sign + download the signed file), revoke/restore with reason
- signature validation console (paste JSON or load a `.json` file)
- authority status panel (`/health`) and admin-token entry

Source: `../stitch_pam_suite_dashboard_ui/license_entitlement_center/code.html`
(kept with the rest of the Stitch screens so the visual language stays in one
place). It is served **same-origin** — its `fetch('api/v1/...')` calls resolve
against this server, so no CORS is needed or enabled. Open it at
`http://127.0.0.1:5000/` rather than as a `file://` page.

Admin actions (issue / revoke / restore / download) send the token as
`X-Admin-Token`; enter it once in the UI (kept in `sessionStorage` for that tab
only). If `LICENSE_ADMIN_TOKEN` is unset the server runs in open mode.

First start creates `phase2_license_server/licenses.db` (override with
`LICENSE_DATABASE_URI`) and validates the key pair in the repository root.

```bash
python -m pytest tests -q     # 26 tests
```

## Configuration

See `.env.example`. Highlights:

- `LICENSE_ADMIN_TOKEN` — bearer token guarding issue/revoke/restore/download.
  Unset means open mode (responses then carry `X-Auth-Mode: open`); always set it
  outside a trusted network.
- `LICENSE_PRIVATE_KEY_PATH` / `LICENSE_PUBLIC_KEY_PATH` — defaults to the Phase 1
  keys at the repository root. Startup aborts if the pair does not match.
- `LICENSE_AUTOGENERATE_KEYS=1` — allow creating a missing key pair (dev only;
  it changes which licenses are verifiable).

## API

Base path `/api/v1`. All bodies are JSON.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | – | Liveness + DB check |
| POST | `/licenses` | admin | Issue and sign a license (201) |
| GET | `/licenses` | – | List/filter licenses (`status`, `license_type`, `issued_to`, `q`, `limit`, `offset`) |
| GET | `/licenses/<key>` | – | Detail incl. audit events |
| GET | `/licenses/<key>/file` | admin | Original signed license file (download) |
| POST | `/licenses/<key>/revoke` | admin | Soft-revoke with optional `{"reason"}` |
| POST | `/licenses/<key>/restore` | admin | Undo a revocation |
| POST | `/licenses/validate` | – | Full check: signature → revocation → expiry |
| POST | `/licenses/<key>/check` | – | Feature / usage-limit checks |

Admin auth: `Authorization: Bearer <token>` or `X-Admin-Token: <token>`.

### Issue

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses \
  -H "Authorization: Bearer $LICENSE_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"license_type":"subscription","issued_to":"Acme Ltd","usage_limits":{"max_users":25}}'
```

`license_type` is one of `trial`, `subscription`, `perpetual`, `enterprise`.
Optional: `trial_days`, `features`, `usage_limits`, `metadata`. Defaults per type
(features, limits, 30-day trial, 365-day subscription) come from the Phase 1
generator. The response carries both the stored record and the ready-to-deliver
`license_file` (`{license_data, signature, algorithm, version}`).

### Validate

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/validate \
  -H "Content-Type: application/json" -d @license_<KEY>.json
```

Responds with `valid`, `status` (`valid` / `revoked` / `expired` /
`signature_invalid` / `malformed`), `registered` (present in this server's
database), `matches_registered_record`, and the human-readable license info.

The check order is: structure → signature → revocation list → expiry. A license
issued offline with the same key pair still validates (`registered: false`);
only revocation and expiry are enforced by this server.

### Check features / usage

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/licenses/<KEY>/check \
  -H "Content-Type: application/json" \
  -d '{"feature":"api_access","limit_type":"max_users","current_usage":12}'
```

## Design notes

- **Revocation is server-side.** Phase 1 licenses are stateless; this server keeps
  the revocation list, so `POST /licenses/validate` is the authority for
  "is this license still good?".
- **Audit trail.** Every issue/revoke/restore writes a `LicenseEvent` row,
  returned with `GET /licenses/<key>`.
- **Naive local datetimes.** Expiry is compared in Python, not SQL, so results do
  not depend on the database's timezone handling.
- **Errors are JSON**: `{"error": "...", "details": {...}}` with 400/401/404/405/500.
