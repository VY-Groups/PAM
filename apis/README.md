# API Contracts

`openapi.yaml` is the contract for everything the VY-PAM backend serves over
HTTP — today the Phase 2 license + platform-settings API
(`backend/phase2_license_server`); future services from
`VY-PAM_Enterprise_PAM_Architecture.md` append their paths here as they land.

## What's here

| File | Purpose |
| --- | --- |
| `openapi.yaml` | OpenAPI 3.1: every `/api/v1/*` route plus `/health` — paths, methods, auth, request/response schemas, error shapes |
| `README.md` | This file |

## Keeping it honest

`backend/phase2_license_server/tests/test_openapi_contract.py` loads the spec
and cross-checks it against the live Flask route map **in both directions**:

- every documented path + method must actually be served (no stale docs),
- every `/api/v1/*` route and `/health` must be documented (no dark endpoints),
- admin operations must declare the admin-token security schemes,
- the `{group}` path enum must match `service.SETTINGS_GROUPS`.

```bash
python -m pytest backend/phase2_license_server/tests/test_openapi_contract.py -q
```

## Conventions

| Concern | Rule |
| --- | --- |
| Base path | `/api/v1` — breaking changes bump the segment, not individual fields |
| Content type | `application/json` (validation also accepts a raw compact token body) |
| Errors | `{"error": "<message>", "details": {...}}` with 400 / 401 / 404 |
| Admin auth | `Authorization: Bearer <token>` **or** `X-Admin-Token: <token>`; when `LICENSE_ADMIN_TOKEN` is unset the server runs in open dev mode (`X-Auth-Mode: open`) |
| Actor | `X-Actor` header names who made a settings change (recorded in the audit changelog) |
| Pagination | `limit` (max 200) + `offset`; responses echo both |
| Timestamps | ISO 8601 strings |

## Viewing

Paste `openapi.yaml` into <https://editor.swagger.io>, Redocly Studio, or run
`npx @redocly/cli preview-docs openapi.yaml`.
