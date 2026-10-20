# ADR-0019: PostgreSQL as the only storage engine (SQLite removed)

Date: 2026-10-19 (amended 2026-10-20)
Status: Accepted (user directive, batch program 11.9: "PostgreSQL for production
storage"; amended 2026-10-20 by the same directive - "switch on postgres...
remove sqlite from the project... only one database postgres, and all
development production-grade"; contract-first, no vibe coding - every fact
below is a checked line)

## Context - the storage layer was SQLite-shaped end to end

The starting point (before this batch) ran on SQLite everywhere: tests, dev
compose, CI and the shipped defaults. That was a deliberate single-node
choice, but the production ask names PostgreSQL. Before any code, every
SQLite-shaped corner was pinned from source (no guessing):

| Fact | Evidence |
|---|---|
| schema migration spoke PRAGMA (SQLite-only) | `ensure_schema` models.py:76-104 - `PRAGMA table_info` :87, `PRAGMA index_list` :98, `DROP/CREATE INDEX` :101-102 |
| append-only audit triggers were SQLite-only | `_TRIGGERS` audit.py:97-106 (`RAISE(ABORT, 'audit_events is append-only (architecture 19)')`), installers guarded `dialect.name != "sqlite"` audit.py:952-955 and :972-975 |
| id allocation was single-writer max+1 | `_ensure_id` audit.py:893-907 ("single-writer sqlite: max+1") |
| backups used SQLite's online backup API with an honest 503 for other engines | `create_cluster_backup` service.py:12628-12688, guard :12636-12640; `test_backup_refuses_a_non_sqlite_storage_engine` test_cluster.py:1198 already answered with `postgresql://pam@db-host/pam` |
| startup wiring | `db.create_all()` + `ensure_schema` + `ensure_audit_chain` app.py:228-241; URI from `LICENSE_DATABASE_URI` config.py:78-81 |
| no SQLite-only SQL existed in the query layer | grep over backend: the only driver-SQL sites were models.py:87-102 and the guarded backup `sqlite3.connect` (service.py:12651/12653/12694); every `strftime` hit is Python datetime formatting |
| tests hardcoded SQLite per test, no central override | 34 inline `database_uri=f"sqlite:///{tmp_path...}"` sites across 30 files, no conftest; direct-file tests test_cluster.py:678/1152, test_rbac.py:294 |
| CI proved SQLite only | 6 jobs; `backend-tests` pip-installs and runs `python -m pytest backend -q` ci.yml:53-87; `docker-tests` runs the dev compose (SQLite in-container) ci.yml:117-123 |
| the market ships a dual-backend pattern | REA shipped-artifact runs: Teleport v18.10.0 `tctl` carries `jackc/pgx/v5` **and** `mattn/go-sqlite3` in one build; OpenBao v2.7.1 carries `jackc/pgx/v5` **and** `bbolt` - `docs/REVERSE_ENGINEERING_TOOLING.md` §5.4/§5.5 (evidence IDs `ev_3bae8688...`, `ev_573b793d...`). This batch originally mirrored that parity posture; the 2026-10-20 amendment supersedes it with a single-engine production posture. |

**Source confirmation** (read-only study of OpenBao v2.7.1's PostgreSQL
backend at `internal/physical/postgresql/postgresql.go`, tag `v2.7.1`,
clone under `Temp/openbao-src` - study only, their `AGENTS.md` permits
Q&A-style AI use of the codebase and forbids generated contributions; none
were made):

- the driver choice is `sql.Open("pgx", ...)` - our D1 `psycopg[binary]`
  wheel is the same dependency philosophy (bundled client, no host libpq);
- schema bootstrap is idempotent-at-startup: `CREATE TABLE IF NOT
  EXISTS` + `CREATE INDEX IF NOT EXISTS` inside a RepeatableRead
  transaction, treating SQLSTATE 23505 (a concurrent creator won) as
  benign - D2's "ensure at boot, additive only" is the same school;
- writes are PG-native upserts (`INSERT ... ON CONFLICT ... DO UPDATE`);
  identifiers are quoted, and a shipped CVE fix (schema-name quoting,
  CVE-2026-39946) underlines the rule our D2 follows - DDL identifiers
  come from the frozen `SCHEMA_COLUMNS`/`SOFT_UNIQUE_INDEXES` dicts, never
  from request data;
- HA leadership is a **lease table** (`ha_key`/`ha_identity`/`valid_until`)
  with periodic renewal plus `FencingHABackend` write validation - a
  long-lived-leadership design. Our D6 advisory lock solves the different,
  short-lived problem (serialising id allocation inside one transaction);
  the two techniques are complementary, not competing.

## Decision 1 - driver pin

`backend/phase2_license_server/requirements.txt` gains
`psycopg[binary]>=3.2`. The `[binary]` wheel bundles libpq, so hosts and
images need no system PostgreSQL client libraries (portability mirror of
OpenBao's `CGO_ENABLED=0` posture, REA doc §6 decision 6).

## Decision 2 - inspector-based `ensure_schema`, PostgreSQL branch only

`ensure_schema` (models.py:88-150) reads through the SQLAlchemy inspector
(`sqlalchemy.inspect(engine)`), then executes the reconciliations. With the
SQLite engine removed (amendment D10 below) the dialect conditionals
collapse to their PostgreSQL arms:

- existing columns per table via `get_columns` (replaces `PRAGMA table_info`);
  `ALTER TABLE ... ADD COLUMN` executes the spec DDL with the `DATETIME`
  token mapped to `TIMESTAMP` (the spec token has no PostgreSQL spelling;
  a fresh database never reaches the ALTER path - the models define the
  current shape);
- soft-unique relaxation via `get_indexes` (replaces `PRAGMA index_list`):
  when `ix_gateway_nodes_name` is present **and unique**, `DROP INDEX` +
  non-unique `CREATE INDEX`;
- `EVIDENCE_FOREIGN_KEYS` drops `gateway_nodes_zone_id_fkey` at startup
  (present -> dropped and reported, absent -> nothing to do);
- the return contract is unchanged: the list of changes, empty when current.

## Decision 3 - PostgreSQL append-only triggers, verbatim contract

`_install_triggers` / `triggers_installed` (audit.py:991-1050) keep their
PostgreSQL branch as the only implementation:

- one plpgsql function `audit_events_append_only()` that raises
  `RAISE EXCEPTION 'audit_events is append-only (architecture 19)'` - the
  **verbatim** message every caller and test asserts;
- two row triggers, `audit_events_no_update` (BEFORE UPDATE) and
  `audit_events_no_delete` (BEFORE DELETE), created when missing per
  `pg_trigger` (excluding internals);
- unknown dialects keep the fail-closed `return False` (ADR-0019 D3
  original); the SQLite trigger DDL (`_TRIGGERS`, `sqlite_master` queries)
  is removed with the engine (D10).

## Decision 4 (amended) - PostgreSQL-native logical backup bundle

The original D4 ("backups stay SQLite-honest, answer 503") is superseded:
an engine that owns the product must back itself up. `create_cluster_backup`
(service.py:12628) writes a **logical NDJSON bundle** of the live store:

- every table (sorted by name) is streamed as one JSON line per row
  (`{"table": "<name>", "row": {...}}`), streamed to
  `CLUSTER_BACKUP_DIR/pam-backup-<stamp>-seq<seq>.ndjson` without stopping
  writes - a point-in-time logical export, the PostgreSQL-school backup
  (the same family as the already-shipped `/audit/export` NDJSON stream and
  the section-18 peer replication exports);
- the file is hashed (sha256), then re-parsed: `_verify_backup_chain`
  re-walks the embedded `audit_events` records with the same chain
  recomputation `/audit/verify` performs - every verifier string keeps its
  exact wording (`content hash mismatch at seq N`, `chain link broken at
  seq N`, `chain break at seq N (expected N)`, `chain intact over N
  records`); a bundle without chain records answers the honest
  `backup bundle carries no audit_events records`;
- the `ClusterBackup` row, cluster event detail and overview counters are
  unchanged (path, sha256, size_bytes, audit_seq, verified, verify_detail,
  created_by);
- exposure posture is identical to the removed flow: the SQLite lane copied
  the whole store byte-for-byte, the bundle carries the same rows (vault
  rows stay sealed - sealing happens at write time, D8 of ADR-0005);
- `pg_dump`/`pg_basebackup` remain the operations-grade physical lane for a
  future batch; this batch ships the verified logical bundle, not a gap.

## Decision 5 (amended) - one engine in the suite, in CI, in the matrix

The 2-engine CI matrix and the SQLite-default test path never shipped to
`origin/main` (they were part of this uncommitted batch), so the workflow
**stays at 6 checks** - the original "6 -> 7" disclosure is withdrawn with
the matrix:

- `tests/_testdb.py::test_database_uri` **requires** `PAM_TEST_DATABASE_URI`
  and fails fast with the exact setup command (PostgreSQL is the only
  storage engine - there is no embedded default to fall back to);
- `tests/conftest.py` fails the session once, up front, with that same
  honest message when the variable is missing - no 800-error storm;
- `tests/test_postgres.py` becomes the always-on PostgreSQL contract module
  (its skip guard removed): triggers, advisory-lock allocation,
  inspector migration, token-at-rest;
- **zero skip markers**: the five file-reading tests are rewritten as
  engine-neutral SQL tests, not skipped - tamper-peer drops the trigger by
  name over a direct connection and updates (test_cluster.py), the backup
  tests operate on the bundle file (test_cluster.py), the RBAC at-rest read
  queries `role_bindings.token_sha256` (test_rbac.py), the at-rest plaintext
  scan walks every table's text columns (test_rotation.py);
- `backend-tests` collapses to one leg: the same `postgres:16` service
  (with `--shm-size 1g`), `PAM_TEST_DATABASE_URI` always set;
- `docker-tests` drops `--no-deps` so the compose `postgres` dependency
  starts, and passes the same variable in-container;
- the Windows standing-gate rig boots start a `postgres:16` container on
  the runner (fresh database per rig: `pam_ci_open` / `pam_ci_token`);
- the local standing gate's own server boot
  (`shots_tool/__verify_discovery.mjs`) creates a fresh dedicated database
  on the developer's PostgreSQL before spawning `python app.py`.

## Decision 6 - concurrency-safe id allocation on PostgreSQL

`_ensure_id` (audit.py:893-907) keeps max+1 and serialises allocators with
`SELECT pg_advisory_xact_lock(:key)` (documented API) - the key is a 63-bit
SHA-256 of `pam-id-alloc:<table>`, computed in Python so it is stable
across nodes and needs no undocumented `hashtext`.

## Decision 7 (amended) - one production-shape compose, `:5010` entry kept

`backend/phase2_license_server/docker-compose.yml` becomes the only compose
file: a `postgres:16` service (healthcheck, `shm_size: "1gb"`, named volume)
plus the `license-server` service pointed at it via
`LICENSE_DATABASE_URI=postgresql+psycopg://pam:pam@postgres:5432/pam`,
`depends_on: service_healthy` - host entry **5010 -> 5000** unchanged (the
documented developer URL). The sibling `docker-compose.postgres.yml` (never
committed) is dropped from the batch - its shape is now the default, so
`docker compose up --build` starts the production shape directly.

## Decision 8 - fail-fast configuration (production-grade startup contract)

`Config.from_env` (config.py:75-81) no longer defaults to an embedded
file:

- `LICENSE_DATABASE_URI` unset -> `ValueError` naming the variable, the
  engine and this ADR (`PostgreSQL is the only storage engine (ADR-0019)`);
- a non-`postgresql` scheme (including any `sqlite:` URI) -> the same class
  of honest error, so a stale `.env` line fails loudly at boot instead of
  silently reverting engines;
- every boot path sets the variable and is inventoried in this batch:
  bare `python app.py`/`wsgi.py` read `.env` (dotenv, config.py:16/23 -
  `.env.example` now carries a PostgreSQL example), the compose service
  (D7), the CI standing-gate rigs (D5), the local gate discovery boot (D5),
  and the dev rig containers;
- tests never call `from_env` (verified: the only callers are app.py:73 and
  wsgi.py) - fixtures build `Config(...)` through `_testdb`.

## Decision 9 - scope boundary: internal tooling keeps its embedded store

`pam_master` (the internal workflow/architecture tooling tree, own config,
ships nothing to customers) keeps its `MASTER_DATABASE_URI` embedded
default; `ipam_licensing` and `pam_master` touch no database otherwise
(grep: zero SQLite references outside `backend/phase2_license_server`).
The boundary is deliberate and recorded here rather than silent: the
**product** is PostgreSQL-only; **repo-internal tooling** is not the
product surface. If pam_master ever ships, this decision reopens.

## Decision 10 - the SQLite removal inventory (the amendment itself)

Every removal is a checked location, not a sweep:

| Area | Removed | Kept/converted |
|---|---|---|
| config | `sqlite:///` default (config.py:77-81), SQLite-backup comment (config.py:63-65) | required PG URI + scheme guard (D8) |
| triggers | `_TRIGGERS` sqlite DDL (audit.py:97-106), both `sqlite_master` branches (audit.py:994-1008, 1031-1042) | PG function + triggers, fail-closed unknown dialect |
| schema | dialect conditionals in `ensure_schema` (models.py:103, 130-134) | inspector reconciliation, evidence-FK drop (unconditional now) |
| backups | `sqlite3` import + online-backup flow + sqlite file verifier (service.py:12636-12731) | NDJSON bundle + same verifier contract (D4) |
| test infra | sqlite fallback in `_testdb` (61), `postgres_override()` (77-80), all 5 skip markers | required-env fail-fast (D5), session check in conftest |
| tests | `test_backup_refuses_a_non_sqlite_storage_engine` (its behaviour is now the honest error at boot, D8, tested there), sqlite direct-file reads | rewritten SQL equivalents, `test_postgres.py` always-on |
| CI | engine matrix (ci.yml:60-61), sqlite rig URIs (ci.yml:240, 267) | single PG leg, PG-backed gate rigs (D5) |
| compose | sibling `docker-compose.postgres.yml` (uncommitted) | merged single compose (D7) |
| API copy | openapi backup description + `trigger_protection` description (openapi.yaml:4426-4429, 7828) | orval-regenerated client, `triggersFooter` copy (`i18n/en.json:1008`) |
| docs | runbook/TRD/README/`.env.example` SQLite defaults and the `503` backup note | one documented PostgreSQL requirement + fresh-database semantics |

## First full PostgreSQL battery - findings (2026-10-19)

The first complete suite run against the real server (834 collected,
`PAM_TEST_DATABASE_URI` set) ended **12 failed, 683 passed, 3 skipped,
136 errors** - and every failure sorted into environment or contract,
none left as a maybe:

- **Environment: docker's 64MB default `/dev/shm` crashed the server
  mid-run.** Verbatim server log: `ERROR: could not resize shared memory
  segment "/PostgreSQL.3106961468" to 33554432 bytes: No space left on
  device` -> `server process (PID 25741) was terminated by signal 11:
  Segmentation fault` -> `all server processes terminated;
  reinitializing` -> every later connection answered `FATAL: the database
  system is in recovery mode` (the server stayed in recovery, fsyncing a
  14GB data directory of leaked test databases, until the run ended).
  All 136 errors and 7 of the 12 failures are that crash: the errors all
  belong to files that collect at or after `test_sessions`, where the
  DiskFull first surfaced (pytest ran sequentially), and
  `test_vault_dashboard.py::test_overview_flags_open_auth_mode` carries
  the recovery FATAL verbatim in its traceback. Fix: `--shm-size 1g` on
  the CI service container, `shm_size: "1gb"` on the compose (D7),
  `--shm-size=1g` on local verification containers.
- **Five real findings, fixed where they live:**
  1. `test_cluster.py::test_backup_is_a_real_verified_file` was a missed
     skip (its tampered-copy sibling had one): it expects a 201 backup
     file, then-D4 made PostgreSQL answer the honest 503 - marker added
     (removed again by this amendment: the bundle flow runs everywhere).
  2. `test_postgres.py::test_pg_backup_answers_the_honest_503` expected
     `{"scheme": "postgresql"}` but the server derives the value
     verbatim from the configured URI (`uri.split("://", 1)[0]`,
     service.py:12639) - the D1 driver-qualified spelling
     `postgresql+psycopg` is the contract; the expectation was corrected
     to it (the test itself retires with D4's rewrite).
  3. `test_audit.py::test_missing_record_is_a_gap_even_if_the_trigger_is_dropped`
     dropped the trigger with the SQLite-only spelling and failed with
     `psycopg.errors.SyntaxError: syntax error at end of input`; the
     drop is now dialect-aware (`... ON audit_events` on PostgreSQL -
     the trigger names themselves already match across engines,
     audit.py `_TRIGGERS`/`_PG_TRIGGERS`; with D10 only the PostgreSQL
     spelling remains).
  4. `test_rotation.py::test_no_plaintext_in_the_database_file` scanned
     the SQLite store file's bytes (`licenses.db`); there is no such
     file on PostgreSQL - skip marker added, same engine-internal class
     as D5's original three (this amendment rewrites it as a SQL walk
     over every text column - a stronger property than one file's bytes).
  5. **`gateway_nodes.zone_id` is a contract-bearing evidence
     reference, not an enforced relationship.**
     `test_gateway.py::test_zone_delete_refuses_live_nodes_and_frees_after_revoke`
     failed on PostgreSQL with `ForeignKeyViolation: update or delete on
     table "zones" violates foreign key constraint
     "gateway_nodes_zone_id_fkey"` - while `gateway.delete_zone`
     documents that a revoked node's row keeps its `zone_id` as where
     the node once lived, and the test requires the subsequent delete
     to answer 200. The shipped baseline declares the FK in its DDL
     (REA `licenses-schema.json`) but never enforced it (no
     `PRAGMA foreign_keys` exists in the product), so the dangling
     evidence row IS the shipped behaviour. Resolved in D2's own idiom:
     `EVIDENCE_FOREIGN_KEYS` drops `gateway_nodes_zone_id_fkey` at
     startup on PostgreSQL (reported by `ensure_schema` like every other
     reconciliation entry), and the test now asserts the surviving row
     directly instead of only commenting it.
     `AssetZoneBinding`/`GatewayPool` keep their FKs: `delete_zone`
     refuses while they exist (409 before any DELETE).

## Second PostgreSQL battery - the engine-divergence catch (2026-10-20)

Rerun on the batch tree: **1 failed, 828 passed, 5 skipped** - the single
failure is the reason dual-engine proof exists, and it is now the only
engine that exists:

- `test_vendor_pam.py::test_list_filters_and_paging` searched
  `q=industries` (lower) against "Beta Industries" and got 0 rows **only
  on PostgreSQL**: the vendor search was the codebase's last raw
  `.like()` call (service.py:7903) - SQLite's ASCII-case-insensitive
  `LIKE` masked it, PostgreSQL's case-sensitive `LIKE` exposed it. Fixed
  to the house-standard `.ilike()` used at the other 20+ call sites
  (service.py:597, 2061, 3483, 5494, ...), verified 22/22 vendor tests
  green on PostgreSQL. With this catch, the user directive that followed
  (one engine, one battery) removes the class of surprise entirely: the
  engine the suite runs on **is** the engine that ships.

## Final single-engine battery - the close-out (2026-10-20)

After D10 landed, the full suite on the local `postgres:16` server:
**834 passed, 161 warnings in 3600.35s (1:00:00)** - the whole
collection, **0 failed, 0 skipped** (D5 removed every skip guard, so the
printed count is the entire suite; the first battery's 834 collected
reappears as 834 passed). Supporting bars on the same tree: `pam_master`
**46 passed**; bandit 1.9.4 **0 findings** (the origin/main baseline was
verified clean first, and the batch's one B608 - the bundle writer's
f-string `SELECT` - was fixed by Core reflection with dialect-quoted
identifiers instead of string-built SQL); ruff E9/F63/F7/F82 clean;
frontend battery green (prettier, eslint, tsc, vitest **450 passed**,
vite build, storybook build); the standing gate `__verify_agent.mjs`
**ALL CHECKS PASSED in both modes** - the open rig on :5100 and the
token rig on :5101, both rebuilt from this tree and backed by dedicated
PostgreSQL databases; gitleaks `protect --staged` clean.
The second CI leg then ran the exact `docker-tests` command over the
compose `postgres:16`, detached: **752 passed, 161 warnings in 4057.31s
(1:07:37)**, `exitcode=0`, `oom=false` - the counts differ only by
scope, since `pytest tests` runs phase2's `tests/` only and 752 + the 82
`ipam_licensing` tests the repo-root `pytest backend -q` adds = 834.

## Batch table

| Batch | Surface | Contract delta | Evidence bar |
|---|---|---|---|
| 11.9 | backend + CI + deploy + API copy | storage-engine contract: PostgreSQL **only** - inspector `ensure_schema`, PG append-only triggers (verbatim message), advisory-lock id allocation, PG-native logical backup bundle, required-env fail-fast config, single production-shape compose, zero test skips, SQLite removed from code/tests/CI/copy/docs (D10) | full backend suite green **on PostgreSQL**: **834 passed, 0 failed, 0 skipped** (printed 2026-10-20), `pam_master` **46**, standing gate green in both modes on PG-backed rigs, frontend battery green (prettier/eslint/tsc/vitest **450**/build/storybook), bandit + ruff clean, gitleaks clean, CI **6 checks** |

Cross-references: the 75-table/175-index baseline the port must reproduce is
the REA shipped-schema audit (`docs/REVERSE_ENGINEERING_TOOLING.md` §5.2);
batch numbering in ADR-0017 (must_change + Access -> 11.10) and ADR-0018
(first-run setup -> 11.11) shifts by one to make room for this batch, same
date, same program. ADR-0020 (reference-verified UI/UX direction) is the
frontend batch that follows this landing.
