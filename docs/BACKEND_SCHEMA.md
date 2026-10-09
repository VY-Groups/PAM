# VY-PAM — Backend Schema

**Status:** as-built for Phase 4h
Two databases: the **shipped runtime DB** (`backend/phase2_license_server/
licenses.db`, SQLAlchemy/Flask-SQLAlchemy) and the **vendor-tool DB**
(`pam_master/master.db`, raw `sqlite3`). Both are SQLite, both git-ignored.

Schema management: `db.create_all()` at first boot +
`models.ensure_schema()` for **additive** column backfill on upgrade — no
external migration tool.

---

## 1. Shipped runtime - 28 tables

### ERD (logical)

```
licenses ─1:n─ license_events
platform_settings ─1:n─ settings_events
vault_items ─1:n─ vault_events
vault_items ─1:n─ vault_secret_versions
discovered_assets ─1:n─ discovered_accounts
discovery_scans ─1:n─ discovery_events        discovery_assets links via asset_id
jit_requests ─1:n─ jit_events
privileged_sessions ─1:n─ session_events      (item_id → vault_items, jit_request_id → jit_requests)
privileged_sessions ─1:n─ command_incidents   (event_seq → session_events.seq)
command_rules                                  (referenced by rules/incidents, not FK)
risk_events
behavior_baselines                          (per-principal UEBA profile, §11)
anomaly_incidents                           (UEBA incidents → ledger source `risk`)
bypass_signals ─1:n─ bypass_incidents         (signal_id → bypass_signals)
bypass_events                                  (module actions → ledger source `bypass`)
break_glass_requests ─1:n─ break_glass_approvals (request_id → break_glass_requests)
break_glass_events                             (emergency actions → ledger source `break-glass`)
integration_events                             (connector actions → ledger source `integration`)
audit_events                                    (hash chain over all of the above)
```

Referential integrity in the runtime DB is **application-enforced** (indexed
integer references, no `FOREIGN KEY` constraints) — deliberate for SQLite
`create_all` simplicity; tests assert cascade behavior. The vendor DB does
use real FKs (`PRAGMA foreign_keys = ON`).

### 1.1 `licenses` — imported signed entitlements

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| license_key | String(36) | ✗ | | unique |
| license_type | String(32) | ✗ | | |
| issued_to | String(255) | ✗ | | |
| issued_date | DateTime | ✗ | | |
| expires_on | DateTime | ✓ | | |
| license_id | String(64) | ✓ | | |
| tier | String(64) | ✓ | | |
| plan | String(64) | ✓ | | |
| subject_entity | String(255) | ✓ | | |
| classification | String(128) | ✓ | | |
| issuer | String(160) | ✓ | | |
| enclave_binding | String(160) | ✓ | | |
| features | JSON | ✗ | `[]` | |
| usage_limits | JSON | ✗ | `{}` | |
| metadata *(column name `metadata`)* | JSON | ✗ | `{}` | Python attr `license_metadata` |
| quotas | JSON | ✗ | `{}` | |
| modules | JSON | ✗ | `[]` | |
| account | JSON | ✗ | `{}` | |
| reported_usage | JSON | ✗ | `{}` | |
| last_reported_at | DateTime | ✓ | | |
| status | String(16) | ✗ | `active` | `active`/`revoked`, indexed |
| signature | Text | ✗ | | envelope signature |
| algorithm | String(32) | ✗ | `RSA-PSS-SHA256` | or Ed25519 |
| signature_format | String(16) | ✗ | `json` | |
| fingerprint | String(80) | ✓ | | |
| created_at | DateTime | ✗ | `datetime.now` | |
| revoked_at | DateTime | ✓ | | |
| revoked_reason | String(255) | ✓ | | |

### 1.2 `license_events` — per-license action log
`id` PK · `license_key` String(36) indexed · `action` String(32) ·
`detail` JSON · `created_at` DateTime.

### 1.3 `platform_settings` — group store (one row per group)
`id` PK · `group_name` String(32) **unique** indexed (`sso|hsm|zsp|worm|mfa|itsm|siem|ldap`) ·
`value` JSON · `updated_at` · `updated_by` String(64) default `admin`.

### 1.4 `settings_events` — change log with diffs
`id` PK · `group_name` String(32) indexed · `action` String(32) ·
`changes` JSON (per-field before/after) · `actor` String(64) default `admin` ·
`created_at`.

### 1.5 `vault_items` — credential inventory
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| name | String(120) | ✗ | **unique** indexed |
| secret_type | String(32) | ✗ | indexed (`password`/`ssh-key`/`api-token`/…) |
| description | String(255) | ✗ | `""` |
| target | String(255) | ✗ | |
| target_detail | String(255) | ✗ | `""` |
| principal | String(128) | ✗ | |
| access_tier | String(16) | ✗ | `Tier-2` |
| auth_method | String(32) | ✗ | `Password` |
| rotation_interval_hours | Integer | ✗ | `24` |
| last_rotated_at | DateTime | ✓ | |
| secret_version | Integer | ✓ | current version pointer |
| secret_updated_at | DateTime | ✓ | |
| status | String(16) | ✗ | `available` (indexed) — `available`/`checked_out` |
| checked_out_by | String(64) | ✓ | |
| checked_out_at | DateTime | ✓ | |
| created_at | DateTime | ✗ | `datetime.now` |

### 1.6 `vault_events` — item actions
`id` · `item_id` (indexed) · `item_name` · `action` · `actor` (default
`system`) · `detail` JSON · `created_at`.

### 1.7 `vault_secret_versions` — append-only ciphertext history
`id` · `item_id` indexed · `version` Integer · `blob` JSON
(**nonce + ciphertext + tag + AAD metadata**, AES-256-GCM) · `source`
String(16) default `generated` · `trigger` String(32) default `onboarded` ·
`created_by` · `created_at`.
Plaintext **never** stored; only the current version decrypts via the
vault key.

### 1.8 `discovered_assets`
`id` · `address` String(64) **unique** indexed · `hostname` · `asset_type`
String(32) indexed default `unknown` · `risk` String(16) indexed default
`LOW` (`CRITICAL|HIGH|MEDIUM|LOW`) · `pam_status` String(16) indexed default
`unmanaged` (`unmanaged|managed|ignored`) · `detail` String(255) · `ports`
JSON · `source` default `scan` · `method` default `probe` · `notes` ·
`first_seen` / `last_seen` DateTime.

### 1.9 `discovered_accounts`
`id` · `asset_id` indexed · `asset_address` · `username` indexed · `kind`
String(32) indexed default `other` · `source` default `manual` · `created_at`.

### 1.10 `discovery_scans`
`id` · `scope` String(64) · `method` default `probe` · `ports` JSON ·
`status` String(16) indexed default `running` (`running|completed|failed`) ·
`hosts_probed` / `hosts_open` / `services_found` / `findings` Integer ·
`error` String(255) · `triggered_by` · `started_at` · `finished_at` ✓.

### 1.11 `discovery_events`
`id` · `action` · `subject` String(128) · `actor` · `detail` JSON ·
`created_at`.

### 1.12 `jit_requests` — access requests + approvals + grants
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| item_id | Integer | ✗ | indexed (vault item) |
| requester | String(64) | ✗ | |
| reason | String(255) | ✗ | |
| ticket | String(64) | ✗ | |
| minutes | Integer | ✗ | 15 |
| risk_score | Integer | ✗ | 0 |
| risk_level | String(16) | ✗ | `low` |
| risk_factors | JSON | ✗ | `[]` (input snapshots) |
| status | String(16) | ✗ | `pending`, indexed (`pending|approved|denied|consumed|expired|closed`) |
| manager_approval | JSON | ✓ | `{actor, at, role?}` snapshot |
| security_approval | JSON | ✓ | snapshot |
| granted_at / expires_at / closed_at | DateTime | ✓ | |
| session_ref | String(64) | ✓ | consumed session |
| created_at | DateTime | ✗ | |

### 1.13 `jit_events`
`id` · `request_id` indexed · `action` · `actor` · `detail` JSON ·
`created_at`.

### 1.14 `privileged_sessions`
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| session_ref | String(64) | ✗ | **unique** indexed (`s-…`) |
| protocol | String(16) | ✗ | 13 allowed values |
| target | String(255) | ✗ | |
| actor | String(64) | ✗ | `system` |
| item_id | Integer | ✓ | indexed — vault credential link |
| jit_request_id | Integer | ✓ | indexed — grant link |
| status | String(16) | ✗ | `active`, indexed (`active|paused|locked|terminated|completed`) |
| record / keystroke_log / watermark / clipboard_allowed / upload_allowed / download_allowed / screenshot_allowed | Boolean | ✗ | `True` |
| started_at | DateTime | ✗ | |
| ended_at | DateTime | ✓ | |
| end_reason | String(32) | ✓ | |
| created_at | DateTime | ✗ | |

### 1.15 `session_events` — append-only recording (no update/delete API)
`id` · `session_id` indexed · `seq` Integer · `type` String(16) ·
`content` Text ✓ (null when `keystroke_log=false` → `withheld=true`) ·
`allowed` Boolean default `True` · `blocked_reason` String(64) ✓ ·
`withheld` Boolean default `False` · `decision` String(16) ✓ ·
`rule_id` Integer ✓ · `ref_seq` Integer ✓ (approval reference) ·
`watermark` String(160) ✓ (custody string) · `actor` · `created_at`.

### 1.16 `command_rules` — §9 policy table (seeds 15 rows once)
`id` · `name` String(120) · `pattern` String(160) indexed (substring match) ·
`action` String(16) default `allow` (`block|approval|allow`) ·
`target_pattern` String(120) default `""` (fnmatch glob) ·
`terminate_on_match` Boolean default `False` · `description` ·
`enabled` Boolean default `True` · `created_at` · `updated_at` ·
`updated_by` default `admin`.

### 1.17 `command_incidents` — preserved evidence
`id` · `incident_ref` String(32) **unique** (`inc-<hex>`) · `session_id`
indexed · `event_seq` Integer (evidence pointer) · `rule_id` ✓ ·
`rule_name` · `rule_pattern` · `command` Text · `target` · `actor` ·
`status` String(16) indexed default `open` (`open|resolved`) · `closed_by` /
`closed_at` / `close_note` · `created_at`.

### 1.18 `risk_events` — §7 evaluations (console + gate)
`id` · `created_at` indexed · `actor` · `subject` String(160) indexed ·
`context` String(32) indexed default `manual` (`manual|session_start`) ·
`target` · `device` · `source_ip` · `ticket` · `command` String(1000) ·
`score` Integer (0–100) · `band` String(16) indexed (`low|medium|high|critical`) ·
`decision` String(16) (`allow|mfa|approval|block`) · `result` String(16)
default `advisory` · `components` JSON — the 8-element
`[{name, value, cap, detail}]` breakdown.

### 1.19 `audit_events` — §19 hash chain (append-only, enforced by triggers)
| Column | Type | Null | Notes |
|---|---|---|---|
| id | PK | ✗ | |
| seq | Integer | ✗ | **unique**, indexed — chain position |
| event_ref | String(64) | ✗ | **unique** indexed (`ev-…`) |
| source | String(16) | ✗ | indexed — `license, settings, vault, discovery, jit, session, command, risk, bypass, break-glass, integration` |
| action | String(32) | ✗ | |
| actor | String(64) | ✗ | `system` default |
| subject | String(160) | ✗ | |
| detail | JSON | ✗ | `{}` |
| created_at | DateTime | ✗ | indexed |
| prev_hash | String(64) | ✗ | previous `event_hash`, genesis `0`×64 |
| event_hash | String(64) | ✗ | sha256 over canonical record |

Triggers (created in `audit.py`):

```sql
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only (architecture 19)'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only (architecture 19)'); END;
```

### 1.20 `bypass_signals` — §10 connection observations (verbatim evidence)
`id` · `created_at` indexed · `observed_at` DateTime indexed (the line's own
timestamp when it carried one, else ingest time — recorded in
`detail.at_source`) · `user` String(128) indexed · `source_ip` String(64)
indexed · `target` String(255) default `""` (bundle-level for OpenSSH lines,
per-line for structured JSON) · `protocol` String(16) default `unknown` ·
`origin` String(128) default `api` (log bundle name) · `raw` Text — the
original line, never rewritten · `status` String(16) indexed
(`observed|candidate|covered|out_of_scope`) · `detail` JSON — correlation
notes (matched asset, covering session, reason).

### 1.21 `bypass_incidents` — managed target reached outside any session
`id` · `created_at` indexed · `incident_ref` String(32) **unique** indexed
(`byp-…`) · `signal_id` Integer indexed → `bypass_signals` · `user` /
`source_ip` / `target` / `protocol` / `observed_at` — snapshot of the
signal · `status` String(16) indexed (`open|closed`) · `actions` JSON — the
architecture's ACTION block (`alert`, `rotation` with the real §5 outcome,
`block_source` honestly `not_connected`) · `closed_by` · `closed_at` ·
`close_note` String(255).

### 1.22 `bypass_events` — §10 module action log (ledger source `bypass`)
`id` · `created_at` indexed · `action` String(32) (`ingested|scanned|
detected|closed`) · `actor` String(64) default `system` · `subject`
String(160) · `detail` JSON — folded into the §19 ledger by `_map_bypass`
(action, `bypass:<id>` ref, counts); signal rows stay evidence, only
product actions reach the chain.

### 1.23 `break_glass_requests` — §17 emergency request lifecycle
`id` · `created_at` indexed · `request_ref` String(32) **unique** indexed
(`bg-…`) · `requester` String(64) indexed · `target` String(255) indexed ·
`reason` String(1000) · `severity` String(8) (`sev1|sev2|sev3`) · `protocol`
String(16) · `status` String(16) indexed (`pending|approved|denied|used|
closed`) · `approvals_required` Integer default `2` · `mfa` String(32)
honestly `not configured` until §20 · `session_id` Integer indexed →
`privileged_sessions` (set at open) · `opened_item_id` Integer →
`vault_items` (the released credential) · `opened_at` / `closed_at` ·
`denied_by` · `deny_note` String(500) · `review` String(1000) (required to
close) · `close_detail` JSON — cascade + forced-rotation outcome.

### 1.24 `break_glass_approvals` — append-only signature snapshots
`id` · `created_at` · `request_id` Integer indexed → `break_glass_requests` ·
`approver` String(64) (≠ requester, ≠ first approver) · `note` String(500).
Two distinct rows satisfy the dual approval; no update/delete API (same
append-only treatment as `jit_events` approval columns).

### 1.25 `break_glass_events` — §17 module action log (ledger source `break-glass`)
`id` · `created_at` indexed · `action` String(32) (`requested|approved|
denied|opened|closed`) · `actor` String(64) · `subject` String(160) ·
`detail` JSON — folded into the §19 ledger by `_map_break_glass`
(action, `bg:<request_ref>` ref, detail); the 10th source in
`LEDGER_MODELS`/`MAPPERS`.

### 1.26 `integration_events` — §20 module action log (ledger source `integration`)
`id` PK · `created_at` DateTime indexed · `action` String(32)
(`mfa-enrolled|mfa-verified|mfa-verify-failed|mfa-gate|itsm-verified|
itsm-verify-failed|siem-push-failed|ldap-login|ldap-login-failed`) ·
`actor` String(64) default `system` · `subject` String(160) · `detail` JSON
— folded into the §19 ledger by `_map_integration` (11th source in
`LEDGER_MODELS`/`MAPPERS`). Secrets (TOTP seeds, API tokens, passwords)
never appear in `detail`. Connector *configuration* stays on the
settings changelog (`settings_events`); this trail records what the
product did against an external system.

---

### 1.27 `behavior_baselines` - §11 per-principal UEBA profiles
`id` PK → `subject` String(160) unique indexed → `window_days` Integer
default 30 → `samples` Integer → `profile` JSON → `trained_by` String(64)
default `system` → `created_at` / `updated_at` DateTime
- one row per principal (evaluation subject / session actor). The profile
  holds the hours, devices, source IPs, targets, command verbs, privilege
  verbs, protocols, session cadence and sample counts learned from real
  history rows (`risk_events`, `privileged_sessions`, `session_events`,
  `command_incidents`) inside the rolling window. Trained only via
  `POST /risk/baselines/train`, never invented for an unseen principal.
  Derived state, not a ledger model - the evaluations and incidents it
  produces are already on the ledger.

---

### 1.28 `anomaly_incidents` - §11 incident record (ledger source `risk`)
`id` PK → `incident_ref` String(64) unique indexed (`anom-<hex>`) →
`evaluation_id` Integer unique indexed (the refused evaluation) → `actor`
String(64) → `subject` String(160) indexed → `target` String(255) → `score`
Integer → `band` String(16) → `reasons` JSON → `actions` JSON → `created_at`
DateTime indexed
- one row per critical *deviation* refusal: the named deviations verbatim
  from the behavior component and the response chain it ran (sessions ended
  by the release-and-rotate cascade, rotations, honest failure notes).
  Preserved evidence, never rewritten. Folded into the §19 ledger by
  `_map_anomaly` under the existing `risk` source (`action:
  anomaly-incident`, ref `anom:<id>`), so the ledger source count stays 11.
  The model class is named `AnomalyEvent` deliberately: the audit drift
  guard requires every `*Event` table to join the ledger.

---

## 2. Vendor tool - `pam_master/master.db` (4 tables)

Raw SQL (`pam_master/db.py`), `PRAGMA foreign_keys = ON`, ISO-8601 TEXT
timestamps.

```sql
customers (
  id INTEGER PK AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,      -- 32-hex external id
  data_ct TEXT NOT NULL,               -- AES-256-GCM ciphertext of PII blob
  created_at / updated_at TEXT NOT NULL
)
licenses (
  id INTEGER PK AUTOINCREMENT,
  license_id TEXT NOT NULL UNIQUE,
  license_key TEXT NOT NULL,
  customer_public_id TEXT NOT NULL REFERENCES customers(public_id),
  license_type TEXT NOT NULL, tier TEXT NOT NULL, plan TEXT,
  algorithm TEXT NOT NULL, status TEXT NOT NULL,
  issued_date TEXT NOT NULL, expires_on TEXT,
  fingerprint TEXT NOT NULL,
  superseded_by TEXT,                  -- renewal chain
  archive_ct TEXT NOT NULL,            -- encrypted full archive (JSON payload)
  created_at / updated_at TEXT NOT NULL
)
issuance_history (
  id INTEGER PK AUTOINCREMENT,
  customer_public_id TEXT NOT NULL REFERENCES customers(public_id),
  license_id TEXT NOT NULL, action TEXT NOT NULL, detail TEXT,
  created_at TEXT NOT NULL
)
master_audit (                          -- vendor-tool action log
  id INTEGER PK AUTOINCREMENT,
  action TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT,
  created_at TEXT NOT NULL
)
+ indexes: idx_issuance_customer, idx_licenses_customer
```

Privacy notes:
- Customer PII and license archives are **ciphertext at rest**; the key comes
  from `MASTER_CUSTOMER_KEY_PATH` or `MASTER_CUSTOMER_KEY_B64`.
- The full signed payload is regenerated from `archive_ct` when re-issuing or
  renewing; the shipped server never sees this table.

---

## 3. Upgrade & integrity rules

1. **Additive only.** New columns arrive via `ensure_schema()` (`ALTER TABLE
   … ADD COLUMN` guarded); destructive changes are a versioned release, not a
   boot step.
2. **Chain first boot.** `ensure_audit_chain()` backfills pre-chain history
   exactly once (guarded flag) so genesis is stable.
3. **Seeds run once into empty tables** (`ensure_command_rules()` 15 rows) —
   operator deletions are never resurrected.
4. **Append-only semantics:** `audit_events` (DB triggers) and
   `session_events` (no mutating endpoints + tests) — matches architecture
   §19.
5. **Backup = file copy** of `licenses.db` (+ `vault.key`, license PEMs);
   see `DEPLOYMENT_RUNBOOK.md`.

---

## 4. Planned tables (NOT yet created — see `IMPLEMENTATION_PLAN.md`)

Design sketches only; they become normative when the phase starts. Final
column sets land with the code + contract commit; counts are `—` until then.

| Phase | Tables | Notes |
|---|---|---|
| 4k §12 | *(none - payload assembled from `privileged_sessions`/`session_events`)* | |
| 5a §13 | `vendor_accounts`, vendor link columns on `jit_requests` | |
| 5b §14 | `cloud_connectors` | credentials themselves in vault, not in the row |
| 5c §15 | `broker_policies`, `broker_credentials` | JIT semantics; expiry enforced like grants |
| 5d §16 | `agent_identities`, `agent_task_scopes` | command restrictions reference `command_rules` |
| 6a §18 | replication topology (external store decision) | may replace SQLite — design item of the phase |
| 6b | `roles`, `role_bindings` | attribute rules as JSON policy rows |
| 6c | SSO/HSM state columns in existing settings groups | |

All planned tables follow the standing rules: additive `ensure_schema()`,
ledger emission in the same transaction, application-enforced references
(runtime DB), and append-only treatment where the architecture demands it.
