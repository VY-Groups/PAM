# VY-PAM — Backend Schema

**Status:** as-built for Phase 7
Two databases: the **shipped runtime DB** (`backend/phase2_license_server/
licenses.db`, SQLAlchemy/Flask-SQLAlchemy) and the **vendor-tool DB**
(`pam_master/master.db`, raw `sqlite3`). Both are SQLite, both git-ignored.

Schema management: `db.create_all()` at first boot +
`models.ensure_schema()` for **additive** column backfill on upgrade — no
external migration tool.

---

## 1. Shipped runtime - 67 tables

### ERD (logical)

```
licenses ─1:n─ license_events
platform_settings ─1:n─ settings_events
vault_items ─1:n─ vault_events
vault_items ─1:n─ vault_secret_versions
discovered_assets ─1:n─ discovered_accounts
discovery_scans ─1:n─ discovery_events        discovery_assets links via asset_id
jit_requests ─1:n─ jit_events                (item_id → vault_items, vendor_account_id → vendor_accounts, cloud_connector_id → cloud_connectors, agent_id → agent_identities)
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
vendor_accounts ─1:n─ vendor_events           (vendor_id → vendor_accounts; lifecycle actions → ledger source `vendor`)
cloud_connectors ─1:n─ cloud_events           (connector_id → cloud_connectors; §14 actions → ledger source `cloud`)
broker_policies ─1:n─ broker_credentials      (policy_id → broker_policies; item_id → vault_items; §15 pipeline identities + time-boxed credentials)
broker_events                                 (policy/credential actions → ledger source `broker`)
agent_identities ─1:n─ agent_task_scopes      (agent_id → agent_identities; §16 declared tasks with their allowed_commands allow-list)
agent_identities ─1:n─ agent_events           (agent/task/request ids captured at write time; agent actions → ledger source `agent`)
cluster_nodes ─1:n─ cluster_events            (node_id → cluster_nodes; §18 actions → ledger source `cluster`)
cluster_nodes ─1:n─ cluster_audit_replicas    (peer chain evidence re-hashed here - never merged into audit_events)
cluster_nodes ─1:n─ cluster_secret_replicas   (peer vault ciphertext stored sealed; plaintext_here flags a local key match)
cluster_nodes ─1:n─ cluster_session_replicas  (peer session metadata as evidence, not a merge)
cluster_backups                              (verified SQLite copies: path + sha256 + audit_seq)
roles                                     (the five built-in roles, seeded once at startup; per-operation policy in code)
role_bindings                             (who holds which role + ABAC scope; local tokens sha256 at rest, revocation is a timestamp - row kept as evidence)
rbac_events                               (grant/revoke actions → ledger source `rbac`; the minted token never enters `detail`)
sso_flows                                 (one outstanding SAML AuthnRequest id / OIDC state; single-use, TTL-bound → ledger source `sso`)
sso_subjects ─1:n─ sso_sessions           (JIT subject directory (slot, subject unique) ← subject_id; existence only - privilege comes from a role binding)
sso_sessions                              (server-side sessions minted at login; `vypam-sso1.` bearer sha256 at rest → ledger source `sso`)
hsm_key_events                            (wrap/unwrap/health/seal/unseal/rotate custody trail → ledger source `hsm`)
users ─1:n─ console_sessions             (user_id → users; `vypam-ui1.` bearer + csrf both sha256 at rest; revoke = timestamp, row kept as evidence)
users ─1:n─ mfa_factors                   (user_id → users; kind totp/webauthn/email/radius; `last_step` blocks a reused TOTP time step)
users ─1:n─ login_challenges              (user_id → users; the two-step `vypam-mfa1` / `vypam-enr1` tickets, single-use + TTL → fail-closed MFA)
users ─1:n─ mfa_backup_codes              (user_id → users; hashed, single-use, replay refused)
users ─1:n─ auth_otps ─1:n─ smtp_deliveries (challenge bound to an HMAC-hashed code, attempt-capped, TTL'd; delivery measured - never a code)
users ─1:n─ auth_devices                  (user_id → users; RADIUS device bindings, hashed)
users ─1:n─ webauthn_credentials          (user_id → users; public key + sign_count for clone detection)
users ─1:n─ webauthn_challenges           (user_id → users; single-use register/authenticate options - 202 for known and unknown handles)
users ─1:n─ factor_recovery_requests ─1:n─ factor_recovery_approvals (request_id → factor_recovery_requests; dual control, never the requester)
users                                     (source=scim joiners land here from the IdP; source=emergency is the sealed break-glass admin)
emergency_grants ─1:n─ emergency_approvals (grant_id → emergency_grants; dual control, time-boxed window, single use → ledger source `auth`)
scim_groups                               (IdP group directory; SCIM bearer is the sealed `scim.token_sha256` settings field)
auth_events                               (identity actions → ledger source `auth`; the true reason lives here, never in the reply)
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
| vendor_account_id | Integer | ✓ | indexed (§13 vendor link — set when the request was filed through a vendor account) |
| cloud_connector_id | Integer | ✓ | indexed (§14 link — set when the request was filed through a cloud connector's RBAC path) |
| cloud_binding | JSON | ✓ | `{namespace, role, binding}` at filing; the grant adds `applied_at`/`expires_at`/`http_status`, a successful removal adds `removed_at` — the real RoleBinding this grant applies/removes (§14) |
| agent_id | Integer | ✓ | indexed (§16 link — set when the request was filed through an agent's API token) |
| agent_binding | JSON | ✓ | `{agent_id, agent_name, task_id, task}` snapshot at filing (§16) — the command channel enforces against this, so expiry never re-resolves the identity or the task |
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
| source_ip | String(64) | ✓ | §12 watermark SOURCE line (4k, via `ensure_schema`; null → `—`) |
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
  anomaly-incident`, ref `anom:<id>`), so the anomaly rows added no new
  ledger source (11 sources at 4j; **17** today - the §13 `vendor` source
  joined in 5a, the §14 `cloud` source in 5b, the §15 `broker` source in
  5c, the §16 `agent` source in 5d, the §18 `cluster` source in 6a and
  the §10 `rbac` source in 6b).
  The model class is named `AnomalyEvent` deliberately: the audit drift
  guard requires every `*Event` table to join the ledger.

### 1.29 `vendor_accounts` — §13 third-party vendor lifecycle
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| name | String(128) | ✗ | unique indexed (re-invite reuses the row for denied/revoked/expired names) |
| contact | String(160) | ✗ | `""` |
| status | String(16) | ✗ | `invited`, indexed (`invited\|approved\|denied\|revoked\|expired`) |
| invited_by | String(64) | ✗ | `system` |
| created_at | DateTime | ✗ | indexed |
| mfa_secret | JSON | ✓ | sealed AES-256-GCM (AAD `vendor:{id}:mfa_secret`) — plaintext returned once at invite, never again |
| mfa_verified_at | DateTime | ✓ | step 1 (real RFC-6238 over the sealed seed) |
| nda_ref | String(64) | ✓ | step 2 reference (optional; the timestamp is not) |
| nda_signed_at | DateTime | ✓ | step 2 |
| ticket | String(64) | ✓ | step 3 — the verified ITSM reference |
| ticket_verified_at | DateTime | ✓ | step 3 |
| ticket_verification | JSON | ✗ | `{}` honest outcome snapshot (ticket/configured/verified/vendor/http_status/detail/checked_at) |
| approved_at / approved_by | DateTime / String(64) | ✓ | step 4 |
| denied_reason | String(255) | ✓ | denial note, recorded verbatim |
| allowed_targets / denied_targets | JSON | ✗ | `[]` target strings (deny beats allow at every gate) |
| window_start / window_end | String(5) | ✓ | daily valid window `HH:MM` (`None` = any hour), e.g. `14:00`–`16:00` |
| recording | Boolean | ✗ | `true` — vendor sessions record server-side regardless of any caller flag |
| expires_at | DateTime | ✓ | account expiry; the lazy refresh marks the row `expired` |

### 1.30 `vendor_events` — §13 module action log (ledger source `vendor`)
`id` PK · `vendor_id` Integer indexed · `created_at` DateTime indexed ·
`action` String(32) · `actor` String(64) · `subject` String(160) (display
name captured at the time — renames never rewrite history) · `detail` JSON.
- actions: `invited` · `updated` · `mfa-verified` · `mfa-verify-failed` ·
  `nda-signed` · `ticket-verified` · `ticket-refused` · `approval-refused` ·
  `approved` · `denied` · `revoked` · `access-requested` · `access-refused` ·
  `session-refused` · `expired`. The TOTP seed and any submitted code never
  appear in `detail`. Folded into the §19 ledger by `_map_vendor` (ref
  `vendor:<id>`) as the twelfth source.

### 1.31 `cloud_connectors` — §14 cloud account / cluster connector
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| name | String(64) | ✗ | unique indexed |
| provider | String(16) | ✗ | indexed (`aws\|azure\|gcp\|kubernetes`) |
| account_ref | String(128) | ✗ | `""` account / subscription / project reference |
| endpoint | String(255) | ✗ | `""` — `https` required (`http` loopback-only); empty = `not connected` |
| regions / services | JSON | ✗ | `[]` in-scope regions / services from the §14 surface |
| credential_item_id | Integer | ✓ | the vault item holding this cloud's credential — secret material never lives in this row |
| status | String(16) | ✗ | `not connected`, indexed (`not connected\|configured\|connected\|error`) — honest state; only a real probe moves it |
| last_test_at | DateTime | ✓ | last real probe |
| last_test_detail | String(255) | ✗ | `""` — the probe's honest verdict (`HTTP 200 (12ms)` / `connection failed …`), also the `error` reason |
| created_at | DateTime | ✗ | indexed |
| created_by | String(64) | ✗ | `system` |

### 1.32 `cloud_events` — §14 module action log (ledger source `cloud`)
`id` PK · `connector_id` Integer indexed · `created_at` DateTime indexed ·
`action` String(32) · `actor` String(64) · `subject` String(64) (display
name captured at the time — renames never rewrite history) · `detail` JSON.
- actions: `connector-added` · `connector-updated` · `connector-removed` ·
  `probe-succeeded` · `probe-failed` · `inventory-ran` · `inventory-failed` ·
  `rbac-requested` · `rbac-granted` · `rbac-binding-failed` · `rbac-closed` ·
  `rbac-expired` · `rbac-aborted`. The credential used for a call never
  appears in `detail`; the outcome does. Folded into the §19 ledger by
  `_map_cloud` (ref `cloud:<id>`) as the **thirteenth** source.

### 1.33 `broker_policies` — §15 CI/CD pipeline identity + approval policy
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| name | String(128) | ✗ | unique indexed (pipeline identity, e.g. `jenkins-deploy-prod`) |
| ci_system | String(32) | ✗ | indexed (`jenkins\|gitlab\|github\|azure_devops\|terraform\|ansible\|argocd\|docker\|other`) |
| contact | String(160) | ✗ | `""` |
| approval_mode | String(16) | ✗ | `manual` (`manual\|auto`) — `auto` releases on request, `manual` queues for an admin approval |
| max_ttl_minutes | Integer | ✗ | `30` — hard cap on this pipeline's windows (1–480; a higher request is refused 400 `details.cap`) |
| allowed_targets | JSON | ✗ | `[]` exact vault targets this pipeline may request (empty = any; a miss is refused 403 + `refused` on the trail) |
| token_hash | String(64) | ✗ | sha256 hex of the token secret; the API token `vypam-ci1.<id>.<secret>` is shown exactly once at creation and is never recoverable |
| status | String(16) | ✗ | `active`, indexed (`active\|revoked\|expired`) |
| expires_at | DateTime | ✓ | identity expiry; the lazy refresh marks `expired` and closes open credentials |
| revoked_at / revoked_reason | DateTime / String(255) | ✓ | revoke moment + note; open credentials are closed (released ones rotated) before the token stops authenticating |
| last_used_at | DateTime | ✓ | set by every successful token authentication |
| use_count | Integer | ✗ | `0` — successful authentications |
| created_at | DateTime | ✗ | indexed |
| created_by | String(64) | ✗ | `system` |

### 1.34 `broker_credentials` — §15 one time-boxed credential for a pipeline
| Column | Type | Null | Default |
|---|---|---|---|
| id | PK | ✗ | |
| policy_id | Integer | ✗ | indexed → `broker_policies.id` |
| item_id | Integer | ✗ | indexed → `vault_items.id` (the credential being requested — no static secret ever lives in CI) |
| reason | String(255) | ✗ | ≥ 8 characters |
| ticket | String(64) | ✗ | ITSM reference, non-empty |
| minutes | Integer | ✗ | `15` — window length, capped by the policy |
| status | String(16) | ✗ | `pending`, indexed (`pending\|approved\|released\|denied\|closed\|expired`) |
| build_ref | String(255) | ✗ | `""` — the pipeline build/job that asked; context, never a credential |
| approved_by / approved_at | String(64) / DateTime | ✓ | the admin, or `broker-policy` for an auto approval |
| denied_reason | String(255) | ✓ | refusal note, recorded verbatim |
| released_at | DateTime | ✓ | the moment the secret was handed out (exactly once) |
| released_version | Integer | ✓ | which vault secret version was released |
| expires_at | DateTime | ✓ | `released_at + minutes`; the lazy refresh ends the grant and rotates |
| closed_at | DateTime | ✓ | early close or rotation end |
| session_ref | String(64) | ✓ | `broker-<id>` — the checkout/rotation reference, the same machinery as a JIT grant |
| created_at | DateTime | ✗ | indexed |
- The secret never lands on this row; `released_at` records only that it
  happened. Close/expiry release the checkout and rotate the credential
  through the §5 pipeline (`session_end` trigger), exactly like a JIT
  grant.

### 1.35 `broker_events` — §15 module action log (ledger source `broker`)
`id` PK · `policy_id` Integer indexed · `credential_id` Integer indexed ·
`created_at` DateTime indexed · `action` String(32) · `actor` String(64) ·
`subject` String(128) (display name captured at the time) · `detail` JSON.
- actions: `policy-created` · `policy-updated` · `policy-revoked` ·
  `policy-expired` · `requested` · `approved` · `denied` · `refused` ·
  `released` · `closed` · `expired`. The API token and the released secret
  never appear in `detail`; the outcome does. On pipeline-authenticated
  actions the actor is the policy name — the pipeline *is* its identity
  row. Folded into the §19 ledger by `_map_broker` (ref `broker:<id>`) as
  the **fourteenth** source.

### 1.36 `agent_identities` — §16 AI-agent identity

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| name | String(128) | ✗ | | unique, indexed |
| description | String(255) | ✗ | `''` | |
| contact | String(160) | ✗ | `''` | the human owner behind the agent |
| token_hash | String(64) | ✗ | | sha256 of `vypam-agt1.<id>.<secret>`; the token itself is shown exactly once |
| status | String(16) | ✗ | `active` | indexed · `active\|disabled\|revoked` |
| max_ttl_minutes | Integer | ✗ | `15` | identity-level window cap (1–480); a task may set a lower one |
| last_used_at | DateTime | ✓ | | stamped on every valid token presentation |
| use_count | Integer | ✗ | `0` | valid presentations recorded |
| created_at | DateTime | ✗ | now | indexed |
| created_by | String(64) | ✗ | `system` | |
- No standing expiry: the identity lives until revoked. `disabled` is
  reversible; `revoked` is terminal and freezes settings/task scopes (409).
  The API token never appears on this row — only its hash.

### 1.37 `agent_task_scopes` — §16 declared task + allow-list

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| agent_id | Integer | ✗ | | indexed → `agent_identities.id` |
| name | String(128) | ✗ | | unique per agent; access requests reference the task by this name |
| description | String(255) | ✗ | `''` | |
| allowed_commands | JSON | ✗ | `[]` | exhaustive allow-list, 1–32 literal substrings (case-insensitive, the same matching as the §9 engine); default-deny |
| allowed_targets | JSON | ✗ | `[]` | exact vault targets (empty = any); a miss is 403 + recorded |
| max_minutes | Integer | ✗ | `5` | window cap for this task (the effective cap is min(task, identity)) |
| created_at | DateTime | ✗ | now | indexed |
- A §9 block rule still vetoes a listed command; the allow-list supersedes
  §9 *approval* holds (the declaration is the pre-authorization).

### 1.38 `agent_events` — §16 module action log (ledger source `agent`)
`id` PK · `agent_id` Integer indexed nullable · `task_id` Integer indexed
nullable · `request_id` Integer indexed nullable · `action` String(32) ·
`actor` String(64) · `subject` String(128) · `detail` JSON · `created_at`
DateTime indexed.
- actions: `agent-created` · `agent-updated` · `agent-disabled` ·
  `agent-enabled` · `agent-revoked` · `task-added` · `task-updated` ·
  `task-removed` · `access-requested` · `access-refused` ·
  `access-opened` · `access-ended` · `command-blocked`. The API token
  never appears in `detail`; the outcome does. On agent-authenticated
  actions the actor is the agent's own name. Folded into the §19 ledger
  by `_map_agent` (ref `agent:<id>`) as the **fifteenth** source.

### 1.39 `cluster_nodes` — §18 node registry (this node + peers)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| name | String(64) | ✗ | | unique, indexed · this node's row is created at startup from `PAM_NODE_NAME`, never re-created by a restart |
| site | String(8) | ✗ | `dc` | `dc` or `dr` (validated on write; `PAM_SITE` for self) |
| role | String(8) | ✗ | `active` | `active` or `passive` — the row *is* the passive gate's source of truth; a restart never resets it |
| base_url | String(255) | ✗ | `''` | peer base URL — `https` unless loopback; empty on self |
| health | String(16) | ✗ | `unknown` | `unknown\|healthy\|degraded\|unreachable` — only ever set by a real probe or sync, never assumed |
| last_probe_at | DateTime | ✓ | | last probe/sync measurement |
| last_latency_ms | Integer | ✓ | | measured round-trip; `null` before the first probe |
| last_error | String(255) | ✗ | `''` | verbatim transport error of the last failure |
| consecutive_failures | Integer | ✗ | `0` | probe failures since the last success; ≥ 3 feeds auto-failover |
| created_at | DateTime | ✗ | now | indexed |
| created_by | String(64) | ✗ | `system` | startup self-registration vs the admin who added the peer |

### 1.40 `cluster_events` — §18 topology trail (ledger source `cluster`)

`id` PK · `node_id` Integer indexed nullable · `action` String(32) ·
`actor` String(64) · `subject` String(128) · `detail` JSON · `created_at`
DateTime indexed.
- actions: `node-registered` · `node-updated` · `node-removed` · `probe` ·
  `synced` · `sync-failed` · `promoted` · `demoted` · `backup`. A `probe`
  event is recorded only when health **state changes** (repeat probes stay
  off the trail); an automatic monitor promotion carries
  `detail.automatic: true`. Folded into the §19 ledger by `_map_cluster`
  (ref `cluster:<id>`) as the **sixteenth** source.

### 1.41 `cluster_audit_replicas` — §18 pulled chain evidence (per peer)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| node_id | Integer | ✗ | | indexed → `cluster_nodes.id` |
| seq | Integer | ✗ | | the peer's ledger sequence |
| prev_hash | String(64) | ✗ | `''` | as the peer published it |
| event_hash | String(64) | ✗ | | re-hashed locally on pull |
| source | String(32) | ✗ | `''` | |
| event_ref | String(128) | ✗ | `''` | |
| action | String(64) | ✗ | `''` | |
| actor | String(64) | ✗ | `''` | |
| subject | String(255) | ✗ | `''` | |
| detail | JSON | ✗ | `{}` | |
| created_at | DateTime | ✗ | now | |
| verified | Boolean | ✗ | `false` | true only when the local re-hash matched the published chain — a break stores the rest as `verified: false` with `first_break_seq` on the response |
| synced_at | DateTime | ✗ | now | indexed |
- Evidence, never merged: these rows live only under `node_id`; this
  node's own `audit_events` chain is untouched by every sync.

### 1.42 `cluster_secret_replicas` — §18 sealed vault ciphertext (per peer)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| node_id | Integer | ✗ | | indexed → `cluster_nodes.id` |
| item_id | Integer | ✗ | | the peer's item id — not a local FK, the item need not exist here |
| name | String(160) | ✗ | `''` | |
| target | String(255) | ✗ | `''` | |
| secret_type | String(64) | ✗ | `''` | |
| version | Integer | ✗ | `1` | |
| sealed_blob | Text | ✗ | | stored exactly as the peer sealed it |
| plaintext_here | Boolean | ✗ | `false` | true only when a real decrypt under **this** node's vault key succeeded — a foreign key keeps it sealed |
| synced_at | DateTime | ✗ | now | indexed |

### 1.43 `cluster_session_replicas` — §18 session metadata (per peer)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| node_id | Integer | ✗ | | indexed → `cluster_nodes.id` |
| session_id | String(64) | ✗ | | indexed · the peer's session reference |
| payload | JSON | ✗ | `{}` | metadata only — ids, targets, times; never recording content |
| synced_at | DateTime | ✗ | now | indexed |

### 1.44 `cluster_backups` — §18 verified SQLite backup ledger

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| path | String(255) | ✗ | | file under `CLUSTER_BACKUP_DIR` |
| sha256 | String(64) | ✗ | `''` | of the copied file |
| size_bytes | Integer | ✗ | `0` | |
| audit_seq | Integer | ✗ | `0` | chain head at backup time |
| verified | Boolean | ✗ | `false` | the copy was re-opened read-only and its chain re-walked before the 201 |
| verify_detail | String(255) | ✗ | `''` | honest reason whenever verification fails |
| created_at | DateTime | ✗ | now | |
| created_by | String(64) | ✗ | `system` | |

---

### 1.45 `roles` — §10 the five built-in roles (seeded once at startup)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| name | String(64) | ✗ | | unique indexed (`admin`, `approver`, `operator`, `auditor`, `auditor-read-only`) |
| description | String(255) | ✗ | `''` | what the role may call, in plain words |
| created_at | DateTime | ✗ | now | |

The per-operation policy - which of the 127 admin operations each role
may call - is code, not data: `service.ROLE_OPERATIONS` derives it from
`service.ADMIN_OPERATIONS` (the single source the contract test pins).

### 1.46 `role_bindings` — §10 who holds a role

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| principal | String(128) | ✗ | | indexed (not column-unique: a revoked row keeps its principal as evidence; uniqueness enforced among **active** rows only) |
| role | String(64) | ✗ | | indexed → the granted role |
| kind | String(16) | ✗ | `local` | `local` (minted API token) or `ldap` (directory username) |
| token_sha256 | String(64) | ✓ | NULL | sha256 of the minted token's secret part; NULL for `ldap` - the token itself is never stored |
| token_prefix | String(40) | ✗ | `''` | the public part (`vypam-rbac1.<id>.…`) so the UI can match a credential to a row |
| scope | JSON | ✗ | `{}` | ABAC rules: `{"targets": [fnmatch], "vault_items": [ids]}` - empty = the role governs everywhere |
| last_used_at | DateTime | ✓ | NULL | recorded on every successful token verify |
| revoked_at | DateTime | ✓ | NULL | revocation is a timestamp; the row stays as ledger-side evidence |
| created_at | DateTime | ✗ | now | |
| created_by | String(64) | ✗ | `system` | |

### 1.47 `rbac_events` — §10 grant/revoke trail (ledger source `rbac`)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| action | String(64) | ✗ | | `rbac.binding.created` / `rbac.binding.revoked` |
| actor | String(64) | ✗ | `system` | the admin (bound principal overrides `X-Actor`) |
| subject | String(128) | ✗ | `''` | the bound principal |
| detail | JSON | ✗ | `{}` | role, kind, scope - **never the minted token** |
| created_at | DateTime | ✗ | now | indexed |

Folded into the §19 ledger by `_map_rbac` under the seventeenth source
`rbac`. The audit drift guard keeps it honest: the model is an `*Event`
table, so it must join the chain.

### 1.48 `sso_flows` — one outstanding SSO login flow (ledger source `sso`)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | String(64) PK | ✗ | | the SAML AuthnRequest id or the OIDC `state` (single-use) |
| slot | String(16) | ✗ | | which configured slot ran the flow |
| protocol | String(16) | ✗ | | `saml2` / `oidc` |
| nonce | String(128) | ✓ | NULL | the OIDC nonce |
| verifier | String(128) | ✓ | NULL | the OIDC PKCE `code_verifier` |
| result | String(32) | ✗ | `pending` | how the flow ended - failures are evidence, not silence |
| detail | String(255) | ✗ | `''` | honest refusal reason (`mfa_failed`, `bad_signature`, …) |
| expires_at | DateTime | ✗ | | TTL-bound |
| consumed_at | DateTime | ✓ | NULL | set once the flow is used (`InResponseTo` / `state` match) |
| created_at | DateTime | ✗ | now | indexed |

### 1.49 `sso_subjects` — JIT-provisioned IdP subjects (existence only)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| slot | String(16) | ✗ | | unique together with `subject` (`uq_sso_subject_slot_subject`) |
| protocol | String(16) | ✗ | | `saml2` / `oidc` |
| subject | String(255) | ✗ | | indexed (SAML NameID / OIDC `sub`) |
| email | String(255) | ✗ | `''` | |
| name | String(255) | ✗ | `''` | |
| attributes | JSON | ✗ | `{}` | assertion attributes as received |
| first_login_at | DateTime | ✓ | NULL | |
| last_login_at | DateTime | ✓ | NULL | |
| logins | Integer | ✗ | 0 | |
| created_at | DateTime | ✗ | now | |

Existence only — privilege always comes from a role binding (kind
`sso`, principal = subject); a login never grants one. No ledger rows of
its own.

### 1.50 `sso_sessions` — server-side sessions minted at login (ledger source `sso`)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| subject_id | INTEGER FK | ✓ | NULL | → `sso_subjects.id` |
| subject | String(255) | ✗ | | indexed |
| email | String(255) | ✗ | `''` | |
| slot | String(16) | ✗ | | |
| protocol | String(16) | ✗ | | |
| mfa | Boolean | ✗ | false | the IdP's MFA assertion (fail-closed at login) |
| amr | JSON | ✗ | `[]` | the authentication methods as asserted |
| token_sha256 | String(64) | ✗ | | bearer `vypam-sso1.<id>.<secret>` - secret sha256 at rest, shown once |
| token_prefix | String(40) | ✗ | `''` | display prefix only |
| last_used_at | DateTime | ✓ | NULL | |
| expires_at | DateTime | ✗ | | TTL from `sso.session_ttl_minutes` |
| revoked_at | DateTime | ✓ | NULL | revocation is a timestamp; the row stays as evidence |
| created_at | DateTime | ✗ | now | indexed |

### 1.51 `hsm_key_events` — HSM/KMS custody trail (ledger source `hsm`)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| action | String(64) | ✗ | | `wrap` / `unwrap` / `health` / `seal` / `unseal` / `rotate` |
| provider | String(32) | ✗ | `''` | `hashicorp-vault` / `aws-kms` / `azure-keyvault` / `pkcs11` |
| mode | String(16) | ✗ | `''` | `advisory` / `enforced` at write time |
| key_label | String(64) | ✗ | `''` | |
| status | String(16) | ✗ | `ok` | honest outcome |
| actor | String(64) | ✗ | `system` | |
| detail | JSON | ✗ | `{}` | **never key material** |
| created_at | DateTime | ✗ | now | indexed |

Folded into the §19 ledger by `_map_hsm` under the nineteenth source
`hsm` (the flows/sessions fold under `sso` via `_map_sso_flow` /
`_map_sso_session`). The audit drift guard keeps it honest: the model is
an `*Event` table, so it must join the chain.

### 1.52 `users` — local + SCIM + emergency identities (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| username | String(64) | ✗ | | unique, indexed |
| email | String(255) | ✗ | `''` | |
| display_name | String(128) | ✗ | `''` | |
| password_hash | String(255) | ✗ | | scrypt (N=2**14) — the sealed emergency admin holds no usable hash |
| source | String(16) | ✗ | `local` | `local` / `scim` / `emergency` |
| is_active | Boolean | ✗ | True | deactivation revokes live sessions |
| is_emergency | Boolean | ✗ | False | the dedicated sealed break-glass login |
| must_change_password | Boolean | ✗ | False | generated passwords force a change |
| failed_logins | Integer | ✗ | 0 | |
| lockout_streak | Integer | ✗ | 0 | doubling backoff |
| locked_until | DateTime | ✗ | None | nullable |
| last_login_at | DateTime | ✗ | None | nullable |
| password_changed_at | DateTime | ✗ | None | nullable |
| created_at | DateTime | ✗ | now | indexed |
| created_by | String(64) | ✗ | `system` | |

SCIM-managed users (`source=scim`) answer the same uniform login 401 as a
wrong password; the true `scim-managed` reason is recorded only on the
ledger, never in the reply.

### 1.53 `console_sessions` — server-side sessions (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| token_sha256 | String(64) | ✗ | | the `vypam-ui1.…` bearer, sha256 at rest (never plaintext) |
| token_prefix | String(40) | ✗ | `''` | shown in listings |
| csrf_sha256 | String(64) | ✗ | | double-submit secret |
| mfa_at | DateTime | ✗ | None | last successful step-up (drives `stepup_ttl_minutes`) |
| mfa_methods | JSON | ✗ | `[]` | |
| is_emergency | Boolean | ✗ | False | |
| source_ip | String(64) | ✗ | `''` | |
| user_agent | String(255) | ✗ | `''` | |
| last_seen_at | DateTime | ✗ | None | idle clock |
| idle_expires_at | DateTime | ✗ | now | indexed |
| absolute_expires_at | DateTime | ✗ | now | indexed |
| revoked_at | DateTime | ✗ | None | nullable |
| revoked_reason | String(64) | ✗ | `''` | |
| created_at | DateTime | ✗ | now | indexed |

### 1.54 `mfa_factors` — enrolled factors per user (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| kind | String(16) | ✗ | | `totp` / `webauthn` / `email` / `radius` |
| name | String(64) | ✗ | `''` | |
| secret_sealed | JSON | ✗ | None | sealed secret material; never returned after enrol |
| last_step | Integer | ✗ | 0 | TOTP replay guard — reject a reused time step |
| active | Boolean | ✗ | True | |
| created_at | DateTime | ✗ | now | indexed |
| last_used_at | DateTime | ✗ | None | nullable |

### 1.55 `login_challenges` — the two-step `vypam-mfa1` / `vypam-enr1` tickets (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | String(64) PK | ✗ | | the challenge / enrolment-ticket id |
| user_id | INTEGER FK→users | ✗ | | indexed |
| kind | String(16) | ✗ | `mfa` | `mfa` / `enrolment` |
| secret_sha256 | String(64) | ✗ | `''` | |
| expires_at | DateTime | ✗ | | indexed (300 s TTL) |
| consumed_at | DateTime | ✗ | None | single-use — a spent challenge 401s |
| created_at | DateTime | ✗ | now | |

### 1.56 `mfa_backup_codes` — hashed single-use codes (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| code_hash | String(64) | ✗ | | sha256 of the code |
| used_at | DateTime | ✗ | None | nullable — replay refused |
| created_at | DateTime | ✗ | now | |

### 1.57 `auth_otps` — e-mail OTP challenges (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| challenge_id | String(64) | ✗ | | binds the code to its challenge |
| user_id | INTEGER FK→users | ✗ | None | nullable (unknown username still gets a challenge — no enumeration) |
| username | String(64) | ✗ | `''` | |
| purpose | String(16) | ✗ | `login` | |
| code_hmac | String(64) | ✗ | | HMAC-hashed — never the code itself |
| attempts | Integer | ✗ | 0 | |
| max_attempts | Integer | ✗ | 5 | attempt cap locks the challenge |
| delivery_id | INTEGER FK→smtp_deliveries | ✗ | None | nullable |
| expires_at | DateTime | ✗ | | indexed (~5 min TTL) |
| consumed_at | DateTime | ✗ | None | single-use |
| created_at | DateTime | ✗ | now | |

### 1.58 `smtp_deliveries` — measured delivery, never a code (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| purpose | String(16) | ✗ | `otp` | |
| recipient_masked | String(255) | ✗ | `''` | masked address |
| status | String(16) | ✗ | `queued` | `queued` / `sent` / `suppressed` / `failed` |
| attempts | Integer | ✗ | 0 | |
| last_error | String(255) | ✗ | `''` | the honest reason (e.g. "not configured") |
| sent_at | DateTime | ✗ | None | nullable |
| created_at | DateTime | ✗ | now | indexed |

### 1.59 `auth_devices` — RADIUS device bindings (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| device_sha256 | String(64) | ✗ | | |
| device_prefix | String(40) | ✗ | `''` | |
| expires_at | DateTime | ✗ | | indexed |
| last_used_at | DateTime | ✗ | None | nullable |
| revoked_at | DateTime | ✗ | None | nullable |
| created_at | DateTime | ✗ | now | |

### 1.60 `auth_events` — identity module action log (Phase 7, ledger source `auth`)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| action | String(64) | ✗ | | e.g. `auth.login.failed`, `auth.mfa.enrolled`, `auth.emergency.opened`, `otp-suppressed` |
| actor | String(64) | ✗ | `system` | |
| subject | String(128) | ✗ | `''` | indexed |
| detail | JSON | ✗ | `{}` | the true reason — never a secret, token, or code |
| created_at | DateTime | ✗ | now | indexed |

Folded into the §19 ledger under the **twentieth** source `auth` by the
identity/mfa/otp/radius/scim/webauthn modules. The audit drift guard
keeps it honest: it is an `*Event` table, so it must join the chain.

### 1.61 `webauthn_credentials` — registered authenticators (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| credential_id | String(255) | ✗ | | unique |
| public_key_b64 | String(512) | ✗ | | |
| sign_count | Integer | ✗ | 0 | clone detection |
| name | String(64) | ✗ | `''` | |
| transports | JSON | ✗ | `[]` | |
| created_at | DateTime | ✗ | now | indexed |
| last_used_at | DateTime | ✗ | None | nullable |

### 1.62 `webauthn_challenges` — single-use options (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | String(64) PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| purpose | String(16) | ✗ | `register` | `register` / `authenticate` |
| challenge | String(128) | ✗ | | |
| expires_at | DateTime | ✗ | | indexed |
| consumed_at | DateTime | ✗ | None | single-use |
| created_at | DateTime | ✗ | now | |

### 1.63 `emergency_grants` — sealed-admin open requests (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| status | String(16) | ✗ | `pending` | `pending` / `open` / `denied` / `used` / `expired` |
| requested_by | String(64) | ✗ | `''` | |
| reason | String(255) | ✗ | `''` | ≥ 8 chars enforced |
| ticket | String(64) | ✗ | `''` | |
| opened_at | DateTime | ✗ | None | nullable |
| expires_at | DateTime | ✗ | None | nullable (`auth.emergency_window_minutes`) |
| used_at | DateTime | ✗ | None | single-use once the sealed password is spent |
| rotated_at | DateTime | ✗ | None | nullable |
| created_at | DateTime | ✗ | now | indexed |

### 1.64 `emergency_approvals` — append-only dual-control signatures (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| grant_id | INTEGER FK→emergency_grants | ✗ | | indexed |
| approver | String(64) | ✗ | | never the requester (403 verbatim) |
| decision | String(16) | ✗ | | `approve` / `deny` |
| note | String(255) | ✗ | `''` | |
| created_at | DateTime | ✗ | now | |

### 1.65 `factor_recovery_requests` — lost-every-factor recovery (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| user_id | INTEGER FK→users | ✗ | | indexed |
| status | String(16) | ✗ | `pending` | `pending` / `approved` / `denied` |
| reason | String(255) | ✗ | `''` | |
| resolved_at | DateTime | ✗ | None | nullable |
| created_at | DateTime | ✗ | now | |

### 1.66 `factor_recovery_approvals` — dual-control signatures (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| request_id | INTEGER FK→factor_recovery_requests | ✗ | | indexed |
| approver | String(64) | ✗ | | never the requester |
| decision | String(16) | ✗ | | `approve` / `deny` |
| note | String(255) | ✗ | `''` | |
| created_at | DateTime | ✗ | now | |

### 1.67 `scim_groups` — IdP group directory (Phase 7)

| Column | Type | Null | Default | Index/Notes |
|---|---|---|---|---|
| id | INTEGER PK | ✗ | | |
| scim_id | String(64) | ✗ | | unique |
| display_name | String(128) | ✗ | | |
| members | JSON | ✗ | `[]` | |
| active | Boolean | ✗ | True | |
| created_at | DateTime | ✗ | now | |
| updated_at | DateTime | ✗ | None | nullable |

SCIM users are not a separate table — a joiner's User lands in §1.52
`users` with `source=scim` (the IdP owns lifecycle; local console users
stay invisible to the `/scim/v2/Users` surface). The SCIM bearer itself is
the sealed `scim.token_sha256` settings field, minted once via
`POST /settings/scim/rotate`.

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
| — | none pending | 7 landed (`users` … `scim_groups`, §1.52–1.67); the next phase's tables are recorded here when it starts |

All planned tables follow the standing rules: additive `ensure_schema()`,
ledger emission in the same transaction, application-enforced references
(runtime DB), and append-only treatment where the architecture demands it.
