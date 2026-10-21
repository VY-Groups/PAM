import { vi } from 'vitest';

// ADR-0013 fixtures: verbatim rig captures for the /topology network
// view (generated from Temp/opencode/cap-topo/ - see the header in
// topologyFixtures.ts).
import {
  TOPOLOGY_CLUSTER_RESPONSE,
  TOPOLOGY_HEALTH_RESPONSE,
  TOPOLOGY_INTEGRATIONS_RESPONSE,
} from './topologyFixtures';
export * from './topologyFixtures';

// F4 screen 3 fixtures: verbatim rig captures (generated from
// Temp/opencode/fixtures/*.json - see the header in jitFixtures.ts).
// Imported here for the route helpers' default bodies below, and
// re-exported for tests (`export *` alone would not bring the names
// into scope inside this module).
import {
  AA_REQUESTS_BODY,
  AA_STATS_BODY,
  AGENT_ACCESS_CLOSE_RESPONSE,
  AGENT_DETAIL_BODY,
  AGENT_DETAIL_PROBE_BODY,
  AGENT_DISABLE_RESPONSE,
  AGENT_REGISTER_RESPONSE,
  AGENT_REVOKE_RESPONSE,
  AGENT_TASK_RESPONSE,
  AGENTS_BODY,
  BROKER_CREDENTIALS_BODY,
  BROKER_CRED_APPROVE_RESPONSE,
  BROKER_CRED_CLOSE_RESPONSE,
  BROKER_CRED_DENY_RESPONSE,
  BROKER_POLICIES_BODY,
  BROKER_POLICY_REGISTER_RESPONSE,
  BROKER_POLICY_REVOKE_RESPONSE,
  BROKER_STATS_BODY,
  JIT_APPROVE_RESPONSE,
  JIT_CLOSE_RESPONSE,
  JIT_DENY_RESPONSE,
  JIT_DETAIL_ACTIVE_BODY,
  JIT_DETAIL_AGENT_ACTIVE_BODY,
  JIT_DETAIL_AGENT_APPROVED_BODY,
  JIT_DETAIL_AGENT_CLOSED_BODY,
  JIT_DETAIL_APPROVED_BODY,
  JIT_DETAIL_CLOSED_BODY,
  JIT_DETAIL_DENIED_BODY,
  JIT_DETAIL_PENDING_ALT_BODY,
  JIT_DETAIL_PENDING_BODY,
  JIT_FILED_RESPONSE,
  JIT_GRANT_RESPONSE,
  JIT_QUEUE_BODY,
  JIT_STATS_BODY,
} from './jitFixtures';
export * from './jitFixtures';

// F4 screen 4 fixtures: verbatim rig captures for the Live Session Hub
// (see the header in sessionFixtures.ts).
import {
  SESSION_CONTROLS_RESPONSE,
  SESSION_DETAIL_ENDED_GATEWAY_RESPONSE,
  SESSION_DETAIL_GATEWAY_ACTIVE_RESPONSE,
  SESSION_DETAIL_JIT_RESPONSE,
  SESSION_DETAIL_LIVE_RESPONSE,
  SESSION_DETAIL_PAUSED_RESPONSE,
  SESSION_EVENTS_ENDED_RESPONSE,
  SESSION_EVENTS_GATEWAY_ACTIVE_RESPONSE,
  SESSION_EVENTS_JIT_RESPONSE,
  SESSION_EVENTS_LIVE_RESPONSE,
  SESSION_EVENTS_PAUSED_RESPONSE,
  SESSION_IDS,
  SESSION_LINKED_GRANT_RESPONSE,
  SESSION_LOCK_RESPONSE,
  SESSION_PAUSE_RESPONSE,
  SESSION_RESUME_RESPONSE,
  SESSION_START_RESPONSE,
  SESSION_TERMINATE_RESPONSE,
  SESSIONS_LIST_RESPONSE,
  SESSIONS_STATS_RESPONSE,
  VAULT_ITEMS_RESPONSE,
} from './sessionFixtures';
export * from './sessionFixtures';

// F4 screen 5 fixtures: verbatim rig captures for Policy & Zero Trust
// (see the header in policyFixtures.ts).
import {
  ANOMALIES_RESPONSE,
  APPROVALS_PENDING_RESPONSE,
  APPROVE_RESPONSE,
  BASELINES_RESPONSE,
  COMMAND_RULES_RESPONSE,
  COMMAND_STATS_RESPONSE,
  DENY_RESPONSE,
  EVALUATE_DEFAULT_RESPONSE,
  INCIDENT_CLOSE_RESPONSE,
  INCIDENTS_OPEN_RESPONSE,
  POLICY_IDS,
  RISK_EVALUATIONS_RESPONSE,
  RISK_EVALUATE_RESPONSE,
  RISK_STATS_RESPONSE,
  RISK_TRAIN_RESPONSE,
  RULE_CREATE_RESPONSE,
  RULE_DELETE_RESPONSE,
  RULE_UPDATE_RESPONSE,
} from './policyFixtures';
export * from './policyFixtures';

// F4 screen 6 fixtures: verbatim rig captures for Compliance & SOC2
// (see the header in complianceFixtures.ts).
import {
  AUDIT_EXPORT_TEXT,
  AUDIT_STATS_RESPONSE,
  AUDIT_VERIFY_RESPONSE,
  EVENTS_ALL_RESPONSE,
  EVENTS_VAULT_RESPONSE,
  INTEGRATIONS_STATUS_RESPONSE,
} from './complianceFixtures';
export * from './complianceFixtures';

// F4 screen 7 fixtures: verbatim rig captures for Target Infrastructure
// (see the header in infrastructureFixtures.ts).
import {
  ACCOUNTS_LIST_RESPONSE,
  ASSETS_LIST_RESPONSE,
  ASSET_ADOPT_RESPONSE,
  ASSET_CREATE_RESPONSE,
  ASSET_IGNORE_RESPONSE,
  ASSET_RESTORE_RESPONSE,
  CLOUD_STATS_RESPONSE,
  CONNECTOR_CREATE_RESPONSE,
  CONNECTOR_DELETE_RESPONSE,
  CONNECTORS_LIST_RESPONSE,
  DISCOVER_REFUSED_RESPONSE,
  DISCOVERY_EVENTS_RESPONSE,
  DISCOVERY_STATS_RESPONSE,
  PROBE_RESPONSE,
  SCAN_CREATE_RESPONSE,
  SCANS_LIST_RESPONSE,
} from './infrastructureFixtures';
export * from './infrastructureFixtures';

// F4 screen 8 fixtures: verbatim rig captures for Vendor Access
// (see the header in vendorFixtures.ts).
import {
  VENDOR_APPROVE_RESPONSE,
  VENDOR_DENY_RESPONSE,
  INVITE_RESPONSE,
  MFA_OK_RESPONSE,
  NDA_RESPONSE,
  REVOKE_RESPONSE,
  REQUEST_FILED_RESPONSE,
  TICKET_OK_RESPONSE,
  VENDORS_LIST_RESPONSE,
  VENDOR_DETAIL_RESPONSE,
} from './vendorFixtures';
export * from './vendorFixtures';

// F4 screen 9 fixtures: verbatim rig captures for Break-Glass
// (see the header in breakGlassFixtures.ts). The lifecycle write
// captures (approve/deny/open/close) and the refusal bodies are
// re-exported for the screen's tests; the route helpers below import
// only the read-side defaults.
import {
  BG_DETAIL_APPROVED_RESPONSE,
  BG_DETAIL_CLOSED_RESPONSE,
  BG_DETAIL_DENIED_RESPONSE,
  BG_DETAIL_PENDING_RESPONSE,
  BG_DETAIL_USED_RESPONSE,
  BG_FILE_RESPONSE,
  BG_LIST_RESPONSE,
  BG_STATS_RESPONSE,
} from './breakGlassFixtures';
export * from './breakGlassFixtures';

// F4 screen 10 fixtures: verbatim rig captures for Enterprise Licensing
// (see the header in licensingFixtures.ts). The write-lifecycle captures
// (import 201, the duplicate-import 409, validate, revoke, restore) and
// the raw JWT file answer are re-exported for the screen's tests; the
// route helpers below import only the read-side defaults.
import {
  LIC_DETAIL_ACTIVE_RESPONSE,
  LIC_DETAIL_REVOKED_RESPONSE,
  LIC_FILE_JWT_ACTIVE_TEXT,
  LIC_FILE_JWT_TEXT,
  LIC_FILE_JSON_RESPONSE,
  LIC_FILE_SCRATCH_JSON_RESPONSE,
  LIC_IMPORT_RESPONSE,
  LIC_KEYS,
  LIC_LIST_RESPONSE,
  LIC_META_RESPONSE,
  LIC_OVERVIEW_RESPONSE,
  LIC_RESTORE_RESPONSE,
  LIC_REVOKE_RESPONSE,
  LIC_VALIDATE_ACTIVE_RESPONSE,
  LIC_VALIDATE_RESPONSE,
} from './licensingFixtures';
export * from './licensingFixtures';

// Screen 11 fixtures: verbatim rig captures for the Platform Settings
// screen (ADR-0015). The sealed-HSM capture and the SSO/HSM read bodies
// are re-exported; the route helpers below import the read-side
// defaults. The cluster overview and integrations status are REUSED from
// the topology/compliance captures - same endpoints, one verbatim
// capture each (see settingsFixtures.ts header).
import {
  CLUSTER_BACKUPS_RESPONSE,
  CLUSTER_FAILOVER_DEMOTE_RESPONSE,
  EMERGENCY_GRANTS_EMPTY_RESPONSE,
  EMERGENCY_OPEN_REQUESTED_RESPONSE,
  HSM_STATUS_RESPONSE,
  ITSM_VERIFY_UNCONFIGURED_RESPONSE,
  LDAP_BIND_UNCONFIGURED_RESPONSE,
  MFA_ENROLL_RESPONSE,
  ROLE_BINDINGS_RESPONSE,
  ROLE_BINDING_CREATE_RESPONSE,
  ROLE_BINDING_REVOKE_RESPONSE,
  ROLES_RESPONSE,
  SCIM_ROTATE_RESPONSE,
  SETTINGS_AUDIT_RESPONSE,
  SETTINGS_PUT_RESPONSE,
  SETTINGS_RESPONSE,
  SMTP_TEST_UNCONFIGURED_RESPONSE,
  SSO_STATUS_RESPONSE,
} from './settingsFixtures';
export * from './settingsFixtures';

// ADR-0016 fixtures (batches 11.6 + 11.7): verbatim rig captures for the
// password-recovery flow and the Users & Credentials screen (see the
// header in identityFixtures.ts). The recovery pair, the refusal bodies
// and the alternate write answers are re-exported for the screens'
// tests; the route helpers below import only the read-side defaults.
import {
  USER_PASSWORD_RESET_RESPONSE,
  USER_PATCH_DEACTIVATE_RESPONSE,
  USER_REVOKE_SESSIONS_RESPONSE,
  USER_UNLOCK_RESPONSE,
  USERS_CREATE_GENERATED_RESPONSE,
  USERS_LIST_RESPONSE,
} from './identityFixtures';
export * from './identityFixtures';

// ADR-0017 fixtures (batch 11.8): verbatim rig captures for the forced
// password change, the e-mail OTP login arm and the /auth/mfa self-service
// surface (see the header in securityFixtures.ts). The refusals and the
// alternate write answers are re-exported for the screens' tests; the
// route helpers below import the defaults.
import {
  BACKUP_CODES_RESPONSE,
  DELETE_FACTOR_OK_RESPONSE,
  ENROLL_EMAIL_RESPONSE,
  ENROLL_EMAIL_VERIFY_BAD_RESPONSE,
  ENROLL_RADIUS_UNCONFIGURED_RESPONSE,
  ENROLL_TOTP_RESPONSE,
  ENROLL_TOTP_VERIFY_WRONG_RESPONSE,
  MFA_FACTORS_RESPONSE,
  OTP_START_LOGIN_RESPONSE,
  PASSWORD_CHANGE_OK_RESPONSE,
  STEPUP_OK_RESPONSE,
} from './securityFixtures';
export * from './securityFixtures';

/** Build a fetch-shaped Response with the backend's JSON body. */
export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** The honest /auth/whoami 401 body (no credential presented). */
export const UNAUTHENTICATED_BODY = { error: 'Not authenticated' };

/** A minimal /health 200 body (ok posture) for the login footer. */
export const HEALTH_OK_BODY = {
  status: 'ok',
  database: 'ok',
  auth: 'open',
  algorithms: [],
  formats: [],
};

/**
 * An honest `GET /auth/whoami` 200 body for the open/dev posture
 * (openapi WhoAmI schema, required fields only).
 */
export const WHOAMI_OPEN_BODY = {
  mode: 'open',
  principal: 'open',
  role: 'admin',
  kind: 'open',
  operations: 'all',
  operations_count: 1,
};

/** Ready-made route: GET /auth/whoami answers `body` with `status`. */
export function whoamiRoute(body: unknown, status = 200) {
  return {
    match: (url: string) => url.includes('/auth/whoami'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /health answers the ok posture. */
export function healthRoute() {
  return {
    match: (url: string) => url.includes('/health'),
    respond: () => jsonResponse(200, HEALTH_OK_BODY),
  };
}

/**
 * Contract fixture (ADR-0018 batch 11.11): GET /setup/state on a virgin
 * install - unconfigured, no branding, SMTP unconfigured, the two
 * bootstrap officer usernames. Secret-free by construction.
 */
export const SETUP_STATE_OPEN_BODY = {
  configured: false,
  company_name: '',
  logo_data_uri: '',
  contact_email: '',
  smtp_configured: false,
  bootstrap: { maker: 'vypam-maker', checker: 'vypam-checker' },
};

/**
 * Ready-made route: GET /api/v1/setup/state answers `body`
 * (default: the virgin-install posture above).
 */
export function setupStateRoute(body: unknown = SETUP_STATE_OPEN_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/setup/state'),
    respond: () => jsonResponse(status, body),
  };
}

/**
 * Contract-shaped Command Center fixtures (F4 screen tests). The values
 * mirror real rig payloads - never invented display strings.
 */
export const OVERVIEW_BODY = {
  generated_at: '2026-10-13T11:44:00.000000',
  health: { status: 'ok', auth: 'open', algorithms: ['RSA-PSS-SHA256'], formats: ['json'] },
  licenses: {
    total: 1,
    active: 1,
    revoked: 0,
    expired: 0,
    expiring_soon: 0,
    by_tier: { Enterprise: 1 },
    usage: { nodes: 0, sessions: 0, reported_licenses: 1, bastion_tunnels: 0 },
  },
  vault: {
    total: 0,
    by_type: {},
    by_status: {},
    rotation: { compliance_pct: 100, due: 0, on_demand: 0 },
    secrets: { managed: 0, unmanaged: 0, versions: 0 },
    attention: { failed: 0 },
    checked_out: 0,
    events_today: { checkouts: 0, rotations: 0 },
  },
  settings: {
    groups: 15,
    groups_stored: 1,
    sso_provider: null,
    worm_immutable: true,
    worm_retention_days: 2555,
    zsp_quorum_approvers: 2,
  },
  counters: {
    license_events: 1,
    settings_events: 1,
    vault_events: 0,
    discovery_events: 0,
    total_events: 3,
  },
  posture: {
    score: 62.5,
    violations: 3,
    controls: [
      {
        id: 'worm-immutable',
        label: 'WORM audit retention',
        passed: true,
        evidence: 'worm_retention_days=2555',
      },
      {
        id: 'sso-enforced',
        label: 'SSO provider enforced',
        passed: false,
        evidence: 'sso_provider not set',
      },
    ],
  },
  activity: [],
};

export const EVENTS_BODY = {
  events: [
    {
      id: 'license:1',
      seq: 3,
      source: 'license',
      action: 'imported',
      subject: 'LIC-DEMO',
      actor: 'system',
      created_at: '2026-10-13T11:44:00.000000',
      event_hash: 'a'.repeat(64),
    },
  ],
  total: 1,
  limit: 10,
  source: 'all',
};

export const BYPASS_STATS_BODY = {
  actions: { closed: 0, detected: 0, ingested: 0, scanned: 0 },
  incidents: { closed: 1, open: 0, total: 1 },
  last_ingest_at: null,
  last_scan_at: null,
  rotations_forced: 0,
  signals: { candidate: 0, covered: 0, observed: 2, out_of_scope: 0, total: 2 },
};

export const BYPASS_INCIDENTS_BODY = { incidents: [], limit: 5, offset: 0, total: 0 };

/** Ready-made route: GET /api/v1/overview answers `body` with `status`. */
export function overviewRoute(body: unknown = OVERVIEW_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/overview'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/events answers `body` with `status`. */
export function eventsRoute(body: unknown = EVENTS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/events'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/bypass/stats answers `body` with `status`. */
export function bypassStatsRoute(body: unknown = BYPASS_STATS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/bypass/stats'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/bypass/incidents answers `body` with `status`. */
export function bypassIncidentsRoute(body: unknown = BYPASS_INCIDENTS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/bypass/incidents'),
    respond: () => jsonResponse(status, body),
  };
}

/** The full Command Center route set (whoami + health + the four screens queries). */
export function commandCenterRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    overviewRoute(),
    eventsRoute(),
    bypassStatsRoute(),
    bypassIncidentsRoute(),
  ];
}

/**
 * Contract-shaped Credential Vault fixtures (F4 screen 2 tests). Every
 * field below was captured verbatim from a live rig (onboard -> checkout ->
 * stats/events/detail/secret), so the tests assert server truth rather
 * than invented display strings.
 */
export const VAULT_STATS_BODY = {
  attention: { failed: 0 },
  by_status: { available: 1, checked_out: 1, failed: 0, rotating: 0, rotation_due: 0 },
  by_type: {
    api_token: 0,
    cloud_iam: 0,
    database: 1,
    domain_password: 0,
    service_account: 0,
    ssh_key: 1,
  },
  checked_out: 1,
  events_today: { checkouts: 1, rotations: 0 },
  rotation: { compliance_pct: 100.0, due: 0, on_demand: 0 },
  secrets: { managed: 2, unmanaged: 0, versions: 2 },
  total: 2,
};

export const VAULT_ITEMS_BODY = {
  items: [
    {
      access_tier: 'Tier-0',
      auth_method: 'Password',
      checked_out_at: '2026-10-13T23:29:03.919865',
      checked_out_by: 'j.okafor',
      created_at: '2026-10-13T23:28:46.825806',
      description: 'Primary bastion administrator',
      id: 1,
      last_rotated_at: '2026-10-13T23:28:46.823129',
      name: 'bastion-01 root',
      principal: 'root',
      rotation_hours_remaining: 23,
      rotation_interval_hours: 24,
      rotation_interval_label: 'Every 1d',
      secret_type: 'ssh_key',
      secret_updated_at: '2026-10-13T23:28:46.906521',
      secret_version: 1,
      status: 'checked_out',
      target: 'bastion-01.lab',
      target_detail: '',
    },
    {
      access_tier: 'Tier-1',
      auth_method: 'Password',
      checked_out_at: null,
      checked_out_by: null,
      created_at: '2026-10-13T23:28:47.135454',
      description: 'Application database account',
      id: 2,
      last_rotated_at: '2026-10-13T23:28:47.134651',
      name: 'payments-db app',
      principal: 'svc_payments',
      rotation_hours_remaining: 719,
      rotation_interval_hours: 720,
      rotation_interval_label: 'Every 30d',
      secret_type: 'database',
      secret_updated_at: '2026-10-13T23:28:47.142011',
      secret_version: 1,
      status: 'available',
      target: 'payments-db.prod',
      target_detail: '',
    },
  ],
  limit: 20,
  offset: 0,
  total: 2,
};

export const VAULT_EVENTS_BODY = {
  events: [
    {
      action: 'checked_out',
      actor: 'j.okafor',
      created_at: '2026-10-13T23:29:03.921539',
      detail: { reason: 'inc-4821' },
      id: 3,
      item_id: 1,
      item_name: 'bastion-01 root',
    },
    {
      action: 'onboarded',
      actor: 'admin',
      created_at: '2026-10-13T23:28:47.145728',
      detail: { rotation_interval_hours: 720, secret_source: 'generated' },
      id: 2,
      item_id: 2,
      item_name: 'payments-db app',
    },
  ],
  limit: 10,
  total: 3,
};

export const VAULT_DETAIL_BODY = {
  item: {
    ...VAULT_ITEMS_BODY.items[1],
    events: [
      {
        action: 'onboarded',
        actor: 'admin',
        created_at: '2026-10-13T23:28:47.145728',
        detail: { rotation_interval_hours: 720, secret_source: 'generated' },
        id: 2,
        item_id: 2,
        item_name: 'payments-db app',
      },
    ],
  },
};

export const SECRET_REVEAL_BODY = {
  alg: 'AES-256-GCM',
  entropy_bits: 177,
  item_id: 2,
  item_name: 'payments-db app',
  rotated_at: '2026-10-13T23:28:47.142011',
  // Every other field here is a verbatim rig capture; the plaintext is the
  // one deliberate substitution - a rig-generated secret never enters the
  // repo. The value is clearly synthetic and its entropy_bits is computed
  // with the backend's own `approximate_entropy_bits` (27 chars x log2(95)).
  secret: 'fixture-NotARealSecret-0000',
  source: 'generated',
  version: 1,
};

/** Ready-made route: GET /api/v1/vault/stats answers `body` with `status`. */
export function vaultStatsRoute(body: unknown = VAULT_STATS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/vault/stats'),
    respond: () => jsonResponse(status, body),
  };
}

/**
 * Ready-made route: GET /api/v1/vault/items (the list, never `/items/{id}`)
 * answers `body` with `status`.
 */
export function vaultItemsRoute(body: unknown = VAULT_ITEMS_BODY, status = 200) {
  return {
    match: (url: string) =>
      /\/api\/v1\/vault\/items(\?|$)/.test(url) && !url.includes('/vault/items/'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/vault/events answers `body` with `status`. */
export function vaultEventsRoute(body: unknown = VAULT_EVENTS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/vault/events'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/vault/items/{id} answers the detail body. */
export function vaultItemDetailRoute(body: unknown = VAULT_DETAIL_BODY, status = 200) {
  return {
    match: (url: string) =>
      /\/api\/v1\/vault\/items\/\d+(\?|$)/.test(url) && !url.includes('/secret'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /api/v1/vault/items/{id}/secret answers the reveal. */
export function vaultSecretRoute(body: unknown = SECRET_REVEAL_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/api/v1/vault/items/') && url.endsWith('/secret'),
    respond: () => jsonResponse(status, body),
  };
}

/**
 * Ready-made route: POST /api/v1/vault/items/{id}/{checkout|revoke|rotate}
 * echoes a `VaultActionResponse`-shaped body (item + server message).
 */
export function vaultActionRoute(
  action: 'checkout' | 'revoke' | 'rotate',
  item: unknown,
  message: string,
  status = 200,
) {
  return {
    match: (url: string) =>
      url.endsWith(`/vault/items/${(item as { id: number }).id}/${action}`),
    respond: () => jsonResponse(status, { item, message }),
  };
}

/** The full Credential Vault route set (whoami + health + vault queries). */
export function vaultRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    vaultStatsRoute(),
    vaultItemsRoute(),
    vaultEventsRoute(),
  ];
}

// ---------------------------------------------------------------------------
// F4 screen 3 - JIT Access & Approvals. Routes mirror the query/mutation URLs
// in features/jit/queries.ts; fixtures are the generated verbatim captures.
// ---------------------------------------------------------------------------

/**
 * A verbatim rig capture of a WRITE response: the HTTP status and the JSON
 * body actually served (the fixtures keep `{status, body}` exactly as the
 * rig answered; route helpers unwrap them so mocks never double-wrap).
 */
export interface CapturedResponse {
  status: number;
  body: unknown;
}

/** GET /api/v1/jit/stats - queue totals per status and risk band. */
export function jitStatsRoute(body: unknown = JIT_STATS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/jit/stats'),
    respond: () => jsonResponse(status, body),
  };
}

/**
 * GET /api/v1/jit/requests?... - the queue. The query marker separates it
 * from POST /jit/requests (file a request), which carries no query string.
 */
export function jitQueueRoute(body: unknown = JIT_QUEUE_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/jit/requests?'),
    respond: () => jsonResponse(status, body),
  };
}

/** GET /api/v1/jit/requests/{id} - one detail body per request id. */
export function jitDetailRoute(id: number, body: unknown, status = 200) {
  return {
    match: (url: string) => new RegExp(`/jit/requests/${id}(\\?|$)`).test(url),
    respond: () => jsonResponse(status, body),
  };
}

/** POST /api/v1/jit/requests - file a request (201, echoed request row). */
export function jitFileRequestRoute(capture: CapturedResponse = JIT_FILED_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/jit/requests'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * POST /api/v1/jit/requests/{id}/{approve|deny|consume|close} - the four
 * console-side JIT mutations (each answers its own captured response).
 */
export function jitActionRoute(
  action: 'approve' | 'deny' | 'consume' | 'close',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) => url.includes('/jit/requests/') && url.endsWith(`/${action}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/agent-access/stats - identity/request/task aggregates. */
export function agentAccessStatsRoute(body: unknown = AA_STATS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/agent-access/stats'),
    respond: () => jsonResponse(status, body),
  };
}

/** GET /api/v1/agent-access/requests?... - the agent access queue. */
export function agentAccessRequestsRoute(body: unknown = AA_REQUESTS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/agent-access/requests?'),
    respond: () => jsonResponse(status, body),
  };
}

/** POST /api/v1/agent-access/requests/{id}/close - console-side grant close. */
export function agentAccessCloseRoute(
  capture: CapturedResponse = AGENT_ACCESS_CLOSE_RESPONSE,
) {
  return {
    match: (url: string) =>
      url.includes('/agent-access/requests/') && url.endsWith('/close'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/broker/stats - policy/credential aggregates. */
export function brokerStatsRoute(body: unknown = BROKER_STATS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/broker/stats'),
    respond: () => jsonResponse(status, body),
  };
}

/** GET /api/v1/broker/policies?... - pipeline identities, newest first. */
export function brokerPoliciesRoute(body: unknown = BROKER_POLICIES_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/broker/policies?'),
    respond: () => jsonResponse(status, body),
  };
}

/** POST /api/v1/broker/policies - register an identity (token shown once). */
export function brokerPolicyRegisterRoute(
  capture: CapturedResponse = BROKER_POLICY_REGISTER_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/broker/policies'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** DELETE /api/v1/broker/policies/{id} - revoke an identity. */
export function brokerPolicyRevokeRoute(
  id: number,
  capture: CapturedResponse = BROKER_POLICY_REVOKE_RESPONSE,
) {
  return {
    match: (url: string) => new RegExp(`/broker/policies/${id}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/broker/credentials?... - the pipeline credential queue. */
export function brokerCredentialsRoute(
  body: unknown = BROKER_CREDENTIALS_BODY,
  status = 200,
) {
  return {
    match: (url: string) => url.includes('/broker/credentials?'),
    respond: () => jsonResponse(status, body),
  };
}

/** POST /api/v1/broker/credentials/{id}/{approve|deny|close} - admin actions. */
export function brokerCredActionRoute(
  action: 'approve' | 'deny' | 'close',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) =>
      url.includes('/broker/credentials/') && url.endsWith(`/${action}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/agents?... - agent identities, newest first. */
export function agentsRoute(body: unknown = AGENTS_BODY, status = 200) {
  return {
    match: (url: string) => url.includes('/agents?'),
    respond: () => jsonResponse(status, body),
  };
}

/**
 * GET/PATCH/DELETE /api/v1/agents/{id} - one route per identity: the method
 * picks the response (detail body, status-flip echo, revoke echo).
 */
export function agentDetailRoute(
  id: number,
  detail: unknown,
  mutations?: { patch?: CapturedResponse; del?: CapturedResponse },
) {
  return {
    match: (url: string) => new RegExp(`/agents/${id}(\\?|$)`).test(url),
    respond: (init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'PATCH' && mutations?.patch !== undefined) {
        return jsonResponse(mutations.patch.status, mutations.patch.body);
      }
      if (method === 'DELETE' && mutations?.del !== undefined) {
        return jsonResponse(mutations.del.status, mutations.del.body);
      }
      return jsonResponse(200, detail);
    },
  };
}

/** POST /api/v1/agents - register an identity (agent token shown once). */
export function agentRegisterRoute(capture: CapturedResponse = AGENT_REGISTER_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/agents'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/agents/{id}/tasks - declare a task's allow-list. */
export function agentTaskDeclareRoute(
  id: number,
  capture: CapturedResponse = AGENT_TASK_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith(`/agents/${id}/tasks`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full JIT Access page route set (F4 screen 3, /jit). */
export function jitRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    jitStatsRoute(),
    jitQueueRoute(),
    jitDetailRoute(1, JIT_DETAIL_DENIED_BODY),
    jitDetailRoute(2, JIT_DETAIL_CLOSED_BODY),
    jitDetailRoute(3, JIT_DETAIL_AGENT_CLOSED_BODY),
    jitDetailRoute(6, JIT_DETAIL_PENDING_BODY),
    jitDetailRoute(7, JIT_DETAIL_APPROVED_BODY),
    jitDetailRoute(8, JIT_DETAIL_ACTIVE_BODY),
    jitDetailRoute(10, JIT_DETAIL_AGENT_APPROVED_BODY),
    jitDetailRoute(12, JIT_DETAIL_PENDING_ALT_BODY),
    jitDetailRoute(13, JIT_DETAIL_AGENT_ACTIVE_BODY),
    jitFileRequestRoute(),
    jitActionRoute('approve', JIT_APPROVE_RESPONSE),
    jitActionRoute('deny', JIT_DENY_RESPONSE),
    jitActionRoute('consume', JIT_GRANT_RESPONSE),
    jitActionRoute('close', JIT_CLOSE_RESPONSE),
    agentAccessCloseRoute(),
    agentAccessRequestsRoute(),
    agentAccessStatsRoute(),
    brokerStatsRoute(),
    brokerPoliciesRoute(),
    brokerPolicyRegisterRoute(),
    brokerPolicyRevokeRoute(3),
    brokerCredentialsRoute(),
    brokerCredActionRoute('approve', BROKER_CRED_APPROVE_RESPONSE),
    brokerCredActionRoute('deny', BROKER_CRED_DENY_RESPONSE),
    brokerCredActionRoute('close', BROKER_CRED_CLOSE_RESPONSE),
    agentsRoute(),
    agentDetailRoute(1, AGENT_DETAIL_BODY, {
      patch: AGENT_DISABLE_RESPONSE,
      del: AGENT_REVOKE_RESPONSE,
    }),
    agentDetailRoute(2, AGENT_DETAIL_PROBE_BODY, {
      patch: AGENT_DISABLE_RESPONSE,
      del: AGENT_REVOKE_RESPONSE,
    }),
    agentRegisterRoute(),
    agentTaskDeclareRoute(1),
    vaultItemsRoute(),
  ];
}

/** GET /api/v1/sessions/stats - real monitoring aggregates. */
export function sessionStatsRoute(capture: CapturedResponse = SESSIONS_STATS_RESPONSE) {
  return {
    match: (url: string) => url.includes('/sessions/stats'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET /api/v1/sessions?... - the session list. The query marker
 * separates it from POST /sessions (start a session).
 */
export function sessionListRoute(capture: CapturedResponse = SESSIONS_LIST_RESPONSE) {
  return {
    match: (url: string) => url.includes('/sessions?'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/sessions/{id} - one detail body per session id. */
export function sessionDetailRoute(id: number, capture: CapturedResponse) {
  return {
    match: (url: string) => new RegExp(`/sessions/${id}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/sessions/{id}/events... - one recording per session id. */
export function sessionEventsRoute(id: number, capture: CapturedResponse) {
  return {
    match: (url: string) => url.includes(`/sessions/${id}/events`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/sessions - start a session (201, risk + broker verdict). */
export function sessionStartRoute(capture: CapturedResponse = SESSION_START_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/sessions'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * POST /api/v1/sessions/{id}/{pause|lock|resume} - the supervisor
 * lifecycle actions (each answers its own captured response).
 */
export function sessionLifecycleRoute(
  kind: 'pause' | 'lock' | 'resume',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) => url.includes('/sessions/') && url.endsWith(`/${kind}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/sessions/{id}/terminate - kill switch + cascade outcome. */
export function sessionTerminateRoute(
  capture: CapturedResponse = SESSION_TERMINATE_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/terminate'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/sessions/{id}/controls - flip control flags (audited). */
export function sessionControlsRoute(
  capture: CapturedResponse = SESSION_CONTROLS_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/controls'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Live Session Hub route set (F4 screen 4, /sessions). */
export function sessionsRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    sessionStatsRoute(),
    sessionListRoute(),
    sessionDetailRoute(SESSION_IDS.live, SESSION_DETAIL_LIVE_RESPONSE),
    sessionEventsRoute(SESSION_IDS.live, SESSION_EVENTS_LIVE_RESPONSE),
    sessionDetailRoute(SESSION_IDS.paused, SESSION_DETAIL_PAUSED_RESPONSE),
    sessionEventsRoute(SESSION_IDS.paused, SESSION_EVENTS_PAUSED_RESPONSE),
    sessionDetailRoute(SESSION_IDS.jit, SESSION_DETAIL_JIT_RESPONSE),
    sessionEventsRoute(SESSION_IDS.jit, SESSION_EVENTS_JIT_RESPONSE),
    sessionDetailRoute(SESSION_IDS.endedGateway, SESSION_DETAIL_ENDED_GATEWAY_RESPONSE),
    sessionEventsRoute(SESSION_IDS.endedGateway, SESSION_EVENTS_ENDED_RESPONSE),
    sessionDetailRoute(SESSION_IDS.gatewayActive, SESSION_DETAIL_GATEWAY_ACTIVE_RESPONSE),
    sessionEventsRoute(SESSION_IDS.gatewayActive, SESSION_EVENTS_GATEWAY_ACTIVE_RESPONSE),
    sessionLifecycleRoute('pause', SESSION_PAUSE_RESPONSE),
    sessionLifecycleRoute('resume', SESSION_RESUME_RESPONSE),
    sessionLifecycleRoute('lock', SESSION_LOCK_RESPONSE),
    sessionTerminateRoute(),
    sessionControlsRoute(),
    sessionStartRoute(),
    jitDetailRoute(SESSION_IDS.linkedGrant, SESSION_LINKED_GRANT_RESPONSE.body),
    vaultItemsRoute(VAULT_ITEMS_RESPONSE.body, VAULT_ITEMS_RESPONSE.status),
  ];
}

// ---------------------------------------------------------------------------
// F4 screen 5 - Policy & Zero Trust. Routes mirror features/policy/queries.ts;
// fixtures are the generated verbatim rig captures (policyFixtures.ts).
// ---------------------------------------------------------------------------

/** GET /api/v1/command-control/stats - the live policy aggregates. */
export function policyStatsRoute(capture: CapturedResponse = COMMAND_STATS_RESPONSE) {
  return {
    match: (url: string) => url.includes('/command-control/stats'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET/POST /api/v1/command-control/rules - the list (GET) and rule
 * creation (POST) share the path, so the method picks the response.
 */
export function policyRulesRoute(
  capture: CapturedResponse = COMMAND_RULES_RESPONSE,
  create: CapturedResponse = RULE_CREATE_RESPONSE,
) {
  return {
    match: (url: string) => /\/command-control\/rules(\?|$)/.test(url),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST')
        return jsonResponse(create.status, create.body);
      return jsonResponse(capture.status, capture.body);
    },
  };
}

/** PUT/DELETE /api/v1/command-control/rules/{id} - edit / remove a rule. */
export function policyRuleDetailRoute(
  id: number,
  mutations?: { put?: CapturedResponse; del?: CapturedResponse },
) {
  return {
    match: (url: string) => new RegExp(`/command-control/rules/${id}(\\?|$)`).test(url),
    respond: (init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'PUT' && mutations?.put !== undefined) {
        return jsonResponse(mutations.put.status, mutations.put.body);
      }
      if (method === 'DELETE' && mutations?.del !== undefined) {
        return jsonResponse(mutations.del.status, mutations.del.body);
      }
      return jsonResponse(405, { error: `No mock for ${method} on command rule ${id}` });
    },
  };
}

/** GET /api/v1/command-control/approvals - held commands awaiting a decision. */
export function policyApprovalsRoute(
  capture: CapturedResponse = APPROVALS_PENDING_RESPONSE,
) {
  return {
    match: (url: string) => url.includes('/command-control/approvals'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/command-control/incidents?... - escalation incidents, newest first. */
export function policyIncidentsRoute(capture: CapturedResponse = INCIDENTS_OPEN_RESPONSE) {
  return {
    match: (url: string) => /\/command-control\/incidents(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/command-control/incidents/{id}/close - close after review. */
export function policyIncidentCloseRoute(
  capture: CapturedResponse = INCIDENT_CLOSE_RESPONSE,
) {
  return {
    match: (url: string) =>
      url.includes('/command-control/incidents/') && url.endsWith('/close'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/command-control/evaluate - the real dry-run decision. */
export function policyEvaluateRoute(capture: CapturedResponse = EVALUATE_DEFAULT_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/command-control/evaluate'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/risk/stats - evaluation aggregates (bands, decisions, refusals). */
export function riskStatsRoute(capture: CapturedResponse = RISK_STATS_RESPONSE) {
  return {
    match: (url: string) => url.includes('/risk/stats'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/risk/evaluations?... - recorded evaluations, newest first. */
export function riskEvaluationsRoute(
  capture: CapturedResponse = RISK_EVALUATIONS_RESPONSE,
) {
  return {
    match: (url: string) => /\/risk\/evaluations(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/risk/baselines - trained UEBA behavior baselines. */
export function riskBaselinesRoute(capture: CapturedResponse = BASELINES_RESPONSE) {
  return {
    match: (url: string) => /\/risk\/baselines(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/risk/anomalies?... - UEBA incidents, newest first. */
export function riskAnomaliesRoute(capture: CapturedResponse = ANOMALIES_RESPONSE) {
  return {
    match: (url: string) => /\/risk\/anomalies(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/risk/evaluate - score one access request (advises only). */
export function riskEvaluateRoute(capture: CapturedResponse = RISK_EVALUATE_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/risk/evaluate'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/risk/baselines/train - learn from the real history. */
export function riskTrainRoute(capture: CapturedResponse = RISK_TRAIN_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/risk/baselines/train'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * POST /api/v1/sessions/{id}/events/{seq}/{approve|deny} - resolve a held
 * command (the append-only resolution row answers its captured response).
 */
export function heldCommandResolutionRoute(
  decision: 'approve' | 'deny',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) => url.includes('/events/') && url.endsWith(`/${decision}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Policy & Zero Trust route set (F4 screen 5, /policy). */
export function policyRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    policyStatsRoute(),
    policyRulesRoute(),
    policyRuleDetailRoute(POLICY_IDS.idA, {
      put: RULE_UPDATE_RESPONSE,
      del: RULE_DELETE_RESPONSE,
    }),
    policyApprovalsRoute(),
    policyIncidentsRoute(),
    policyIncidentCloseRoute(),
    policyEvaluateRoute(),
    riskStatsRoute(),
    riskEvaluationsRoute(),
    riskBaselinesRoute(),
    riskAnomaliesRoute(),
    riskEvaluateRoute(),
    riskTrainRoute(),
    heldCommandResolutionRoute('approve', APPROVE_RESPONSE),
    heldCommandResolutionRoute('deny', DENY_RESPONSE),
  ];
}

/** GET /api/v1/audit/stats - the ledger digest aggregates. */
export function auditStatsRoute(capture: CapturedResponse = AUDIT_STATS_RESPONSE) {
  return {
    match: (url: string) => /\/audit\/stats(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/audit/verify - the on-demand hash-chain walk. */
export function auditVerifyRoute(capture: CapturedResponse = AUDIT_VERIFY_RESPONSE) {
  return {
    match: (url: string) => /\/audit\/verify(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET /api/v1/audit/export - the whole ledger as `application/x-ndjson`
 * text (a non-JSON body, so it answers a raw Response).
 */
export function auditExportRoute(text: string = AUDIT_EXPORT_TEXT, status = 200) {
  return {
    match: (url: string) => /\/audit\/export(\?|$)/.test(url),
    respond: () =>
      new Response(text, {
        status,
        headers: { 'Content-Type': 'application/x-ndjson' },
      }),
  };
}

/**
 * GET /api/v1/events for the compliance trail - answers the capture for
 * the requested `source` (default `all`). An unknown source answers an
 * honest 404 instead of silently falling back, so a missing fixture
 * fails the test loudly rather than passing on the wrong body.
 */
export function complianceEventsRoute(
  bySource: Record<string, CapturedResponse> = {
    all: EVENTS_ALL_RESPONSE,
    vault: EVENTS_VAULT_RESPONSE,
  },
) {
  let source = 'all';
  return {
    match: (url: string) => {
      if (!url.includes('/api/v1/events')) return false;
      const found = /[?&]source=([^&]+)/.exec(url);
      source = found ? decodeURIComponent(found[1]) : 'all';
      return true;
    },
    respond: () => {
      const capture = bySource[source];
      if (!capture) {
        return jsonResponse(404, { error: `no events fixture for source "${source}"` });
      }
      return jsonResponse(capture.status, capture.body);
    },
  };
}

/** GET /api/v1/integrations/status - the honest connector chips. */
export function integrationsStatusRoute(
  capture: CapturedResponse = INTEGRATIONS_STATUS_RESPONSE,
) {
  return {
    match: (url: string) => /\/integrations\/status(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Compliance & SOC2 route set (F4 screen 6, /compliance). */
export function complianceRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    auditStatsRoute(),
    auditVerifyRoute(),
    auditExportRoute(),
    complianceEventsRoute(),
    integrationsStatusRoute(),
  ];
}

/* ------------------------------------------------------ F4 screen 7 routes */

/**
 * GET /api/v1/discovery/stats - the discovery aggregates. The GET list
 * routes match a query string (the hooks always send `limit=`), which
 * keeps them apart from the bare-POST writes on the same paths.
 */
export function discoveryStatsRoute(capture: CapturedResponse = DISCOVERY_STATS_RESPONSE) {
  return {
    match: (url: string) => /\/discovery\/stats(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET /api/v1/discovery/assets - the target list with the contract's
 * own filters applied exactly like the rig applies them: `pam_status`
 * and `type` by equality, `q` as a substring over address/hostname,
 * `total` echoing the filtered length. The URL is parsed in `match`
 * (the same closure trick complianceEventsRoute uses).
 */
export function discoveredAssetsRoute(capture: CapturedResponse = ASSETS_LIST_RESPONSE) {
  type AssetRow = {
    address: string;
    hostname?: string;
    asset_type: string;
    pam_status: string;
  };
  let params = new URLSearchParams();
  return {
    match: (url: string) => {
      if (!/\/discovery\/assets\?/.test(url)) return false;
      params = new URL(url, 'http://test.local').searchParams;
      return true;
    },
    respond: () => {
      const body = capture.body as {
        assets: AssetRow[];
        total: number;
        limit: number;
        offset: number;
      };
      const pam = params.get('pam_status');
      const type = params.get('type');
      const q = (params.get('q') ?? '').toLowerCase();
      let rows = body.assets;
      if (pam) rows = rows.filter((a) => a.pam_status === pam);
      if (type) rows = rows.filter((a) => a.asset_type === type);
      if (q !== '') {
        rows = rows.filter(
          (a) =>
            a.address.toLowerCase().includes(q) ||
            (a.hostname ?? '').toLowerCase().includes(q),
        );
      }
      return jsonResponse(capture.status, {
        assets: rows,
        total: rows.length,
        limit: body.limit,
        offset: body.offset,
      });
    },
  };
}

/** GET /api/v1/discovery/accounts - the privileged-account inventory. */
export function discoveryAccountsRoute(capture: CapturedResponse = ACCOUNTS_LIST_RESPONSE) {
  return {
    match: (url: string) => /\/discovery\/accounts\?/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/discovery/scans - the scan history. */
export function discoveryScansRoute(capture: CapturedResponse = SCANS_LIST_RESPONSE) {
  return {
    match: (url: string) => /\/discovery\/scans\?/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/discovery/scans - run a real scan (captured result). */
export function runScanRoute(capture: CapturedResponse = SCAN_CREATE_RESPONSE) {
  return {
    match: (url: string) => /\/discovery\/scans(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/discovery/assets - register a target (bare path = POST). */
export function onboardAssetRoute(capture: CapturedResponse = ASSET_CREATE_RESPONSE) {
  return {
    match: (url: string) => /\/discovery\/assets(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** PATCH /api/v1/discovery/assets/{id} - operator overrides. */
export function assetPatchRoute(
  assetId: number,
  capture: CapturedResponse = ASSET_IGNORE_RESPONSE,
) {
  return {
    match: (url: string) => new RegExp(`/discovery/assets/${assetId}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/discovery/assets/{id}/onboard - adopt into the vault. */
export function adoptAssetRoute(
  assetId: number,
  capture: CapturedResponse = ASSET_ADOPT_RESPONSE,
) {
  return {
    match: (url: string) => url.includes(`/discovery/assets/${assetId}/onboard`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/cloud/stats - the connector fleet aggregates. */
export function cloudStatsRoute(capture: CapturedResponse = CLOUD_STATS_RESPONSE) {
  return {
    match: (url: string) => /\/cloud\/stats(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/cloud/connectors - the fleet with the contract's filters. */
export function connectorsListRoute(capture: CapturedResponse = CONNECTORS_LIST_RESPONSE) {
  type ConnectorRow = { provider: string; status: string };
  let params = new URLSearchParams();
  return {
    match: (url: string) => {
      if (!/\/cloud\/connectors\?/.test(url)) return false;
      params = new URL(url, 'http://test.local').searchParams;
      return true;
    },
    respond: () => {
      const body = capture.body as {
        connectors: ConnectorRow[];
        total: number;
        limit: number;
        offset: number;
      };
      const provider = params.get('provider');
      const status = params.get('status');
      let rows = body.connectors;
      if (provider) rows = rows.filter((c) => c.provider === provider);
      if (status) rows = rows.filter((c) => c.status === status);
      return jsonResponse(capture.status, {
        ...body,
        connectors: rows,
        total: rows.length,
      });
    },
  };
}

/** POST /api/v1/cloud/connectors - register a fleet connector. */
export function connectorCreateRoute(
  capture: CapturedResponse = CONNECTOR_CREATE_RESPONSE,
) {
  return {
    match: (url: string) => /\/cloud\/connectors(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/cloud/connectors/{id}/test - the live probe. */
export function connectorProbeRoute(capture: CapturedResponse = PROBE_RESPONSE) {
  return {
    match: (url: string) => /\/cloud\/connectors\/\d+\/test(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/cloud/connectors/{id}/discover - inventory import. */
export function connectorDiscoverRoute(
  capture: CapturedResponse = DISCOVER_REFUSED_RESPONSE,
) {
  return {
    match: (url: string) => /\/cloud\/connectors\/\d+\/discover(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** DELETE /api/v1/cloud/connectors/{id} - remove a connector. */
export function connectorRemoveRoute(
  capture: CapturedResponse = CONNECTOR_DELETE_RESPONSE,
) {
  return {
    match: (url: string) => /\/cloud\/connectors\/\d+(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/events?source=discovery - the discovery event tape. */
export function discoveryEventsRoute(
  capture: CapturedResponse = DISCOVERY_EVENTS_RESPONSE,
) {
  return {
    match: (url: string) =>
      url.includes('/api/v1/events') && url.includes('source=discovery'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Target Infrastructure route set (F4 screen 7, /infrastructure). */
export function infrastructureRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    discoveryStatsRoute(),
    // Order matters on shared stems: the query-string GETs first, then
    // the bare-path POSTs, then the id-scoped writes.
    discoveredAssetsRoute(),
    discoveryAccountsRoute(),
    discoveryScansRoute(),
    connectorsListRoute(),
    cloudStatsRoute(),
    discoveryEventsRoute(),
    runScanRoute(),
    onboardAssetRoute(),
    adoptAssetRoute(3),
    assetPatchRoute(2),
    assetPatchRoute(1, ASSET_RESTORE_RESPONSE),
    connectorCreateRoute(),
    connectorProbeRoute(),
    connectorDiscoverRoute(),
    connectorRemoveRoute(),
  ];
}

/* ------------------------------------------------------ F4 screen 8 routes */

/**
 * GET /api/v1/vendors - the registry with the contract's own filters
 * applied exactly like the rig applies them: `status` by equality, `q`
 * as a substring over name/contact. The URL is parsed in `match` (the
 * same closure trick discoveryAssetsRoute uses), and the query string
 * keeps the list apart from the bare-path POST invite on the same stem.
 */
export function vendorsListRoute(capture: CapturedResponse = VENDORS_LIST_RESPONSE) {
  type VendorRow = { name: string; contact?: string; status: string };
  let params = new URLSearchParams();
  return {
    match: (url: string) => {
      if (!/\/vendors\?/.test(url)) return false;
      params = new URL(url, 'http://test.local').searchParams;
      return true;
    },
    respond: () => {
      if (capture.status >= 400) return jsonResponse(capture.status, capture.body);
      const body = capture.body as {
        vendors: VendorRow[];
        total: number;
        limit: number;
        offset: number;
      };
      const status = params.get('status');
      const q = (params.get('q') ?? '').toLowerCase();
      let rows = body.vendors;
      if (status) rows = rows.filter((v) => v.status === status);
      if (q !== '') {
        rows = rows.filter(
          (v) =>
            v.name.toLowerCase().includes(q) || (v.contact ?? '').toLowerCase().includes(q),
        );
      }
      return jsonResponse(capture.status, {
        ...body,
        vendors: rows,
        total: rows.length,
      });
    },
  };
}

/** GET /api/v1/vendors/{id} - one vendor's dashboard payload. */
export function vendorDetailRoute(
  vendorId: number,
  capture: CapturedResponse = VENDOR_DETAIL_RESPONSE,
) {
  return {
    match: (url: string) => new RegExp(`/vendors/${vendorId}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * POST /api/v1/vendors - invite (or reinvite: the contract starts a
 * fresh cycle on the same row for terminal names). Anchored on the
 * bare path so a query-string list GET never matches.
 */
export function inviteVendorRoute(capture: CapturedResponse = INVITE_RESPONSE) {
  return {
    match: (url: string) => /\/vendors$/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/vendors/{id}/{step} - the four chain steps, deny, revoke. */
export function vendorStepRoute(
  vendorId: number,
  step: 'mfa' | 'nda' | 'ticket' | 'approve' | 'deny' | 'revoke',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) => url.includes(`/vendors/${vendorId}/${step}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/vendors/{id}/requests - file a real scoped request. */
export function vendorRequestRoute(
  vendorId: number,
  capture: CapturedResponse = REQUEST_FILED_RESPONSE,
) {
  return {
    match: (url: string) => url.includes(`/vendors/${vendorId}/requests`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Vendor Access route set (F4 screen 8, /vendor-access). */
export function vendorRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    // Order matters on shared stems: the query-string GET first, then
    // the id-scoped dashboard, then the bare-path POST invite, then the
    // step writes.
    vendorsListRoute(),
    vendorDetailRoute(1),
    integrationsStatusRoute(),
    vaultItemsRoute(),
    inviteVendorRoute(),
    vendorStepRoute(1, 'mfa', MFA_OK_RESPONSE),
    vendorStepRoute(1, 'nda', NDA_RESPONSE),
    vendorStepRoute(1, 'ticket', TICKET_OK_RESPONSE),
    vendorStepRoute(1, 'approve', VENDOR_APPROVE_RESPONSE),
    vendorStepRoute(1, 'deny', VENDOR_DENY_RESPONSE),
    vendorStepRoute(1, 'revoke', REVOKE_RESPONSE),
    vendorRequestRoute(1),
  ];
}

/* ------------------------------------------------------------------ */
/* F4 screen 9: Break-Glass route helpers (contract shapes verbatim). */
/* ------------------------------------------------------------------ */

/** `GET /api/v1/break-glass/stats` - the real aggregates. */
export function breakGlassStatsRoute(capture: CapturedResponse = BG_STATS_RESPONSE) {
  return {
    match: (url: string) => url.includes('/break-glass/stats'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * `GET /api/v1/break-glass/requests` - the registry; the lifecycle
 * filter is driven server-side by the `status` query parameter (the
 * chips send it for real), mirroring the contract's enum.
 */
export function breakGlassListRoute(capture: CapturedResponse = BG_LIST_RESPONSE) {
  type BreakGlassRow = { status: string };
  let params = new URLSearchParams();
  return {
    match: (url: string) => {
      if (!/\/break-glass\/requests\?/.test(url)) return false;
      params = new URL(url, 'http://test.local').searchParams;
      return true;
    },
    respond: () => {
      if (capture.status >= 400) return jsonResponse(capture.status, capture.body);
      const body = capture.body as {
        requests: BreakGlassRow[];
        total: number;
        limit: number;
        offset: number;
      };
      const status = params.get('status');
      let rows = body.requests;
      if (status) rows = rows.filter((r) => r.status === status);
      return jsonResponse(capture.status, {
        ...body,
        requests: rows,
        total: rows.length,
      });
    },
  };
}

/** `GET /api/v1/break-glass/requests/{id}` - one request's full record. */
export function breakGlassDetailRoute(requestId: number, capture: CapturedResponse) {
  return {
    match: (url: string) =>
      new RegExp(`/break-glass/requests/${requestId}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/break-glass/requests` - file one emergency (201). */
export function breakGlassFileRoute(capture: CapturedResponse = BG_FILE_RESPONSE) {
  return {
    match: (url: string) => /\/break-glass\/requests$/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/break-glass/requests/{id}/{step}` - the four lifecycle writes. */
export function breakGlassWriteRoute(
  requestId: number,
  step: 'approve' | 'deny' | 'open' | 'close',
  capture: CapturedResponse,
) {
  return {
    match: (url: string) => url.includes(`/break-glass/requests/${requestId}/${step}`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Break-Glass route set (F4 screen 9, /break-glass). */
export function breakGlassRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    // The factor state (mfa.configured=false on this rig) drives the
    // banner line, the process rail and the direct-open path.
    integrationsStatusRoute(),
    breakGlassStatsRoute(),
    breakGlassListRoute(),
    breakGlassDetailRoute(1, BG_DETAIL_CLOSED_RESPONSE),
    breakGlassDetailRoute(2, BG_DETAIL_DENIED_RESPONSE),
    breakGlassDetailRoute(3, BG_DETAIL_APPROVED_RESPONSE),
    breakGlassDetailRoute(4, BG_DETAIL_PENDING_RESPONSE),
    breakGlassDetailRoute(5, BG_DETAIL_USED_RESPONSE),
  ];
}

/* ------------------------------------------------------------------ */
/* F4 screen 10: Enterprise Licensing route helpers (verbatim captures).*/
/* ------------------------------------------------------------------ */

/** `GET /api/v1/meta` - the platform catalog behind the rail. */
export function licenseMetaRoute(capture: CapturedResponse = LIC_META_RESPONSE) {
  return {
    match: (url: string) => url.includes('/api/v1/meta'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `GET /api/v1/overview` - the aggregates behind the KPI quad. */
export function licenseOverviewRoute(capture: CapturedResponse = LIC_OVERVIEW_RESPONSE) {
  return {
    match: (url: string) => url.includes('/api/v1/overview'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * `GET /api/v1/licenses?...` - the registry, with the contract's own
 * server-side filter semantics mirrored from live rig probes (2026-10-16):
 * `status` matches the record status OR the effective status (the live
 * `status=active` probe returns the demo row whose effective status is
 * the captured `valid`, and `status=expired` returns 0 rows because no
 * captured row carries expired in either field), `tier` and
 * `license_type` are equality, and `q` is a case-insensitive substring
 * over key, license ID, issued-to and tier (the rig's `q=Air-Gapped`
 * probe against the classification returns 0 - classification is NOT
 * searched). The chips and selects therefore drive real parameters and
 * the mock re-queries exactly like the server does.
 */
export function licensesListRoute(capture: CapturedResponse = LIC_LIST_RESPONSE) {
  type LicenseRow = {
    license_key: string;
    license_id?: string | null;
    issued_to?: string | null;
    tier?: string | null;
    license_type?: string;
    status: string;
    effective_status: string;
  };
  let params = new URLSearchParams();
  return {
    match: (url: string) => {
      if (!/\/api\/v1\/licenses\?/.test(url)) return false;
      params = new URL(url, 'http://test.local').searchParams;
      return true;
    },
    respond: () => {
      if (capture.status >= 400) return jsonResponse(capture.status, capture.body);
      const body = capture.body as {
        licenses: LicenseRow[];
        total: number;
        limit: number;
        offset: number;
      };
      const status = params.get('status');
      const tier = params.get('tier');
      const licenseType = params.get('license_type');
      const q = params.get('q');
      let rows = body.licenses;
      if (status) {
        rows = rows.filter(
          (row) => row.status === status || row.effective_status === status,
        );
      }
      if (tier) rows = rows.filter((row) => row.tier === tier);
      if (licenseType) {
        rows = rows.filter((row) => row.license_type === licenseType);
      }
      if (q) {
        const needle = q.toLowerCase();
        rows = rows.filter((row) =>
          [row.license_key, row.license_id ?? '', row.issued_to ?? '', row.tier ?? ''].some(
            (field) => field.toLowerCase().includes(needle),
          ),
        );
      }
      return jsonResponse(capture.status, {
        ...body,
        licenses: rows,
        total: rows.length,
      });
    },
  };
}

/**
 * `GET /api/v1/licenses/{key}` - one license's record + event trail.
 * The UUID-shaped key keeps this route disjoint from `/import`,
 * `/validate` and the `/{key}/file|revoke|restore` suffixes.
 */
export function licenseDetailRoute(licenseKey: string, capture: CapturedResponse) {
  return {
    match: (url: string) => new RegExp(`/api/v1/licenses/${licenseKey}(\\?.*)?$`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * `GET /api/v1/licenses/{key}/file` - the signed file in both wire
 * formats: `format=json` answers the envelope JSON, `format=jwt`
 * answers the compact token as raw `text/plain` (the contract's own
 * content type).
 */
export function licenseFileRoute(
  licenseKey: string,
  jsonCapture: CapturedResponse = LIC_FILE_JSON_RESPONSE,
  jwtText: string = LIC_FILE_JWT_TEXT,
) {
  let format = 'json';
  return {
    match: (url: string) => {
      if (!new RegExp(`/api/v1/licenses/${licenseKey}/file`).test(url)) {
        return false;
      }
      format = new URL(url, 'http://test.local').searchParams.get('format') ?? 'json';
      return true;
    },
    respond: () =>
      format === 'jwt'
        ? new Response(jwtText, {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          })
        : jsonResponse(jsonCapture.status, jsonCapture.body),
  };
}

/** `POST /api/v1/licenses/import` - air-gap ingestion (201, or the 409 refusal). */
export function licenseImportRoute(capture: CapturedResponse = LIC_IMPORT_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/licenses\/import$/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * The license key inside a posted validate payload: the envelope arm
 * (`license_data.license_key`), the wrapper arm (`license.license_key`)
 * or the compact JWT string (its payload IS the license_data claims).
 * Malformed payloads return undefined -> the route answers an honest
 * 404 (the house rule: a missing capture fails loudly, never on the
 * wrong body).
 */
function validatePayloadKey(raw: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'string') {
      const parts = parsed.split('.');
      if (parts.length !== 3) return undefined;
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      const claims = JSON.parse(atob(padded)) as {
        license_key?: string;
        license_data?: { license_key?: string };
      };
      return claims.license_key ?? claims.license_data?.license_key;
    }
    if (typeof parsed === 'object' && parsed !== null) {
      const env = parsed as {
        license_data?: { license_key?: string };
        license?: { license_key?: string };
      };
      return env.license_data?.license_key ?? env.license?.license_key;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * `POST /api/v1/licenses/validate` - the offline-parity verdict,
 * dispatched by the posted payload's own license key to that license's
 * captured verdict (the demo envelope and the scratch envelope were
 * both really validated on the rig). A payload with no captured verdict
 * answers 404 instead of borrowing another license's answer.
 */
export function licenseValidateRoute(
  byKey: Record<string, CapturedResponse> = {
    [LIC_KEYS.active]: LIC_VALIDATE_ACTIVE_RESPONSE,
    [LIC_KEYS.revoked]: LIC_VALIDATE_RESPONSE,
  },
) {
  return {
    match: (url: string) => /\/api\/v1\/licenses\/validate$/.test(url),
    respond: (init?: RequestInit) => {
      const key =
        typeof init?.body === 'string' ? validatePayloadKey(init.body) : undefined;
      const capture = key !== undefined ? byKey[key] : undefined;
      return capture
        ? jsonResponse(capture.status, capture.body)
        : jsonResponse(404, { error: 'No captured verdict for this payload' });
    },
  };
}

/** `POST /api/v1/licenses/{key}/revoke` / `.../restore` - lifecycle writes. */
export function licenseLifecycleRoute(
  action: 'revoke' | 'restore',
  capture: CapturedResponse = action === 'revoke'
    ? LIC_REVOKE_RESPONSE
    : LIC_RESTORE_RESPONSE,
) {
  return {
    match: (url: string) => new RegExp(`/licenses/[^/]+/${action}$`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The full Enterprise Licensing route set (F4 screen 10, /licensing). */
export function licenseRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    licenseMetaRoute(),
    licenseOverviewRoute(),
    // The file routes precede the detail routes: both address the same
    // key, and `/file?format=` is the more specific pattern. Each key
    // answers its OWN captured file (json envelope + raw jwt token).
    licenseFileRoute(LIC_KEYS.active, LIC_FILE_JSON_RESPONSE, LIC_FILE_JWT_ACTIVE_TEXT),
    licenseFileRoute(LIC_KEYS.revoked, LIC_FILE_SCRATCH_JSON_RESPONSE, LIC_FILE_JWT_TEXT),
    licenseDetailRoute(LIC_KEYS.active, LIC_DETAIL_ACTIVE_RESPONSE),
    licenseDetailRoute(LIC_KEYS.revoked, LIC_DETAIL_REVOKED_RESPONSE),
    licensesListRoute(),
    licenseImportRoute(),
    licenseValidateRoute(),
    licenseLifecycleRoute('revoke'),
    licenseLifecycleRoute('restore'),
  ];
}

/* ------------------------------------------- ADR-0013 routes (/topology) */

/**
 * GET /health with the VERBATIM rig body: the network map renders the
 * node's name, site and role, which the reduced HEALTH_OK_BODY omits.
 */
export function healthVerbatimRoute(
  body: unknown = TOPOLOGY_HEALTH_RESPONSE,
  status = 200,
) {
  return {
    match: (url: string) => /\/health(\?|$)/.test(url),
    respond: () => jsonResponse(status, body),
  };
}

/** GET /api/v1/cluster - the verbatim cluster overview (self + peers). */
export function clusterRoute(body: unknown = TOPOLOGY_CLUSTER_RESPONSE, status = 200) {
  return {
    match: (url: string) => /\/api\/v1\/cluster(\?|$)/.test(url),
    respond: () => jsonResponse(status, body),
  };
}

/** The System & Workflow Maps route set (ADR-0013, /topology). */
export function topologyRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthVerbatimRoute(),
    clusterRoute(),
    integrationsStatusRoute({ status: 200, body: TOPOLOGY_INTEGRATIONS_RESPONSE }),
  ];
}

/** GET /api/v1/auth/sso/status - the IdP federation posture (screen 11). */
export function ssoStatusRoute(capture: CapturedResponse = SSO_STATUS_RESPONSE) {
  return {
    match: (url: string) => /\/auth\/sso\/status(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/hsm/status - the key custody posture (screen 11). */
export function hsmStatusRoute(capture: CapturedResponse = HSM_STATUS_RESPONSE) {
  return {
    match: (url: string) => /\/hsm\/status(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** GET /api/v1/cluster/backups - the backup ledger rows (screen 11). */
export function clusterBackupsRoute(capture: CapturedResponse = CLUSTER_BACKUPS_RESPONSE) {
  return {
    match: (url: string) => /\/cluster\/backups(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * POST /api/v1/cluster/failover - the real role flip (screen 11.5). The
 * method picks the answer (house pattern): a POST answers the captured
 * flip, anything else gets an honest 405 (there is no read endpoint).
 */
export function clusterFailoverRoute(
  capture: CapturedResponse = CLUSTER_FAILOVER_DEMOTE_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/cluster\/failover(\?|$)/.test(url),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') !== 'POST') {
        return jsonResponse(405, { error: 'Method not allowed' });
      }
      return jsonResponse(capture.status, capture.body);
    },
  };
}

/** GET /api/v1/roles - the seeded role directory (screen 11). */
export function rolesRoute(capture: CapturedResponse = ROLES_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/roles(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET / POST / DELETE /api/v1/role-bindings[/{id}] - the binding list,
 * the grant write (201) and the revoke write (200). All three share the
 * stem, so the method picks the response (house pattern:
 * `agentDetailRoute`, `policyRulesRoute`).
 */
export function roleBindingsRoute(
  list: CapturedResponse = ROLE_BINDINGS_RESPONSE,
  create: CapturedResponse = ROLE_BINDING_CREATE_RESPONSE,
  revoke: CapturedResponse = ROLE_BINDING_REVOKE_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/role-bindings(\/\d+)?(\?|$)/.test(url),
    respond: (init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (method === 'POST') return jsonResponse(create.status, create.body);
      if (method === 'DELETE') return jsonResponse(revoke.status, revoke.body);
      return jsonResponse(list.status, list.body);
    },
  };
}

/**
 * `GET /api/v1/settings` - the schema + values for all 15 groups (11.3).
 * Anchored on the bare path so `/settings/audit`, the `PUT /settings/{group}`
 * writes and the two action stems never match it.
 */
export function settingsSchemaRoute(capture: CapturedResponse = SETTINGS_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/settings(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `GET /api/v1/settings/audit?limit=20` - the configuration changelog. */
export function settingsAuditRoute(capture: CapturedResponse = SETTINGS_AUDIT_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/settings\/audit(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

const SETTINGS_GROUP_STEM =
  /\/api\/v1\/settings\/(sso|hsm|zsp|worm|mfa|itsm|siem|ldap|auth|webauthn|smtp|sms|radius|scim|gateway)(\?|$)/;

/**
 * `PUT /api/v1/settings/{group}` - one of the 15 group writes. The method
 * picks the answer (house pattern): a PUT answers the captured write,
 * anything else gets an honest 405 (there is no read endpoint per group).
 */
export function settingsPutGroupRoute(capture: CapturedResponse = SETTINGS_PUT_RESPONSE) {
  return {
    match: (url: string) => SETTINGS_GROUP_STEM.test(url),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') !== 'PUT') {
        return jsonResponse(405, { error: 'Method not allowed' });
      }
      return jsonResponse(capture.status, capture.body);
    },
  };
}

/** `POST /api/v1/settings/smtp/test` - the real test-message action (11.3). */
export function smtpTestRoute(capture: CapturedResponse = SMTP_TEST_UNCONFIGURED_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/settings\/smtp\/test(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/settings/scim/rotate` - the one-time SCIM token mint (11.3). */
export function scimRotateRoute(capture: CapturedResponse = SCIM_ROTATE_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/settings\/scim\/rotate(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * `GET /api/v1/auth/emergency` - sealed-admin grants + username (11.4).
 * Anchored so `/auth/emergency/open` never falls through to it.
 */
export function emergencyRoute(
  capture: CapturedResponse = EMERGENCY_GRANTS_EMPTY_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/auth\/emergency(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/auth/emergency/open` - the dual-approved open request (11.4). */
export function emergencyOpenRoute(
  capture: CapturedResponse = EMERGENCY_OPEN_REQUESTED_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/auth\/emergency\/open(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * `POST /api/v1/mfa/enroll` - the one-time TOTP seed mint (11.4). Anchored
 * on `/api/v1/mfa/enroll` so the `auth/mfa/enroll/*` factor routes never
 * match it.
 */
export function mfaEnrollRoute(capture: CapturedResponse = MFA_ENROLL_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/mfa\/enroll(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/itsm/verify` - real ticket lookup (11.4 NEW action). */
export function itsmVerifyRoute(
  capture: CapturedResponse = ITSM_VERIFY_UNCONFIGURED_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/itsm\/verify(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** `POST /api/v1/auth/ldap` - real directory bind (11.4 NEW action). */
export function ldapBindRoute(capture: CapturedResponse = LDAP_BIND_UNCONFIGURED_RESPONSE) {
  return {
    match: (url: string) => /\/api\/v1\/auth\/ldap(\?|$)/.test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * The full Platform Settings route set (screen 11, ADR-0015): the 11.1
 * posture reads, the 11.2 RBAC directory, the 11.3 settings reads
 * (schema+values, changelog) and the 11.4 identity specials (emergency
 * state, MFA enroll, ITSM verify, LDAP bind) with the write/action stubs
 * the page never fires on load. Tests that drive a save or an action pass
 * their own captures via the override args (the verbatim write-arm
 * fixtures) - an `undefined` override keeps each helper's default.
 */
export function settingsRoutes(overrides?: {
  schema?: CapturedResponse;
  audit?: CapturedResponse;
  putGroup?: CapturedResponse;
  smtpTest?: CapturedResponse;
  scimRotate?: CapturedResponse;
  emergency?: CapturedResponse;
  emergencyOpen?: CapturedResponse;
  mfaEnroll?: CapturedResponse;
  itsmVerify?: CapturedResponse;
  ldapBind?: CapturedResponse;
}) {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    ssoStatusRoute(),
    hsmStatusRoute(),
    integrationsStatusRoute(),
    clusterBackupsRoute(),
    clusterFailoverRoute(),
    rolesRoute(),
    roleBindingsRoute(),
    settingsSchemaRoute(overrides?.schema),
    settingsAuditRoute(overrides?.audit),
    settingsPutGroupRoute(overrides?.putGroup),
    smtpTestRoute(overrides?.smtpTest),
    scimRotateRoute(overrides?.scimRotate),
    emergencyRoute(overrides?.emergency),
    emergencyOpenRoute(overrides?.emergencyOpen),
    mfaEnrollRoute(overrides?.mfaEnroll),
    itsmVerifyRoute(overrides?.itsmVerify),
    ldapBindRoute(overrides?.ldapBind),
  ];
}

/* ------------------------------------------------------ ADR-0016 routes */

/**
 * GET/POST /api/v1/users - the registry list (GET, `?source=` filter) and
 * create (POST) share the path, so the method picks the response.
 */
export function usersRoute(
  list: CapturedResponse = USERS_LIST_RESPONSE,
  create: CapturedResponse = USERS_CREATE_GENERATED_RESPONSE,
) {
  return {
    match: (url: string) => /\/api\/v1\/users(\?|$)/.test(url),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST')
        return jsonResponse(create.status, create.body);
      return jsonResponse(list.status, list.body);
    },
  };
}

/**
 * PATCH /api/v1/users/{id} - activate / deactivate. No GET detail exists
 * (list-only contract), so every method on the exact id stem answers the
 * capture; deeper stems (`/unlock`, `/password-reset`, `/sessions`) are
 * anchored past this regex and never match it.
 */
export function userPatchRoute(
  id: number,
  capture: CapturedResponse = USER_PATCH_DEACTIVATE_RESPONSE,
) {
  return {
    match: (url: string) => new RegExp(`/users/${id}(\\?|$)`).test(url),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/users/{id}/unlock - clear a lockout (captured). */
export function userUnlockRoute(
  id: number,
  capture: CapturedResponse = USER_UNLOCK_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith(`/users/${id}/unlock`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/users/{id}/password-reset - admin reset (captured). */
export function userResetRoute(
  id: number,
  capture: CapturedResponse = USER_PASSWORD_RESET_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith(`/users/${id}/password-reset`),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * DELETE /api/v1/users/{id}/sessions - revoke every live session (the
 * screen never reads this path; any other method answers an honest 405
 * instead of a guessed body).
 */
export function userSessionsRevokeRoute(
  id: number,
  capture: CapturedResponse = USER_REVOKE_SESSIONS_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith(`/users/${id}/sessions`),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'DELETE')
        return jsonResponse(capture.status, capture.body);
      return jsonResponse(405, { error: `No mock for method on users/${id}/sessions` });
    },
  };
}

/** The full Users & Credentials route set (ADR-0016 batch 11.7, /users). */
export function usersRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    usersRoute(),
    userUnlockRoute(2),
    userResetRoute(2),
    userSessionsRevokeRoute(2),
    userPatchRoute(2),
  ];
}

/* ---------------------------------------------------- ADR-0017 routes */

/** POST /api/v1/auth/password - the forced first-login change (captured). */
export function passwordChangeRoute(
  capture: CapturedResponse = PASSWORD_CHANGE_OK_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/auth/password'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/otp/start - the generic e-mail OTP challenge (captured). */
export function otpStartRoute(capture: CapturedResponse = OTP_START_LOGIN_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/auth/otp/start'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * GET/DELETE /api/v1/auth/mfa/factors - the factor list (GET on the bare
 * path) and factor removal (DELETE on `/{id}`) share the stem, so the
 * method picks the response; the optional `/{id}` group keeps one matcher
 * for both.
 */
export function mfaFactorsRoute(
  list: CapturedResponse = MFA_FACTORS_RESPONSE,
  remove: CapturedResponse = DELETE_FACTOR_OK_RESPONSE,
) {
  return {
    match: (url: string) => /\/auth\/mfa\/factors(\/\d+)?(\?|$)/.test(url),
    respond: (init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'DELETE')
        return jsonResponse(remove.status, remove.body);
      return jsonResponse(list.status, list.body);
    },
  };
}

/** POST /api/v1/auth/mfa/backup-codes - ten single-use codes (captured). */
export function mfaBackupCodesRoute(capture: CapturedResponse = BACKUP_CODES_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/backup-codes'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/enroll/totp - enrol (or rotate) the TOTP factor. */
export function mfaEnrollTotpRoute(capture: CapturedResponse = ENROLL_TOTP_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/enroll/totp'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/enroll/totp/verify - prove the live code. */
export function mfaEnrollTotpVerifyRoute(
  capture: CapturedResponse = ENROLL_TOTP_VERIFY_WRONG_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/enroll/totp/verify'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/enroll/email - start the mailbox enrolment. */
export function mfaEnrollEmailRoute(capture: CapturedResponse = ENROLL_EMAIL_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/enroll/email'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/enroll/email/verify - activate the e-mail factor. */
export function mfaEnrollEmailVerifyRoute(
  capture: CapturedResponse = ENROLL_EMAIL_VERIFY_BAD_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/enroll/email/verify'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/enroll/radius - the honest captured 503 by default. */
export function mfaEnrollRadiusRoute(
  capture: CapturedResponse = ENROLL_RADIUS_UNCONFIGURED_RESPONSE,
) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/enroll/radius'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** POST /api/v1/auth/mfa/stepup - the fresh-assertion window (captured). */
export function mfaStepupRoute(capture: CapturedResponse = STEPUP_OK_RESPONSE) {
  return {
    match: (url: string) => url.endsWith('/auth/mfa/stepup'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/**
 * A login stub for the identity flows: the callback decides per request
 * (the forced-change 403, the MFA challenge, the OTP retry, the mint).
 */
export function authLoginRoute(
  respond: (init?: RequestInit) => Response | Promise<Response>,
) {
  return {
    match: (url: string) => url.endsWith('/auth/login'),
    respond,
  };
}

/** The Security & MFA route set (ADR-0017 batch 11.8, /security). */
export function securityRoutes() {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    // The shell footer reads the cluster context (ADR-0020), so every
    // full-shell route set answers /api/v1/cluster honestly.
    clusterRoute(),
    mfaFactorsRoute(),
    mfaBackupCodesRoute(),
    mfaEnrollTotpRoute(),
    mfaEnrollTotpVerifyRoute(),
    mfaEnrollEmailRoute(),
    mfaEnrollEmailVerifyRoute(),
    mfaEnrollRadiusRoute(),
    mfaStepupRoute(),
  ];
}

/**
 * Install a URL-matching fetch mock. `routes` is consulted in order;
 * unmatched URLs reject (honest backend-down in tests, not silent success).
 */
export function stubFetch(
  routes: Array<{
    match: (url: string) => boolean;
    respond: (init?: RequestInit) => Response | Promise<Response>;
  }>,
): ReturnType<typeof vi.fn> {
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const route = routes.find((r) => r.match(url));
    if (!route) return Promise.reject(new TypeError(`Unhandled fetch: ${url}`));
    return Promise.resolve(route.respond(init));
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}
