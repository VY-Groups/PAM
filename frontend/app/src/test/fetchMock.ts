import { vi } from 'vitest';

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
