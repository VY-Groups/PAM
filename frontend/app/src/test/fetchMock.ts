import { vi } from 'vitest';

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
