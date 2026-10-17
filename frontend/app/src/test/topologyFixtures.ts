/**
 * Verbatim rig captures for the System & Workflow Maps network view
 * (ADR-0013, /topology). Captured live from the gate rig on
 * 2026-10-16 (Temp/opencode/cap-topo/): GET /health, GET /api/v1/cluster
 * and GET /api/v1/integrations/status exactly as the server answered
 * them. Never hand-edited; regenerate with
 * Temp/opencode/gen_topo_fixtures.py when the rig changes.
 */

/** `GET /health` - the node's own posture as captured (status ok). */
export const TOPOLOGY_HEALTH_RESPONSE = {
  algorithms: ['RSA-PSS-SHA256', 'Ed25519'],
  auth: 'open',
  database: 'ok',
  ed25519_key: true,
  formats: ['json', 'jwt'],
  node: 'pam-node-1',
  private_key: '/data/vypam-keys/private.pem',
  role: 'active',
  site: 'dc',
  status: 'ok',
} as const;

/** `GET /api/v1/cluster` - self, peers, replication, backups, monitor. */
export const TOPOLOGY_CLUSTER_RESPONSE = {
  backups: {
    latest: null,
    total: 0,
    verified: 0,
  },
  monitor: {
    failover_failures: 3,
    probe_timeout_seconds: 5,
    sync_timeout_seconds: 30,
  },
  nodes: [
    {
      base_url: '',
      consecutive_failures: 0,
      created_at: '2026-10-14T20:35:37.374405',
      created_by: 'deployment',
      health: 'unknown',
      id: 1,
      last_error: '',
      last_latency_ms: null,
      last_probe_at: null,
      name: 'pam-node-1',
      role: 'active',
      site: 'dc',
    },
  ],
  peers: {
    by_health: {
      degraded: 0,
      healthy: 0,
      unknown: 0,
      unreachable: 0,
    },
    total: 0,
  },
  replication: {
    nodes: {},
    totals: {
      audit: 0,
      sessions: 0,
      vault: 0,
    },
  },
  self: {
    auth: 'open',
    name: 'pam-node-1',
    role: 'active',
    site: 'dc',
  },
} as const;

/** `GET /api/v1/integrations/status` - ITSM/LDAP/MFA/SIEM honest states. */
export const TOPOLOGY_INTEGRATIONS_RESPONSE = {
  itsm: {
    base_url: '',
    configured: false,
    credentials_configured: false,
    detail: 'not connected - set itsm.base_url',
    path_template: '',
    timeout_seconds: 5,
    username: '',
    vendor: 'servicenow',
  },
  ldap: {
    configured: false,
    detail: 'not connected - set ldap.server and ldap.user_bind_template',
    port: 389,
    server: '',
    ticket_ttl_seconds: 900,
    timeout_seconds: 5,
    use_ssl: false,
    user_bind_template: '',
  },
  mfa: {
    algorithm: 'SHA1',
    configured: false,
    created_at: null,
    digits: 6,
    enrolled_for: '',
    gate: 'not configured - the mfa band stays advisory',
    last_verified_at: null,
    period: 30,
  },
  siem: {
    configured: false,
    detail: 'not connected - set siem.webhook_url, a signing secret and enabled=true',
    enabled: false,
    last_push: {
      batches_failed: 0,
      batches_ok: 0,
      last_error: null,
      last_http_status: null,
      last_push_at: null,
      last_push_status: 'never',
      records_pushed: 0,
    },
    signing_secret_set: false,
    state: 'not connected',
    webhook_url: '',
  },
} as const;
