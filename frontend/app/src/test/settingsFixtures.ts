/**
 * Screen 11 (Platform Settings, ADR-0015) test fixtures - VERBATIM rig
 * captures from the live open rig (:5100) on 2026-10-17, taken with
 * Temp/opencode/capture_settings_rig.mjs (scratch, never staged):
 *
 * - GET /api/v1/auth/sso/status - the pristine rig has no IdP slot
 *   configured (configured=false, zero sessions/subjects, ttl 480).
 * - GET /api/v1/hsm/status - advisory file custody: no provider,
 *   unsealed, rotation not due, last_health empty (never probed).
 * - GET /api/v1/cluster/backups - the backup ledger is empty on a
 *   pristine node ({ backups: [] }), so the ledger table renders its
 *   honest empty row.
 *
 * The cluster overview and integrations status fixtures are REUSED from
 * the topology screen (topologyFixtures.ts / complianceFixtures.ts) -
 * same endpoints, same rig, one capture each; re-capturing them here
 * would fork the verbatim truth. Every response body below is what the
 * server answered.
 */

/** `GET /api/v1/auth/sso/status` - IdP federation posture (verbatim). */
export const SSO_STATUS_RESPONSE = {
  status: 200,
  body: {
    configured: false,
    enforce_sso: false,
    jit_provisioning: false,
    last_login_at: null,
    primary_entity_id: null,
    require_mfa: false,
    session_ttl_minutes: 480,
    sessions_active: 0,
    sessions_total: 0,
    slots: {
      primary: {
        enabled: false,
        metadata_url: '',
        protocol: 'saml2',
        provider: '',
      },
      secondary: {
        enabled: false,
        metadata_url: '',
        protocol: 'saml2',
        provider: '',
      },
    },
    sp_metadata_url: 'http://127.0.0.1:5100/api/v1/auth/sso/saml/primary/metadata',
    subjects: 0,
  },
};

/** `GET /api/v1/hsm/status` - key custody posture (verbatim). */
export const HSM_STATUS_RESPONSE = {
  status: 200,
  body: {
    cluster_id: null,
    fips_profile: null,
    key_in_use: 'file',
    key_label: null,
    key_rotation_hours: 24,
    last_health: {},
    mode: 'advisory',
    provider: '',
    region: null,
    rotation_due: false,
    seal_delay_seconds: null,
    seal_reason: '',
    sealed: false,
    wrap_error: 'No wrapped master key on disk',
    wrapped_key: null,
  },
};

/**
 * The same `GET /api/v1/hsm/status` captured while the advisory rig is
 * SEALED - verbatim output of the live seal->capture->unseal cycle in
 * Temp/opencode/capture_hsm_sealed.mjs on 2026-10-17 (the gate's own 6c
 * flow, reason string the same one the cycle posted). The rig was
 * unsealed back to this baseline afterwards.
 */
export const HSM_STATUS_SEALED_RESPONSE = {
  status: 200,
  body: {
    cluster_id: null,
    fips_profile: null,
    key_in_use: 'file',
    key_label: null,
    key_rotation_hours: 24,
    last_health: {},
    mode: 'advisory',
    provider: '',
    region: null,
    rotation_due: false,
    seal_delay_seconds: null,
    seal_reason: 'settings 11.1 fixture capture',
    sealed: true,
    wrap_error: 'No wrapped master key on disk',
    wrapped_key: null,
  },
};

/**
 * `GET /api/v1/cluster/backups` - the backup ledger rows (verbatim):
 * empty on the pristine node.
 */
export const CLUSTER_BACKUPS_RESPONSE = {
  status: 200,
  body: {
    backups: [],
  },
};

/**
 * `GET /api/v1/roles` - the seeded role directory (verbatim from the
 * open rig :5100, Temp/opencode/settings_rig_captures.json). Five
 * built-in roles, each with its computed operation count; the count is
 * the contract (the gate's role-tile check reads the seeded five).
 */
export const ROLES_RESPONSE = {
  status: 200,
  body: {
    roles: [
      {
        created_at: '2026-10-14T20:35:37.440971',
        description: 'Every admin operation - the admin token equivalent.',
        id: 1,
        name: 'admin',
        operations: 144,
      },
      {
        created_at: '2026-10-14T20:35:37.440975',
        description:
          'Decision operations only: approve, deny, close and release across JIT, command control, break-glass, vendor and broker requests.',
        id: 2,
        name: 'approver',
        operations: 13,
      },
      {
        created_at: '2026-10-14T20:35:37.440976',
        description:
          'Every read-only admin operation including the evidence exports (license files, vault and session chain exports) - no writes.',
        id: 4,
        name: 'auditor',
        operations: 34,
      },
      {
        created_at: '2026-10-14T20:35:37.440976',
        description:
          'Every read-only admin operation except the evidence exports and secret reveals - metadata only.',
        id: 5,
        name: 'auditor-read-only',
        operations: 31,
      },
      {
        created_at: '2026-10-14T20:35:37.440975',
        description:
          'Day-2 operations: vault checkout/rotate, session lifecycle, rotation, discovery, integrations, monitoring, backups and failover - never approvals.',
        id: 3,
        name: 'operator',
        operations: 48,
      },
    ],
  },
};

/**
 * `GET /api/v1/role-bindings` - the seeded binding table (verbatim from
 * the open rig :5100). Three `local` demo principals, all with an empty
 * scope (which the page renders as "unscoped (role governs
 * everywhere)") and `last_used_at: null` (rendered "never"). The token
 * is never returned in full - only the public `token_prefix`.
 */
export const ROLE_BINDINGS_RESPONSE = {
  status: 200,
  body: {
    bindings: [
      {
        created_at: '2026-10-14T20:36:54.777325',
        created_by: 'demo-seed',
        has_token: true,
        id: 1,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-admin',
        revoked_at: null,
        role: 'admin',
        scope: {},
        token_prefix: 'vypam-rbac1.1.',
      },
      {
        created_at: '2026-10-14T20:36:54.876922',
        created_by: 'demo-seed',
        has_token: true,
        id: 2,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-operator',
        revoked_at: null,
        role: 'operator',
        scope: {},
        token_prefix: 'vypam-rbac1.2.',
      },
      {
        created_at: '2026-10-14T20:36:54.977025',
        created_by: 'demo-seed',
        has_token: true,
        id: 3,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-auditor',
        revoked_at: null,
        role: 'auditor',
        scope: {},
        token_prefix: 'vypam-rbac1.3.',
      },
    ],
  },
};

/**
 * `POST /api/v1/role-bindings` - the grant write (verbatim from the
 * token-mode rig :5101, Temp/opencode/rbac_capture_112.json, probe id
 * 16). A `local` principal answers 201 with the one-time token in the
 * body; the binding it created carries only the public `token_prefix`.
 *
 * The live token string is the one deliberate substitution - the house
 * rule (see SECRET_REVEAL_BODY) is that a rig-generated secret never
 * enters the repo. The real token was revoked via DELETE and its death
 * is captured as a 401 in the same scratch file; the value below is
 * clearly synthetic and the shape is verbatim.
 */
export const ROLE_BINDING_CREATE_RESPONSE = {
  status: 201,
  body: {
    binding: {
      created_at: '2026-10-18T02:47:19.674196',
      created_by: 'capture-112',
      has_token: true,
      id: 16,
      kind: 'local',
      last_used_at: null,
      principal: 'capture-112-probe',
      revoked_at: null,
      role: 'operator',
      scope: {
        targets: ['capture-*'],
      },
      token_prefix: 'vypam-rbac1.16.',
    },
    message: 'Role binding created',
    token: 'vypam-rbac1.16.<redacted-shown-once>',
    token_notice: 'Shown once - store it now; it cannot be recovered.',
  },
};

/**
 * The same `POST /api/v1/role-bindings` for an `sso` principal
 * (verbatim, probe id 17 in the same capture cycle): NO `token` in the
 * 201 - an SSO subject's session bearer is minted by the IdP login, not
 * by the grant, so the page must not show a token box for it.
 */
export const ROLE_BINDING_CREATE_SSO_RESPONSE = {
  status: 201,
  body: {
    binding: {
      created_at: '2026-10-18T02:50:24.717637',
      created_by: 'capture-112',
      has_token: false,
      id: 17,
      kind: 'sso',
      last_used_at: null,
      principal: 'capture-112-sso-probe',
      revoked_at: null,
      role: 'auditor',
      scope: {},
      token_prefix: '',
    },
    message: 'Role binding created',
  },
};

/**
 * `GET /api/v1/role-bindings` re-read immediately after the probe
 * grant (verbatim): the table now carries the created row - the page
 * reloads the list after a successful grant, and this is what it sees.
 */
export const ROLE_BINDINGS_WITH_PROBE_RESPONSE = {
  status: 200,
  body: {
    bindings: [
      {
        created_at: '2026-10-14T20:36:54.777325',
        created_by: 'demo-seed',
        has_token: true,
        id: 1,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-admin',
        revoked_at: null,
        role: 'admin',
        scope: {},
        token_prefix: 'vypam-rbac1.1.',
      },
      {
        created_at: '2026-10-14T20:36:54.876922',
        created_by: 'demo-seed',
        has_token: true,
        id: 2,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-operator',
        revoked_at: null,
        role: 'operator',
        scope: {},
        token_prefix: 'vypam-rbac1.2.',
      },
      {
        created_at: '2026-10-14T20:36:54.977025',
        created_by: 'demo-seed',
        has_token: true,
        id: 3,
        kind: 'local',
        last_used_at: null,
        principal: 'demo-auditor',
        revoked_at: null,
        role: 'auditor',
        scope: {},
        token_prefix: 'vypam-rbac1.3.',
      },
      {
        created_at: '2026-10-18T02:47:19.674196',
        created_by: 'capture-112',
        has_token: true,
        id: 16,
        kind: 'local',
        last_used_at: null,
        principal: 'capture-112-probe',
        revoked_at: null,
        role: 'operator',
        scope: {
          targets: ['capture-*'],
        },
        token_prefix: 'vypam-rbac1.16.',
      },
    ],
  },
};

/**
 * `DELETE /api/v1/role-bindings/{id}` - the revoke write (verbatim,
 * the same probe): 200, the binding echoed back with `revoked_at` now
 * stamped, and the server's own message. The row stays as audit
 * evidence; only the token stops working.
 */
export const ROLE_BINDING_REVOKE_RESPONSE = {
  status: 200,
  body: {
    binding: {
      created_at: '2026-10-18T02:47:19.674196',
      created_by: 'capture-112',
      has_token: true,
      id: 16,
      kind: 'local',
      last_used_at: null,
      principal: 'capture-112-probe',
      revoked_at: '2026-10-18T02:47:20.191206',
      role: 'operator',
      scope: {
        targets: ['capture-*'],
      },
      token_prefix: 'vypam-rbac1.16.',
    },
    message: 'Role binding revoked',
  },
};
