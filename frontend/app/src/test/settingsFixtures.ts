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
 * `POST /api/v1/cluster/failover` - the real role flip (screen 11.5).
 * Contract shape per `ClusterFailoverResponse` (`{node, from, to}`, the
 * fields the legacy toast composes); no rig capture exists because the
 * standing rigs are never failovered - the endpoint itself is the repo's
 * own OpenAPI contract, and the test asserts the exact request body.
 */
export const CLUSTER_FAILOVER_DEMOTE_RESPONSE = {
  status: 200,
  body: {
    node: 'pam-node-1',
    from: 'active',
    to: 'passive',
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

/* ---------------------------------------------------- screen 11.3 captures */

/**
 * `GET /api/v1/settings` - the full schema + values for all 15 groups
 * (verbatim, open rig :5100, Temp/opencode/settings_captures_113.mjs,
 * 2026-10-18). Field descriptors carry type / default / min / max /
 * max_length / allow_empty / readonly / choices / allow_http / help - the
 * source the 11.3 forms derive their Zod rules from. Honest-state facts in
 * this capture: auth/gateway/itsm are `stored` (demo-seed / gate), the
 * other twelve report `stored:false`, and every secret reads `""` on the
 * pristine rig (sealed secrets read `<set>` once set - the server never
 * echoes material).
 */
export const SETTINGS_RESPONSE = {
  status: 200,
  body: {
    schema: {
      auth: {
        breached_password_extra: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'str',
        },
        emergency_window_minutes: {
          default: 15,
          max: 120,
          min: 5,
          type: 'int',
        },
        lockout_minutes: {
          default: 15,
          max: 1440,
          min: 1,
          type: 'int',
        },
        lockout_threshold: {
          default: 5,
          max: 10,
          min: 3,
          type: 'int',
        },
        max_sessions_per_user: {
          default: 5,
          max: 50,
          min: 1,
          type: 'int',
        },
        mfa_required: {
          default: true,
          type: 'bool',
        },
        password_min_length: {
          default: 14,
          max: 64,
          min: 8,
          type: 'int',
        },
        progressive_delay: {
          default: true,
          type: 'bool',
        },
        rate_limit_per_account: {
          default: 15,
          max: 500,
          min: 3,
          type: 'int',
        },
        rate_limit_per_ip: {
          default: 30,
          max: 1000,
          min: 5,
          type: 'int',
        },
        remember_device_days: {
          default: 30,
          max: 90,
          min: 1,
          type: 'int',
        },
        require_device_posture: {
          default: false,
          type: 'bool',
        },
        session_absolute_hours: {
          default: 12,
          max: 72,
          min: 1,
          type: 'int',
        },
        session_idle_minutes: {
          default: 30,
          max: 240,
          min: 1,
          type: 'int',
        },
        spray_threshold: {
          default: 10,
          max: 50,
          min: 3,
          type: 'int',
        },
        stepup_ttl_minutes: {
          default: 5,
          max: 60,
          min: 1,
          type: 'int',
        },
      },
      gateway: {
        enabled: {
          default: false,
          help: "Broker gateway-capable sessions onto approved nodes in the target's zone",
          type: 'bool',
        },
        guacd_host: {
          default: '127.0.0.1',
          max_length: 255,
          type: 'str',
        },
        guacd_port: {
          default: 4822,
          max: 65535,
          min: 1,
          type: 'int',
        },
        node_heartbeat_ttl_seconds: {
          default: 90,
          help: 'An active node with no heartbeat for this long reports offline',
          max: 3600,
          min: 5,
          type: 'int',
        },
        recording_failure_policy: {
          choices: ['block', 'flag'],
          default: 'block',
          help: 'When recording cannot be established: block the session or start it flagged',
          type: 'enum',
        },
        require_zone: {
          default: false,
          help: 'Refuse gateway-capable sessions to targets not mapped to any zone (recommended in production)',
          type: 'bool',
        },
        retention_default_days: {
          default: 90,
          help: 'Recordings older than this are pruned + crypto-shredded by the retention run',
          max: 3650,
          min: 1,
          type: 'int',
        },
        retention_overrides: {
          allow_empty: true,
          default: '{}',
          help: 'JSON map of per-protocol retention, e.g. {"ssh": 365}',
          max_length: 1024,
          type: 'str',
        },
        segment_seconds: {
          default: 60,
          help: 'Recording segment length: gzip + AES-256-GCM sealed per segment',
          max: 3600,
          min: 5,
          type: 'int',
        },
        spool_alert_threshold_pct: {
          default: 70,
          max: 100,
          min: 1,
          type: 'int',
        },
        spool_full_threshold_pct: {
          default: 85,
          max: 100,
          min: 1,
          type: 'int',
        },
        spool_max_bytes: {
          default: 10737418240,
          help: "The recording volume's size in bytes (spool usage is measured against it)",
          max: 1099511627776,
          min: 1048576,
          type: 'int',
        },
      },
      hsm: {
        cluster_id: {
          default: 'hsm-cluster-k10-east',
          max_length: 64,
          type: 'str',
        },
        enforcement: {
          choices: ['advisory', 'enforced'],
          default: 'advisory',
          type: 'enum',
        },
        fips_profile: {
          choices: ['fips-140-2-level-3', 'fips-140-2-level-4', 'fips-140-3-level-1'],
          default: 'fips-140-2-level-4',
          type: 'enum',
        },
        key_rotation_hours: {
          default: 24,
          max: 720,
          min: 1,
          type: 'int',
        },
        kms_endpoint: {
          default: 'https://hsm-cluster-k10-east.prod.aegis.internal:443',
          type: 'url',
        },
        master_key_label: {
          default: 'aegispam-root-lmk',
          max_length: 64,
          type: 'str',
        },
        pin_reference: {
          default: 'vault://kv/pam/hsm',
          max_length: 255,
          type: 'str',
        },
        provider: {
          choices: [
            'aws-cloudhsm',
            'azure-dedicated-hsm',
            'gcp-cloud-hsm',
            'hashicorp-vault',
            'local-pkcs11',
          ],
          default: 'aws-cloudhsm',
          type: 'enum',
        },
        region: {
          default: 'us-east-1',
          max_length: 32,
          type: 'str',
        },
        seal_delay_seconds: {
          default: 18,
          max: 120,
          min: 0,
          type: 'int',
        },
      },
      itsm: {
        api_token: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        base_url: {
          allow_empty: true,
          allow_http: true,
          default: '',
          type: 'url',
        },
        path_template: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        username: {
          allow_empty: true,
          default: '',
          max_length: 128,
          type: 'str',
        },
        vendor: {
          choices: ['freshservice', 'jira', 'servicenow', 'bmc'],
          default: 'servicenow',
          type: 'enum',
        },
      },
      ldap: {
        port: {
          default: 389,
          max: 65535,
          min: 1,
          type: 'int',
        },
        server: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        ticket_ttl_seconds: {
          default: 900,
          max: 86400,
          min: 60,
          type: 'int',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        use_ssl: {
          default: false,
          type: 'bool',
        },
        user_bind_template: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
      },
      mfa: {
        factor_created_at: {
          allow_empty: true,
          default: '',
          max_length: 32,
          readonly: true,
          type: 'str',
        },
        factor_enrolled_for: {
          allow_empty: true,
          default: '',
          max_length: 64,
          readonly: true,
          type: 'str',
        },
        factor_last_verified_at: {
          allow_empty: true,
          default: '',
          max_length: 32,
          readonly: true,
          type: 'str',
        },
        factor_secret: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          readonly: true,
          type: 'secret',
        },
      },
      radius: {
        enabled: {
          default: false,
          type: 'bool',
        },
        host: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        port: {
          default: 1812,
          max: 65535,
          min: 1,
          type: 'int',
        },
        secret: {
          allow_empty: true,
          default: '',
          max_length: 512,
          type: 'secret',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
      },
      scim: {
        enabled: {
          default: false,
          type: 'bool',
        },
        token_sha256: {
          allow_empty: true,
          default: '',
          max_length: 64,
          readonly: true,
          type: 'str',
        },
      },
      siem: {
        enabled: {
          default: false,
          type: 'bool',
        },
        signing_secret: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        webhook_url: {
          allow_empty: true,
          allow_http: true,
          default: '',
          type: 'url',
        },
      },
      sms: {
        country: {
          default: 'IN',
          max_length: 2,
          type: 'str',
        },
        enabled: {
          default: false,
          type: 'bool',
        },
        provider: {
          choices: ['none', 'twilio', 'aws-sns', 'plivo'],
          default: 'none',
          type: 'enum',
        },
        sender_id: {
          allow_empty: true,
          default: '',
          help: 'DLT-registered sender ID (required for India)',
          max_length: 16,
          type: 'str',
        },
        template_id: {
          allow_empty: true,
          default: '',
          help: 'DLT-registered content template id (required for India)',
          max_length: 64,
          type: 'str',
        },
      },
      smtp: {
        enabled: {
          default: false,
          type: 'bool',
        },
        from_address: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        host: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        password: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        port: {
          default: 587,
          max: 65535,
          min: 1,
          type: 'int',
        },
        use_tls: {
          default: true,
          type: 'bool',
        },
        username: {
          allow_empty: true,
          default: '',
          max_length: 128,
          type: 'str',
        },
      },
      sso: {
        enforce_sso: {
          default: true,
          type: 'bool',
        },
        jit_provisioning: {
          default: true,
          type: 'bool',
        },
        primary_entity_id: {
          default: 'urn:aegispam.internal:sp:primary',
          max_length: 255,
          type: 'str',
        },
        primary_metadata_url: {
          default: 'https://aegispam.okta.com/app/aegis-sso/sso/saml/metadata',
          type: 'url',
        },
        primary_provider: {
          choices: ['okta', 'entra', 'ping-federate', 'adfs', 'keycloak'],
          default: 'okta',
          type: 'enum',
        },
        protocol: {
          choices: ['saml2', 'oidc'],
          default: 'saml2',
          type: 'enum',
        },
        require_mfa: {
          default: true,
          type: 'bool',
        },
        secondary_metadata_url: {
          allow_empty: true,
          default:
            'https://login.microsoftonline.com/8c1f2a64-3d77-4b1e-9f5a-2e6b0d4c7a91/federationmetadata/2.000/federationmetadata.xml',
          type: 'url',
        },
        secondary_provider: {
          choices: ['okta', 'entra', 'ping-federate', 'adfs', 'keycloak', 'disabled'],
          default: 'entra',
          type: 'enum',
        },
        session_ttl_minutes: {
          default: 480,
          max: 1440,
          min: 5,
          type: 'int',
        },
      },
      webauthn: {
        allowed_origins: {
          allow_empty: true,
          default: '',
          help: 'Comma-separated origins, e.g. https://pam.corp.example',
          max_length: 2048,
          type: 'str',
        },
        rp_id: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        rp_name: {
          default: 'VY-PAM',
          max_length: 128,
          type: 'str',
        },
      },
      worm: {
        bucket: {
          default: 'aegispam-immutable-worm-audit-prod-01',
          type: 'slug',
        },
        destination: {
          choices: [
            's3-object-lock',
            'azure-blob-immutability',
            'gcs-locked',
            'offline-archive',
          ],
          default: 's3-object-lock',
          type: 'enum',
        },
        immutability_enabled: {
          default: true,
          type: 'bool',
        },
        object_lock_mode: {
          choices: ['COMPLIANCE', 'GOVERNANCE'],
          default: 'COMPLIANCE',
          type: 'enum',
        },
        region: {
          default: 'us-east-1',
          max_length: 32,
          type: 'str',
        },
        retention_days: {
          default: 2555,
          max: 3650,
          min: 30,
          type: 'int',
        },
      },
      zsp: {
        default_jit_ttl_minutes: {
          default: 60,
          max: 1440,
          min: 1,
          type: 'int',
        },
        max_ttl_extension_minutes: {
          default: 120,
          max: 4320,
          min: 0,
          type: 'int',
        },
        session_inactivity_timeout_minutes: {
          default: 15,
          max: 240,
          min: 1,
          type: 'int',
        },
        tier0_quorum_approvers: {
          default: 2,
          max: 10,
          min: 1,
          type: 'int',
        },
      },
    },
    settings: {
      auth: {
        group: 'auth',
        stored: true,
        updated_at: '2026-10-14T20:36:54.123345',
        updated_by: 'demo-seed',
        values: {
          breached_password_extra: '',
          emergency_window_minutes: 15,
          lockout_minutes: 15,
          lockout_threshold: 5,
          max_sessions_per_user: 5,
          mfa_required: false,
          password_min_length: 14,
          progressive_delay: true,
          rate_limit_per_account: 15,
          rate_limit_per_ip: 30,
          remember_device_days: 30,
          require_device_posture: false,
          session_absolute_hours: 12,
          session_idle_minutes: 30,
          spray_threshold: 10,
          stepup_ttl_minutes: 5,
        },
      },
      gateway: {
        group: 'gateway',
        stored: true,
        updated_at: '2026-10-18T03:37:46.658605',
        updated_by: 'gate',
        values: {
          enabled: false,
          guacd_host: '127.0.0.1',
          guacd_port: 4822,
          node_heartbeat_ttl_seconds: 90,
          recording_failure_policy: 'block',
          require_zone: false,
          retention_default_days: 90,
          retention_overrides: '{}',
          segment_seconds: 60,
          spool_alert_threshold_pct: 70,
          spool_full_threshold_pct: 85,
          spool_max_bytes: 10737418240,
        },
      },
      hsm: {
        group: 'hsm',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          cluster_id: 'hsm-cluster-k10-east',
          enforcement: 'advisory',
          fips_profile: 'fips-140-2-level-4',
          key_rotation_hours: 24,
          kms_endpoint: 'https://hsm-cluster-k10-east.prod.aegis.internal:443',
          master_key_label: 'aegispam-root-lmk',
          pin_reference: 'vault://kv/pam/hsm',
          provider: 'aws-cloudhsm',
          region: 'us-east-1',
          seal_delay_seconds: 18,
        },
      },
      itsm: {
        group: 'itsm',
        stored: true,
        updated_at: '2026-10-14T23:51:36.464418',
        updated_by: 'open',
        values: {
          api_token: '',
          base_url: '',
          path_template: '',
          timeout_seconds: 5,
          username: '',
          vendor: 'servicenow',
        },
      },
      ldap: {
        group: 'ldap',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          port: 389,
          server: '',
          ticket_ttl_seconds: 900,
          timeout_seconds: 5,
          use_ssl: false,
          user_bind_template: '',
        },
      },
      mfa: {
        group: 'mfa',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          factor_created_at: '',
          factor_enrolled_for: '',
          factor_last_verified_at: '',
          factor_secret: '',
        },
      },
      radius: {
        group: 'radius',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          host: '',
          port: 1812,
          secret: '',
          timeout_seconds: 5,
        },
      },
      scim: {
        group: 'scim',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          token_sha256: '',
        },
      },
      siem: {
        group: 'siem',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          signing_secret: '',
          timeout_seconds: 5,
          webhook_url: '',
        },
      },
      sms: {
        group: 'sms',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          country: 'IN',
          enabled: false,
          provider: 'none',
          sender_id: '',
          template_id: '',
        },
      },
      smtp: {
        group: 'smtp',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          from_address: '',
          host: '',
          password: '',
          port: 587,
          use_tls: true,
          username: '',
        },
      },
      sso: {
        group: 'sso',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enforce_sso: true,
          jit_provisioning: true,
          primary_entity_id: 'urn:aegispam.internal:sp:primary',
          primary_metadata_url: 'https://aegispam.okta.com/app/aegis-sso/sso/saml/metadata',
          primary_provider: 'okta',
          protocol: 'saml2',
          require_mfa: true,
          secondary_metadata_url:
            'https://login.microsoftonline.com/8c1f2a64-3d77-4b1e-9f5a-2e6b0d4c7a91/federationmetadata/2.000/federationmetadata.xml',
          secondary_provider: 'entra',
          session_ttl_minutes: 480,
        },
      },
      webauthn: {
        group: 'webauthn',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          allowed_origins: '',
          rp_id: '',
          rp_name: 'VY-PAM',
        },
      },
      worm: {
        group: 'worm',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          bucket: 'aegispam-immutable-worm-audit-prod-01',
          destination: 's3-object-lock',
          immutability_enabled: true,
          object_lock_mode: 'COMPLIANCE',
          region: 'us-east-1',
          retention_days: 2555,
        },
      },
      zsp: {
        group: 'zsp',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          default_jit_ttl_minutes: 60,
          max_ttl_extension_minutes: 120,
          session_inactivity_timeout_minutes: 15,
          tier0_quorum_approvers: 2,
        },
      },
    },
  },
};

/**
 * `GET /api/v1/settings/audit?limit=20` - the configuration changelog
 * (verbatim, open rig :5100, same capture). Real history: the gate's own
 * gateway `enabled` flips by actor `gate`, newest first - exactly what the
 * legacy changelog renders.
 */
export const SETTINGS_AUDIT_RESPONSE = {
  status: 200,
  body: {
    events: [
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-18T03:37:46.666808',
        group: 'gateway',
        id: 33,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-18T03:37:40.177370',
        group: 'gateway',
        id: 32,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-18T01:57:58.121686',
        group: 'gateway',
        id: 31,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-18T01:57:51.306410',
        group: 'gateway',
        id: 30,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-17T08:28:36.004150',
        group: 'gateway',
        id: 29,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-17T08:28:31.837845',
        group: 'gateway',
        id: 28,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-17T06:42:25.059292',
        group: 'gateway',
        id: 27,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-17T06:42:20.889141',
        group: 'gateway',
        id: 26,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-17T05:20:38.656497',
        group: 'gateway',
        id: 25,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-17T05:20:32.419739',
        group: 'gateway',
        id: 24,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-17T02:46:49.031753',
        group: 'gateway',
        id: 23,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-17T02:46:43.311173',
        group: 'gateway',
        id: 22,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-16T08:20:05.843673',
        group: 'gateway',
        id: 21,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-16T08:19:59.079251',
        group: 'gateway',
        id: 20,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-16T02:21:16.507081',
        group: 'gateway',
        id: 19,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-16T02:21:01.809941',
        group: 'gateway',
        id: 18,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-15T12:14:32.251066',
        group: 'gateway',
        id: 17,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-15T12:14:24.966184',
        group: 'gateway',
        id: 16,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: false,
            old: true,
          },
        },
        created_at: '2026-10-15T02:11:46.618709',
        group: 'gateway',
        id: 15,
      },
      {
        action: 'updated',
        actor: 'gate',
        changes: {
          enabled: {
            new: true,
            old: false,
          },
        },
        created_at: '2026-10-15T02:11:39.708261',
        group: 'gateway',
        id: 14,
      },
    ],
    limit: 20,
    total: 33,
  },
};

/**
 * `PUT /api/v1/settings/auth` - a real write cycle on the token rig :5101
 * (create->capture->restore, 2026-10-18): lockout_minutes 15 -> 16 with
 * `X-Actor: capture-113`, answering the SettingsWriteResponse shape with
 * the per-field diff. The restore PUT (16 -> 15) plus the re-read proved
 * the baseline came back before this capture file was closed.
 */
export const SETTINGS_PUT_RESPONSE = {
  status: 200,
  body: {
    changed_fields: ['lockout_minutes'],
    changes: {
      lockout_minutes: {
        new: 16,
        old: 15,
      },
    },
    group: 'auth',
    message: 'Settings stored',
    stored: true,
    updated_at: '2026-10-18T05:48:52.833444',
    updated_by: 'capture-113',
    values: {
      breached_password_extra: '',
      emergency_window_minutes: 15,
      lockout_minutes: 16,
      lockout_threshold: 5,
      max_sessions_per_user: 5,
      mfa_required: false,
      password_min_length: 14,
      progressive_delay: true,
      rate_limit_per_account: 15,
      rate_limit_per_ip: 30,
      remember_device_days: 30,
      require_device_posture: false,
      session_absolute_hours: 12,
      session_idle_minutes: 30,
      spray_threshold: 10,
      stepup_ttl_minutes: 5,
    },
  },
};

/**
 * The no-op arm of the same endpoint (verbatim): re-submitting the stored
 * value answers `message: "No changes"` with an empty `changed_fields` and
 * records no changelog event - the save flow renders its "no value changes"
 * toast from exactly this body.
 */
export const SETTINGS_PUT_NOOP_RESPONSE = {
  status: 200,
  body: {
    changed_fields: [],
    changes: {},
    group: 'auth',
    message: 'No changes',
    values: {
      breached_password_extra: '',
      emergency_window_minutes: 15,
      lockout_minutes: 15,
      lockout_threshold: 5,
      max_sessions_per_user: 5,
      mfa_required: false,
      password_min_length: 14,
      progressive_delay: true,
      rate_limit_per_account: 15,
      rate_limit_per_ip: 30,
      remember_device_days: 30,
      require_device_posture: false,
      session_absolute_hours: 12,
      session_idle_minutes: 30,
      spray_threshold: 10,
      stepup_ttl_minutes: 5,
    },
  },
};

/**
 * The server's own out-of-range refusal (verbatim 400): strict validation
 * keeps the authority; the save banner prints `error` and the captured
 * `details.field` exactly like the legacy banner does.
 */
export const SETTINGS_PUT_REJECTED_RESPONSE = {
  status: 400,
  body: {
    details: {
      field: 'auth.lockout_minutes',
      max: 1440,
    },
    error: "'auth.lockout_minutes' must be <= 1440",
  },
};

/**
 * No admin token presented (verbatim 401) - the honest refusal a write
 * gets on a token-mode rig with an empty session.
 */
export const SETTINGS_PUT_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `POST /api/v1/settings/smtp/test` (verbatim 503, token rig): SMTP is
 * unconfigured on the pristine rig and the server refuses honestly,
 * naming what to set. (A probe without `to` answers the same 503 - the
 * unconfigured check runs first.)
 */
export const SMTP_TEST_UNCONFIGURED_RESPONSE = {
  status: 503,
  body: {
    details: {
      configured: false,
    },
    error:
      'SMTP is not configured - set host, port and from_address in the `smtp` settings group and enable it first',
  },
};

/** `POST /api/v1/settings/smtp/test` without the admin token (verbatim 401). */
export const SMTP_TEST_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `POST /api/v1/settings/scim/rotate` - the one-time SCIM bearer mint
 * (verbatim shape, token rig): message verbatim; the token string is the
 * one deliberate substitution - a rig-generated secret never enters the
 * repo (house rule). The real token was proven live in the same capture
 * cycle: it answered `GET /scim/v2/Users` 200 (scratch capture file),
 * so the fixture shape is the shape of a working token.
 */
export const SCIM_ROTATE_RESPONSE = {
  status: 200,
  body: {
    message: 'Shown once - configure it on the identity provider now.',
    token: 'vypam-scim1.<redacted-shown-once>',
  },
};

/** `POST /api/v1/settings/scim/rotate` without the admin token (verbatim 401). */
export const SCIM_ROTATE_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `GET /api/v1/settings` re-read AFTER the rotation (verbatim, same
 * capture cycle; the sha256 redacted for the same house rule - the hash is
 * derived from the live token). Server truth this fixture pins: the rotate
 * stamps the `scim` group itself (`stored:true`, `updated_by:"scim-rotate"`)
 * and flips `enabled` to true, so a post-rotate invalidation of the settings
 * query is what the form must re-read.
 */
export const SETTINGS_AFTER_ROTATE_RESPONSE = {
  status: 200,
  body: {
    schema: {
      auth: {
        breached_password_extra: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'str',
        },
        emergency_window_minutes: {
          default: 15,
          max: 120,
          min: 5,
          type: 'int',
        },
        lockout_minutes: {
          default: 15,
          max: 1440,
          min: 1,
          type: 'int',
        },
        lockout_threshold: {
          default: 5,
          max: 10,
          min: 3,
          type: 'int',
        },
        max_sessions_per_user: {
          default: 5,
          max: 50,
          min: 1,
          type: 'int',
        },
        mfa_required: {
          default: true,
          type: 'bool',
        },
        password_min_length: {
          default: 14,
          max: 64,
          min: 8,
          type: 'int',
        },
        progressive_delay: {
          default: true,
          type: 'bool',
        },
        rate_limit_per_account: {
          default: 15,
          max: 500,
          min: 3,
          type: 'int',
        },
        rate_limit_per_ip: {
          default: 30,
          max: 1000,
          min: 5,
          type: 'int',
        },
        remember_device_days: {
          default: 30,
          max: 90,
          min: 1,
          type: 'int',
        },
        require_device_posture: {
          default: false,
          type: 'bool',
        },
        session_absolute_hours: {
          default: 12,
          max: 72,
          min: 1,
          type: 'int',
        },
        session_idle_minutes: {
          default: 30,
          max: 240,
          min: 1,
          type: 'int',
        },
        spray_threshold: {
          default: 10,
          max: 50,
          min: 3,
          type: 'int',
        },
        stepup_ttl_minutes: {
          default: 5,
          max: 60,
          min: 1,
          type: 'int',
        },
      },
      gateway: {
        enabled: {
          default: false,
          help: "Broker gateway-capable sessions onto approved nodes in the target's zone",
          type: 'bool',
        },
        guacd_host: {
          default: '127.0.0.1',
          max_length: 255,
          type: 'str',
        },
        guacd_port: {
          default: 4822,
          max: 65535,
          min: 1,
          type: 'int',
        },
        node_heartbeat_ttl_seconds: {
          default: 90,
          help: 'An active node with no heartbeat for this long reports offline',
          max: 3600,
          min: 5,
          type: 'int',
        },
        recording_failure_policy: {
          choices: ['block', 'flag'],
          default: 'block',
          help: 'When recording cannot be established: block the session or start it flagged',
          type: 'enum',
        },
        require_zone: {
          default: false,
          help: 'Refuse gateway-capable sessions to targets not mapped to any zone (recommended in production)',
          type: 'bool',
        },
        retention_default_days: {
          default: 90,
          help: 'Recordings older than this are pruned + crypto-shredded by the retention run',
          max: 3650,
          min: 1,
          type: 'int',
        },
        retention_overrides: {
          allow_empty: true,
          default: '{}',
          help: 'JSON map of per-protocol retention, e.g. {"ssh": 365}',
          max_length: 1024,
          type: 'str',
        },
        segment_seconds: {
          default: 60,
          help: 'Recording segment length: gzip + AES-256-GCM sealed per segment',
          max: 3600,
          min: 5,
          type: 'int',
        },
        spool_alert_threshold_pct: {
          default: 70,
          max: 100,
          min: 1,
          type: 'int',
        },
        spool_full_threshold_pct: {
          default: 85,
          max: 100,
          min: 1,
          type: 'int',
        },
        spool_max_bytes: {
          default: 10737418240,
          help: "The recording volume's size in bytes (spool usage is measured against it)",
          max: 1099511627776,
          min: 1048576,
          type: 'int',
        },
      },
      hsm: {
        cluster_id: {
          default: 'hsm-cluster-k10-east',
          max_length: 64,
          type: 'str',
        },
        enforcement: {
          choices: ['advisory', 'enforced'],
          default: 'advisory',
          type: 'enum',
        },
        fips_profile: {
          choices: ['fips-140-2-level-3', 'fips-140-2-level-4', 'fips-140-3-level-1'],
          default: 'fips-140-2-level-4',
          type: 'enum',
        },
        key_rotation_hours: {
          default: 24,
          max: 720,
          min: 1,
          type: 'int',
        },
        kms_endpoint: {
          default: 'https://hsm-cluster-k10-east.prod.aegis.internal:443',
          type: 'url',
        },
        master_key_label: {
          default: 'aegispam-root-lmk',
          max_length: 64,
          type: 'str',
        },
        pin_reference: {
          default: 'vault://kv/pam/hsm',
          max_length: 255,
          type: 'str',
        },
        provider: {
          choices: [
            'aws-cloudhsm',
            'azure-dedicated-hsm',
            'gcp-cloud-hsm',
            'hashicorp-vault',
            'local-pkcs11',
          ],
          default: 'aws-cloudhsm',
          type: 'enum',
        },
        region: {
          default: 'us-east-1',
          max_length: 32,
          type: 'str',
        },
        seal_delay_seconds: {
          default: 18,
          max: 120,
          min: 0,
          type: 'int',
        },
      },
      itsm: {
        api_token: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        base_url: {
          allow_empty: true,
          allow_http: true,
          default: '',
          type: 'url',
        },
        path_template: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        username: {
          allow_empty: true,
          default: '',
          max_length: 128,
          type: 'str',
        },
        vendor: {
          choices: ['freshservice', 'jira', 'servicenow', 'bmc'],
          default: 'servicenow',
          type: 'enum',
        },
      },
      ldap: {
        port: {
          default: 389,
          max: 65535,
          min: 1,
          type: 'int',
        },
        server: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        ticket_ttl_seconds: {
          default: 900,
          max: 86400,
          min: 60,
          type: 'int',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        use_ssl: {
          default: false,
          type: 'bool',
        },
        user_bind_template: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
      },
      mfa: {
        factor_created_at: {
          allow_empty: true,
          default: '',
          max_length: 32,
          readonly: true,
          type: 'str',
        },
        factor_enrolled_for: {
          allow_empty: true,
          default: '',
          max_length: 64,
          readonly: true,
          type: 'str',
        },
        factor_last_verified_at: {
          allow_empty: true,
          default: '',
          max_length: 32,
          readonly: true,
          type: 'str',
        },
        factor_secret: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          readonly: true,
          type: 'secret',
        },
      },
      radius: {
        enabled: {
          default: false,
          type: 'bool',
        },
        host: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        port: {
          default: 1812,
          max: 65535,
          min: 1,
          type: 'int',
        },
        secret: {
          allow_empty: true,
          default: '',
          max_length: 512,
          type: 'secret',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
      },
      scim: {
        enabled: {
          default: false,
          type: 'bool',
        },
        token_sha256: {
          allow_empty: true,
          default: '',
          max_length: 64,
          readonly: true,
          type: 'str',
        },
      },
      siem: {
        enabled: {
          default: false,
          type: 'bool',
        },
        signing_secret: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        timeout_seconds: {
          default: 5,
          max: 30,
          min: 1,
          type: 'int',
        },
        webhook_url: {
          allow_empty: true,
          allow_http: true,
          default: '',
          type: 'url',
        },
      },
      sms: {
        country: {
          default: 'IN',
          max_length: 2,
          type: 'str',
        },
        enabled: {
          default: false,
          type: 'bool',
        },
        provider: {
          choices: ['none', 'twilio', 'aws-sns', 'plivo'],
          default: 'none',
          type: 'enum',
        },
        sender_id: {
          allow_empty: true,
          default: '',
          help: 'DLT-registered sender ID (required for India)',
          max_length: 16,
          type: 'str',
        },
        template_id: {
          allow_empty: true,
          default: '',
          help: 'DLT-registered content template id (required for India)',
          max_length: 64,
          type: 'str',
        },
      },
      smtp: {
        enabled: {
          default: false,
          type: 'bool',
        },
        from_address: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        host: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        password: {
          allow_empty: true,
          default: '',
          max_length: 4096,
          type: 'secret',
        },
        port: {
          default: 587,
          max: 65535,
          min: 1,
          type: 'int',
        },
        use_tls: {
          default: true,
          type: 'bool',
        },
        username: {
          allow_empty: true,
          default: '',
          max_length: 128,
          type: 'str',
        },
      },
      sso: {
        enforce_sso: {
          default: true,
          type: 'bool',
        },
        jit_provisioning: {
          default: true,
          type: 'bool',
        },
        primary_entity_id: {
          default: 'urn:aegispam.internal:sp:primary',
          max_length: 255,
          type: 'str',
        },
        primary_metadata_url: {
          default: 'https://aegispam.okta.com/app/aegis-sso/sso/saml/metadata',
          type: 'url',
        },
        primary_provider: {
          choices: ['okta', 'entra', 'ping-federate', 'adfs', 'keycloak'],
          default: 'okta',
          type: 'enum',
        },
        protocol: {
          choices: ['saml2', 'oidc'],
          default: 'saml2',
          type: 'enum',
        },
        require_mfa: {
          default: true,
          type: 'bool',
        },
        secondary_metadata_url: {
          allow_empty: true,
          default:
            'https://login.microsoftonline.com/8c1f2a64-3d77-4b1e-9f5a-2e6b0d4c7a91/federationmetadata/2.000/federationmetadata.xml',
          type: 'url',
        },
        secondary_provider: {
          choices: ['okta', 'entra', 'ping-federate', 'adfs', 'keycloak', 'disabled'],
          default: 'entra',
          type: 'enum',
        },
        session_ttl_minutes: {
          default: 480,
          max: 1440,
          min: 5,
          type: 'int',
        },
      },
      webauthn: {
        allowed_origins: {
          allow_empty: true,
          default: '',
          help: 'Comma-separated origins, e.g. https://pam.corp.example',
          max_length: 2048,
          type: 'str',
        },
        rp_id: {
          allow_empty: true,
          default: '',
          max_length: 255,
          type: 'str',
        },
        rp_name: {
          default: 'VY-PAM',
          max_length: 128,
          type: 'str',
        },
      },
      worm: {
        bucket: {
          default: 'aegispam-immutable-worm-audit-prod-01',
          type: 'slug',
        },
        destination: {
          choices: [
            's3-object-lock',
            'azure-blob-immutability',
            'gcs-locked',
            'offline-archive',
          ],
          default: 's3-object-lock',
          type: 'enum',
        },
        immutability_enabled: {
          default: true,
          type: 'bool',
        },
        object_lock_mode: {
          choices: ['COMPLIANCE', 'GOVERNANCE'],
          default: 'COMPLIANCE',
          type: 'enum',
        },
        region: {
          default: 'us-east-1',
          max_length: 32,
          type: 'str',
        },
        retention_days: {
          default: 2555,
          max: 3650,
          min: 30,
          type: 'int',
        },
      },
      zsp: {
        default_jit_ttl_minutes: {
          default: 60,
          max: 1440,
          min: 1,
          type: 'int',
        },
        max_ttl_extension_minutes: {
          default: 120,
          max: 4320,
          min: 0,
          type: 'int',
        },
        session_inactivity_timeout_minutes: {
          default: 15,
          max: 240,
          min: 1,
          type: 'int',
        },
        tier0_quorum_approvers: {
          default: 2,
          max: 10,
          min: 1,
          type: 'int',
        },
      },
    },
    settings: {
      auth: {
        group: 'auth',
        stored: true,
        updated_at: '2026-10-18T05:48:53.148415',
        updated_by: 'capture-113',
        values: {
          breached_password_extra: '',
          emergency_window_minutes: 15,
          lockout_minutes: 15,
          lockout_threshold: 5,
          max_sessions_per_user: 5,
          mfa_required: false,
          password_min_length: 14,
          progressive_delay: true,
          rate_limit_per_account: 15,
          rate_limit_per_ip: 30,
          remember_device_days: 30,
          require_device_posture: false,
          session_absolute_hours: 12,
          session_idle_minutes: 30,
          spray_threshold: 10,
          stepup_ttl_minutes: 5,
        },
      },
      gateway: {
        group: 'gateway',
        stored: true,
        updated_at: '2026-10-18T03:38:40.729039',
        updated_by: 'gate',
        values: {
          enabled: false,
          guacd_host: '127.0.0.1',
          guacd_port: 4822,
          node_heartbeat_ttl_seconds: 90,
          recording_failure_policy: 'block',
          require_zone: false,
          retention_default_days: 90,
          retention_overrides: '{}',
          segment_seconds: 60,
          spool_alert_threshold_pct: 70,
          spool_full_threshold_pct: 85,
          spool_max_bytes: 10737418240,
        },
      },
      hsm: {
        group: 'hsm',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          cluster_id: 'hsm-cluster-k10-east',
          enforcement: 'advisory',
          fips_profile: 'fips-140-2-level-4',
          key_rotation_hours: 24,
          kms_endpoint: 'https://hsm-cluster-k10-east.prod.aegis.internal:443',
          master_key_label: 'aegispam-root-lmk',
          pin_reference: 'vault://kv/pam/hsm',
          provider: 'aws-cloudhsm',
          region: 'us-east-1',
          seal_delay_seconds: 18,
        },
      },
      itsm: {
        group: 'itsm',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          api_token: '',
          base_url: '',
          path_template: '',
          timeout_seconds: 5,
          username: '',
          vendor: 'servicenow',
        },
      },
      ldap: {
        group: 'ldap',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          port: 389,
          server: '',
          ticket_ttl_seconds: 900,
          timeout_seconds: 5,
          use_ssl: false,
          user_bind_template: '',
        },
      },
      mfa: {
        group: 'mfa',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          factor_created_at: '',
          factor_enrolled_for: '',
          factor_last_verified_at: '',
          factor_secret: '',
        },
      },
      radius: {
        group: 'radius',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          host: '',
          port: 1812,
          secret: '',
          timeout_seconds: 5,
        },
      },
      scim: {
        group: 'scim',
        stored: true,
        updated_at: '2026-10-18T05:48:53.468491',
        updated_by: 'scim-rotate',
        values: {
          enabled: true,
          token_sha256: '<redacted-sha256-of-the-rotated-token>',
        },
      },
      siem: {
        group: 'siem',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          signing_secret: '',
          timeout_seconds: 5,
          webhook_url: '',
        },
      },
      sms: {
        group: 'sms',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          country: 'IN',
          enabled: false,
          provider: 'none',
          sender_id: '',
          template_id: '',
        },
      },
      smtp: {
        group: 'smtp',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enabled: false,
          from_address: '',
          host: '',
          password: '',
          port: 587,
          use_tls: true,
          username: '',
        },
      },
      sso: {
        group: 'sso',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          enforce_sso: true,
          jit_provisioning: true,
          primary_entity_id: 'urn:aegispam.internal:sp:primary',
          primary_metadata_url: 'https://aegispam.okta.com/app/aegis-sso/sso/saml/metadata',
          primary_provider: 'okta',
          protocol: 'saml2',
          require_mfa: true,
          secondary_metadata_url:
            'https://login.microsoftonline.com/8c1f2a64-3d77-4b1e-9f5a-2e6b0d4c7a91/federationmetadata/2.000/federationmetadata.xml',
          secondary_provider: 'entra',
          session_ttl_minutes: 480,
        },
      },
      webauthn: {
        group: 'webauthn',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          allowed_origins: '',
          rp_id: '',
          rp_name: 'VY-PAM',
        },
      },
      worm: {
        group: 'worm',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          bucket: 'aegispam-immutable-worm-audit-prod-01',
          destination: 's3-object-lock',
          immutability_enabled: true,
          object_lock_mode: 'COMPLIANCE',
          region: 'us-east-1',
          retention_days: 2555,
        },
      },
      zsp: {
        group: 'zsp',
        stored: false,
        updated_at: null,
        updated_by: null,
        values: {
          default_jit_ttl_minutes: 60,
          max_ttl_extension_minutes: 120,
          session_inactivity_timeout_minutes: 15,
          tier0_quorum_approvers: 2,
        },
      },
    },
  },
};

/* ---------------------------------------------------------------------------
 * 11.4 captures (ADR-0015) - verbatim from the live rigs, 2026-10-18
 * (raw bodies: Temp/opencode/capture_settings_114.mjs, never staged).
 *
 * Capture cycle notes (honest rig drift, verified gate-legal):
 * - The emergency pending state cannot exist without creating a grant, so
 *   the capture ran the real flow: open (X-Actor capture-114) -> pending
 *   GET -> single deny (restore; deny needs no dual control). The rig now
 *   holds 1 DENIED grant: the state line stays `sealed - emergency-admin
 *   grants nothing` and the grants line becomes `1 grant(s) on record` -
 *   both accepted by the gate's honest-state regexes.
 * - `POST /mfa/enroll` minted a real factor on the open rig (the settings
 *   `mfa.factor_*` fields are readonly, so this is irreversible via API).
 *   No gate check touches the factor fields or the integrations chips; the
 *   raw TOTP secret stayed in the Temp capture file only - the fixture
 *   carries the deliberate redaction below (house rule: rig-generated
 *   secrets never enter the repo).
 * - The refusal arms (400 short reason, 409 not-configured, 400 field
 *   validation) all raise BEFORE any state change - they are pure.
 * ------------------------------------------------------------------------- */

/** `GET /api/v1/auth/emergency` - pristine baseline (grants: []). */
export const EMERGENCY_GRANTS_EMPTY_RESPONSE = {
  status: 200,
  body: { grants: [], username: 'emergency-admin' },
};

/** `POST /api/v1/auth/emergency/open` - the real 201 (reason >= 8 chars). */
export const EMERGENCY_OPEN_REQUESTED_RESPONSE = {
  status: 201,
  body: {
    grant: {
      created_at: '2026-10-18T11:08:32.629993',
      expires_at: null,
      id: 1,
      opened_at: null,
      reason: '11.4 capture of the pending grant state',
      requested_by: 'capture-114',
      rotated_at: null,
      status: 'pending',
      ticket: '',
      used_at: null,
    },
    message: 'Emergency grant requested',
  },
};

/** `GET /api/v1/auth/emergency` - the pending window (1 grant, no approvals). */
export const EMERGENCY_GRANTS_PENDING_RESPONSE = {
  status: 200,
  body: {
    grants: [
      {
        approvals: [],
        created_at: '2026-10-18T11:08:32.629993',
        expires_at: null,
        id: 1,
        opened_at: null,
        reason: '11.4 capture of the pending grant state',
        requested_by: 'capture-114',
        rotated_at: null,
        status: 'pending',
        ticket: '',
        used_at: null,
      },
    ],
    username: 'emergency-admin',
  },
};

/**
 * `GET /api/v1/auth/emergency` - AFTER the deny restore: the rig's new
 * baseline (1 denied grant with its deny approval recorded).
 */
export const EMERGENCY_GRANTS_DENIED_RESPONSE = {
  status: 200,
  body: {
    grants: [
      {
        approvals: [
          {
            approver: 'capture-114-approver',
            created_at: '2026-10-18T11:08:33.165291',
            decision: 'deny',
            grant_id: 1,
            id: 1,
            note: '',
          },
        ],
        created_at: '2026-10-18T11:08:32.629993',
        expires_at: null,
        id: 1,
        opened_at: null,
        reason: '11.4 capture of the pending grant state',
        requested_by: 'capture-114',
        rotated_at: null,
        status: 'denied',
        ticket: '',
        used_at: null,
      },
    ],
    username: 'emergency-admin',
  },
};

/** `POST /api/v1/auth/emergency/open` with a short reason -> verbatim 400. */
export const EMERGENCY_OPEN_REFUSED_RESPONSE = {
  status: 400,
  body: { error: 'A reason of at least 8 characters is required' },
};

/** `GET /api/v1/auth/emergency` without the admin token (verbatim 401). */
export const EMERGENCY_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/** `POST /api/v1/auth/emergency/open` without the admin token (verbatim 401). */
export const EMERGENCY_OPEN_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `POST /api/v1/mfa/enroll` (verbatim 201 shape, open rig) - `message` and
 * `factor` verbatim; the TOTP seed and the `otpauth://` URI that encodes it
 * are the two deliberate substitutions: rig-generated secrets never enter
 * the repo (house rule, same as the SCIM token above). The real material
 * was captured live in the same cycle (Temp file) and the rig now holds
 * the enrolled factor.
 */
export const MFA_ENROLL_RESPONSE = {
  status: 201,
  body: {
    factor: {
      algorithm: 'SHA1',
      configured: true,
      created_at: '2026-10-18T11:08:33.893905',
      digits: 6,
      enrolled_for: 'admin',
      gate: 'medium-risk (mfa-decision) session starts require a valid code',
      last_verified_at: null,
      period: 30,
    },
    message: 'Factor enrolled - add it to your authenticator app; the secret is shown once',
    otpauth_uri: '<redacted-shown-once>',
    secret: '<redacted-shown-once>',
  },
};

/** `POST /api/v1/mfa/enroll` without the admin token (verbatim 401). */
export const MFA_ENROLL_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `POST /api/v1/itsm/verify` (verbatim 409, both rigs): no instance is
 * configured - `details.detail` is the verify-side honest gap.
 */
export const ITSM_VERIFY_UNCONFIGURED_RESPONSE = {
  status: 409,
  body: {
    details: { configured: false, detail: 'itsm is not configured', field: 'itsm' },
    error: 'ITSM is not configured',
  },
};

/** `POST /api/v1/itsm/verify` without a ticket (verbatim 400). */
export const ITSM_VERIFY_INVALID_TICKET_RESPONSE = {
  status: 400,
  body: { details: { field: 'ticket' }, error: "'ticket' is required" },
};

/** `POST /api/v1/itsm/verify` without the admin token (verbatim 401). */
export const ITSM_VERIFY_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/**
 * `POST /api/v1/auth/ldap` (verbatim 409): the configured check runs BEFORE
 * any bind, so the pristine rig refuses with its honest gap and no password
 * ever leaves the request. The same body answers on the token rig - the
 * endpoint needs no admin credential (login surface, no auth wall).
 */
export const LDAP_BIND_UNCONFIGURED_RESPONSE = {
  status: 409,
  body: {
    details: {
      configured: false,
      detail: 'not connected - set ldap.server and ldap.user_bind_template',
      field: 'ldap',
    },
    error: 'LDAP is not configured',
  },
};

/** `POST /api/v1/auth/ldap` without a password (verbatim 400). */
export const LDAP_BIND_INVALID_RESPONSE = {
  status: 400,
  body: { details: { field: 'password' }, error: "'password' is required" },
};
