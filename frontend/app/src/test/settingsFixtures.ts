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
