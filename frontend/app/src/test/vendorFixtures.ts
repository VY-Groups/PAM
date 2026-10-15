/**
 * F4 screen 8 (Vendor Access) test fixtures - VERBATIM rig captures,
 * generated from the Docker rig responses saved in Temp/opencode/cap8/
 * (scratch directory, never staged) on the :5100 open rig. Every value -
 * chain steps, ITSM verification detail, the 409/401/403 refusal bodies,
 * lifecycle messages, the filed request's risk band, the twenty-event
 * trail - is byte-for-byte what the license server returned. The write
 * captures were produced against the dev rig with synthetic vypam-
 * vendor names (screen 5/7 precedent): the MFA codes were real RFC-6238
 * over the rig's own seed, the ITSM ticket verification really ran
 * against a local stub through the configured itsm group (restored to
 * unconfigured afterwards - integrations/status verifies), and the
 * access request really filed (risk: low) before the vendor was
 * revoked again.
 *
 * One standing-rule adjustment: the TOTP seeds in the invite captures
 * are rig one-time secrets and NEVER enter the repo - the mfa block of
 * INVITE_RESPONSE carries a clearly synthetic base32 seed of the same
 * shape (the otpauth URI is rebuilt from it; digits/period/algorithm/
 * note stay verbatim).
 *
 * One clearly-labelled SYNTHETIC addition (schema-valid state the rig
 * does not produce): VENDORS_EMPTY_RESPONSE proves the honest empty
 * list.
 */

export const VENDORS_LIST_RESPONSE = {
  status: 200,
  body: {
    limit: 200,
    offset: 0,
    total: 2,
    vendors: [
      {
        access: {
          allowed: ['10.99.8.42'],
          denied: [],
          expires_at: null,
          recording: true,
          window: null,
        },
        approved_at: '2026-10-14T23:51:35.919426',
        approved_by: 'open',
        contact: 'vypam-vendor-alpha@example.test',
        created_at: '2026-10-14T23:51:35.369015',
        denied_reason: null,
        id: 1,
        invited_by: 'open',
        mfa_verified_at: '2026-10-14T23:51:35.517335',
        name: 'vypam-vendor-alpha.test',
        nda: {
          ref: 'NDA-2026-0043',
          signed_at: '2026-10-14T23:51:35.619454',
        },
        status: 'revoked',
        steps: {
          approval: 'approved',
          mfa: 'verified',
          nda: 'signed',
          ticket: 'verified',
        },
        ticket: 'INC-23892',
        ticket_verification: {
          checked_at: '2026-10-14T23:51:35.736798',
          configured: true,
          detail: 'HTTP 200',
          http_status: 200,
          ticket: 'INC-23892',
          vendor: 'servicenow',
          verified: true,
        },
        ticket_verified_at: '2026-10-14T23:51:35.810096',
      },
      {
        access: {
          allowed: ['10.77.77.0/24'],
          denied: [],
          expires_at: null,
          recording: true,
          window: null,
        },
        approved_at: null,
        approved_by: null,
        contact: 'vypam-vendor-beta@example.test',
        created_at: '2026-10-14T23:51:34.942463',
        denied_reason: 'vypam synthetic capture deny',
        id: 2,
        invited_by: 'open',
        mfa_verified_at: null,
        name: 'vypam-vendor-beta.test',
        nda: {
          ref: null,
          signed_at: null,
        },
        status: 'denied',
        steps: {
          approval: 'denied',
          mfa: 'pending',
          nda: 'pending',
          ticket: 'pending',
        },
        ticket: null,
        ticket_verification: {},
        ticket_verified_at: null,
      },
    ],
  },
};

export const VENDOR_DETAIL_RESPONSE = {
  status: 200,
  body: {
    access: {
      allowed: ['10.99.8.42'],
      denied: [],
      expires_at: null,
      recording: true,
      window: null,
    },
    approved_at: '2026-10-14T23:51:35.919426',
    approved_by: 'open',
    contact: 'vypam-vendor-alpha@example.test',
    created_at: '2026-10-14T23:51:35.369015',
    denied_reason: null,
    events: [
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:51:36.237831',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 45,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-requested',
        actor: 'open',
        created_at: '2026-10-14T23:51:36.151466',
        detail: {
          item_id: 1,
          jit_status: 'approved',
          minutes: 30,
          request_id: 1,
          risk: {
            level: 'low',
            score: 25,
          },
          target: '10.99.8.42',
        },
        id: 44,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.921915',
        detail: {
          allowed: ['10.99.8.42'],
          denied: [],
          recording: true,
          ticket: 'INC-23892',
          window: null,
        },
        id: 43,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.825613',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23892',
        },
        id: 42,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.622467',
        detail: {
          ref: 'NDA-2026-0043',
        },
        id: 41,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.519378',
        detail: {
          method: 'totp',
        },
        id: 40,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.390153',
        detail: {
          allowed: ['10.99.8.42'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: null,
        },
        id: 39,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.272751',
        detail: {
          reason: 'account is revoked',
          target: null,
        },
        id: 38,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.163790',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 37,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.852458',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          reason: "target is not in the vendor's access list",
          target: '10.99.8.42',
        },
        id: 34,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.686704',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          denied: ['10.66.66.9'],
          recording: true,
          ticket: 'INC-23891',
          window: '14:00–16:00',
        },
        id: 33,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.603260',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23891',
        },
        id: 32,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approval-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.273590',
        detail: {
          missing: ['ticket'],
        },
        id: 31,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.184978',
        detail: {
          reason: 'itsm is not configured',
          ticket: 'INC-23891',
        },
        id: 30,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.077906',
        detail: {
          ref: 'NDA-2026-0042',
        },
        id: 29,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.973065',
        detail: {
          method: 'totp',
        },
        id: 28,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verify-failed',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.826804',
        detail: {
          reason: 'invalid or expired TOTP code',
        },
        id: 27,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.716834',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: ['10.66.66.9'],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: '14:00–16:00',
        },
        id: 26,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:37.072627',
        detail: {
          reason: 'account is revoked',
          target: null,
        },
        id: 25,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.962290',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 24,
        subject: 'vypam-vendor-alpha.test',
      },
    ],
    id: 1,
    invited_by: 'open',
    mfa_verified_at: '2026-10-14T23:51:35.517335',
    name: 'vypam-vendor-alpha.test',
    nda: {
      ref: 'NDA-2026-0043',
      signed_at: '2026-10-14T23:51:35.619454',
    },
    request_count: 1,
    requests: [
      {
        agent_binding: null,
        agent_id: null,
        approvals: {
          manager: null,
          security: null,
        },
        closed_at: null,
        cloud_binding: null,
        cloud_connector_id: null,
        created_at: '2026-10-14T23:51:36.035686',
        expires_at: null,
        granted_at: null,
        id: 1,
        item_id: 1,
        minutes: 30,
        minutes_left: null,
        reason: 'vypam synthetic capture request',
        requester: 'vypam-vendor-alpha.test',
        risk: {
          factors: [
            {
              detail: '30 minutes requested',
              factor: 'duration',
              points: 5,
            },
            {
              detail: 'Wednesday 23:51 local',
              factor: 'off_hours',
              points: 20,
            },
          ],
          level: 'low',
          score: 25,
        },
        session_ref: null,
        status: 'approved',
        ticket: 'INC-23892',
        vendor_account_id: 1,
      },
    ],
    status: 'revoked',
    steps: {
      approval: 'approved',
      mfa: 'verified',
      nda: 'signed',
      ticket: 'verified',
    },
    ticket: 'INC-23892',
    ticket_verification: {
      checked_at: '2026-10-14T23:51:35.736798',
      configured: true,
      detail: 'HTTP 200',
      http_status: 200,
      ticket: 'INC-23892',
      vendor: 'servicenow',
      verified: true,
    },
    ticket_verified_at: '2026-10-14T23:51:35.810096',
  },
};

export const VENDOR_DETAIL_APPROVED_RESPONSE = {
  status: 200,
  body: {
    access: {
      allowed: ['10.66.66.0/24', 'db-alpha.internal'],
      denied: ['10.66.66.9'],
      expires_at: null,
      recording: true,
      window: '14:00–16:00',
    },
    approved_at: '2026-10-14T23:51:34.684488',
    approved_by: 'open',
    contact: 'vypam-vendor-alpha@example.test',
    created_at: '2026-10-14T23:51:33.694208',
    denied_reason: null,
    events: [
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.686704',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          denied: ['10.66.66.9'],
          recording: true,
          ticket: 'INC-23891',
          window: '14:00–16:00',
        },
        id: 33,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.603260',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23891',
        },
        id: 32,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approval-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.273590',
        detail: {
          missing: ['ticket'],
        },
        id: 31,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.184978',
        detail: {
          reason: 'itsm is not configured',
          ticket: 'INC-23891',
        },
        id: 30,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.077906',
        detail: {
          ref: 'NDA-2026-0042',
        },
        id: 29,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.973065',
        detail: {
          method: 'totp',
        },
        id: 28,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verify-failed',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.826804',
        detail: {
          reason: 'invalid or expired TOTP code',
        },
        id: 27,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.716834',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: ['10.66.66.9'],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: '14:00–16:00',
        },
        id: 26,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:37.072627',
        detail: {
          reason: 'account is revoked',
          target: null,
        },
        id: 25,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.962290',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 24,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.637695',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          reason: "target is not in the vendor's access list",
          target: '10.99.8.42',
        },
        id: 21,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.451438',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          denied: ['10.66.66.9'],
          recording: true,
          ticket: 'INC-23891',
          window: '14:00–16:00',
        },
        id: 20,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.369123',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23891',
        },
        id: 19,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approval-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.031073',
        detail: {
          missing: ['ticket'],
        },
        id: 18,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.936225',
        detail: {
          reason: 'itsm is not configured',
          ticket: 'INC-23891',
        },
        id: 17,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.783912',
        detail: {
          ref: 'NDA-2026-0042',
        },
        id: 16,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.672645',
        detail: {
          method: 'totp',
        },
        id: 15,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verify-failed',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.536217',
        detail: {
          reason: 'invalid or expired TOTP code',
        },
        id: 14,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.415712',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: ['10.66.66.9'],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: '14:00–16:00',
        },
        id: 13,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'denied',
        actor: 'open',
        created_at: '2026-10-14T23:49:35.170258',
        detail: {
          reason: 'vypam capture cleanup',
        },
        id: 12,
        subject: 'vypam-vendor-alpha.test',
      },
    ],
    id: 1,
    invited_by: 'open',
    mfa_verified_at: '2026-10-14T23:51:33.969978',
    name: 'vypam-vendor-alpha.test',
    nda: {
      ref: 'NDA-2026-0042',
      signed_at: '2026-10-14T23:51:34.073114',
    },
    request_count: 0,
    requests: [],
    status: 'approved',
    steps: {
      approval: 'approved',
      mfa: 'verified',
      nda: 'signed',
      ticket: 'verified',
    },
    ticket: 'INC-23891',
    ticket_verification: {
      checked_at: '2026-10-14T23:51:34.523453',
      configured: true,
      detail: 'HTTP 200',
      http_status: 200,
      ticket: 'INC-23891',
      vendor: 'servicenow',
      verified: true,
    },
    ticket_verified_at: '2026-10-14T23:51:34.589440',
  },
};

export const VENDOR_DETAIL_INVITED_RESPONSE = {
  status: 200,
  body: {
    access: {
      allowed: ['10.66.66.0/24'],
      denied: [],
      expires_at: null,
      recording: true,
      window: null,
    },
    approved_at: null,
    approved_by: null,
    contact: 'vypam-vendor-alpha@example.test',
    created_at: '2026-10-15T00:23:49.877700',
    denied_reason: null,
    events: [
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-15T00:23:49.989741',
        detail: {
          allowed: ['10.66.66.0/24'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: null,
        },
        id: 46,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:51:36.237831',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 45,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-requested',
        actor: 'open',
        created_at: '2026-10-14T23:51:36.151466',
        detail: {
          item_id: 1,
          jit_status: 'approved',
          minutes: 30,
          request_id: 1,
          risk: {
            level: 'low',
            score: 25,
          },
          target: '10.99.8.42',
        },
        id: 44,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.921915',
        detail: {
          allowed: ['10.99.8.42'],
          denied: [],
          recording: true,
          ticket: 'INC-23892',
          window: null,
        },
        id: 43,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.825613',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23892',
        },
        id: 42,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.622467',
        detail: {
          ref: 'NDA-2026-0043',
        },
        id: 41,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.519378',
        detail: {
          method: 'totp',
        },
        id: 40,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.390153',
        detail: {
          allowed: ['10.99.8.42'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: null,
        },
        id: 39,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.272751',
        detail: {
          reason: 'account is revoked',
          target: null,
        },
        id: 38,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'revoked',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.163790',
        detail: {
          grants_ended: [],
          reason: 'vypam synthetic capture revoke',
        },
        id: 37,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.852458',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          reason: "target is not in the vendor's access list",
          target: '10.99.8.42',
        },
        id: 34,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approved',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.686704',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          denied: ['10.66.66.9'],
          recording: true,
          ticket: 'INC-23891',
          window: '14:00–16:00',
        },
        id: 33,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.603260',
        detail: {
          http_status: 200,
          itsm: 'servicenow',
          ticket: 'INC-23891',
        },
        id: 32,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'approval-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.273590',
        detail: {
          missing: ['ticket'],
        },
        id: 31,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'ticket-refused',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.184978',
        detail: {
          reason: 'itsm is not configured',
          ticket: 'INC-23891',
        },
        id: 30,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'nda-signed',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.077906',
        detail: {
          ref: 'NDA-2026-0042',
        },
        id: 29,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verified',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.973065',
        detail: {
          method: 'totp',
        },
        id: 28,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'mfa-verify-failed',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.826804',
        detail: {
          reason: 'invalid or expired TOTP code',
        },
        id: 27,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:33.716834',
        detail: {
          allowed: ['10.66.66.0/24', 'db-alpha.internal'],
          contact: 'vypam-vendor-alpha@example.test',
          denied: ['10.66.66.9'],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: '14:00–16:00',
        },
        id: 26,
        subject: 'vypam-vendor-alpha.test',
      },
      {
        action: 'access-refused',
        actor: 'open',
        created_at: '2026-10-14T23:49:37.072627',
        detail: {
          reason: 'account is revoked',
          target: null,
        },
        id: 25,
        subject: 'vypam-vendor-alpha.test',
      },
    ],
    id: 1,
    invited_by: 'open',
    mfa_verified_at: null,
    name: 'vypam-vendor-alpha.test',
    nda: {
      ref: null,
      signed_at: null,
    },
    request_count: 1,
    requests: [
      {
        agent_binding: null,
        agent_id: null,
        approvals: {
          manager: null,
          security: null,
        },
        closed_at: null,
        cloud_binding: null,
        cloud_connector_id: null,
        created_at: '2026-10-14T23:51:36.035686',
        expires_at: null,
        granted_at: null,
        id: 1,
        item_id: 1,
        minutes: 30,
        minutes_left: null,
        reason: 'vypam synthetic capture request',
        requester: 'vypam-vendor-alpha.test',
        risk: {
          factors: [
            {
              detail: '30 minutes requested',
              factor: 'duration',
              points: 5,
            },
            {
              detail: 'Wednesday 23:51 local',
              factor: 'off_hours',
              points: 20,
            },
          ],
          level: 'low',
          score: 25,
        },
        session_ref: null,
        status: 'approved',
        ticket: 'INC-23892',
        vendor_account_id: 1,
      },
    ],
    status: 'invited',
    steps: {
      approval: 'pending',
      mfa: 'pending',
      nda: 'pending',
      ticket: 'pending',
    },
    ticket: null,
    ticket_verification: {},
    ticket_verified_at: null,
  },
};

export const VENDOR_DETAIL_B_RESPONSE = {
  status: 200,
  body: {
    access: {
      allowed: ['10.77.77.0/24'],
      denied: [],
      expires_at: null,
      recording: true,
      window: null,
    },
    approved_at: null,
    approved_by: null,
    contact: 'vypam-vendor-beta@example.test',
    created_at: '2026-10-14T23:51:34.942463',
    denied_reason: 'vypam synthetic capture deny',
    events: [
      {
        action: 'denied',
        actor: 'open',
        created_at: '2026-10-14T23:51:35.054415',
        detail: {
          reason: 'vypam synthetic capture deny',
        },
        id: 36,
        subject: 'vypam-vendor-beta.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:51:34.961400',
        detail: {
          allowed: ['10.77.77.0/24'],
          contact: 'vypam-vendor-beta@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: null,
        },
        id: 35,
        subject: 'vypam-vendor-beta.test',
      },
      {
        action: 'denied',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.854031',
        detail: {
          reason: 'vypam synthetic capture deny',
        },
        id: 23,
        subject: 'vypam-vendor-beta.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:49:36.760890',
        detail: {
          allowed: ['10.77.77.0/24'],
          contact: 'vypam-vendor-beta@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          reinvited: true,
          window: null,
        },
        id: 22,
        subject: 'vypam-vendor-beta.test',
      },
      {
        action: 'denied',
        actor: 'open',
        created_at: '2026-10-14T23:47:15.903469',
        detail: {
          reason: 'vypam synthetic capture deny',
        },
        id: 11,
        subject: 'vypam-vendor-beta.test',
      },
      {
        action: 'invited',
        actor: 'open',
        created_at: '2026-10-14T23:47:15.779390',
        detail: {
          allowed: ['10.77.77.0/24'],
          contact: 'vypam-vendor-beta@example.test',
          denied: [],
          expires_at: null,
          recording: true,
          window: null,
        },
        id: 10,
        subject: 'vypam-vendor-beta.test',
      },
    ],
    id: 2,
    invited_by: 'open',
    mfa_verified_at: null,
    name: 'vypam-vendor-beta.test',
    nda: {
      ref: null,
      signed_at: null,
    },
    request_count: 0,
    requests: [],
    status: 'denied',
    steps: {
      approval: 'denied',
      mfa: 'pending',
      nda: 'pending',
      ticket: 'pending',
    },
    ticket: null,
    ticket_verification: {},
    ticket_verified_at: null,
  },
};

export const INVITE_RESPONSE = {
  status: 200,
  body: {
    message: 'Vendor vypam-vendor-alpha.test invited - MFA secret shown once',
    mfa: {
      algorithm: 'SHA1',
      digits: 6,
      note: 'shown once, at invite - it never appears again',
      otpauth_uri:
        'otpauth://totp/VY-PAM%3Avypam-vendor-alpha.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=VY-PAM&algorithm=SHA1&digits=6&period=30',
      period: 30,
      secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
    },
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: null,
      approved_by: null,
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: null,
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: null,
        signed_at: null,
      },
      status: 'invited',
      steps: {
        approval: 'pending',
        mfa: 'pending',
        nda: 'pending',
        ticket: 'pending',
      },
      ticket: null,
      ticket_verification: {},
      ticket_verified_at: null,
    },
  },
};

export const MFA_OK_RESPONSE = {
  status: 200,
  body: {
    message: 'MFA verified for vypam-vendor-alpha.test',
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: null,
      approved_by: null,
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: '2026-10-14T23:51:33.969978',
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: null,
        signed_at: null,
      },
      status: 'invited',
      steps: {
        approval: 'pending',
        mfa: 'verified',
        nda: 'pending',
        ticket: 'pending',
      },
      ticket: null,
      ticket_verification: {},
      ticket_verified_at: null,
    },
  },
};

export const NDA_RESPONSE = {
  status: 200,
  body: {
    message: 'NDA signed for vypam-vendor-alpha.test (NDA-2026-0042)',
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: null,
      approved_by: null,
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: '2026-10-14T23:51:33.969978',
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: 'NDA-2026-0042',
        signed_at: '2026-10-14T23:51:34.073114',
      },
      status: 'invited',
      steps: {
        approval: 'pending',
        mfa: 'verified',
        nda: 'signed',
        ticket: 'pending',
      },
      ticket: null,
      ticket_verification: {},
      ticket_verified_at: null,
    },
  },
};

export const TICKET_OK_RESPONSE = {
  status: 200,
  body: {
    message: 'Ticket INC-23891 verified against ITSM',
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: null,
      approved_by: null,
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: '2026-10-14T23:51:33.969978',
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: 'NDA-2026-0042',
        signed_at: '2026-10-14T23:51:34.073114',
      },
      status: 'invited',
      steps: {
        approval: 'pending',
        mfa: 'verified',
        nda: 'signed',
        ticket: 'verified',
      },
      ticket: 'INC-23891',
      ticket_verification: {
        checked_at: '2026-10-14T23:51:34.523453',
        configured: true,
        detail: 'HTTP 200',
        http_status: 200,
        ticket: 'INC-23891',
        vendor: 'servicenow',
        verified: true,
      },
      ticket_verified_at: '2026-10-14T23:51:34.589440',
    },
  },
};

export const VENDOR_APPROVE_RESPONSE = {
  status: 200,
  body: {
    message: 'Vendor vypam-vendor-alpha.test approved - access enabled inside its scope',
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: '2026-10-14T23:51:34.684488',
      approved_by: 'open',
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: '2026-10-14T23:51:33.969978',
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: 'NDA-2026-0042',
        signed_at: '2026-10-14T23:51:34.073114',
      },
      status: 'approved',
      steps: {
        approval: 'approved',
        mfa: 'verified',
        nda: 'signed',
        ticket: 'verified',
      },
      ticket: 'INC-23891',
      ticket_verification: {
        checked_at: '2026-10-14T23:51:34.523453',
        configured: true,
        detail: 'HTTP 200',
        http_status: 200,
        ticket: 'INC-23891',
        vendor: 'servicenow',
        verified: true,
      },
      ticket_verified_at: '2026-10-14T23:51:34.589440',
    },
  },
};

export const VENDOR_DENY_RESPONSE = {
  status: 200,
  body: {
    message: 'Vendor vypam-vendor-beta.test denied',
    vendor: {
      access: {
        allowed: ['10.77.77.0/24'],
        denied: [],
        expires_at: null,
        recording: true,
        window: null,
      },
      approved_at: null,
      approved_by: null,
      contact: 'vypam-vendor-beta@example.test',
      created_at: '2026-10-14T23:51:34.942463',
      denied_reason: 'vypam synthetic capture deny',
      id: 2,
      invited_by: 'open',
      mfa_verified_at: null,
      name: 'vypam-vendor-beta.test',
      nda: {
        ref: null,
        signed_at: null,
      },
      status: 'denied',
      steps: {
        approval: 'denied',
        mfa: 'pending',
        nda: 'pending',
        ticket: 'pending',
      },
      ticket: null,
      ticket_verification: {},
      ticket_verified_at: null,
    },
  },
};

export const REVOKE_RESPONSE = {
  status: 200,
  body: {
    grants_ended: [],
    message: 'Vendor vypam-vendor-alpha.test revoked',
    vendor: {
      access: {
        allowed: ['10.66.66.0/24', 'db-alpha.internal'],
        denied: ['10.66.66.9'],
        expires_at: null,
        recording: true,
        window: '14:00–16:00',
      },
      approved_at: '2026-10-14T23:51:34.684488',
      approved_by: 'open',
      contact: 'vypam-vendor-alpha@example.test',
      created_at: '2026-10-14T23:51:33.694208',
      denied_reason: null,
      id: 1,
      invited_by: 'open',
      mfa_verified_at: '2026-10-14T23:51:33.969978',
      name: 'vypam-vendor-alpha.test',
      nda: {
        ref: 'NDA-2026-0042',
        signed_at: '2026-10-14T23:51:34.073114',
      },
      status: 'revoked',
      steps: {
        approval: 'approved',
        mfa: 'verified',
        nda: 'signed',
        ticket: 'verified',
      },
      ticket: 'INC-23891',
      ticket_verification: {
        checked_at: '2026-10-14T23:51:34.523453',
        configured: true,
        detail: 'HTTP 200',
        http_status: 200,
        ticket: 'INC-23891',
        vendor: 'servicenow',
        verified: true,
      },
      ticket_verified_at: '2026-10-14T23:51:34.589440',
    },
  },
};

export const REQUEST_FILED_RESPONSE = {
  status: 200,
  body: {
    message: 'Access request #1 filed for this vendor (risk: low, status: approved)',
    request: {
      agent_binding: null,
      agent_id: null,
      approvals: {
        manager: null,
        security: null,
      },
      closed_at: null,
      cloud_binding: null,
      cloud_connector_id: null,
      created_at: '2026-10-14T23:51:36.035686',
      expires_at: null,
      granted_at: null,
      id: 1,
      item_id: 1,
      minutes: 30,
      minutes_left: null,
      reason: 'vypam synthetic capture request',
      requester: 'vypam-vendor-alpha.test',
      risk: {
        factors: [
          {
            detail: '30 minutes requested',
            factor: 'duration',
            points: 5,
          },
          {
            detail: 'Wednesday 23:51 local',
            factor: 'off_hours',
            points: 20,
          },
        ],
        level: 'low',
        score: 25,
      },
      session_ref: null,
      status: 'approved',
      ticket: 'INC-23892',
      vendor_account_id: 1,
    },
  },
};
export const INVITE_CONFLICT_RESPONSE = {
  status: 409,
  body: {
    details: {
      field: 'name',
      status: 'invited',
      vendor_id: 1,
    },
    error: 'A vendor with this name already exists',
  },
};
export const MFA_WRONG_RESPONSE = {
  status: 401,
  body: {
    details: {
      field: 'mfa_code',
      mfa: 'invalid or expired TOTP code',
    },
    error: 'TOTP code is invalid or expired',
  },
};
export const TICKET_UNCONFIGURED_RESPONSE = {
  status: 409,
  body: {
    details: {
      configured: false,
      detail: 'itsm is not configured',
      field: 'itsm',
    },
    error: 'itsm is not configured',
  },
};
export const APPROVE_MISSING_RESPONSE = {
  status: 409,
  body: {
    details: {
      field: 'steps',
      missing: ['ticket'],
    },
    error: 'Every lifecycle step must be complete before approval',
  },
};
export const REQUEST_REFUSED_RESPONSE = {
  status: 403,
  body: {
    details: {
      vendor: {
        name: 'vypam-vendor-alpha.test',
        reason: 'account is revoked',
        status: 'revoked',
      },
    },
    error: 'Vendor access refused',
  },
};

/** SYNTHETIC (labelled): schema-valid empty vendor list. */
export const VENDORS_EMPTY_RESPONSE = {
  status: 200,
  body: {
    vendors: [],
    total: 0,
    limit: 200,
    offset: 0,
  },
};

/** The ids/messages/lines the screen tests lean on (from the captures above). */
export const VENDOR_FACTS = {
  vendorAId: 1,
  vendorAName: 'vypam-vendor-alpha.test',
  vendorBId: 2,
  vendorBName: 'vypam-vendor-beta.test',
  listTotal: 2,
  detailEvents: 20,
  detailRequests: 1,
  inviteMessage: 'Vendor vypam-vendor-alpha.test invited - MFA secret shown once',
  mfaMessage: 'MFA verified for vypam-vendor-alpha.test',
  ndaMessage: 'NDA signed for vypam-vendor-alpha.test (NDA-2026-0042)',
  ticketMessage: 'Ticket INC-23891 verified against ITSM',
  approveMessage:
    'Vendor vypam-vendor-alpha.test approved - access enabled inside its scope',
  denyMessage: 'Vendor vypam-vendor-beta.test denied',
  revokeMessage: 'Vendor vypam-vendor-alpha.test revoked',
  requestMessage: 'Access request #1 filed for this vendor (risk: low, status: approved)',
  requestId: 1,
  requestRisk: 'low',
  deniedReason: 'vypam synthetic capture deny',
  ticketRef: 'INC-23892',
  ticketDetail: 'HTTP 200',
  seedNote: 'shown once, at invite - it never appears again',
  seedOtpauthPrefix: 'otpauth://totp/',
  allowedFirst: '10.99.8.42',
  windowPhase2: null,
  itsmUnconfigured: 'not connected - set itsm.base_url',
};
