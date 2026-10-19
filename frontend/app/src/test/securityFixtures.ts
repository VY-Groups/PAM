/**
 * ADR-0017 (batch 11.8) test fixtures - VERBATIM rig captures from the
 * throwaway container `vypam-capture-118` (image `vypam-rig:11.6`,
 * ephemeral DB, never a standing rig) on 2026-10-19, taken with
 * `Temp/capture118.py` + `Temp/capture118b.py` + `Temp/capture118c.py` +
 * `Temp/capture118d.py` (scratch, never staged); raw output in
 * `Temp/capture118.json`:
 *
 * - POST /auth/login 403 `password-change-required` (admin reset first),
 *   then POST /auth/password: the wrong-old 401, the NIST 400 refusal and
 *   the success answer (`Password changed`).
 * - POST /auth/otp/start purpose=login - the identical generic 202 for an
 *   existing user AND for `nobody.here` (no enumeration, captured both
 *   ways); a wrong code at login - the verbatim 401.
 * - The whole /auth/mfa surface with a real console session: factors list
 *   (replay counter + last use), backup codes (shown once), the real
 *   step-up 403 after the window went stale (`auth.stepup_ttl_minutes`
 *   was set to the contract minimum 1 to force it) and the 200 refresh,
 *   TOTP enrol -> wrong first code -> verified, e-mail enrol start, the
 *   no-address 400, the e-mail verify 401, last-factor delete refusal and
 *   the no-session 401.
 *
 * The ONLY substitutions (house rule, `SECRET_REVEAL_BODY` precedent):
 * rig-generated secrets never enter the repo - clearly synthetic stand-ins
 * keep every other byte verbatim:
 * - TOTP `secret` (+ the `otpauth_uri` that embeds it) -> clearly
 *   synthetic, same key-value shape;
 * - the 10 one-time backup codes -> obviously synthetic repeated groups
 *   (a rig's real codes are live sign-in credentials).
 * Three documented derivations (arms no rig can observe):
 * - `MFA_FACTORS_EMPTY_RESPONSE`: the captured list shape with zero rows;
 * - `ENROLL_EMAIL_VERIFY_OK_RESPONSE`: source-verified at
 *   `routes.py:3290` (`{status, kind}`) - rigs have no SMTP, so no real
 *   enrolment code ever arrives and the success arm is unobservable live
 *   (backend-tested);
 * - `DELETE_FACTOR_OK_RESPONSE`: source-verified at `routes.py:3334` +
 *   `mfa.py:248` (`{factor: {deleted, factor_id}, message}`) - the rig
 *   could only answer the fail-closed last-factor 403 (captured above),
 *   never a success (backend-tested).
 */

/** The captured 403 that forces the change-password card before sign-in. */
export const PASSWORD_CHANGE_REQUIRED_RESPONSE = {
  status: 403,
  body: {
    details: {
      reason: 'password-change-required',
    },
    error:
      'Password must be changed before signing in (POST /api/v1/auth/password with the current password)',
  },
};

/** `POST /api/v1/auth/password` with a wrong current password - verbatim 401. */
export const PASSWORD_CHANGE_WRONG_OLD_RESPONSE = {
  status: 401,
  body: {
    error: 'Current password is incorrect',
  },
};

/** `POST /api/v1/auth/password` below the captured policy - verbatim 400. */
export const PASSWORD_CHANGE_WEAK_RESPONSE = {
  status: 400,
  body: {
    details: {
      field: 'password',
      min_length: 14,
    },
    error: 'Password must be at least 14 characters (NIST: length over complexity)',
  },
};

/** `POST /api/v1/auth/password` success - verbatim (`Password changed`). */
export const PASSWORD_CHANGE_OK_RESPONSE = {
  status: 200,
  body: {
    message: 'Password changed',
    sessions_revoked: 0,
    user: {
      created_at: '2026-10-18T23:57:30.755554',
      created_by: 'admin',
      display_name: 'Password Change',
      email: 'pw.change@example.com',
      failed_logins: 0,
      has_password: true,
      id: 3,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: false,
      password_changed_at: '2026-10-18T23:57:31.268977',
      source: 'local',
      username: 'pw.change',
    },
  },
};

/** `POST /api/v1/auth/otp/start` purpose=login - verbatim generic 202. */
export const OTP_START_LOGIN_RESPONSE = {
  status: 202,
  body: {
    challenge_id: '237aa7357d14dc633f29c118a807d52d',
    status: 'sent',
  },
};

/**
 * The SAME call for `nobody.here` - verbatim 202 with the identical shape
 * (only the random id differs): the anti-enumeration proof pair.
 */
export const OTP_START_UNKNOWN_RESPONSE = {
  status: 202,
  body: {
    challenge_id: 'c863409990b7f1e73338dac74ece8285',
    status: 'sent',
  },
};

/**
 * A wrong MFA assertion - verbatim 401, captured THREE times with
 * identical bytes (login with a bad e-mail OTP, login with a bad TOTP
 * code, step-up with a bad code).
 */
export const MFA_ASSERTION_FAILED_RESPONSE = {
  status: 401,
  body: {
    error: 'MFA assertion failed',
  },
};

/** `GET /api/v1/auth/mfa/factors` - verbatim (replay counter, last use). */
export const MFA_FACTORS_RESPONSE = {
  status: 200,
  body: {
    factors: [
      {
        active: true,
        created_at: '2026-10-18T23:55:41.652280',
        id: 1,
        kind: 'totp',
        last_step: 59745602,
        last_used_at: '2026-10-19T00:01:00.540025',
        name: 'Authenticator app',
        user_id: 2,
      },
    ],
  },
};

/**
 * The same captured list shape with zero rows (derivation, see header):
 * the rig always had the enrolled TOTP factor (fail-closed kept it alive),
 * so an empty list was never observable there.
 */
export const MFA_FACTORS_EMPTY_RESPONSE = {
  status: 200,
  body: {
    factors: [],
  },
};

/** `GET /api/v1/auth/mfa/factors` without a console session - verbatim 401. */
export const MFA_FACTORS_NO_SESSION_RESPONSE = {
  status: 401,
  body: {
    error: 'Console session required',
  },
};

/**
 * `POST /api/v1/auth/mfa/backup-codes` - verbatim; the 10 one-time codes
 * are the documented synthetic substitution (see header), `count` and the
 * server's own `message` are the capture.
 */
export const BACKUP_CODES_RESPONSE = {
  status: 200,
  body: {
    codes: [
      '0001-0001-0001-0001',
      '0002-0002-0002-0002',
      '0003-0003-0003-0003',
      '0004-0004-0004-0004',
      '0005-0005-0005-0005',
      '0006-0006-0006-0006',
      '0007-0007-0007-0007',
      '0008-0008-0008-0008',
      '0009-0009-0009-0009',
      '0010-0010-0010-0010',
    ],
    count: 10,
    message: 'Shown once - store them now; they cannot be recovered.',
  },
};

/**
 * `POST /api/v1/auth/mfa/backup-codes` after the step-up window went
 * stale - verbatim 403. The captured text interpolates the rig's
 * `auth.stepup_ttl_minutes`, which was set to the contract minimum (1) to
 * force this arm; the default policy says "within 5 min".
 */
export const STEPUP_REQUIRED_RESPONSE = {
  status: 403,
  body: {
    details: {
      reason: 'stepup_required',
    },
    error:
      'Step-up MFA required for this action (POST /api/v1/auth/mfa/stepup within 1 min)',
  },
};

/** `POST /api/v1/auth/mfa/stepup` with a live TOTP code - verbatim 200. */
export const STEPUP_OK_RESPONSE = {
  status: 200,
  body: {
    method: 'totp',
    mfa_at: '2026-10-19T00:00:30.539916',
    status: 'verified',
  },
};

/**
 * `POST /api/v1/auth/mfa/enroll/totp` (console-session arm) - verbatim;
 * `secret` and the `otpauth_uri` that embeds it are the documented
 * synthetic substitution (see header).
 */
export const ENROLL_TOTP_RESPONSE = {
  status: 201,
  body: {
    factor: {
      active: true,
      created_at: '2026-10-18T23:55:41.652280',
      id: 1,
      kind: 'totp',
      last_step: 0,
      last_used_at: null,
      name: 'Authenticator app',
      user_id: 2,
    },
    otpauth_uri:
      'otpauth://totp/VY-PAM%3Asec.user?secret=fixture-TotpSecret-0000&issuer=VY-PAM&algorithm=SHA1&digits=6&period=30',
    secret: 'fixture-TotpSecret-0000',
    shown_once: true,
  },
};

/** `POST /api/v1/auth/mfa/enroll/totp/verify` wrong first code - verbatim 401. */
export const ENROLL_TOTP_VERIFY_WRONG_RESPONSE = {
  status: 401,
  body: {
    error: 'TOTP code invalid',
  },
};

/** `POST /api/v1/auth/mfa/enroll/totp/verify` with a live code - verbatim 200. */
export const ENROLL_TOTP_VERIFY_OK_RESPONSE = {
  status: 200,
  body: {
    method: 'totp',
    status: 'verified',
  },
};

/** `POST /api/v1/auth/mfa/enroll/email` (console-session arm) - verbatim 202. */
export const ENROLL_EMAIL_RESPONSE = {
  status: 202,
  body: {
    challenge_id: '6ef05d9c4d5f8c4a1bd7d1190541b760',
    status: 'sent',
  },
};

/** `POST /api/v1/auth/mfa/enroll/email/verify` wrong code - verbatim 401. */
export const ENROLL_EMAIL_VERIFY_BAD_RESPONSE = {
  status: 401,
  body: {
    error: 'One-time code invalid or expired',
  },
};

/**
 * `POST /api/v1/auth/mfa/enroll/email/verify` success - contract shape,
 * NOT a rig capture (see header): rigs have no SMTP, so no real enrolment
 * code ever arrives and the arm is unobservable on a live rig. Source
 * verified at `routes.py:3290` (`{status: "enrolled", kind: "email"}`).
 */
export const ENROLL_EMAIL_VERIFY_OK_RESPONSE = {
  status: 200,
  body: {
    status: 'enrolled',
    kind: 'email',
  },
};

/** `POST /api/v1/auth/mfa/enroll/email` for an addressless user - verbatim 400. */
export const ENROLL_EMAIL_NO_ADDRESS_RESPONSE = {
  status: 400,
  body: {
    error:
      'This account has no e-mail address - an admin sets it first (PATCH /api/v1/users/{user_id})',
  },
};

/** `POST /api/v1/auth/mfa/enroll/radius` with no RADIUS group - verbatim 503. */
export const ENROLL_RADIUS_UNCONFIGURED_RESPONSE = {
  status: 503,
  body: {
    details: {
      configured: false,
    },
    error:
      'RADIUS is not configured - set host, port and the shared secret in the `radius` settings group and enable it first',
  },
};

/**
 * `POST /api/v1/auth/mfa/enroll/radius` on a configured deployment -
 * contract shape, NOT a rig capture (see header): rigs run without a
 * RADIUS server, so only the honest 503 above was observable. Source
 * verified at `routes.py:3301` (`{factor}`) + `radius_client.py:217`
 * (the factor row dict; backend-tested).
 */
export const ENROLL_RADIUS_OK_RESPONSE = {
  status: 201,
  body: {
    factor: {
      active: true,
      created_at: '2026-10-19T00:20:00.000000',
      id: 2,
      kind: 'radius',
      last_step: 0,
      last_used_at: null,
      name: 'RADIUS push/OTP',
      user_id: 2,
    },
  },
};

/** `DELETE /api/v1/auth/mfa/factors/{id}` last factor - verbatim 403. */
export const DELETE_LAST_FACTOR_RESPONSE = {
  status: 403,
  body: {
    details: {
      mfa_required: true,
    },
    error:
      "This is the user's last factor and mfa_required is on - request a two-admin recovery instead (POST /api/v1/auth/factor-recovery/request)",
  },
};

/**
 * `DELETE /api/v1/auth/mfa/factors/{id}` success - contract shape, NOT a
 * rig capture (see header): the rig's only factor was the fail-closed
 * last one, which refuses. Source verified at `routes.py:3334` +
 * `mfa.py:248` (`{factor: {deleted, factor_id}, message: "Factor removed"}`).
 */
export const DELETE_FACTOR_OK_RESPONSE = {
  status: 200,
  body: {
    factor: {
      deleted: true,
      factor_id: 1,
    },
    message: 'Factor removed',
  },
};
