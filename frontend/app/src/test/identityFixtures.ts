/**
 * ADR-0016 (batches 11.6 + 11.7) test fixtures - VERBATIM rig captures from
 * the throwaway container `vypam-capture-116` (image `vypam-rig:11.5`,
 * ephemeral DB, never a standing rig) on 2026-10-19, taken with
 * `Temp/capture116.py` + `Temp/capture_lock.py` (scratch, never staged);
 * raw output in `Temp/capture116.json` + `Temp/capture_lock.json`:
 *
 * - POST /api/v1/users - created without a password (generated, shown once)
 *   and with a given password; 409 duplicate and the 400 NIST length refusal.
 * - GET /api/v1/users - the three seeded rows (local ops.user, the sealed
 *   emergency row, the audit reader), ordered by username as the server does.
 * - PATCH /users/{id} activate/deactivate, POST unlock (a REAL lockout after
 *   5 failed logins - `Temp/capture_lock.json`), admin password-reset,
 *   GET/DELETE sessions, the 401 admin-token refusal.
 * - POST /auth/recovery/start - the identical generic 202 for an existing
 *   user AND for `nobody.here` (no enumeration, captured both ways).
 * - POST /auth/recovery/reset with a wrong code - the verbatim 401.
 *
 * The ONLY substitutions (house rule, `SECRET_REVEAL_BODY` precedent): the
 * server-generated passwords never enter the repo - clearly synthetic
 * stand-ins keep every other byte verbatim. Two documented derivations:
 * `USER_LOCKED_ROW` shifts the captured `locked_until` into the future (the
 * real value is already past at test time; every other field is the
 * captured lockout row) and `RECOVERY_RESET_OK_RESPONSE` is a source- and
 * backend-test-verified contract shape - the success arm cannot be captured
 * because the rigs have no SMTP, so no code ever arrives (`otp.py`
 * `_send_or_suppress`; shape at `routes.py:3198-3204`, asserted by
 * `tests/test_otp.py`).
 */

/** `GET /api/v1/users` - the seeded registry, ordered by username (verbatim). */
export const USERS_LIST_RESPONSE = {
  status: 200,
  body: {
    users: [
      {
        created_at: '2026-10-18T18:59:47.631419',
        created_by: 'admin',
        display_name: 'Audit Reader',
        email: 'audit.reader@example.com',
        failed_logins: 0,
        has_password: true,
        id: 3,
        is_active: true,
        is_emergency: false,
        last_login_at: null,
        locked_until: null,
        lockout_streak: 0,
        must_change_password: false,
        password_changed_at: '2026-10-18T18:59:47.630757',
        source: 'local',
        username: 'audit.readonly',
      },
      {
        created_at: '2026-10-18T18:59:17.038868',
        created_by: 'system',
        display_name: 'Emergency administrator (offline)',
        email: '',
        failed_logins: 0,
        has_password: true,
        id: 1,
        is_active: true,
        is_emergency: true,
        last_login_at: null,
        locked_until: null,
        lockout_streak: 0,
        must_change_password: false,
        password_changed_at: null,
        source: 'emergency',
        username: 'emergency-admin',
      },
      {
        created_at: '2026-10-18T18:59:47.509998',
        created_by: 'admin',
        display_name: 'Ops User',
        email: 'ops.user@example.com',
        failed_logins: 0,
        has_password: true,
        id: 2,
        is_active: true,
        is_emergency: false,
        last_login_at: null,
        locked_until: null,
        lockout_streak: 0,
        must_change_password: true,
        password_changed_at: null,
        source: 'local',
        username: 'ops.user',
      },
    ],
  },
};

/**
 * The REAL lockout row from `Temp/capture_lock.json` (5 failed logins ->
 * `locked_until` set, `lockout_streak: 1`, counters reset) with only
 * `locked_until` shifted to a future instant - the captured value is real
 * but already past when tests run, and the client derivation is
 * `locked_until > now`. Every other byte is the capture.
 */
export const USER_LOCKED_ROW = {
  created_at: '2026-10-18T18:59:47.509998',
  created_by: 'admin',
  display_name: 'Ops User',
  email: 'ops.user@example.com',
  failed_logins: 0,
  has_password: true,
  id: 2,
  is_active: true,
  is_emergency: false,
  last_login_at: null,
  locked_until: '2099-01-01T00:00:00.000000',
  lockout_streak: 1,
  must_change_password: true,
  password_changed_at: '2026-10-18T18:59:47.848070',
  source: 'local',
  username: 'ops.user',
};

/** `POST /api/v1/users` without a password - generated, shown once (verbatim). */
export const USERS_CREATE_GENERATED_RESPONSE = {
  status: 201,
  body: {
    generated_password: 'fixture-GeneratedOnce-0000',
    message: 'User created',
    password_notice: 'Shown once - the user must change it at first sign-in.',
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      has_password: true,
      id: 2,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: null,
      source: 'local',
      username: 'ops.user',
    },
  },
};

/** `POST /api/v1/users` with a given password - no generated secret (verbatim). */
export const USERS_CREATE_WITH_PASSWORD_RESPONSE = {
  status: 201,
  body: {
    message: 'User created',
    user: {
      created_at: '2026-10-18T18:59:47.631419',
      created_by: 'admin',
      display_name: 'Audit Reader',
      email: 'audit.reader@example.com',
      failed_logins: 0,
      has_password: true,
      id: 3,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: false,
      password_changed_at: '2026-10-18T18:59:47.630757',
      source: 'local',
      username: 'audit.readonly',
    },
  },
};

/** `POST /api/v1/users` duplicate - verbatim 409. */
export const USERS_CREATE_CONFLICT_RESPONSE = {
  status: 409,
  body: {
    error: "User 'ops.user' already exists",
  },
};

/** `POST /api/v1/users` weak password - verbatim 400 (the captured policy). */
export const USERS_CREATE_WEAK_RESPONSE = {
  status: 400,
  body: {
    details: {
      field: 'password',
      min_length: 14,
    },
    error: 'Password must be at least 14 characters (NIST: length over complexity)',
  },
};

/** `PATCH /api/v1/users/{id}` `{active:false}` - verbatim (sessions die). */
export const USER_PATCH_DEACTIVATE_RESPONSE = {
  status: 200,
  body: {
    message: 'User updated',
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      has_password: true,
      id: 2,
      is_active: false,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: null,
      source: 'local',
      username: 'ops.user',
    },
  },
};

/** `PATCH /api/v1/users/{id}` `{active:true}` - verbatim. */
export const USER_PATCH_ACTIVATE_RESPONSE = {
  status: 200,
  body: {
    message: 'User updated',
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      has_password: true,
      id: 2,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: null,
      source: 'local',
      username: 'ops.user',
    },
  },
};

/** `POST /api/v1/users/{id}/unlock` - verbatim. */
export const USER_UNLOCK_RESPONSE = {
  status: 200,
  body: {
    message: 'User unlocked',
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      has_password: true,
      id: 2,
      is_active: false,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: null,
      source: 'local',
      username: 'ops.user',
    },
  },
};

/** `POST /api/v1/users/{id}/password-reset` - verbatim (password substituted). */
export const USER_PASSWORD_RESET_RESPONSE = {
  status: 200,
  body: {
    generated_password: 'fixture-ResetOnce-0000',
    message: 'Password reset - every session revoked',
    password_notice: 'Shown once - store it now.',
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      generated_password: 'fixture-ResetOnce-0000',
      has_password: true,
      id: 2,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: '2026-10-18T18:59:47.848070',
      source: 'local',
      username: 'ops.user',
    },
  },
};

/** `DELETE /api/v1/users/{id}/sessions` - verbatim (fresh rig: none open). */
export const USER_REVOKE_SESSIONS_RESPONSE = {
  status: 200,
  body: {
    message: '0 session(s) revoked',
    revoked: 0,
  },
};

/** `GET /api/v1/users` without the admin token - verbatim 401. */
export const USERS_LIST_UNAUTHORIZED_RESPONSE = {
  status: 401,
  body: {
    error: 'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
  },
};

/** `POST /api/v1/auth/recovery/start` - verbatim generic 202 (existing user). */
export const RECOVERY_START_RESPONSE = {
  status: 202,
  body: {
    challenge_id: '4c27cc0058a3ec853ace76153ef03e5b',
    status: 'sent',
  },
};

/**
 * The SAME call for `nobody.here` - verbatim 202 with the identical shape
 * (only the random id differs): the anti-enumeration proof pair.
 */
export const RECOVERY_START_UNKNOWN_RESPONSE = {
  status: 202,
  body: {
    challenge_id: 'ccc08f44977d570352935df9a0c9fc4d',
    status: 'sent',
  },
};

/** `POST /api/v1/auth/recovery/reset` wrong code - verbatim 401. */
export const RECOVERY_RESET_REFUSED_RESPONSE = {
  status: 401,
  body: {
    error: 'One-time code invalid or expired',
  },
};

/**
 * `POST /api/v1/auth/recovery/reset` success - contract shape, NOT a rig
 * capture: rigs have no SMTP, so a real code can never arrive and the arm
 * is unobservable on a live rig. Shape source-verified at
 * `routes.py:3198-3204` (`{user, sessions_revoked, message}`) and
 * backend-tested (`tests/test_otp.py`); the user row is the captured
 * `GET /users` row - a real reset would move `password_changed_at`.
 */
export const RECOVERY_RESET_OK_RESPONSE = {
  status: 200,
  body: {
    user: {
      created_at: '2026-10-18T18:59:47.509998',
      created_by: 'admin',
      display_name: 'Ops User',
      email: 'ops.user@example.com',
      failed_logins: 0,
      has_password: true,
      id: 2,
      is_active: true,
      is_emergency: false,
      last_login_at: null,
      locked_until: null,
      lockout_streak: 0,
      must_change_password: true,
      password_changed_at: null,
      source: 'local',
      username: 'ops.user',
    },
    sessions_revoked: 0,
    message: 'Password reset - sign in again',
  },
};
