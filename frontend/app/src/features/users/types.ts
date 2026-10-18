/**
 * Users & Credentials domain types (ADR-0016 batch 11.7).
 *
 * Every field below is byte-shaped by the verbatim rig capture
 * `Temp/capture116.json` (throwaway container `vypam-capture-116`, image
 * `vypam-rig:11.5`, ephemeral DB - 2026-10-19). The generated client types
 * these response bodies as `{ [key: string]: unknown }` (the OpenAPI
 * schemas carry no per-field properties), so the capture is the contract
 * the screen and its tests render against.
 */

/** One `GET /api/v1/users` row (captured verbatim). */
export interface ConsoleUser {
  created_at: string;
  created_by: string;
  display_name: string;
  email: string;
  failed_logins: number;
  has_password: boolean;
  id: number;
  is_active: boolean;
  is_emergency: boolean;
  last_login_at: string | null;
  locked_until: string | null;
  lockout_streak: number;
  must_change_password: boolean;
  password_changed_at: string | null;
  source: string;
  username: string;
}

/** `GET /api/v1/users` answer. */
export interface UsersListBody {
  users?: ConsoleUser[];
}

/**
 * The create / patch / unlock / password-reset answers (captured):
 * `{message, user}` plus `generated_password` + `password_notice` when a
 * password was generated (create without a password, admin reset). The
 * password-reset capture also echoes `generated_password` inside `user`.
 */
export interface UserWriteBody {
  message: string;
  user: ConsoleUser & { generated_password?: string };
  generated_password?: string;
  password_notice?: string;
}

/** `DELETE /api/v1/users/{id}/sessions` answer (captured). */
export interface RevokeSessionsBody {
  message: string;
  revoked: number;
}
