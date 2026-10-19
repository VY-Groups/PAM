/**
 * Security & MFA result shapes (ADR-0017 batch 11.8). Every field mirrors
 * a captured rig answer (`test/securityFixtures.ts`) or the source-verified
 * success arms - the page renders them verbatim and never invents fields.
 */

/** One row of `GET /auth/mfa/factors` (captured: kind, label, replay state). */
export interface MfaFactorRow {
  id: number;
  kind: string;
  name: string;
  active: boolean;
  last_step: number;
  last_used_at: string | null;
  created_at: string;
  user_id: number;
}

/** `GET /auth/mfa/factors` body (captured). */
export interface FactorsBody {
  factors: MfaFactorRow[];
}

/** `POST /auth/mfa/enroll/totp` body (captured; secret shown once). */
export interface EnrollTotpBody {
  factor: MfaFactorRow;
  otpauth_uri: string;
  secret: string;
  shown_once: boolean;
}

/** `POST /auth/mfa/enroll/totp/verify` body (captured `{status, method}`). */
export interface TotpVerifyBody {
  status: string;
  method: string;
}

/** `POST /auth/mfa/backup-codes` body (captured; codes shown once). */
export interface BackupCodesBody {
  codes: string[];
  count: number;
  message: string;
}

/** `POST /auth/mfa/enroll/email` body (captured generic 202). */
export interface EnrollEmailBody {
  status: string;
  challenge_id: string;
}

/** `POST /auth/mfa/enroll/email/verify` body (source-verified routes.py:3290). */
export interface EmailVerifyBody {
  status: string;
  kind: string;
}

/** `DELETE /auth/mfa/factors/{id}` body (source-verified routes.py:3334). */
export interface DeleteFactorBody {
  factor: { deleted: boolean; factor_id: number };
  message: string;
}

/** `POST /auth/mfa/enroll/radius` body (configured arm, source routes.py:3301). */
export interface EnrollRadiusBody {
  factor: MfaFactorRow;
}

/** `POST /auth/mfa/stepup` body (captured `{status, method, mfa_at}`). */
export interface StepUpBody {
  status: string;
  method: string;
  mfa_at: string;
}
