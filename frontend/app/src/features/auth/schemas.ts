import { z } from 'zod';

/**
 * ADR-0006: Zod schema mirrors the contract's field limits
 * (openapi /auth/login: username max 64, password max 200). The client is
 * UX only - the server validates always (checklist D/F). Messages are not
 * embedded here; the page maps invalid submits to i18n strings.
 */
export const loginSchema = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(1).max(200),
});

export const mfaSchema = z.object({
  code: z.string().trim().min(1),
});

/**
 * ADR-0016 batch 11.6 - password recovery. `recoveryStartSchema` mirrors
 * openapi `/auth/recovery/start` (username max 64); `recoveryResetSchema`
 * mirrors `/auth/recovery/reset` (code max 16, new_password max 200) and
 * the server's own captured policy refusal (`details.min_length: 14` -
 * "Password must be at least 14 characters (NIST: length over complexity)").
 * The server stays authoritative; these are UX mirrors only.
 */
export const recoveryStartSchema = z.object({
  username: z.string().trim().min(1).max(64),
});

export const recoveryResetSchema = z.object({
  code: z.string().trim().min(1).max(16),
  new_password: z.string().min(14).max(200),
});

/**
 * ADR-0017 batch 11.8 - the forced first-login change (captured 403
 * `details.reason: password-change-required` -> POST /auth/password).
 * Mirrors openapi `/auth/password` (old_password required, new_password
 * max 200) and the captured policy refusal (`details.min_length: 14`);
 * the server stays authoritative (401 "Current password is incorrect"
 * renders verbatim from the real answer).
 */
export const changePasswordSchema = z.object({
  old_password: z.string().min(1).max(200),
  new_password: z.string().min(14).max(200),
});

export type LoginFormValues = z.infer<typeof loginSchema>;
export type MfaFormValues = z.infer<typeof mfaSchema>;
export type RecoveryStartFormValues = z.infer<typeof recoveryStartSchema>;
export type RecoveryResetFormValues = z.infer<typeof recoveryResetSchema>;
export type ChangePasswordFormValues = z.infer<typeof changePasswordSchema>;
