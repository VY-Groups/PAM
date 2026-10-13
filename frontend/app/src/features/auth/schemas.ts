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

export type LoginFormValues = z.infer<typeof loginSchema>;
export type MfaFormValues = z.infer<typeof mfaSchema>;
