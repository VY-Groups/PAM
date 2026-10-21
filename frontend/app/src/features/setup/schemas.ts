import { z } from 'zod';

/**
 * ADR-0018 batch 11.11 - first-run wizard forms, mirroring the contract's
 * field limits (openapi `/setup/*` paths, the settings `smtp` group schema
 * and `POST /users`): company_name 1-128, contact 255, SMTP port 1-65535,
 * passwords NIST-14 with empty meaning "let the server generate one".
 * The logo is bounded server side (64 KB decoded) and re-checked here
 * before the bytes travel; the server validates always (ADR-0006) and its
 * refusal renders verbatim.
 */
export const setupProfileSchema = z.object({
  company_name: z.string().trim().min(1).max(128),
  contact_email: z.union([z.string().trim().max(255), z.literal('')]).optional(),
});
export type SetupProfileFormValues = z.infer<typeof setupProfileSchema>;

export const setupSmtpSchema = z.object({
  enabled: z.boolean(),
  host: z.string().trim().max(255),
  port: z.number().int().min(1).max(65535),
  username: z.string().trim().max(128),
  password: z.string().max(4096),
  from_address: z.string().trim().max(255),
  use_tls: z.boolean(),
});
export type SetupSmtpFormValues = z.infer<typeof setupSmtpSchema>;

export const setupAdminSchema = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.union([z.string().min(14).max(200), z.literal('')]).optional(),
});
export type SetupAdminFormValues = z.infer<typeof setupAdminSchema>;

export const setupAttestationSchema = z.object({
  maker_password: z.string().min(1).max(200),
  checker_password: z.string().min(1).max(200),
});
export type SetupAttestationFormValues = z.infer<typeof setupAttestationSchema>;
