import { z } from 'zod';

/**
 * Break-Glass form schemas (ADR-0006: RHF + Zod, client UX only -
 * the server-side contract validation is always authoritative). Field
 * limits mirror the contract exactly, never tighter: a client rule that
 * disagreed with the contract would hide real server behaviour (the
 * requester-signs-own 403, the duplicate-signer 400, the status gates
 * and the required review note are all server-side).
 */

/** The lifecycle statuses the list filter enum offers. */
export const breakGlassStatuses = [
  'pending',
  'approved',
  'denied',
  'used',
  'closed',
] as const;

/** `BreakGlassSeverity` enum, mirrored from the contract. */
export const breakGlassSeverities = ['sev1', 'sev2', 'sev3'] as const;

/** The contract's session protocols (the emergency session uses one). */
export const breakGlassProtocols = [
  'ssh',
  'rdp',
  'telnet',
  'vnc',
  'http',
  'https',
  'sql',
  'oracle',
  'postgresql',
  'mssql',
  'mysql',
  'sap',
  'kubernetes',
] as const;

/**
 * `BreakGlassCreateRequest`: target required (<= 255), reason required
 * verbatim (<= 1000), severity defaults to sev1 and the protocol to
 * ssh exactly like the contract. The `confirm` field is the legacy
 * console's EMERGENCY-AUTHORIZE typing guard - a deliberate
 * friction the old screen demanded before filing an emergency; it is
 * client-only and never sent to the server.
 */
export const fileSchema = z
  .object({
    target: z.string().trim().min(1).max(255),
    severity: z.enum(breakGlassSeverities),
    protocol: z.enum(breakGlassProtocols),
    reason: z.string().trim().min(1).max(1000),
    confirm: z.string().trim(),
  })
  .refine((v) => v.confirm === 'EMERGENCY-AUTHORIZE', {
    message: 'type EMERGENCY-AUTHORIZE exactly',
    path: ['confirm'],
  })
  .transform((v) => ({
    target: v.target,
    reason: v.reason,
    severity: v.severity,
    protocol: v.protocol,
  }));
export type FileValues = z.output<typeof fileSchema>;
export type FileForm = z.input<typeof fileSchema>;

/**
 * `PostApiV1BreakGlassRequestsRequestIdOpenBody`: the section-20
 * release code. The dialog only exists when a factor is enrolled
 * (`integrations/status` says so) and the global factor runs 6-digit
 * TOTP - the server verifies, a 401 renders its own reason.
 */
export const releaseSchema = z.object({
  mfaCode: z
    .string()
    .trim()
    .regex(/^\d{6}$/, '6 digits'),
});
export type ReleaseValues = z.output<typeof releaseSchema>;

/**
 * `BreakGlassCloseRequest`: the post-incident review note is REQUIRED
 * (the contract refuses an unreviewed close) and stays under 1000
 * chars like the server's own limit.
 */
export const reviewSchema = z.object({
  review: z.string().trim().min(1).max(1000),
});
export type ReviewValues = z.output<typeof reviewSchema>;
