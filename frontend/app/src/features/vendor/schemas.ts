import { z } from 'zod';

/**
 * Vendor Access form schemas (ADR-0006: RHF + Zod, client UX only -
 * the server-side contract validation is always authoritative). Field
 * limits mirror `apis/openapi.yaml` exactly, never tighter: a client
 * rule that disagreed with the contract would hide real server
 * behaviour (the four-step chain refusals, the ITSM check, the
 * approved+scope+window access gate are all server-side).
 */

/** `VendorAccountStatus` enum, mirrored from the contract filter enum. */
export const vendorStatuses = [
  'invited',
  'approved',
  'denied',
  'revoked',
  'expired',
] as const;

/** HH:MM in 24h time (the contract's window pair pattern). */
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

/** One target per line -> `string[]`; blank keeps the key absent. */
const targetLines = z
  .string()
  .max(4000)
  .transform((v) =>
    v
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== ''),
  )
  .refine((arr) => arr.length <= 50, 'max 50 targets')
  .refine((arr) => arr.every((target) => target.length <= 255), 'target <= 255 chars')
  .transform((arr) => (arr.length === 0 ? undefined : arr));

/**
 * `VendorInviteRequest`: name required (2-128), contact <= 160, the
 * allowed/denied target lists one per line (contract: <= 50 items, each
 * <= 255), the access window only as an HH:MM pair ("must be given as a
 * pair" - enforced here as UX, the 400 stays authoritative), recording
 * on by default. `expires_at` is a contract field the legacy modal
 * never exposed, so this form omits it too.
 */
export const inviteSchema = z
  .object({
    name: z.string().trim().min(2).max(128),
    contact: z
      .string()
      .trim()
      .max(160)
      .transform((v) => (v === '' ? undefined : v)),
    allowedText: targetLines,
    deniedText: targetLines,
    windowStart: z
      .string()
      .refine((v) => v === '' || HHMM.test(v), 'HH:MM')
      .transform((v) => (v === '' ? undefined : v)),
    windowEnd: z
      .string()
      .refine((v) => v === '' || HHMM.test(v), 'HH:MM')
      .transform((v) => (v === '' ? undefined : v)),
    recording: z.boolean(),
  })
  .refine((v) => (v.windowStart === undefined) === (v.windowEnd === undefined), {
    message: 'the window needs a start and an end',
    path: ['windowEnd'],
  })
  .transform((v) => ({
    name: v.name,
    contact: v.contact,
    allowed_targets: v.allowedText,
    denied_targets: v.deniedText,
    window_start: v.windowStart,
    window_end: v.windowEnd,
    recording: v.recording,
  }));
export type InviteValues = z.output<typeof inviteSchema>;
export type InviteForm = z.input<typeof inviteSchema>;

/** `VendorMfaRequest`: the vendor's TOTP code, contract range 6-8 chars. */
export const mfaSchema = z.object({
  code: z
    .string()
    .trim()
    .regex(/^\d{6,8}$/, '6-8 digits'),
});
export type MfaValues = z.output<typeof mfaSchema>;

/** `VendorNdaRequest`: optional agreement reference <= 64 chars. */
export const ndaSchema = z.object({
  ref: z
    .string()
    .trim()
    .max(64)
    .transform((v) => (v === '' ? undefined : v)),
});
export type NdaValues = z.output<typeof ndaSchema>;
export type NdaForm = z.input<typeof ndaSchema>;

/**
 * `VendorTicketRequest`: required ITSM key, contract pattern
 * `^[A-Za-z]{2,10}-\d{2,10}$` (e.g. INC-23891). The real upstream
 * check runs server side - unconfigured ITSM is a 409 there, never a
 * client-side guess.
 */
export const ticketSchema = z.object({
  ticket: z
    .string()
    .trim()
    .max(64)
    .regex(/^[A-Za-z]{2,10}-\d{2,10}$/, 'e.g. INC-23891'),
});
export type TicketValues = z.output<typeof ticketSchema>;

/** `VendorReasonRequest`: the optional deny/revoke reason <= 255 chars. */
export const reasonSchema = z.object({
  reason: z
    .string()
    .trim()
    .max(255)
    .transform((v) => (v === '' ? undefined : v)),
});
export type ReasonValues = z.output<typeof reasonSchema>;
export type ReasonForm = z.input<typeof reasonSchema>;

/**
 * `VendorJitCreateRequest`: a real vault item picked from the registry,
 * reason 8-255 (contract minimum), minutes 1-480 with the empty input
 * keeping the parameter absent so the server uses its own default (15),
 * optional ticket <= 64.
 */
export const requestSchema = z.object({
  itemId: z
    .string()
    .transform((v) => Number(v))
    .pipe(z.number().int().min(1)),
  reason: z.string().trim().min(8).max(255),
  minutesText: z
    .string()
    .trim()
    .max(4)
    .refine(
      (v) => v === '' || (/^\d{1,4}$/.test(v) && Number(v) >= 1 && Number(v) <= 480),
      '1-480 minutes',
    )
    .transform((v) => (v === '' ? undefined : Number(v))),
  ticket: z
    .string()
    .trim()
    .max(64)
    .transform((v) => (v === '' ? undefined : v)),
});
export type RequestValues = z.output<typeof requestSchema>;
export type RequestForm = z.input<typeof requestSchema>;
