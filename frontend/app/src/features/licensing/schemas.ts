import { z } from 'zod';

/**
 * Enterprise Licensing form schemas (ADR-0006: RHF + Zod, client UX only -
 * the server-side contract validation is always authoritative). Field
 * limits mirror the contract exactly, never tighter: a client rule that
 * disagreed with the contract would hide real server behaviour (the
 * signature-verification refusal on import, the duplicate-import 409, the
 * revoked-license state gate and the offline-parity verdict are all
 * server-side).
 */

/**
 * The registry list filter enum, mirrored from the contract's `status`
 * filter (`getApiV1LicensesStatus`). Empty string = no filter.
 */
export const licenseStatuses = ['active', 'revoked', 'expired'] as const;

/**
 * `POST /api/v1/licenses/import` - the pasted envelope. The contract body
 * is the `LicenseEnvelope` (`license_data` object + `signature` string,
 * algorithm optional); the server re-verifies everything, so the client
 * only checks that the paste parses as JSON and carries the two required
 * members - never that the signature is valid (it cannot and must not
 * pretend to).
 */
export const importSchema = z.object({
  /** The pasted license file contents (pretty or minified JSON). */
  envelope: z
    .string()
    .trim()
    .min(1, 'licensing.validation.envelopeRequired')
    .refine(
      (raw) => {
        try {
          JSON.parse(raw);
          return true;
        } catch {
          return false;
        }
      },
      { message: 'licensing.validation.envelopeJson' },
    )
    .refine(
      (raw) => {
        try {
          const parsed: unknown = JSON.parse(raw);
          if (typeof parsed !== 'object' || parsed === null) return false;
          const env = parsed as Record<string, unknown>;
          return (
            typeof env.signature === 'string' &&
            typeof env.license_data === 'object' &&
            env.license_data !== null
          );
        } catch {
          return false;
        }
      },
      { message: 'licensing.validation.envelopeShape' },
    ),
});

export type ImportForm = z.infer<typeof importSchema>;

/**
 * `POST /api/v1/licenses/{key}/revoke` - the recorded reason. The
 * contract types `reason?: string` (optional); the client keeps it
 * optional but caps the paste at the contract's own display length so a
 * huge blob cannot silently truncate in the activity timeline.
 */
export const revokeSchema = z.object({
  reason: z.string().trim().max(500, 'licensing.validation.reasonLong'),
});

export type RevokeForm = z.infer<typeof revokeSchema>;

/**
 * `POST /api/v1/licenses/validate` - the contract accepts the envelope,
 * a wrapper, or the compact jwt token as a JSON string. The console's
 * offline-parity box takes the pasted file or token: either a JWT (three
 * base64url segments - the `text/plain` file answer) or parseable JSON
 * carrying `license_data`/`license`/`token`.
 */
export const validateSchema = z.object({
  payload: z
    .string()
    .trim()
    .min(1, 'licensing.validation.payloadRequired')
    .refine(
      (raw) => {
        // A compact JWT: header.payload.signature in base64url.
        if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw)) {
          return true;
        }
        try {
          JSON.parse(raw);
          return true;
        } catch {
          return false;
        }
      },
      { message: 'licensing.validation.payloadShape' },
    ),
});

export type ValidateForm = z.infer<typeof validateSchema>;
