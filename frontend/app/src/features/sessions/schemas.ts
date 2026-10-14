import { z } from 'zod';

/**
 * Live Session Hub form schemas (ADR-0006: RHF + Zod, client UX only -
 * the server-side contract validation is always authoritative). Field
 * limits mirror `apis/openapi.yaml` exactly, never tighter: a client rule
 * that disagreed with the contract would hide real server behaviour.
 */

/** `SessionProtocol` enum, mirrored from the contract (generated const). */
export const sessionProtocols = [
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
 * `SessionStartRequest`: protocol + target required (target <= 255), the
 * vault credential and the seven control flags optional (flags default
 * on server-side; the form sends them explicitly like the legacy start
 * overlay did). The optional credential picker posts `item_id` only when
 * a real credential is chosen (`item` is the select's raw string value).
 */
export const startSessionSchema = z.object({
  protocol: z.enum(sessionProtocols),
  target: z.string().trim().min(1).max(255),
  item: z.string(),
  record: z.boolean(),
  keystroke_log: z.boolean(),
  watermark: z.boolean(),
  clipboard_allowed: z.boolean(),
  upload_allowed: z.boolean(),
  download_allowed: z.boolean(),
  screenshot_allowed: z.boolean(),
});
export type StartSessionValues = z.infer<typeof startSessionSchema>;
/** Form-state twin (no coercion here, kept for the shared page pattern). */
export type StartSessionForm = z.input<typeof startSessionSchema>;

/** `SessionEndRequest`: reason optional, <= 500 (empty sends nothing). */
export const terminateSchema = z.object({
  reason: z.string().trim().max(500),
});
export type TerminateValues = z.infer<typeof terminateSchema>;
