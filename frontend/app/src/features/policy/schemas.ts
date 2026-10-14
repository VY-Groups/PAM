import { z } from 'zod';

/**
 * Policy & Zero Trust form schemas (ADR-0006: RHF + Zod, client UX only -
 * the server-side contract validation is always authoritative). Field
 * limits mirror `apis/openapi.yaml` exactly, never tighter: a client rule
 * that disagreed with the contract would hide real server behaviour.
 */

/** `CommandAction` enum, mirrored from the contract. */
export const ruleActions = ['allow', 'approval', 'block'] as const;

/**
 * `CommandRuleRequest`: name and pattern are required to create; every
 * other field carries the contract's max length (the dialog sends all of
 * them on create and update, exactly like the legacy modal did). The
 * server refuses `terminate_on_match` unless the action is `block` - the
 * dialog mirrors that rule in the UX but the 400 stays authoritative.
 */
export const ruleSchema = z.object({
  name: z.string().trim().min(1).max(120),
  pattern: z.string().trim().min(1).max(160),
  action: z.enum(ruleActions),
  target_pattern: z.string().trim().max(120),
  description: z.string().trim().max(255),
  terminate_on_match: z.boolean(),
  enabled: z.boolean(),
});
export type RuleValues = z.infer<typeof ruleSchema>;
/** Form-state twin (kept for the shared page pattern). */
export type RuleForm = z.input<typeof ruleSchema>;

/**
 * `RiskEvaluateRequest`: subject required, everything else optional and
 * never trimmed away server-side; max lengths from the contract.
 */
export const scoreSchema = z.object({
  subject: z.string().trim().min(1).max(160),
  target: z.string().trim().max(255),
  device: z.string().trim().max(128),
  source_ip: z.string().trim().max(64),
  ticket: z.string().trim().max(64),
  command: z.string().max(1000),
});
export type ScoreValues = z.infer<typeof scoreSchema>;
export type ScoreForm = z.input<typeof scoreSchema>;

/**
 * `CommandEvaluateRequest`: command required (<= 4096), target optional
 * (<= 255). The legacy simulator validated "type a command line" in the
 * guard before posting; the form now says the same thing client-side.
 */
export const dryRunSchema = z.object({
  command: z.string().min(1).max(4096),
  target: z.string().trim().max(255),
});
export type DryRunValues = z.infer<typeof dryRunSchema>;
export type DryRunForm = z.input<typeof dryRunSchema>;
