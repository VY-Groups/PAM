import { z } from 'zod';

/**
 * JIT Access form schemas (ADR-0006: RHF + Zod, client UX only - the
 * server-side contract validation is always authoritative). Field limits
 * mirror `apis/openapi.yaml` exactly, never tighter: a client rule that
 * disagreed with the contract would hide real server behaviour.
 */

const ciSystems = [
  'jenkins',
  'gitlab',
  'github',
  'azure_devops',
  'terraform',
  'ansible',
  'argocd',
  'docker',
  'other',
] as const;

/** `JitCreateRequest`: item_id >= 1, reason 8-255, ticket <= 64, minutes 1-480. */
export const fileRequestSchema = z.object({
  item_id: z.coerce.number().int().min(1),
  reason: z.string().trim().min(8).max(255),
  ticket: z.string().trim().min(1).max(64),
  minutes: z.coerce.number().int().min(1).max(480),
});
export type FileRequestValues = z.infer<typeof fileRequestSchema>;
/**
 * RHF field state (schema input) for `useForm`: the coerced numbers start
 * as `unknown` in the form and become real numbers only after validation,
 * so input and output types differ and RHF needs both (resolvers v5).
 */
export type FileRequestForm = z.input<typeof fileRequestSchema>;

/** `BrokerPolicyCreate`: name required (<=128), the rest contract-optional. */
export const policySchema = z.object({
  name: z.string().trim().min(1).max(128),
  ci_system: z.enum(ciSystems),
  contact: z.string().trim().max(160),
  approval_mode: z.enum(['auto', 'manual']),
  max_ttl_minutes: z.coerce.number().int().min(1).max(480),
  allowed_targets: z.string().trim().max(1024),
});
export type PolicyValues = z.infer<typeof policySchema>;
/** Form-state twin of `PolicyValues` (coerce input != validated output). */
export type PolicyForm = z.input<typeof policySchema>;

/** `AgentIdentityCreate`: name required (<=128), the rest optional. */
export const agentSchema = z.object({
  name: z.string().trim().min(1).max(128),
  contact: z.string().trim().max(160),
  max_ttl_minutes: z.coerce.number().int().min(1).max(480),
});
export type AgentValues = z.infer<typeof agentSchema>;
/** Form-state twin of `AgentValues` (coerce input != validated output). */
export type AgentForm = z.input<typeof agentSchema>;

/** Split a comma-separated targets input into the contract's string array. */
export function splitCommaList(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Split a newline-separated command allow-list into the contract array. */
export function splitLineList(value: string): string[] {
  return value
    .split('\n')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * `AgentTaskCreate`: allowed_commands is a newline-separated literal list
 * (default-deny allow-list), allowed_targets comma-separated; both are
 * split at submit exactly like the legacy console did. The refinement
 * mirrors the contract's `minItems: 1, maxItems: 32` verbatim.
 */
export const taskSchema = z
  .object({
    name: z.string().trim().min(1).max(128),
    allowed_commands: z.string().trim().min(1),
    allowed_targets: z.string().trim().max(1024),
    max_minutes: z.coerce.number().int().min(1).max(480),
  })
  .refine(
    (values) => {
      const count = splitLineList(values.allowed_commands).length;
      return count >= 1 && count <= 32;
    },
    { message: 'allowed_commands must be 1-32 lines', path: ['allowed_commands'] },
  );
export type TaskValues = z.infer<typeof taskSchema>;
/** Form-state twin of `TaskValues` (coerce input != validated output). */
export type TaskForm = z.input<typeof taskSchema>;

/** Optional free-text reason carried on deny/revoke calls (<= 255). */
export const reasonSchema = z.object({
  reason: z.string().trim().max(255),
});
export type ReasonValues = z.infer<typeof reasonSchema>;
