import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1CommandControlRulesRuleId,
  getApiV1CommandControlApprovals,
  getApiV1CommandControlIncidents,
  getApiV1CommandControlRules,
  getApiV1CommandControlStats,
  getApiV1RiskAnomalies,
  getApiV1RiskBaselines,
  getApiV1RiskEvaluations,
  getApiV1RiskStats,
  postApiV1CommandControlEvaluate,
  postApiV1CommandControlIncidentsIncidentIdClose,
  postApiV1CommandControlRules,
  postApiV1RiskBaselinesTrain,
  postApiV1RiskEvaluate,
  postApiV1SessionsSessionIdEventsSeqApprove,
  postApiV1SessionsSessionIdEventsSeqDeny,
  putApiV1CommandControlRulesRuleId,
} from '../../api/generated';
import type {
  BehaviorBaselineList,
  AnomalyList,
  CommandApprovalList,
  CommandApprovalResponse,
  CommandEvaluateResponse,
  CommandIncidentList,
  CommandIncidentResponse,
  CommandRuleDeleteResponse,
  CommandRuleList,
  CommandRuleRequest,
  CommandRuleResponse,
  CommandStats,
  RiskEvaluateRequest,
  RiskEvaluateResponse,
  RiskEvaluationList,
  RiskStats,
  TrainBaselinesResponse,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Policy & Zero Trust data hooks (F4 screen 5, plan §4 line 110: "Command
 * rules, risk, anomalies, incidents"). Every read goes through the
 * generated client and `expectOk`; every write carries the real
 * signed-in principal in the contract's `X-Actor` header so the server-
 * side trail names a human (the header is contract-optional here; DELETE
 * takes none). One `['policy', ...]` key root means any mutation
 * refreshes the whole screen from server truth - no optimistic policy
 * state (a rule either landed or it did not).
 *
 * The command-control half polls every 45 seconds like the legacy
 * console; the risk/UEBA half loads once at boot (same cadence the
 * legacy screen used) - scoring posts only on click.
 */

/** Rules/incidents list page, same limit the legacy console requested. */
export const POLICY_LIMIT = 200;
/** Recent evaluations / anomalies the legacy risk section loaded. */
export const RISK_LIMIT = 8;
/** Command-control live poll cadence, mirroring the legacy 45 s reload. */
const LIVE_POLL_MS = 45_000;

/** `X-Actor` header (contract: writes that name an actor accept it). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `policy` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['policy'] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/command-control/stats` - the real policy aggregates. */
export function usePolicyStats(): UseQueryResult<CommandStats> {
  return useQuery<CommandStats>({
    queryKey: queryKeys.policyStats,
    queryFn: async () => (await expectOk(await getApiV1CommandControlStats())).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/command-control/rules` - the policy, evaluation order. */
export function usePolicyRules(): UseQueryResult<CommandRuleList> {
  return useQuery<CommandRuleList>({
    queryKey: queryKeys.policyRules,
    queryFn: async () => (await expectOk(await getApiV1CommandControlRules())).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/command-control/approvals` - held commands awaiting a decision. */
export function usePolicyApprovals(): UseQueryResult<CommandApprovalList> {
  return useQuery<CommandApprovalList>({
    queryKey: queryKeys.policyApprovals,
    queryFn: async () => (await expectOk(await getApiV1CommandControlApprovals())).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/command-control/incidents` - escalation incidents, newest first. */
export function usePolicyIncidents(): UseQueryResult<CommandIncidentList> {
  return useQuery<CommandIncidentList>({
    queryKey: queryKeys.policyIncidents(POLICY_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1CommandControlIncidents({ limit: POLICY_LIMIT }))).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/risk/stats` - evaluation aggregates (bands, decisions, refusals). */
export function useRiskStats(): UseQueryResult<RiskStats> {
  return useQuery<RiskStats>({
    queryKey: queryKeys.riskStats,
    queryFn: async () => (await expectOk(await getApiV1RiskStats())).data,
  });
}

/** `GET /api/v1/risk/evaluations` - recorded evaluations, newest first. */
export function useRiskEvaluations(): UseQueryResult<RiskEvaluationList> {
  return useQuery<RiskEvaluationList>({
    queryKey: queryKeys.riskEvaluations(RISK_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1RiskEvaluations({ limit: RISK_LIMIT }))).data,
  });
}

/** `GET /api/v1/risk/baselines` - trained UEBA behavior baselines. */
export function useRiskBaselines(): UseQueryResult<BehaviorBaselineList> {
  return useQuery<BehaviorBaselineList>({
    queryKey: queryKeys.riskBaselines,
    queryFn: async () => (await expectOk(await getApiV1RiskBaselines())).data,
  });
}

/** `GET /api/v1/risk/anomalies` - UEBA incidents, newest first. */
export function useRiskAnomalies(): UseQueryResult<AnomalyList> {
  return useQuery<AnomalyList>({
    queryKey: queryKeys.riskAnomalies(RISK_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1RiskAnomalies({ limit: RISK_LIMIT }))).data,
  });
}

/* ----------------------------------------------------------------- writes */

/**
 * `POST /api/v1/command-control/evaluate` - the real dry-run (same engine
 * judging recorded session commands). Pure evaluation: the response is
 * the server's decision and nothing on the screen needs invalidating.
 */
export function useDryRun(): UseMutationResult<
  CommandEvaluateResponse,
  Error,
  { command: string; target: string }
> {
  return useMutation<CommandEvaluateResponse, Error, { command: string; target: string }>({
    mutationFn: async (payload) =>
      (await expectOk(await postApiV1CommandControlEvaluate(payload))).data,
  });
}

/** `POST /api/v1/risk/evaluate` - score one access request (advises only). */
export function useScoreRequest(): UseMutationResult<
  RiskEvaluateResponse,
  Error,
  { actor: string; payload: RiskEvaluateRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    RiskEvaluateResponse,
    Error,
    { actor: string; payload: RiskEvaluateRequest }
  >({
    mutationFn: async ({ actor, payload }) =>
      (await expectOk(await postApiV1RiskEvaluate(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/risk/baselines/train` - learn from the real history. */
export function useTrainBaselines(): UseMutationResult<
  TrainBaselinesResponse,
  Error,
  { actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<TrainBaselinesResponse, Error, { actor: string }>({
    mutationFn: async ({ actor }) =>
      (await expectOk(await postApiV1RiskBaselinesTrain({}, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/command-control/rules` - create a policy rule. */
export function useCreateRule(): UseMutationResult<
  CommandRuleResponse,
  Error,
  { actor: string; payload: CommandRuleRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CommandRuleResponse,
    Error,
    { actor: string; payload: CommandRuleRequest }
  >({
    mutationFn: async ({ actor, payload }) =>
      (await expectOk(await postApiV1CommandControlRules(payload, actorHeaders(actor))))
        .data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `PUT /api/v1/command-control/rules/{id}` - partial update of a rule. */
export function useUpdateRule(): UseMutationResult<
  CommandRuleResponse,
  Error,
  { actor: string; ruleId: number; payload: CommandRuleRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CommandRuleResponse,
    Error,
    { actor: string; ruleId: number; payload: CommandRuleRequest }
  >({
    mutationFn: async ({ actor, ruleId, payload }) =>
      (
        await expectOk(
          await putApiV1CommandControlRulesRuleId(ruleId, payload, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `DELETE /api/v1/command-control/rules/{id}` - recorded events keep their rule_id. */
export function useDeleteRule(): UseMutationResult<
  CommandRuleDeleteResponse,
  Error,
  { ruleId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<CommandRuleDeleteResponse, Error, { ruleId: number }>({
    mutationFn: async ({ ruleId }) =>
      (await expectOk(await deleteApiV1CommandControlRulesRuleId(ruleId))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

export type ApprovalDecision = 'approve' | 'deny';

/**
 * `POST /api/v1/sessions/{id}/events/{seq}/{approve|deny}` - resolve a
 * held command; the append-only resolution row records the decision
 * (and the deciding principal) verbatim from the server.
 */
export function useResolveApproval(): UseMutationResult<
  CommandApprovalResponse,
  Error,
  { sessionId: number; seq: number; decision: ApprovalDecision; actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CommandApprovalResponse,
    Error,
    { sessionId: number; seq: number; decision: ApprovalDecision; actor: string }
  >({
    mutationFn: async ({ sessionId, seq, decision, actor }) => {
      const options = actorHeaders(actor);
      if (decision === 'approve') {
        return (
          await expectOk(
            await postApiV1SessionsSessionIdEventsSeqApprove(sessionId, seq, options),
          )
        ).data;
      }
      return (
        await expectOk(
          await postApiV1SessionsSessionIdEventsSeqDeny(sessionId, seq, options),
        )
      ).data;
    },
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/command-control/incidents/{id}/close` - close after review. */
export function useCloseIncident(): UseMutationResult<
  CommandIncidentResponse,
  Error,
  { incidentId: number; actor: string; note?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CommandIncidentResponse,
    Error,
    { incidentId: number; actor: string; note?: string }
  >({
    mutationFn: async ({ incidentId, actor, note }) =>
      (
        await expectOk(
          await postApiV1CommandControlIncidentsIncidentIdClose(
            incidentId,
            note === undefined || note === '' ? {} : { note },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
