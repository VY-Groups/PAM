import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1AgentsAgentId,
  deleteApiV1BrokerPoliciesPolicyId,
  getApiV1AgentAccessRequests,
  getApiV1AgentAccessStats,
  getApiV1Agents,
  getApiV1AgentsAgentId,
  getApiV1BrokerCredentials,
  getApiV1BrokerPolicies,
  getApiV1BrokerStats,
  getApiV1JitRequests,
  getApiV1JitRequestsRequestId,
  getApiV1JitStats,
  getApiV1VaultItems,
  patchApiV1AgentsAgentId,
  postApiV1AgentAccessRequestsRequestIdClose,
  postApiV1Agents,
  postApiV1AgentsAgentIdTasks,
  postApiV1BrokerCredentialsCredentialIdApprove,
  postApiV1BrokerCredentialsCredentialIdClose,
  postApiV1BrokerCredentialsCredentialIdDeny,
  postApiV1BrokerPolicies,
  postApiV1JitRequests,
  postApiV1JitRequestsRequestIdApprove,
  postApiV1JitRequestsRequestIdClose,
  postApiV1JitRequestsRequestIdConsume,
  postApiV1JitRequestsRequestIdDeny,
} from '../../api/generated';
import type {
  AgentIdentityCreate,
  AgentIdentityDetailResponse,
  AgentIdentityList,
  AgentIdentityMessageResponse,
  AgentIdentityResponse,
  AgentIdentityRevokeResponse,
  AgentIdentityUpdate,
  AgentStats,
  AgentTaskCreate,
  AgentTaskResponse,
  BrokerCredentialList,
  BrokerCredentialResponse,
  BrokerPolicyCreate,
  BrokerPolicyList,
  BrokerPolicyResponse,
  BrokerPolicyRevokeResponse,
  BrokerStats,
  JitCreateRequest,
  JitRequest,
  JitRequestDetail,
  JitRequestList,
  JitRequestResponse,
  JitStats,
  VaultItemList,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * JIT Access data hooks (F4 screen 3, plan §4 line 107: "Requests,
 * approvals, grants, pipeline broker, agent access"). Every read goes
 * through the generated client and `expectOk`; every write carries the
 * real signed-in principal in the contract's `X-Actor` header so the
 * server-side trail names a human. One `['jit', ...]` key root means any
 * screen mutation invalidates the whole screen once - the queue, the
 * broker and the agent consoles share rows (an agent access request IS a
 * JIT request), so partial refreshes would show disagreeing states.
 *
 * The two token-shown-once registrations (pipeline policy, agent
 * identity) are mutations: the token must never enter the query cache,
 * and the page resets the mutation when its modal closes.
 */

export const QUEUE_LIMIT = 20;

/** `X-Actor` header (contract: writes that name an actor accept it). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `jit` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['jit'] });
}

/* ------------------------------------------------------------------ reads */

export type JitStatus = JitRequest['status'];

export interface JitQueueFilter {
  /** `'all'` sends no `status` parameter (the contract's default list). */
  status: JitStatus | 'all';
  /** Case-insensitive requester substring, straight from the contract. */
  requester: string;
}

/** `GET /api/v1/jit/stats` - real queue totals per status and risk band. */
export function useJitStats(): UseQueryResult<JitStats> {
  return useQuery<JitStats>({
    queryKey: queryKeys.jitStats,
    queryFn: async () => (await expectOk(await getApiV1JitStats())).data,
  });
}

/** `GET /api/v1/jit/requests` - the queue, newest first. */
export function useJitQueue(filter: JitQueueFilter): UseQueryResult<JitRequestList> {
  const status = filter.status;
  const requester = filter.requester.trim();
  return useQuery<JitRequestList>({
    queryKey: queryKeys.jitQueue(status, requester, QUEUE_LIMIT),
    queryFn: async () =>
      (
        await expectOk(
          await getApiV1JitRequests({
            limit: QUEUE_LIMIT,
            ...(status === 'all' ? {} : { status }),
            ...(requester === '' ? {} : { requester }),
          }),
        )
      ).data,
  });
}

/** `GET /api/v1/jit/requests/{id}` - one request with its events trail. */
export function useJitRequestDetail(
  requestId: number | null,
): UseQueryResult<JitRequestDetail> {
  return useQuery<JitRequestDetail>({
    queryKey: queryKeys.jitRequest(requestId),
    queryFn: async () =>
      (await expectOk(await getApiV1JitRequestsRequestId(requestId as number))).data,
    enabled: requestId !== null,
  });
}

/** `GET /api/v1/broker/stats` - policy/credential aggregates. */
export function useBrokerStats(): UseQueryResult<BrokerStats> {
  return useQuery<BrokerStats>({
    queryKey: queryKeys.brokerStats,
    queryFn: async () => (await expectOk(await getApiV1BrokerStats())).data,
  });
}

/** `GET /api/v1/broker/policies` - pipeline identities, newest first. */
export function useBrokerPolicies(): UseQueryResult<BrokerPolicyList> {
  return useQuery<BrokerPolicyList>({
    queryKey: queryKeys.brokerPolicies(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1BrokerPolicies({ limit: QUEUE_LIMIT }))).data,
  });
}

/** `GET /api/v1/broker/credentials` - the pipeline credential queue. */
export function useBrokerCredentials(): UseQueryResult<BrokerCredentialList> {
  return useQuery<BrokerCredentialList>({
    queryKey: queryKeys.brokerCredentials(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1BrokerCredentials({ limit: QUEUE_LIMIT }))).data,
  });
}

/** `GET /api/v1/agents` - agent identities, newest first. */
export function useAgents(): UseQueryResult<AgentIdentityList> {
  return useQuery<AgentIdentityList>({
    queryKey: queryKeys.agents(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1Agents({ limit: QUEUE_LIMIT }))).data,
  });
}

/** `GET /api/v1/agents/{id}` - identity with declared tasks and trail. */
export function useAgentDetail(
  agentId: number | null,
): UseQueryResult<AgentIdentityDetailResponse> {
  return useQuery<AgentIdentityDetailResponse>({
    queryKey: queryKeys.agent(agentId),
    queryFn: async () =>
      (await expectOk(await getApiV1AgentsAgentId(agentId as number))).data,
    enabled: agentId !== null,
  });
}

/** `GET /api/v1/agent-access/requests` - agent access queue. */
export function useAgentAccessRequests(): UseQueryResult<JitRequestList> {
  return useQuery<JitRequestList>({
    queryKey: queryKeys.agentAccessRequests(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1AgentAccessRequests({ limit: QUEUE_LIMIT }))).data,
  });
}

/** `GET /api/v1/agent-access/stats` - identity/request/task aggregates. */
export function useAgentAccessStats(): UseQueryResult<AgentStats> {
  return useQuery<AgentStats>({
    queryKey: queryKeys.agentAccessStats,
    queryFn: async () => (await expectOk(await getApiV1AgentAccessStats())).data,
  });
}

/**
 * `GET /api/v1/vault/items` - the file-a-request target picker reads the
 * same cache key as the Credential Vault screen (same endpoint, same
 * limit), so navigating between screens never refetches.
 */
export function useJitTargets(): UseQueryResult<VaultItemList> {
  return useQuery<VaultItemList>({
    queryKey: queryKeys.vaultItems(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1VaultItems({ limit: QUEUE_LIMIT }))).data,
  });
}

/* ----------------------------------------------------------------- writes */

export type JitActionKind =
  'approve-manager' | 'approve-security' | 'deny' | 'grant' | 'close';

export interface JitActionVars {
  kind: JitActionKind;
  requestId: number;
  actor: string;
  /** Deny reason (optional in the contract, recorded when given). */
  reason?: string;
}

/**
 * `POST /api/v1/jit/requests/{id}/{approve|deny|consume|close}` - the
 * lifecycle in one mutation so the page shares a single pending/error
 * state. Quorum is the server's rule (low auto, medium manager, high
 * manager+security, critical blocked) - the UI only offers the action,
 * the contract decides. Success invalidates the screen root so the row
 * re-renders from server truth, never an optimistic guess.
 */
export function useJitAction(): UseMutationResult<
  JitRequestResponse,
  Error,
  JitActionVars
> {
  const queryClient = useQueryClient();
  return useMutation<JitRequestResponse, Error, JitActionVars>({
    mutationFn: async ({ kind, requestId, actor, reason }) => {
      const options = actorHeaders(actor);
      if (kind === 'approve-manager') {
        return (
          await expectOk(
            await postApiV1JitRequestsRequestIdApprove(
              requestId,
              { role: 'manager' },
              options,
            ),
          )
        ).data;
      }
      if (kind === 'approve-security') {
        return (
          await expectOk(
            await postApiV1JitRequestsRequestIdApprove(
              requestId,
              { role: 'security' },
              options,
            ),
          )
        ).data;
      }
      if (kind === 'deny') {
        return (
          await expectOk(
            await postApiV1JitRequestsRequestIdDeny(
              requestId,
              reason === undefined || reason === '' ? undefined : { reason },
              options,
            ),
          )
        ).data;
      }
      if (kind === 'grant') {
        return (
          await expectOk(await postApiV1JitRequestsRequestIdConsume(requestId, options))
        ).data;
      }
      return (await expectOk(await postApiV1JitRequestsRequestIdClose(requestId, options)))
        .data;
    },
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/jit/requests` - file a request (the contract fills
 * `requester` from `X-Actor`; risk is computed server-side). */
export function useFileJitRequest(): UseMutationResult<
  JitRequestResponse,
  Error,
  JitCreateRequest & { actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<JitRequestResponse, Error, JitCreateRequest & { actor: string }>({
    mutationFn: async ({ actor, ...payload }) =>
      (await expectOk(await postApiV1JitRequests(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/broker/policies` - register a pipeline identity. The
 * response token is shown once; it lives only in this mutation's data
 * until the modal resets it (never in the query cache). */
export function useRegisterPolicy(): UseMutationResult<
  BrokerPolicyResponse,
  Error,
  BrokerPolicyCreate & { actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<BrokerPolicyResponse, Error, BrokerPolicyCreate & { actor: string }>({
    mutationFn: async ({ actor, ...payload }) =>
      (await expectOk(await postApiV1BrokerPolicies(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `DELETE /api/v1/broker/policies/{id}` - revoke an identity (its open
 * credentials close and rotate first, per contract). */
export function useRevokePolicy(): UseMutationResult<
  BrokerPolicyRevokeResponse,
  Error,
  { policyId: number; actor: string; reason?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BrokerPolicyRevokeResponse,
    Error,
    { policyId: number; actor: string; reason?: string }
  >({
    mutationFn: async ({ policyId, actor, reason }) =>
      (
        await expectOk(
          await deleteApiV1BrokerPoliciesPolicyId(
            policyId,
            reason === undefined || reason === '' ? undefined : { reason },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

export type BrokerCredentialActionKind = 'approve' | 'deny' | 'close';

export interface BrokerCredentialActionVars {
  kind: BrokerCredentialActionKind;
  credentialId: number;
  actor: string;
  reason?: string;
}

/**
 * `POST /api/v1/broker/credentials/{id}/{approve|deny|close}` - the
 * admin side of the queue. `release` is deliberately absent: the
 * contract authenticates it with the pipeline's own token, never the
 * console session (the secret exists only in that response).
 */
export function useBrokerCredentialAction(): UseMutationResult<
  BrokerCredentialResponse,
  Error,
  BrokerCredentialActionVars
> {
  const queryClient = useQueryClient();
  return useMutation<BrokerCredentialResponse, Error, BrokerCredentialActionVars>({
    mutationFn: async ({ kind, credentialId, actor, reason }) => {
      const options = actorHeaders(actor);
      const body = reason === undefined || reason === '' ? undefined : { reason };
      if (kind === 'approve') {
        return (
          await expectOk(
            await postApiV1BrokerCredentialsCredentialIdApprove(
              credentialId,
              body,
              options,
            ),
          )
        ).data;
      }
      if (kind === 'deny') {
        return (
          await expectOk(
            await postApiV1BrokerCredentialsCredentialIdDeny(credentialId, body, options),
          )
        ).data;
      }
      return (
        await expectOk(
          await postApiV1BrokerCredentialsCredentialIdClose(credentialId, options),
        )
      ).data;
    },
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/agents` - register an agent identity; its token is
 * shown exactly once and lives only in this mutation's data. */
export function useRegisterAgent(): UseMutationResult<
  AgentIdentityResponse,
  Error,
  AgentIdentityCreate & { actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<AgentIdentityResponse, Error, AgentIdentityCreate & { actor: string }>(
    {
      mutationFn: async ({ actor, ...payload }) =>
        (await expectOk(await postApiV1Agents(payload, actorHeaders(actor)))).data,
      onSuccess: () => invalidateScreen(queryClient),
    },
  );
}

export type AgentActionKind = 'enable' | 'disable' | 'revoke';

export interface AgentActionVars {
  kind: AgentActionKind;
  agentId: number;
  actor: string;
  reason?: string;
}

/** `PATCH /api/v1/agents/{id}` (status flip) and `DELETE` (revoke, which
 * ends every open grant first - the response reports `grants_closed`). */
export function useAgentAction(): UseMutationResult<
  AgentIdentityMessageResponse | AgentIdentityRevokeResponse,
  Error,
  AgentActionVars
> {
  const queryClient = useQueryClient();
  return useMutation<
    AgentIdentityMessageResponse | AgentIdentityRevokeResponse,
    Error,
    AgentActionVars
  >({
    mutationFn: async ({ kind, agentId, actor, reason }) => {
      const options = actorHeaders(actor);
      if (kind === 'revoke') {
        return (
          await expectOk(
            await deleteApiV1AgentsAgentId(
              agentId,
              reason === undefined || reason === '' ? undefined : { reason },
              options,
            ),
          )
        ).data;
      }
      const update: AgentIdentityUpdate = {
        status: kind === 'enable' ? 'active' : 'disabled',
      };
      return (await expectOk(await patchApiV1AgentsAgentId(agentId, update, options))).data;
    },
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/agents/{id}/tasks` - declare a task's allow-list. */
export function useDeclareTask(): UseMutationResult<
  AgentTaskResponse,
  Error,
  { agentId: number; payload: AgentTaskCreate; actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    AgentTaskResponse,
    Error,
    { agentId: number; payload: AgentTaskCreate; actor: string }
  >({
    mutationFn: async ({ agentId, payload, actor }) =>
      (
        await expectOk(
          await postApiV1AgentsAgentIdTasks(agentId, payload, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/agent-access/requests/{id}/close` - an admin ends an
 * agent grant (release + rotate, like a JIT close). Invalidates the
 * screen root: the same row also lives in the JIT queue.
 */
export function useCloseAgentAccess(): UseMutationResult<
  JitRequestResponse,
  Error,
  { requestId: number; actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<JitRequestResponse, Error, { requestId: number; actor: string }>({
    mutationFn: async ({ requestId, actor }) =>
      (
        await expectOk(
          await postApiV1AgentAccessRequestsRequestIdClose(requestId, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
