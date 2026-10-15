import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1BreakGlassRequests,
  getApiV1BreakGlassRequestsRequestId,
  getApiV1BreakGlassStats,
  getApiV1IntegrationsStatus,
  postApiV1BreakGlassRequests,
  postApiV1BreakGlassRequestsRequestIdApprove,
  postApiV1BreakGlassRequestsRequestIdClose,
  postApiV1BreakGlassRequestsRequestIdDeny,
  postApiV1BreakGlassRequestsRequestIdOpen,
} from '../../api/generated';
import type {
  BreakGlassCloseRequest,
  BreakGlassCloseResponse,
  BreakGlassCreateRequest,
  BreakGlassDetailResponse,
  BreakGlassOpenResponse,
  BreakGlassRequestList,
  BreakGlassRequestResponse,
  BreakGlassStats,
  GetApiV1BreakGlassRequestsStatus,
  IntegrationsStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Break-Glass data hooks (F4 screen 9, plan line 113: "Filing, dual
 * approval, recorded session"). Every read goes through the generated
 * client and `expectOk`; the list sends its lifecycle filter server-side
 * exactly as the contract offers it (`status` by equality) so the chips
 * drive a real contract parameter, never a client re-filter of a stale
 * page.
 *
 * EVERY break-glass write documents the `X-Actor` header - file,
 * approve, deny, open and close all name the acting identity - and the
 * server judges it hard (the requester cannot sign their own emergency,
 * a second signature must come from someone else). The screen therefore
 * carries the legacy console's editable acting-identity input and every
 * mutation takes that value verbatim, sliced to the contract's 64 chars.
 * One `['breakGlass', ...]` key root keeps every view refreshing
 * together: one signature moves the list row, the detail and the
 * aggregates at once.
 */

/** Contract limit for the request list (max 200). */
export const BREAK_GLASS_LIST_LIMIT = 200;

/** `X-Actor` header (contract: every break-glass write names an actor). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `breakGlass` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['breakGlass'] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/break-glass/stats` - the real aggregates over the module. */
export function useBreakGlassStats(): UseQueryResult<BreakGlassStats> {
  return useQuery<BreakGlassStats>({
    queryKey: queryKeys.breakGlassStats,
    queryFn: async () => (await expectOk(await getApiV1BreakGlassStats())).data,
  });
}

/** `GET /api/v1/break-glass/requests` - newest first, status filter server-side. */
export function useBreakGlassList(
  status: GetApiV1BreakGlassRequestsStatus | undefined,
): UseQueryResult<BreakGlassRequestList> {
  return useQuery<BreakGlassRequestList>({
    queryKey: queryKeys.breakGlassList(status ?? 'all'),
    queryFn: async () => {
      // An absent status stays absent: the contract treats it as "no filter".
      const params: {
        status?: GetApiV1BreakGlassRequestsStatus;
        limit: number;
      } = { limit: BREAK_GLASS_LIST_LIMIT };
      if (status) params.status = status;
      return (await expectOk(await getApiV1BreakGlassRequests(params))).data;
    },
  });
}

/** `GET /api/v1/break-glass/requests/{id}` - one request with its session. */
export function useBreakGlassDetail(
  id: number | null,
): UseQueryResult<BreakGlassDetailResponse> {
  return useQuery<BreakGlassDetailResponse>({
    queryKey: queryKeys.breakGlassDetail(id),
    enabled: id !== null,
    queryFn: async () =>
      (await expectOk(await getApiV1BreakGlassRequestsRequestId(id as number))).data,
  });
}

/**
 * `GET /api/v1/integrations/status` - the honest global factor state
 * (`mfa.configured` / `mfa.gate`): the banner, the process rail and the
 * open action's gate decision all read it, never a client guess.
 */
export function useBreakGlassFactor(): UseQueryResult<IntegrationsStatus> {
  return useQuery<IntegrationsStatus>({
    queryKey: queryKeys.breakGlassIntegrations,
    queryFn: async () => (await expectOk(await getApiV1IntegrationsStatus())).data,
  });
}

/* ----------------------------------------------------------------- writes */

/** `POST /api/v1/break-glass/requests` - file one emergency (201). */
export function useFileBreakGlass(): UseMutationResult<
  BreakGlassRequestResponse,
  Error,
  { actor: string; payload: BreakGlassCreateRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassRequestResponse,
    Error,
    { actor: string; payload: BreakGlassCreateRequest }
  >({
    mutationFn: async ({ actor, payload }) =>
      (await expectOk(await postApiV1BreakGlassRequests(payload, actorHeaders(actor))))
        .data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/break-glass/requests/{id}/approve` - one distinct
 * signature (1/2, then 2/2 flips the request to approved). The 403
 * requester-signs-own and the duplicate-signer 400 are server truth.
 */
export function useApproveBreakGlass(): UseMutationResult<
  BreakGlassRequestResponse,
  Error,
  { actor: string; requestId: number; note?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassRequestResponse,
    Error,
    { actor: string; requestId: number; note?: string }
  >({
    mutationFn: async ({ actor, requestId, note }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdApprove(
            requestId,
            { note },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/break-glass/requests/{id}/deny` - turn a pending request down. */
export function useDenyBreakGlass(): UseMutationResult<
  BreakGlassRequestResponse,
  Error,
  { actor: string; requestId: number; note?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassRequestResponse,
    Error,
    { actor: string; requestId: number; note?: string }
  >({
    mutationFn: async ({ actor, requestId, note }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdDeny(
            requestId,
            { note },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/break-glass/requests/{id}/open` - release the emergency
 * credential through the real vault checkout (201). The section-20
 * factor gate answers 401 without a valid code when a factor is
 * enrolled; `mfa_code` stays absent when none is (never a fake
 * challenge).
 */
export function useOpenBreakGlass(): UseMutationResult<
  BreakGlassOpenResponse,
  Error,
  { actor: string; requestId: number; mfaCode?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassOpenResponse,
    Error,
    { actor: string; requestId: number; mfaCode?: string }
  >({
    mutationFn: async ({ actor, requestId, mfaCode }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdOpen(
            requestId,
            { mfa_code: mfaCode },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/break-glass/requests/{id}/close` - end the emergency:
 * session stopped, credential rotation guaranteed, review note filed
 * (the note is required by the contract, <= 1000 chars).
 */
export function useCloseBreakGlass(): UseMutationResult<
  BreakGlassCloseResponse,
  Error,
  { actor: string; requestId: number; review: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassCloseResponse,
    Error,
    { actor: string; requestId: number; review: string }
  >({
    mutationFn: async ({ actor, requestId, review }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdClose(
            requestId,
            { review } satisfies BreakGlassCloseRequest,
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
