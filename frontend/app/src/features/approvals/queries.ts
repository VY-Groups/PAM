import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1BreakGlassRequests,
  getApiV1BrokerCredentials,
  getApiV1JitRequests,
  getApiV1Vendors,
  postApiV1BreakGlassRequestsRequestIdApprove,
  postApiV1BreakGlassRequestsRequestIdDeny,
  postApiV1BrokerCredentialsCredentialIdApprove,
  postApiV1BrokerCredentialsCredentialIdDeny,
  postApiV1JitRequestsRequestIdApprove,
  postApiV1JitRequestsRequestIdDeny,
  postApiV1VendorsVendorIdApprove,
  postApiV1VendorsVendorIdDeny,
} from '../../api/generated';
import type {
  BreakGlassRequestList,
  BreakGlassRequestResponse,
  BrokerCredentialList,
  BrokerCredentialResponse,
  JitRequestList,
  JitRequestResponse,
  VendorActionResponse,
  VendorList,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * ADR-0021 12.RC approvals-inbox data layer. Features never import each
 * other (plan §3 rule 2), so this feature keeps its own thin hooks over
 * the generated client - the vault screen's documented precedent - while
 * sharing the `api/queryKeys` factories, so the inbox and the owning
 * screens read ONE cache entry and every approval refreshes both at once.
 * Row limits repeat the owning screens' values on purpose: the shared
 * keys embed them (same limit => same entry).
 */

/** jit + broker queue parity (features/jit/queries.ts QUEUE_LIMIT). */
const QUEUE_LIMIT = 20;
/** break-glass + vendor list parity (BREAK_GLASS_LIST_LIMIT / VENDOR_LIST_LIMIT). */
const LIST_LIMIT = 200;

/** `X-Actor` header (contract: writes that name an actor accept it). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** One prefix invalidation refreshes the inbox and the owning screen. */
function invalidate(
  root: readonly string[],
  queryClient: ReturnType<typeof useQueryClient>,
): void {
  void queryClient.invalidateQueries({ queryKey: [...root] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/jit/requests?status=pending` - the JIT decision queue. */
export function usePendingJit(): UseQueryResult<JitRequestList> {
  return useQuery<JitRequestList>({
    queryKey: queryKeys.jitQueue('pending', '', QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1JitRequests({ status: 'pending', limit: QUEUE_LIMIT })))
        .data,
  });
}

/** `GET /api/v1/break-glass/requests?status=pending` - emergency decisions. */
export function usePendingBreakGlass(): UseQueryResult<BreakGlassRequestList> {
  return useQuery<BreakGlassRequestList>({
    queryKey: queryKeys.breakGlassList('pending'),
    queryFn: async () =>
      (
        await expectOk(
          await getApiV1BreakGlassRequests({ status: 'pending', limit: LIST_LIMIT }),
        )
      ).data,
  });
}

/** `GET /api/v1/vendors?status=invited` - invites awaiting approve/deny. */
export function useInvitedVendors(): UseQueryResult<VendorList> {
  return useQuery<VendorList>({
    queryKey: queryKeys.vendorList('invited', ''),
    queryFn: async () =>
      (await expectOk(await getApiV1Vendors({ status: 'invited', limit: LIST_LIMIT })))
        .data,
  });
}

/** `GET /api/v1/broker/credentials` - the pipeline queue (client-side pending). */
export function useBrokerCredentialQueue(): UseQueryResult<BrokerCredentialList> {
  return useQuery<BrokerCredentialList>({
    queryKey: queryKeys.brokerCredentials(QUEUE_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1BrokerCredentials({ limit: QUEUE_LIMIT }))).data,
  });
}

/* ---------------------------------------------------------------- writes */

/** `POST /api/v1/jit/requests/{id}/approve` - one tier of the two-tier rule. */
export function useApproveJitRequest(): UseMutationResult<
  JitRequestResponse,
  Error,
  { actor: string; requestId: number; role: 'manager' | 'security' }
> {
  const queryClient = useQueryClient();
  return useMutation<
    JitRequestResponse,
    Error,
    { actor: string; requestId: number; role: 'manager' | 'security' }
  >({
    mutationFn: async ({ actor, requestId, role }) =>
      (
        await expectOk(
          await postApiV1JitRequestsRequestIdApprove(
            requestId,
            { role },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['jit'], queryClient),
  });
}

/** `POST /api/v1/jit/requests/{id}/deny` - turn a request down. */
export function useDenyJitRequest(): UseMutationResult<
  JitRequestResponse,
  Error,
  { actor: string; requestId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<JitRequestResponse, Error, { actor: string; requestId: number }>({
    mutationFn: async ({ actor, requestId }) =>
      (
        await expectOk(
          await postApiV1JitRequestsRequestIdDeny(
            requestId,
            undefined,
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['jit'], queryClient),
  });
}

/** `POST /api/v1/break-glass/requests/{id}/approve` - sign a request. */
export function useApproveBreakGlassRequest(): UseMutationResult<
  BreakGlassRequestResponse,
  Error,
  { actor: string; requestId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassRequestResponse,
    Error,
    { actor: string; requestId: number }
  >({
    mutationFn: async ({ actor, requestId }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdApprove(
            requestId,
            {},
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['breakGlass'], queryClient),
  });
}

/** `POST /api/v1/break-glass/requests/{id}/deny` - refuse a request. */
export function useDenyBreakGlassRequest(): UseMutationResult<
  BreakGlassRequestResponse,
  Error,
  { actor: string; requestId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BreakGlassRequestResponse,
    Error,
    { actor: string; requestId: number }
  >({
    mutationFn: async ({ actor, requestId }) =>
      (
        await expectOk(
          await postApiV1BreakGlassRequestsRequestIdDeny(
            requestId,
            {},
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['breakGlass'], queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/approve` - step 4 (the 409 names what is missing). */
export function useApproveVendorInvite(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<VendorActionResponse, Error, { actor: string; vendorId: number }>({
    mutationFn: async ({ actor, vendorId }) =>
      (await expectOk(await postApiV1VendorsVendorIdApprove(vendorId, actorHeaders(actor))))
        .data,
    onSuccess: () => invalidate(['vendor'], queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/deny` - refuse the invite. */
export function useDenyVendorInvite(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<VendorActionResponse, Error, { actor: string; vendorId: number }>({
    mutationFn: async ({ actor, vendorId }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdDeny(vendorId, undefined, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidate(['vendor'], queryClient),
  });
}

/** `POST /api/v1/broker/credentials/{id}/approve` - release the queue row. */
export function useApproveBrokerCredential(): UseMutationResult<
  BrokerCredentialResponse,
  Error,
  { actor: string; credentialId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BrokerCredentialResponse,
    Error,
    { actor: string; credentialId: number }
  >({
    mutationFn: async ({ actor, credentialId }) =>
      (
        await expectOk(
          await postApiV1BrokerCredentialsCredentialIdApprove(
            credentialId,
            undefined,
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['jit'], queryClient),
  });
}

/** `POST /api/v1/broker/credentials/{id}/deny` - refuse the queue row. */
export function useDenyBrokerCredential(): UseMutationResult<
  BrokerCredentialResponse,
  Error,
  { actor: string; credentialId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<
    BrokerCredentialResponse,
    Error,
    { actor: string; credentialId: number }
  >({
    mutationFn: async ({ actor, credentialId }) =>
      (
        await expectOk(
          await postApiV1BrokerCredentialsCredentialIdDeny(
            credentialId,
            undefined,
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidate(['jit'], queryClient),
  });
}
