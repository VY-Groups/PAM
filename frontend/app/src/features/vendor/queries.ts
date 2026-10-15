import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1IntegrationsStatus,
  getApiV1VaultItems,
  getApiV1Vendors,
  getApiV1VendorsVendorId,
  postApiV1Vendors,
  postApiV1VendorsVendorIdApprove,
  postApiV1VendorsVendorIdDeny,
  postApiV1VendorsVendorIdMfa,
  postApiV1VendorsVendorIdNda,
  postApiV1VendorsVendorIdRequests,
  postApiV1VendorsVendorIdRevoke,
  postApiV1VendorsVendorIdTicket,
} from '../../api/generated';
import type {
  GetApiV1VendorsStatus,
  IntegrationsStatus,
  JitRequestResponse,
  VendorActionResponse,
  VendorDetailResponse,
  VendorInviteRequest,
  VendorInviteResponse,
  VendorJitCreateRequest,
  VendorList,
  VendorRevokeResponse,
  VaultItemList,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Vendor Access data hooks (F4 screen 8, plan line 114: "Chain steps,
 * invite, scoped requests"). Every read goes through the generated
 * client and `expectOk`; the registry sends its filters server-side
 * exactly as the contract offers them (`status` by equality, `q` as a
 * substring over name/contact) so the chips and the search drive real
 * contract parameters, not a client re-filter of a stale page.
 *
 * EVERY vendor write names the `X-Actor` header in the contract -
 * invite, edit, the four chain steps, deny, revoke and the scoped
 * request all document it - so those mutations send the signed-in
 * principal like Policy/Compliance/Connectors did. One `['vendor', ...]`
 * key root keeps every view refreshing together: a chain step moves the
 * registry row, the selected dashboard and the counts at once.
 */

/** Contract limit for the vendor registry (max 200). */
export const VENDOR_LIST_LIMIT = 200;
/** The request picker reads the first page of the vault registry. */
export const VENDOR_ITEMS_LIMIT = 100;

/** `X-Actor` header (contract: every vendor write names an actor). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `vendor` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['vendor'] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/vendors` - the registry, filtered server-side. */
export function useVendors(filters: {
  status?: GetApiV1VendorsStatus;
  q: string;
}): UseQueryResult<VendorList> {
  const { status, q } = filters;
  return useQuery<VendorList>({
    queryKey: queryKeys.vendorList(status ?? 'all', q),
    queryFn: async () => {
      // Absent params stay absent: the contract treats them as "no filter".
      const params: {
        status?: GetApiV1VendorsStatus;
        q?: string;
        limit: number;
      } = { limit: VENDOR_LIST_LIMIT };
      if (status) params.status = status;
      if (q.trim() !== '') params.q = q.trim();
      return (await expectOk(await getApiV1Vendors(params))).data;
    },
  });
}

/** `GET /api/v1/vendors/{id}` - the selected vendor's dashboard. */
export function useVendorDetail(id: number | null): UseQueryResult<VendorDetailResponse> {
  return useQuery<VendorDetailResponse>({
    queryKey: queryKeys.vendorDetail(id),
    enabled: id !== null,
    queryFn: async () => (await expectOk(await getApiV1VendorsVendorId(id as number))).data,
  });
}

/** `GET /api/v1/vault/items` - the real item picker for a scoped request. */
export function useVendorItems(): UseQueryResult<VaultItemList> {
  return useQuery<VaultItemList>({
    queryKey: queryKeys.vendorItems,
    queryFn: async () =>
      (await expectOk(await getApiV1VaultItems({ limit: VENDOR_ITEMS_LIMIT }))).data,
  });
}

/** `GET /api/v1/integrations/status` - the honest ITSM hint for tickets. */
export function useVendorItsm(): UseQueryResult<IntegrationsStatus> {
  return useQuery<IntegrationsStatus>({
    queryKey: queryKeys.vendorIntegrations,
    queryFn: async () => (await expectOk(await getApiV1IntegrationsStatus())).data,
  });
}

/* ----------------------------------------------------------------- writes */

/** `POST /api/v1/vendors` - invite a third-party vendor (201, seed once). */
export function useInviteVendor(): UseMutationResult<
  VendorInviteResponse,
  Error,
  { actor: string; payload: VendorInviteRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorInviteResponse,
    Error,
    { actor: string; payload: VendorInviteRequest }
  >({
    mutationFn: async ({ actor, payload }) =>
      (await expectOk(await postApiV1Vendors(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/mfa` - step 1, real RFC-6238 verify. */
export function useVendorMfa(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number; code: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorActionResponse,
    Error,
    { actor: string; vendorId: number; code: string }
  >({
    mutationFn: async ({ actor, vendorId, code }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdMfa(vendorId, { code }, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/nda` - step 2, record the agreement. */
export function useVendorNda(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number; ref?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorActionResponse,
    Error,
    { actor: string; vendorId: number; ref?: string }
  >({
    mutationFn: async ({ actor, vendorId, ref }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdNda(vendorId, { ref }, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/ticket` - step 3, real section-20 ITSM check. */
export function useVendorTicket(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number; ticket: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorActionResponse,
    Error,
    { actor: string; vendorId: number; ticket: string }
  >({
    mutationFn: async ({ actor, vendorId, ticket }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdTicket(vendorId, { ticket }, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/approve` - step 4 (the 409 names what is missing). */
export function useVendorApprove(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<VendorActionResponse, Error, { actor: string; vendorId: number }>({
    mutationFn: async ({ actor, vendorId }) =>
      (await expectOk(await postApiV1VendorsVendorIdApprove(vendorId, actorHeaders(actor))))
        .data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/deny` - refuse the invite, optional reason. */
export function useVendorDeny(): UseMutationResult<
  VendorActionResponse,
  Error,
  { actor: string; vendorId: number; reason?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorActionResponse,
    Error,
    { actor: string; vendorId: number; reason?: string }
  >({
    mutationFn: async ({ actor, vendorId, reason }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdDeny(vendorId, { reason }, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/vendors/{id}/revoke` - close access (returns grants ended). */
export function useVendorRevoke(): UseMutationResult<
  VendorRevokeResponse,
  Error,
  { actor: string; vendorId: number; reason?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    VendorRevokeResponse,
    Error,
    { actor: string; vendorId: number; reason?: string }
  >({
    mutationFn: async ({ actor, vendorId, reason }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdRevoke(vendorId, { reason }, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/vendors/{id}/requests` - file a real scoped JIT
 * request (201). The server answers the full governance decision -
 * approved+scope+window and the risk band - never the client.
 */
export function useVendorAccessRequest(): UseMutationResult<
  JitRequestResponse,
  Error,
  { actor: string; vendorId: number; payload: VendorJitCreateRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    JitRequestResponse,
    Error,
    { actor: string; vendorId: number; payload: VendorJitCreateRequest }
  >({
    mutationFn: async ({ actor, vendorId, payload }) =>
      (
        await expectOk(
          await postApiV1VendorsVendorIdRequests(vendorId, payload, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
