import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1CloudConnectorsConnectorId,
  getApiV1CloudConnectors,
  getApiV1CloudStats,
  getApiV1DiscoveryAccounts,
  getApiV1DiscoveryAssets,
  getApiV1DiscoveryScans,
  getApiV1DiscoveryStats,
  getApiV1Events,
  patchApiV1DiscoveryAssetsAssetId,
  postApiV1CloudConnectors,
  postApiV1CloudConnectorsConnectorIdDiscover,
  postApiV1CloudConnectorsConnectorIdTest,
  postApiV1DiscoveryAssets,
  postApiV1DiscoveryAssetsAssetIdOnboard,
  postApiV1DiscoveryScans,
} from '../../api/generated';
import type {
  CloudConnectorDeleteResponse,
  CloudConnectorList,
  CloudConnectorResponse,
  CloudInventoryResponse,
  CloudProbeResponse,
  CloudStats,
  DiscoveredAccountList,
  DiscoveredAssetList,
  DiscoveryActionResponse,
  DiscoveryAdoptRequest,
  DiscoveryAssetPatch,
  DiscoveryAssetType,
  DiscoveryOnboardRequest,
  DiscoveryPamStatus,
  DiscoveryScanList,
  DiscoveryScanResponse,
  DiscoveryStats,
  EventFeed,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Target Infrastructure data hooks (F4 screen 7, plan §4 line 109:
 * "Scans, assets, cloud connectors"). Every read goes through the
 * generated client and `expectOk`; filtered lists send their filters
 * server-side exactly as the contract offers them (`pam_status`/`type`/
 * `q` on the target list, `provider`/`status` on the connector fleet) so
 * the chips and the search drive real contract parameters, not a client
 * re-filter of a stale page.
 *
 * The discovery writes (scan, register, patch, adopt) carry NO
 * `X-Actor`: the contract's discovery section only documents the
 * `rbac:operator` role gate for them. Every cloud write - create,
 * probe, discover, remove - names the `X-Actor` header in the contract,
 * so those mutations send the signed-in principal like Policy did.
 * One `['infrastructure', ...]` key root keeps every view of the store
 * refreshing together: onboarding a target moves the aggregates, the
 * list, the accounts, the scan history and the event stream at once.
 */

/** Contract limit for the target/account/connector lists (max 200). */
export const INFRA_LIST_LIMIT = 200;
/** Scan history page (the legacy screen requested the recent tail). */
export const INFRA_SCANS_LIMIT = 50;
/** Discovery event stream page (the legacy screen's live tape). */
export const INFRA_EVENTS_LIMIT = 20;

/** `X-Actor` header (contract: cloud writes that name an actor accept it). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `infrastructure` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['infrastructure'] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/discovery/stats` - the real discovery aggregates. */
export function useDiscoveryStats(): UseQueryResult<DiscoveryStats> {
  return useQuery<DiscoveryStats>({
    queryKey: queryKeys.infraStats,
    queryFn: async () => (await expectOk(await getApiV1DiscoveryStats())).data,
  });
}

/** `GET /api/v1/discovery/assets` - the target list, filtered server-side. */
export function useDiscoveryAssets(filters: {
  pam?: DiscoveryPamStatus;
  type?: DiscoveryAssetType;
  q: string;
}): UseQueryResult<DiscoveredAssetList> {
  const { pam, type, q } = filters;
  return useQuery<DiscoveredAssetList>({
    queryKey: queryKeys.infraAssets(pam ?? 'all', type ?? 'all', q),
    queryFn: async () => {
      // Absent params stay absent: the contract treats them as "no filter".
      const params: {
        q?: string;
        type?: DiscoveryAssetType;
        pam_status?: DiscoveryPamStatus;
        limit: number;
      } = { limit: INFRA_LIST_LIMIT };
      if (pam) params.pam_status = pam;
      if (type) params.type = type;
      if (q.trim() !== '') params.q = q.trim();
      return (await expectOk(await getApiV1DiscoveryAssets(params))).data;
    },
  });
}

/** `GET /api/v1/discovery/accounts` - privileged accounts ingested at onboard. */
export function useDiscoveryAccounts(): UseQueryResult<DiscoveredAccountList> {
  return useQuery<DiscoveredAccountList>({
    queryKey: queryKeys.infraAccounts(INFRA_LIST_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1DiscoveryAccounts({ limit: INFRA_LIST_LIMIT }))).data,
  });
}

/** `GET /api/v1/discovery/scans` - the real scan history. */
export function useDiscoveryScans(): UseQueryResult<DiscoveryScanList> {
  return useQuery<DiscoveryScanList>({
    queryKey: queryKeys.infraScans(INFRA_SCANS_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1DiscoveryScans({ limit: INFRA_SCANS_LIMIT }))).data,
  });
}

/** `GET /api/v1/cloud/stats` - the connector fleet aggregates. */
export function useCloudStats(): UseQueryResult<CloudStats> {
  return useQuery<CloudStats>({
    queryKey: queryKeys.infraCloudStats,
    queryFn: async () => (await expectOk(await getApiV1CloudStats())).data,
  });
}

/** `GET /api/v1/cloud/connectors` - the fleet, filtered server-side. */
export function useCloudConnectors(filters: {
  provider?: 'aws' | 'azure' | 'gcp' | 'kubernetes';
  status?: 'not connected' | 'configured' | 'connected' | 'error';
}): UseQueryResult<CloudConnectorList> {
  const { provider, status } = filters;
  return useQuery<CloudConnectorList>({
    queryKey: queryKeys.infraConnectors(provider ?? 'all', status ?? 'all'),
    queryFn: async () => {
      const params: {
        provider?: 'aws' | 'azure' | 'gcp' | 'kubernetes';
        status?: 'not connected' | 'configured' | 'connected' | 'error';
        limit: number;
      } = { limit: INFRA_LIST_LIMIT };
      if (provider) params.provider = provider;
      if (status) params.status = status;
      return (await expectOk(await getApiV1CloudConnectors(params))).data;
    },
  });
}

/** `GET /api/v1/events?source=discovery&limit=` - the discovery tape. */
export function useDiscoveryEvents(): UseQueryResult<EventFeed> {
  return useQuery<EventFeed>({
    queryKey: queryKeys.infraEvents(INFRA_EVENTS_LIMIT),
    queryFn: async () =>
      (
        await expectOk(
          await getApiV1Events({ source: 'discovery', limit: INFRA_EVENTS_LIMIT }),
        )
      ).data,
  });
}

/* ----------------------------------------------------------------- writes */

/**
 * `POST /api/v1/discovery/scans` - a REAL synchronous TCP-connect scan
 * against the operator's scope (no X-Actor in the contract). The
 * mutation carries the form payload so a 409 single-flight refusal
 * surfaces its own message.
 */
export function useRunScan(): UseMutationResult<
  DiscoveryScanResponse,
  Error,
  { scope: string; ports?: number[] }
> {
  const queryClient = useQueryClient();
  return useMutation<DiscoveryScanResponse, Error, { scope: string; ports?: number[] }>({
    mutationFn: async (payload) =>
      (await expectOk(await postApiV1DiscoveryScans(payload))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/discovery/assets` - register + classify a target. */
export function useOnboardAsset(): UseMutationResult<
  DiscoveryActionResponse,
  Error,
  DiscoveryOnboardRequest
> {
  const queryClient = useQueryClient();
  return useMutation<DiscoveryActionResponse, Error, DiscoveryOnboardRequest>({
    mutationFn: async (payload) =>
      (await expectOk(await postApiV1DiscoveryAssets(payload))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/discovery/assets/{id}/onboard` - adopt into the vault. */
export function useAdoptAsset(): UseMutationResult<
  DiscoveryActionResponse,
  Error,
  { assetId: number; payload: DiscoveryAdoptRequest }
> {
  const queryClient = useQueryClient();
  return useMutation<
    DiscoveryActionResponse,
    Error,
    { assetId: number; payload: DiscoveryAdoptRequest }
  >({
    mutationFn: async ({ assetId, payload }) =>
      (await expectOk(await postApiV1DiscoveryAssetsAssetIdOnboard(assetId, payload))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `PATCH /api/v1/discovery/assets/{id}` - operator overrides. */
export function usePatchAsset(): UseMutationResult<
  DiscoveryActionResponse,
  Error,
  { assetId: number; payload: DiscoveryAssetPatch }
> {
  const queryClient = useQueryClient();
  return useMutation<
    DiscoveryActionResponse,
    Error,
    { assetId: number; payload: DiscoveryAssetPatch }
  >({
    mutationFn: async ({ assetId, payload }) =>
      (await expectOk(await patchApiV1DiscoveryAssetsAssetId(assetId, payload))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/cloud/connectors` - register a fleet connector. */
export function useCreateConnector(): UseMutationResult<
  CloudConnectorResponse,
  Error,
  {
    actor: string;
    payload: {
      name: string;
      provider: 'aws' | 'azure' | 'gcp' | 'kubernetes';
      account_ref?: string;
      endpoint?: string;
    };
  }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CloudConnectorResponse,
    Error,
    {
      actor: string;
      payload: {
        name: string;
        provider: 'aws' | 'azure' | 'gcp' | 'kubernetes';
        account_ref?: string;
        endpoint?: string;
      };
    }
  >({
    mutationFn: async ({ actor, payload }) =>
      (await expectOk(await postApiV1CloudConnectors(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/cloud/connectors/{id}/test` - real probe on click. */
export function useProbeConnector(): UseMutationResult<
  CloudProbeResponse,
  Error,
  { actor: string; connectorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<CloudProbeResponse, Error, { actor: string; connectorId: number }>({
    mutationFn: async ({ actor, connectorId }) =>
      (
        await expectOk(
          await postApiV1CloudConnectorsConnectorIdTest(connectorId, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/cloud/connectors/{id}/discover` - inventory import on click. */
export function useDiscoverConnector(): UseMutationResult<
  CloudInventoryResponse,
  Error,
  { actor: string; connectorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<CloudInventoryResponse, Error, { actor: string; connectorId: number }>(
    {
      mutationFn: async ({ actor, connectorId }) =>
        (
          await expectOk(
            await postApiV1CloudConnectorsConnectorIdDiscover(
              connectorId,
              actorHeaders(actor),
            ),
          )
        ).data,
      onSuccess: () => invalidateScreen(queryClient),
    },
  );
}

/** `DELETE /api/v1/cloud/connectors/{id}` - remove a fleet connector. */
export function useRemoveConnector(): UseMutationResult<
  CloudConnectorDeleteResponse,
  Error,
  { actor: string; connectorId: number }
> {
  const queryClient = useQueryClient();
  return useMutation<
    CloudConnectorDeleteResponse,
    Error,
    { actor: string; connectorId: number }
  >({
    mutationFn: async ({ actor, connectorId }) =>
      (
        await expectOk(
          await deleteApiV1CloudConnectorsConnectorId(connectorId, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
