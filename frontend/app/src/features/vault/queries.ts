import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1VaultEvents,
  getApiV1VaultItems,
  getApiV1VaultItemsItemId,
  getApiV1VaultItemsItemIdSecret,
  getApiV1VaultStats,
  postApiV1VaultItemsItemIdCheckout,
  postApiV1VaultItemsItemIdRevoke,
  postApiV1VaultItemsItemIdRotate,
} from '../../api/generated';
import type {
  RotationActionResponse,
  SecretReveal,
  VaultActionResponse,
  VaultEventFeed,
  VaultItemDetail,
  VaultItemList,
  VaultStats,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Credential Vault data hooks (per-screen DoD: "generated query hooks only").
 * Every read goes through the orval client (contract-first, ADR-0004) and
 * `expectOk`; every write records the real signed-in principal in the
 * `X-Actor` header the contract documents, so the server-side audit trail
 * names a human, never a fabricated label.
 *
 * The reveal endpoint returns plaintext once per call, so it is a mutation
 * (never cached, never re-fetched by the query cache) and the page clears it
 * when the modal closes.
 */

export const INVENTORY_LIMIT = 20;
export const EVENTS_LIMIT = 10;

/** `X-Actor` header (contract: "writes that name an actor accept it"). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** `GET /api/v1/vault/stats` - posture aggregate for the KPI quad. */
export function useVaultStats(): UseQueryResult<VaultStats> {
  return useQuery<VaultStats>({
    queryKey: queryKeys.vaultStats,
    queryFn: async () => (await expectOk(await getApiV1VaultStats())).data,
  });
}

/** `GET /api/v1/vault/items?limit=...` - the inventory table. */
export function useVaultItems(): UseQueryResult<VaultItemList> {
  return useQuery<VaultItemList>({
    queryKey: queryKeys.vaultItems(INVENTORY_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1VaultItems({ limit: INVENTORY_LIMIT }))).data,
  });
}

/** `GET /api/v1/vault/events?limit=...` - the newest-first audit feed. */
export function useVaultEvents(): UseQueryResult<VaultEventFeed> {
  return useQuery<VaultEventFeed>({
    queryKey: queryKeys.vaultEvents(EVENTS_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1VaultEvents({ limit: EVENTS_LIMIT }))).data,
  });
}

/**
 * `GET /api/v1/vault/items/{id}` - one item with its version history.
 * Disabled while no history modal is open (`itemId === null`).
 */
export function useVaultItemDetail(itemId: number | null): UseQueryResult<VaultItemDetail> {
  return useQuery<VaultItemDetail>({
    queryKey: queryKeys.vaultItem(itemId),
    queryFn: async () =>
      (await expectOk(await getApiV1VaultItemsItemId(itemId as number))).data,
    enabled: itemId !== null,
  });
}

export type VaultActionKind = 'checkout' | 'revoke' | 'rotate';

export interface VaultActionVars {
  kind: VaultActionKind;
  itemId: number;
  actor: string;
}

/**
 * `POST /api/v1/vault/items/{id}/{checkout|revoke|rotate}` - one mutation
 * for the three lifecycle actions so the page shares a single
 * pending/error/success state. On success every `['vault', ...]` key is
 * invalidated (stats, inventory, feed, open detail) so the row re-renders
 * from the server's truth, not an optimistic guess.
 */
export function useVaultAction(): UseMutationResult<
  VaultActionResponse | RotationActionResponse,
  Error,
  VaultActionVars
> {
  const queryClient = useQueryClient();
  return useMutation<VaultActionResponse | RotationActionResponse, Error, VaultActionVars>({
    mutationFn: async ({ kind, itemId, actor }) => {
      const options = actorHeaders(actor);
      if (kind === 'checkout') {
        return (
          await expectOk(
            await postApiV1VaultItemsItemIdCheckout(itemId, undefined, options),
          )
        ).data;
      }
      if (kind === 'revoke') {
        return (await expectOk(await postApiV1VaultItemsItemIdRevoke(itemId, options)))
          .data;
      }
      return (await expectOk(await postApiV1VaultItemsItemIdRotate(itemId, options))).data;
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['vault'] });
    },
  });
}

/**
 * `GET /api/v1/vault/items/{id}/secret` - admin reveal (plaintext once).
 * Deliberately a mutation: the value must never sit in the query cache, and
 * `reset()` on modal close drops the only copy the client holds.
 */
export function useRevealSecret(): UseMutationResult<SecretReveal, Error, number> {
  return useMutation<SecretReveal, Error, number>({
    mutationFn: async (itemId) =>
      (await expectOk(await getApiV1VaultItemsItemIdSecret(itemId))).data,
  });
}
