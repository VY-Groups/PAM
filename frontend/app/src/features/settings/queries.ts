import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1RoleBindingsBindingId,
  getApiV1AuthSsoStatus,
  getApiV1Cluster,
  getApiV1ClusterBackups,
  getApiV1HsmStatus,
  getApiV1IntegrationsStatus,
  getApiV1RoleBindings,
  getApiV1Roles,
  postApiV1RoleBindings,
} from '../../api/generated';
import type {
  ClusterBackupList,
  ClusterOverview,
  DeleteApiV1RoleBindingsBindingId200,
  HsmStatus,
  IntegrationsStatus,
  PostApiV1RoleBindings201,
  RoleBindingCreate,
  RoleBindingList,
  RoleList,
  SsoStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Platform Settings (screen 11, ADR-0015) read hooks for the 11.1 slice:
 * the read-only posture sections, plus the 11.2 RBAC directory reads and
 * the two binding writes. Every read goes through the generated client
 * and `expectOk`, so a non-2xx surfaces the server's own error verbatim
 * and a dead backend becomes the shared BackendDown error the page
 * renders as its honest down-state - never a zeroed posture that would
 * read as "healthy".
 *
 * The reads mirror the endpoints the legacy `platform_settings_center`
 * page already calls (inventory in ADR-0015). 11.1 ships four sections:
 * SSO federation, HSM custody, the Enterprise Integrations chips and the
 * HA/DC/DR cluster posture (overview + its backup ledger). 11.2 adds the
 * role directory and binding table with the grant/revoke writes. The 15
 * schema-group forms join in 11.3 on this same `['settings', ...]` root.
 */

/** `GET /api/v1/auth/sso/status` - IdP federation posture. */
export function useSsoStatus(): UseQueryResult<SsoStatus> {
  return useQuery({
    queryKey: queryKeys.settingsSso,
    queryFn: async () => expectOk(await getApiV1AuthSsoStatus()).data,
  });
}

/** `GET /api/v1/hsm/status` - key custody posture (sealed / mode / key). */
export function useHsmStatus(): UseQueryResult<HsmStatus> {
  return useQuery({
    queryKey: queryKeys.settingsHsm,
    queryFn: async () => expectOk(await getApiV1HsmStatus()).data,
  });
}

/** `GET /api/v1/integrations/status` - the enterprise connector chips. */
export function useIntegrationsStatus(): UseQueryResult<IntegrationsStatus> {
  return useQuery({
    queryKey: queryKeys.settingsIntegrations,
    queryFn: async () => expectOk(await getApiV1IntegrationsStatus()).data,
  });
}

/**
 * `GET /api/v1/cluster` - the HA/DC/DR aggregate (self, peers,
 * replication, backups, monitor). Verbatim rig capture: a pristine node
 * reports `{}` for `peers`/`backups` rather than an empty object with
 * zeroed counters, so every consumer treats those blocks as optional and
 * renders honest zeros - never invented peers.
 */
export function useClusterOverview(): UseQueryResult<ClusterOverview> {
  return useQuery({
    queryKey: queryKeys.settingsCluster,
    queryFn: async () => expectOk(await getApiV1Cluster()).data,
  });
}

/** `GET /api/v1/cluster/backups` - the backup ledger rows. */
export function useClusterBackups(): UseQueryResult<ClusterBackupList> {
  return useQuery({
    queryKey: queryKeys.settingsClusterBackups,
    queryFn: async () => expectOk(await getApiV1ClusterBackups()).data,
  });
}

/**
 * `GET /api/v1/roles` - the seeded role directory. Verbatim rig capture:
 * exactly five built-in roles, each carrying its computed `operations`
 * count, so the page never hardcodes the count (it reads what the server
 * actually seeded).
 */
export function useRoles(): UseQueryResult<RoleList> {
  return useQuery({
    queryKey: queryKeys.settingsRoles,
    queryFn: async () => expectOk(await getApiV1Roles()).data,
  });
}

/**
 * `GET /api/v1/role-bindings` - who holds what (principal, role, kind,
 * ABAC scope, last use). The list can legitimately be empty on a fresh
 * node; the page renders the honest empty row, never a fabricated grant.
 */
export function useRoleBindings(): UseQueryResult<RoleBindingList> {
  return useQuery({
    queryKey: queryKeys.settingsBindings,
    queryFn: async () => expectOk(await getApiV1RoleBindings()).data,
  });
}

/**
 * `POST /api/v1/role-bindings` - grant a role. A `local` principal gets
 * its API token minted ONCE in the 201 body (never recoverable, sha256
 * at rest); an `ldap`/`sso`/`user` principal is a directory identity
 * that gets no token back. Both writes invalidate the role + binding
 * reads so the tiles, summary line and tables re-read the same registry.
 */
export function useCreateRoleBinding(): UseMutationResult<
  PostApiV1RoleBindings201,
  unknown,
  RoleBindingCreate
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: RoleBindingCreate) =>
      expectOk(await postApiV1RoleBindings(payload)).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoles });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsBindings });
    },
  });
}

/**
 * `DELETE /api/v1/role-bindings/{id}` - revoke a grant. The token stops
 * working immediately and the row stays as audit evidence (the server
 * stamps `revoked_at`), so the bindings read is invalidated to show it.
 */
export function useRevokeRoleBinding(): UseMutationResult<
  DeleteApiV1RoleBindingsBindingId200,
  unknown,
  number
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (bindingId: number) =>
      expectOk(await deleteApiV1RoleBindingsBindingId(bindingId)).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsBindings });
    },
  });
}
