import { useQuery } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1AuthSsoStatus,
  getApiV1Cluster,
  getApiV1ClusterBackups,
  getApiV1HsmStatus,
  getApiV1IntegrationsStatus,
} from '../../api/generated';
import type {
  ClusterBackupList,
  ClusterOverview,
  HsmStatus,
  IntegrationsStatus,
  SsoStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Platform Settings (screen 11, ADR-0015) read hooks for the 11.1 slice:
 * the read-only posture sections. Every read goes through the generated
 * client and `expectOk`, so a non-2xx surfaces the server's own error
 * verbatim and a dead backend becomes the shared BackendDown error the
 * page renders as its honest down-state - never a zeroed posture that
 * would read as "healthy".
 *
 * The five reads mirror the endpoints the legacy `platform_settings_center`
 * page already calls (inventory in ADR-0015). 11.1 ships four sections:
 * SSO federation, HSM custody, the Enterprise Integrations chips and the
 * HA/DC/DR cluster posture (overview + its backup ledger). The 15
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
