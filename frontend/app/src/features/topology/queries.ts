import { useQuery } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1Cluster,
  getApiV1IntegrationsStatus,
  getHealth,
} from '../../api/generated';
import type {
  ClusterOverview,
  Health,
  IntegrationsStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Network-view data hooks (ADR-0013, /topology): the three live
 * endpoints the diagram draws from the running node - its own health
 * posture, the cluster overview (self, peers, replication, backups)
 * and the integration states. Every read goes through the generated
 * client and `expectOk` like every other F4 screen; the page renders
 * honest loading/error states and never draws a node the server did
 * not report.
 */

/** `GET /health` - this node's own posture (liveness, keys, HA identity). */
export function useHealth(): UseQueryResult<Health> {
  return useQuery<Health>({
    // Same endpoint the command center reads - one shared cache entry.
    queryKey: queryKeys.health,
    queryFn: async () => (await expectOk(await getHealth())).data,
  });
}

/** `GET /api/v1/cluster` - self + registered peers + replication totals. */
export function useClusterOverview(): UseQueryResult<ClusterOverview> {
  return useQuery<ClusterOverview>({
    queryKey: queryKeys.topologyCluster,
    queryFn: async () => (await expectOk(await getApiV1Cluster())).data,
  });
}

/** `GET /api/v1/integrations/status` - ITSM/LDAP/MFA/SIEM real states. */
export function useTopologyIntegrations(): UseQueryResult<IntegrationsStatus> {
  return useQuery<IntegrationsStatus>({
    queryKey: queryKeys.topologyIntegrations,
    queryFn: async () => (await expectOk(await getApiV1IntegrationsStatus())).data,
  });
}
