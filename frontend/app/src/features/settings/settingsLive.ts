/**
 * `window.settingsLive` (screen 11, ADR-0015 11.4) - the export the
 * standing gate's Settings block reads, in the exact legacy shape
 * (code.html:2174-2177):
 *
 *   window.settingsLive = {
 *     cluster: { load: loadCluster, state: clusterLive },
 *     rbac:    { load: loadRbac,    state: rbacLive }
 *   }
 *
 * The gate type-checks both entries and that `state` is truthy
 * (`__verify_agent.mjs:361-363` for cluster, `411-413` for RBAC) and it
 * AWAITS `window.settingsLive.cluster.load()` after its 6a peer flow
 * (`717`) before re-reading the summary - so `load` must be await-able
 * and must actually refetch.
 *
 * React translation (user-approved 2026-10-18):
 * - `load` awaits the query invalidation for exactly the views the
 *   legacy loader reads (`GET /cluster` for cluster; roles + bindings
 *   for rbac - code.html:1566, 2067/2073).
 * - `state` is a getter over the query cache: the live data once it has
 *   settled (`reachable: true` - the read itself is the proof), and the
 *   honest pre-settle skeleton before (`{reachable: false, role:
 *   "unknown"}` / `{reachable: false, roles: [], bindings: []}`) so it
 *   is ALWAYS truthy, exactly like the legacy `clusterLive`/`rbacLive`
 *   initial objects the gate checks.
 * - Installed while the settings page is mounted, deleted on unmount:
 *   the export exists exactly while the page does.
 */
import { useEffect } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';

import type {
  ClusterOverview,
  RoleBindingList,
  RoleList,
} from '../../api/generated/models';
import { queryKeys } from '../../api/queryKeys';

/** The legacy `clusterLive` contract: reachable + role + the overview. */
export interface SettingsLiveClusterState extends Partial<ClusterOverview> {
  reachable: boolean;
  role: string;
}

/** The legacy `rbacLive` contract: reachable + the two row sets. */
export interface SettingsLiveRbacState {
  reachable: boolean;
  roles: RoleList['roles'];
  bindings: RoleBindingList['bindings'];
}

export interface SettingsLiveEntry<TState> {
  load: () => Promise<void>;
  readonly state: TState;
}

export interface SettingsLiveExport {
  cluster: SettingsLiveEntry<SettingsLiveClusterState>;
  rbac: SettingsLiveEntry<SettingsLiveRbacState>;
}

declare global {
  interface Window {
    settingsLive?: SettingsLiveExport;
  }
}

/**
 * Build the export bound to a query client (pure - the hook below is the
 * mount/unmount lifecycle). `state` is a getter so every property read
 * sees the current cache, the way the legacy mutation-in-place objects
 * always expose their latest fill.
 */
export function buildSettingsLive(queryClient: QueryClient): SettingsLiveExport {
  return {
    cluster: {
      load: async () => {
        await queryClient.invalidateQueries({ queryKey: queryKeys.settingsCluster });
      },
      get state(): SettingsLiveClusterState {
        const overview = queryClient.getQueryData<ClusterOverview>(
          queryKeys.settingsCluster,
        );
        if (!overview) return { reachable: false, role: 'unknown' };
        return { reachable: true, role: overview.self.role, ...overview };
      },
    },
    rbac: {
      load: async () => {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoles }),
          queryClient.invalidateQueries({ queryKey: queryKeys.settingsBindings }),
        ]);
      },
      get state(): SettingsLiveRbacState {
        const roles = queryClient.getQueryData<RoleList>(queryKeys.settingsRoles);
        const bindings = queryClient.getQueryData<RoleBindingList>(
          queryKeys.settingsBindings,
        );
        return {
          reachable: roles !== undefined && bindings !== undefined,
          roles: roles?.roles ?? [],
          bindings: bindings?.bindings ?? [],
        };
      },
    },
  };
}

/** Install `window.settingsLive` while the settings page is mounted. */
export function useSettingsLiveExport(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    window.settingsLive = buildSettingsLive(queryClient);
    return () => {
      delete window.settingsLive;
    };
  }, [queryClient]);
}
