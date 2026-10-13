import { useQuery } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1BypassIncidents,
  getApiV1BypassStats,
  getApiV1Events,
  getApiV1Overview,
  getHealth,
} from '../../api/generated';
import type { getHealthResponse } from '../../api/generated';
import type {
  BypassIncidentList,
  BypassStats,
  EventFeed,
  Health,
  Overview,
} from '../../api/generated/models';
import { ApiError, expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Command Center data hooks (per-screen DoD: "generated query hooks only").
 * Every hook consumes the orval client (contract-first, ADR-0004) and
 * `expectOk`, so a non-2xx arrives as the honest `{error, details}` message
 * and transport failures arrive as the shared `BackendDownError` that the
 * page turns into the plan §5 shared state.
 */

export const ACTIVITY_LIMIT = 10;
export const INCIDENTS_LIMIT = 5;

/** `GET /api/v1/overview` - the dashboard aggregate for this screen. */
export function useOverview(): UseQueryResult<Overview> {
  return useQuery<Overview>({
    queryKey: queryKeys.overview,
    queryFn: async () => (await expectOk(await getApiV1Overview())).data,
  });
}

/**
 * `GET /health` - the liveness probe. A 503 is not a transport failure:
 * the probe answers with its own honest `degraded`/`error` body, which the
 * health strip renders verbatim. Shares `queryKeys.health` with the login
 * footer, so the cache holds the raw envelope exactly once and `select`
 * narrows it to the `Health` body for this screen.
 */
export function useHealth(): UseQueryResult<Health> {
  return useQuery<getHealthResponse, Error, Health>({
    queryKey: queryKeys.health,
    queryFn: getHealth,
    select: (res) => {
      if (res.status === 200 || res.status === 503) return res.data;
      /* c8 ignore next - the contract only has 200 and 503 */
      throw new ApiError(500, 'Unexpected health status');
    },
  });
}

/** `GET /api/v1/events` - the immutable audit chain feed. */
export function useActivityFeed(): UseQueryResult<EventFeed> {
  return useQuery<EventFeed>({
    queryKey: queryKeys.events(ACTIVITY_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1Events({ limit: ACTIVITY_LIMIT }))).data,
  });
}

/** `GET /api/v1/bypass/stats` - signal/incident counters for the section. */
export function useBypassStats(): UseQueryResult<BypassStats> {
  return useQuery<BypassStats>({
    queryKey: queryKeys.bypassStats,
    queryFn: async () => (await expectOk(await getApiV1BypassStats())).data,
  });
}

/** `GET /api/v1/bypass/incidents?status=open` - the open incidents table. */
export function useOpenBypassIncidents(): UseQueryResult<BypassIncidentList> {
  return useQuery<BypassIncidentList>({
    queryKey: queryKeys.bypassIncidents(INCIDENTS_LIMIT),
    queryFn: async () =>
      (
        await expectOk(
          await getApiV1BypassIncidents({ status: 'open', limit: INCIDENTS_LIMIT }),
        )
      ).data,
  });
}
