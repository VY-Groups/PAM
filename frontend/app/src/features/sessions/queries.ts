import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1JitRequestsRequestId,
  getApiV1Sessions,
  getApiV1SessionsSessionId,
  getApiV1SessionsSessionIdEvents,
  getApiV1SessionsStats,
  getApiV1VaultItems,
  postApiV1Sessions,
  postApiV1SessionsSessionIdControls,
  postApiV1SessionsSessionIdLock,
  postApiV1SessionsSessionIdPause,
  postApiV1SessionsSessionIdResume,
  postApiV1SessionsSessionIdTerminate,
} from '../../api/generated';
import type {
  JitRequestDetail,
  SessionControlsUpdate,
  SessionDetail,
  SessionEndResponse,
  SessionEventList,
  SessionList,
  SessionResponse,
  SessionStartRequest,
  SessionStats,
  VaultItemList,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Live Session Hub data hooks (F4 screen 4, plan §4 line 108: "Event
 * stream, controls, watermark overlay; live player later"). Every read
 * goes through the generated client and `expectOk`; every write carries
 * the real signed-in principal in the contract's `X-Actor` header so the
 * server-side trail names a human. One `['sessions', ...]` key root means
 * any mutation refreshes the whole screen from server truth - no
 * optimistic session state (a pause either happened or it did not).
 *
 * The list, detail and recording poll every 15 seconds while the screen
 * is mounted: this is a live-monitoring console and the legacy hub
 * refreshed on the same cadence. The tests never advance that far, so
 * polling cannot mask a rendering bug.
 */

/** The screen's list page (the legacy hub loaded up to 200 rows). */
export const SESSIONS_LIMIT = 200;
/** Recording rows per session in the stream (contract default 500). */
export const EVENTS_LIMIT = 500;
/** Live-data poll cadence, mirroring the legacy hub's 15 s reload. */
const LIVE_POLL_MS = 15_000;

/** `X-Actor` header (contract: writes that name an actor accept it). */
function actorHeaders(actor: string): { headers: Record<string, string> } {
  return { headers: { 'X-Actor': actor.slice(0, 64) } };
}

/** Every screen read lives under the shared `sessions` root. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['sessions'] });
}

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/sessions/stats` - real monitoring aggregates. */
export function useSessionStats(): UseQueryResult<SessionStats> {
  return useQuery<SessionStats>({
    queryKey: queryKeys.sessionStats,
    queryFn: async () => (await expectOk(await getApiV1SessionsStats())).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/sessions` - the session list, newest first. */
export function useSessionList(): UseQueryResult<SessionList> {
  return useQuery<SessionList>({
    queryKey: queryKeys.sessions(SESSIONS_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1Sessions({ limit: SESSIONS_LIMIT }))).data,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/sessions/{id}` - session + watermark + gateway half. */
export function useSessionDetail(sessionId: number | null): UseQueryResult<SessionDetail> {
  return useQuery<SessionDetail>({
    queryKey: queryKeys.sessionDetail(sessionId),
    queryFn: async () =>
      (await expectOk(await getApiV1SessionsSessionId(sessionId as number))).data,
    enabled: sessionId !== null,
    refetchInterval: LIVE_POLL_MS,
  });
}

/** `GET /api/v1/sessions/{id}/events` - the recording, sequence order. */
export function useSessionEvents(
  sessionId: number | null,
): UseQueryResult<SessionEventList> {
  return useQuery<SessionEventList>({
    queryKey: queryKeys.sessionEvents(sessionId),
    queryFn: async () =>
      (
        await expectOk(
          await getApiV1SessionsSessionIdEvents(sessionId as number, {
            limit: EVENTS_LIMIT,
          }),
        )
      ).data,
    enabled: sessionId !== null,
    refetchInterval: LIVE_POLL_MS,
  });
}

/**
 * `GET /api/v1/jit/requests/{id}` - the session's linked grant, for the
 * governance panel (access source, server-truth quorum, expiry). Only
 * fetched when the session carries a `jit_request_id`.
 */
export function useSessionGrant(
  requestId: number | null,
): UseQueryResult<JitRequestDetail> {
  return useQuery<JitRequestDetail>({
    queryKey: queryKeys.sessionGrant(requestId),
    queryFn: async () =>
      (await expectOk(await getApiV1JitRequestsRequestId(requestId as number))).data,
    enabled: requestId !== null,
  });
}

/**
 * `GET /api/v1/vault/items` - the start dialog's credential picker, same
 * endpoint and limit the legacy start overlay loaded.
 */
export function useStartCredentials(): UseQueryResult<VaultItemList> {
  return useQuery<VaultItemList>({
    queryKey: queryKeys.vaultItems(SESSIONS_LIMIT),
    queryFn: async () =>
      (await expectOk(await getApiV1VaultItems({ limit: SESSIONS_LIMIT }))).data,
  });
}

/* ----------------------------------------------------------------- writes */

/** `POST /api/v1/sessions` - start a session (risk scored server-side). */
export function useStartSession(): UseMutationResult<
  SessionResponse,
  Error,
  SessionStartRequest & { actor: string }
> {
  const queryClient = useQueryClient();
  return useMutation<SessionResponse, Error, SessionStartRequest & { actor: string }>({
    mutationFn: async ({ actor, ...payload }) =>
      (await expectOk(await postApiV1Sessions(payload, actorHeaders(actor)))).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

export type SessionLifecycleKind = 'pause' | 'lock' | 'resume';

export interface SessionLifecycleVars {
  kind: SessionLifecycleKind;
  sessionId: number;
  actor: string;
}

/**
 * `POST /api/v1/sessions/{id}/{pause|lock|resume}` - the supervisor
 * controls in one mutation so the toolbar shares one pending/error state.
 * The server decides the legal transition (contract 409s); the UI only
 * offers what the current state allows.
 */
export function useSessionLifecycle(): UseMutationResult<
  SessionResponse,
  Error,
  SessionLifecycleVars
> {
  const queryClient = useQueryClient();
  return useMutation<SessionResponse, Error, SessionLifecycleVars>({
    mutationFn: async ({ kind, sessionId, actor }) => {
      const options = actorHeaders(actor);
      if (kind === 'pause') {
        return (await expectOk(await postApiV1SessionsSessionIdPause(sessionId, options)))
          .data;
      }
      if (kind === 'lock') {
        return (await expectOk(await postApiV1SessionsSessionIdLock(sessionId, options)))
          .data;
      }
      return (await expectOk(await postApiV1SessionsSessionIdResume(sessionId, options)))
        .data;
    },
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/sessions/{id}/terminate` - the kill switch: the response
 * carries the release-and-rotate cascade the UI must report verbatim
 * (checkout released, credential rotated, or the rotation error).
 */
export function useTerminateSession(): UseMutationResult<
  SessionEndResponse,
  Error,
  { sessionId: number; actor: string; reason?: string }
> {
  const queryClient = useQueryClient();
  return useMutation<
    SessionEndResponse,
    Error,
    { sessionId: number; actor: string; reason?: string }
  >({
    mutationFn: async ({ sessionId, actor, reason }) =>
      (
        await expectOk(
          await postApiV1SessionsSessionIdTerminate(
            sessionId,
            reason === undefined || reason === '' ? undefined : { reason },
            actorHeaders(actor),
          ),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/sessions/{id}/controls` - flip control flags (audited). */
export function useUpdateControls(): UseMutationResult<
  SessionResponse,
  Error,
  { sessionId: number; actor: string; update: SessionControlsUpdate }
> {
  const queryClient = useQueryClient();
  return useMutation<
    SessionResponse,
    Error,
    { sessionId: number; actor: string; update: SessionControlsUpdate }
  >({
    mutationFn: async ({ sessionId, actor, update }) =>
      (
        await expectOk(
          await postApiV1SessionsSessionIdControls(sessionId, update, actorHeaders(actor)),
        )
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}
