import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1UsersUserIdSessions,
  getApiV1Users,
  patchApiV1UsersUserId,
  postApiV1Users,
  postApiV1UsersUserIdPasswordReset,
  postApiV1UsersUserIdUnlock,
} from '../../api/generated';
import type {
  GetApiV1UsersSource,
  PatchApiV1UsersUserIdBody,
  PostApiV1UsersBody,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import type { RevokeSessionsBody, UserWriteBody, UsersListBody } from './types';

/**
 * Users & Credentials data hooks (ADR-0016 batch 11.7, `GET/POST /users`
 * + the four admin writes). Every read and write goes through the
 * generated client and `expectOk`, so failures arrive as `ApiError` with
 * the server's own message (`Admin token required ...`, `User 'x' already
 * exists`, the NIST length refusal) for verbatim rendering. The list
 * sends its `source` filter server-side exactly as the contract offers it.
 *
 * One `['users', ...]` key root: every write (create, patch active,
 * unlock, password reset, session revoke) changes the same registry rows,
 * so all mutations invalidate `usersRoot` and the table, tiles and chips
 * move together.
 */

/** Contract limit for the registry list (backend serves up to 100 rows). */
export const USERS_LIST_LIMIT = 100;

/** `GET /api/v1/users` - the console user registry (never hashes/seeds). */
export function useUsersList(
  source: GetApiV1UsersSource | '',
): UseQueryResult<UsersListBody> {
  return useQuery({
    queryKey: queryKeys.usersList(source),
    queryFn: async () =>
      expectOk(await getApiV1Users(source === '' ? undefined : { source }))
        .data as UsersListBody,
  });
}

/** Every write invalidates the whole screen root at once. */
function invalidateUsers(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: queryKeys.usersRoot });
}

/**
 * `POST /api/v1/users` - create a local account. Omit `password` and the
 * server generates a strong one returned exactly once in the answer
 * (captured `generated_password` + `password_notice`).
 */
export function useCreateUser(): UseMutationResult<
  UserWriteBody,
  unknown,
  PostApiV1UsersBody
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: PostApiV1UsersBody) =>
      expectOk(await postApiV1Users(body)).data as unknown as UserWriteBody,
    onSuccess: () => invalidateUsers(queryClient),
  });
}

/** `PATCH /api/v1/users/{id}` - activate / deactivate (revokes sessions). */
export function useUpdateUser(): UseMutationResult<
  UserWriteBody,
  unknown,
  { userId: number; body: PatchApiV1UsersUserIdBody }
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      userId,
      body,
    }: {
      userId: number;
      body: PatchApiV1UsersUserIdBody;
    }) =>
      expectOk(await patchApiV1UsersUserId(userId, body)).data as unknown as UserWriteBody,
    onSuccess: () => invalidateUsers(queryClient),
  });
}

/** `POST /api/v1/users/{id}/unlock` - clear a lockout (counters reset). */
export function useUnlockUser(): UseMutationResult<UserWriteBody, unknown, number> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (userId: number) =>
      expectOk(await postApiV1UsersUserIdUnlock(userId)).data as unknown as UserWriteBody,
    onSuccess: () => invalidateUsers(queryClient),
  });
}

/**
 * `POST /api/v1/users/{id}/password-reset` - admin-assisted reset; the
 * generated password (when none was given) is shown once (captured).
 */
export function useResetPassword(): UseMutationResult<
  UserWriteBody,
  unknown,
  { userId: number; password?: string }
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, password }: { userId: number; password?: string }) =>
      expectOk(
        await postApiV1UsersUserIdPasswordReset(
          userId,
          password ? { password } : undefined,
        ),
      ).data as unknown as UserWriteBody,
    onSuccess: () => invalidateUsers(queryClient),
  });
}

/** `DELETE /api/v1/users/{id}/sessions` - revoke every live session now. */
export function useRevokeUserSessions(): UseMutationResult<
  RevokeSessionsBody,
  unknown,
  number
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (userId: number) =>
      expectOk(await deleteApiV1UsersUserIdSessions(userId)).data as RevokeSessionsBody,
    onSuccess: () => invalidateUsers(queryClient),
  });
}
