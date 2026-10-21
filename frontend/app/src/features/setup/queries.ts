import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query';

import {
  getApiV1SetupState,
  postApiV1SetupComplete,
  putApiV1SetupProfile,
} from '../../api/generated';
import type {
  PostApiV1SetupCompleteBody,
  PutApiV1SetupProfileBody,
  SetupState,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * `GET /api/v1/setup/state` - the public first-run state (ADR-0018):
 * branding, wizard phase, SMTP posture and the two officer usernames.
 * No credential - the login card and the signed-out shell both read it.
 */
export function useSetupState(): UseQueryResult<SetupState> {
  return useQuery({
    queryKey: queryKeys.setupState,
    queryFn: async () => expectOk(await getApiV1SetupState()).data,
  });
}

/**
 * `PUT /api/v1/setup/profile` - the instance rebrand (officers while
 * setup runs, any admin after). The reply IS the fresh state, so it is
 * written straight into the cache: the login card and the shell banner
 * re-brand in the same frame the save lands.
 */
export function useUpdateSetupProfile(): UseMutationResult<
  SetupState,
  unknown,
  PutApiV1SetupProfileBody
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: PutApiV1SetupProfileBody) =>
      expectOk(await putApiV1SetupProfile(body)).data as SetupState,
    onSuccess: (data) => queryClient.setQueryData(queryKeys.setupState, data),
  });
}

/**
 * `POST /api/v1/setup/complete` - the maker-checker attestation (one-way).
 * On success the instance reports `configured: true` from then on, so the
 * state is invalidated for the shell banner and the login card.
 */
export function useCompleteSetup(): UseMutationResult<
  { message: string },
  unknown,
  PostApiV1SetupCompleteBody
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: PostApiV1SetupCompleteBody) =>
      expectOk(await postApiV1SetupComplete(body)).data as { message: string },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.setupState });
    },
  });
}
