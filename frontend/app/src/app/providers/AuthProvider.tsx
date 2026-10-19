import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo } from 'react';
import type { ReactNode } from 'react';

import {
  getApiV1AuthWhoami,
  postApiV1AuthLogin,
  postApiV1AuthLogout,
} from '../../api/generated';
import type {
  getApiV1AuthWhoamiResponse,
  postApiV1AuthLoginResponse,
} from '../../api/generated';
import { ApiError, isBackendDown } from '../../api/http';
import type { HttpErrorBody } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import { clearSession, storeSession } from '../../api/session';
import { AuthContext } from './authContext';
import type { AuthContextValue, LoginOutcome } from './authContext';

/**
 * Session state from `GET /auth/whoami` + login/logout mutations. The
 * `POST /auth/login` 403 `mfa_required` challenge continues in exactly the
 * contract's shape (openapi /auth/login description; legacy login.html).
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const query = useQuery<getApiV1AuthWhoamiResponse>({
    queryKey: queryKeys.whoami,
    queryFn: () => getApiV1AuthWhoami(),
    retry: (failureCount, error) => !isBackendDown(error) && failureCount < 2,
    staleTime: 30_000,
  });

  const login = useCallback(
    async (
      username: string,
      password: string,
      extra?: {
        login_challenge?: string;
        totp_code?: string;
        otp_challenge_id?: string;
        otp_code?: string;
      },
    ): Promise<LoginOutcome> => {
      const res: postApiV1AuthLoginResponse = await postApiV1AuthLogin({
        username,
        password,
        ...extra,
      });
      if (res.status === 200) {
        const mint = res.data;
        if (!mint.session_token) {
          // Honest refusal: a 200 without a minted session is a contract
          // violation, not a session - never store half a login.
          throw new ApiError(res.status, 'Login reply carried no session token.');
        }
        storeSession(mint.session_token, mint.csrf_token);
        await queryClient.invalidateQueries({ queryKey: queryKeys.whoami });
        return { kind: 'ok' };
      }
      const body = res.data as unknown as HttpErrorBody;
      if (res.status === 403 && body.status === 'mfa_required' && body.challenge) {
        return { kind: 'mfa-required', challenge: body.challenge };
      }
      throw new ApiError(
        res.status,
        body.error ?? `Login refused (${res.status}).`,
        body.details,
        body.status,
        body,
      );
    },
    [queryClient],
  );

  const logout = useCallback(async (): Promise<void> => {
    try {
      await postApiV1AuthLogout(); // best effort - a down backend must not trap the session
    } catch {
      /* backend-down: local logout still proceeds */
    }
    clearSession();
    queryClient.removeQueries({ queryKey: queryKeys.whoami });
  }, [queryClient]);

  const refresh = useCallback(async (): Promise<void> => {
    await queryClient.invalidateQueries({ queryKey: queryKeys.whoami });
  }, [queryClient]);

  const value = useMemo<AuthContextValue>(() => {
    const backendDown = isBackendDown(query.error);
    let status: AuthContextValue['status'];
    if (backendDown) {
      status = 'backend-down';
    } else if (query.error) {
      status = 'server-error';
    } else if (query.isPending || query.data === undefined) {
      status = 'loading';
    } else if (query.data.status === 200) {
      status = 'authenticated';
    } else if (query.data.status === 401 || query.data.status === 403) {
      status = 'unauthenticated';
    } else {
      status = 'server-error';
    }
    return {
      status,
      whoami: query.data?.status === 200 ? query.data.data : null,
      sessionError: query.error,
      login,
      logout,
      refresh,
    };
  }, [query.data, query.error, query.isPending, login, logout, refresh]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
