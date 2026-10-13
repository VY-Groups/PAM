import { createContext } from 'react';

import type { WhoAmI } from '../../api/generated/models/whoAmI';

/**
 * Auth state from the contract (ADR-0004):
 * - `GET /auth/whoami` is the session truth: 200 = authenticated (its
 *   `mode` is `open` in dev posture - the guard honours the server, it
 *   never invents a client-side login wall), 401 = unauthenticated.
 * - Transport failures surface as `backend-down` (shared wrapper,
 *   plan §5): the shell shows the shared state instead of pretending
 *   the user is signed out.
 */
export type AuthStatus =
  'loading' | 'authenticated' | 'unauthenticated' | 'backend-down' | 'server-error';

export type LoginOutcome = { kind: 'ok' } | { kind: 'mfa-required'; challenge: string };

export interface AuthContextValue {
  status: AuthStatus;
  whoami: WhoAmI | null;
  /** The raw transport failure when the session cannot be verified. */
  sessionError: unknown;
  login: (
    username: string,
    password: string,
    extra?: { login_challenge?: string; totp_code?: string },
  ) => Promise<LoginOutcome>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
