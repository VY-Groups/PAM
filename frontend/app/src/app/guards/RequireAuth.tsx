import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate } from 'react-router';

import { BackendDownNotice } from '../error/BackendDownNotice';
import { useAuth } from '../providers/useAuth';

/**
 * Route guard (plan §3 `app/guards/`):
 * - `unauthenticated` -> redirect to /login (server said 401/403).
 * - `authenticated` (incl. open/dev posture, whose whoami answers 200) ->
 *   the server's own truth decides, the client never invents a login wall.
 * - `backend-down` / `server-error` -> the honest shared notice; NOT a
 *   redirect, because claiming "signed out" would be a lie (plan §5).
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status, sessionError } = useAuth();
  const { t } = useTranslation();

  if (status === 'loading') {
    return (
      <p
        role="status"
        className="p-space-xl font-body-md text-body-md text-on-surface-variant"
      >
        {t('shell.checkingSession')}
      </p>
    );
  }
  if (status === 'backend-down') {
    return (
      <div className="p-space-xl max-w-2xl mx-auto">
        <BackendDownNotice error={sessionError} body={t('errors.backendDown')} />
      </div>
    );
  }
  if (status === 'server-error') {
    return (
      <div className="p-space-xl max-w-2xl mx-auto">
        <BackendDownNotice
          title={t('errors.unexpectedTitle')}
          body={t('errors.unexpectedBody')}
        />
      </div>
    );
  }
  if (status === 'unauthenticated') {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}
