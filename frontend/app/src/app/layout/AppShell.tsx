import { useTranslation } from 'react-i18next';
import { Outlet } from 'react-router';

import { BackendDownNotice } from '../error/BackendDownNotice';
import { useAuth } from '../providers/useAuth';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

/**
 * The single shell (plan §1: "one copy of the shell"): fixed sidebar +
 * top bar + routed main, exactly the as-built layout classes. The shared
 * backend-down banner sits above routed content when the session cannot
 * be verified live (plan §5).
 */
export function AppShell() {
  const { t } = useTranslation();
  const { status, sessionError } = useAuth();

  return (
    <div className="min-h-screen bg-surface font-body-md text-body-md text-on-surface">
      <Sidebar />
      <div className="pl-64">
        <TopBar />
        <main className="relative pt-16 pb-12 min-h-screen bg-surface w-full px-space-xl">
          {status === 'backend-down' ? (
            <BackendDownNotice error={sessionError} body={t('errors.backendDown')} />
          ) : null}
          <Outlet />
        </main>
      </div>
    </div>
  );
}
