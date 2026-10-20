import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Outlet } from 'react-router';

import { BackendDownNotice } from '../error/BackendDownNotice';
import { useAuth } from '../providers/useAuth';
import { ConsoleDrawer } from './ConsoleDrawer';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

/**
 * The single shell (plan §1: "one copy of the shell"): fixed sidebar +
 * top bar + routed main, exactly the as-built layout classes. ADR-0020
 * Decision 1 adds the skip link (refocuses main), the responsive sidebar
 * drawer state (below lg) and the console drawer toggle; the shared
 * backend-down banner sits above routed content when the session cannot
 * be verified live (plan §5).
 */
export function AppShell() {
  const { t } = useTranslation();
  const { status, sessionError } = useAuth();
  const [navOpen, setNavOpen] = useState(false);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);

  return (
    <div className="min-h-screen bg-surface font-body-md text-body-md text-on-surface">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:bg-surface-container-high focus:text-on-surface focus:px-space-md focus:py-space-sm focus:rounded-lg focus:shadow-sm"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        {t('shell.skipToContent')}
      </a>
      <Sidebar open={navOpen} onNavigate={() => setNavOpen(false)} />
      <div className="lg:pl-64">
        <TopBar
          navOpen={navOpen}
          onToggleNav={() => setNavOpen((open) => !open)}
          consoleOpen={consoleOpen}
          onToggleConsole={() => setConsoleOpen((open) => !open)}
        />
        <main
          id="main"
          ref={mainRef}
          tabIndex={-1}
          className="relative pt-16 pb-12 min-h-screen bg-surface w-full px-space-xl"
        >
          {status === 'backend-down' ? (
            <BackendDownNotice error={sessionError} body={t('errors.backendDown')} />
          ) : null}
          <Outlet />
        </main>
      </div>
      {consoleOpen ? <ConsoleDrawer onClose={() => setConsoleOpen(false)} /> : null}
    </div>
  );
}
