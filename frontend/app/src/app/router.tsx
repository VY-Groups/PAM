import type { DataRouter, RouteObject } from 'react-router';
import { createBrowserRouter, Navigate } from 'react-router';

import { NotFound } from './error/NotFound';
import { RequireAuth } from './guards/RequireAuth';
import { PendingScreen } from './PendingScreen';
import { AppShell } from './layout/AppShell';
import { NAV_ITEMS } from './layout/nav';
import { CommandCenterPage } from '../features/command-center/CommandCenterPage';
import { LoginPage } from '../features/auth/pages/LoginPage';

/**
 * The ADR-0005 route table under the `/app` basename (ADR-0012). Every
 * feature route renders the honest F4-pending state with its live legacy
 * link until its screen migrates (plan §8 strangler); Command Center is
 * the first F4 replacement (live data), the shell, guards and 404 are
 * real from F3 on.
 */
export const routes: RouteObject[] = [
  { path: '/login', element: <LoginPage /> },
  {
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to="/command-center" replace /> },
      { path: '/command-center', element: <CommandCenterPage /> },
      ...NAV_ITEMS.filter((item) => item.path !== '/command-center').map((item) => ({
        path: item.path,
        element: <PendingScreen titleKey={item.labelKey} legacyHref={item.legacyHref} />,
      })),
      { path: '*', element: <NotFound /> },
    ],
  },
];

/** Browser router for the real app (basename collapses at F5, ADR-0005). */
export function createAppRouter(): DataRouter {
  return createBrowserRouter(routes, { basename: '/app' });
}
