import type { DataRouter, RouteObject } from 'react-router';
import { createBrowserRouter, Navigate } from 'react-router';

import { NotFound } from './error/NotFound';
import { RequireAuth } from './guards/RequireAuth';
import { PendingScreen } from './PendingScreen';
import { AppShell } from './layout/AppShell';
import { NAV_ITEMS } from './layout/nav';
import { CommandCenterPage } from '../features/command-center/CommandCenterPage';
import { VaultPage } from '../features/vault/VaultPage';
import { JitPage } from '../features/jit/JitPage';
import { SessionsPage } from '../features/sessions/SessionsPage';
import { PolicyPage } from '../features/policy/PolicyPage';
import { CompliancePage } from '../features/compliance/CompliancePage';
import { InfrastructurePage } from '../features/infrastructure/InfrastructurePage';
import { VendorPage } from '../features/vendor/VendorPage';
import { BreakGlassPage } from '../features/break-glass/BreakGlassPage';
import { LicensingPage } from '../features/licensing/LicensingPage';
import { LoginPage } from '../features/auth/pages/LoginPage';

/**
 * The ADR-0005 route table under the `/app` basename (ADR-0012). Every
 * feature route renders the honest F4-pending state with its live legacy
 * link until its screen migrates (plan §8 strangler); Command Center,
 * Credential Vault, JIT Access, the Live Session Hub, Policy & Zero
 * Trust, Compliance & SOC2, Target Infrastructure, Vendor Access,
 * the Emergency Break-Glass and Enterprise Licensing are the first ten
 * F4 replacements (live data), the shell, guards and 404 are real from
 * F3 on.
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
      { path: '/vault', element: <VaultPage /> },
      { path: '/jit', element: <JitPage /> },
      { path: '/sessions', element: <SessionsPage /> },
      { path: '/policy', element: <PolicyPage /> },
      { path: '/compliance', element: <CompliancePage /> },
      { path: '/infrastructure', element: <InfrastructurePage /> },
      { path: '/vendor-access', element: <VendorPage /> },
      { path: '/break-glass', element: <BreakGlassPage /> },
      { path: '/licensing', element: <LicensingPage /> },
      ...NAV_ITEMS.filter(
        (item) =>
          item.path !== '/command-center' &&
          item.path !== '/vault' &&
          item.path !== '/jit' &&
          item.path !== '/sessions' &&
          item.path !== '/policy' &&
          item.path !== '/compliance' &&
          item.path !== '/infrastructure' &&
          item.path !== '/vendor-access' &&
          item.path !== '/break-glass' &&
          item.path !== '/licensing',
      ).map((item) => ({
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
