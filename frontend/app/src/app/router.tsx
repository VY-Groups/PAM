import type { DataRouter, RouteObject } from 'react-router';
import { createBrowserRouter, Navigate } from 'react-router';

import { NotFound } from './error/NotFound';
import { RequireAuth } from './guards/RequireAuth';
import { PendingScreen } from './PendingScreen';
import { AppShell } from './layout/AppShell';
import { NAV_ITEMS } from './layout/nav';
import type { NavItem } from './layout/nav';
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
import { TopologyPage } from '../features/topology/TopologyPage';
import { LoginPage } from '../features/auth/pages/LoginPage';
import { SettingsPage } from '../features/settings/SettingsPage';
import { UsersPage } from '../features/users/UsersPage';

/**
 * The ADR-0005 route table under the `/app` basename (ADR-0012). Every
 * feature route renders the honest F4-pending state with its live legacy
 * link until its screen migrates (plan §8 strangler); Command Center,
 * Credential Vault, JIT Access, the Live Session Hub, Policy & Zero
 * Trust, Compliance & SOC2, Target Infrastructure, Vendor Access,
 * the Emergency Break-Glass, Enterprise Licensing and the ADR-0013
 * System & Workflow Maps are the implemented surfaces (live data), the
 * shell, guards and 404 are real from F3 on.
 */

/** Sidebar paths with a real F4 page - everything else falls back below. */
const F4_LIVE_ROUTES = new Set([
  '/command-center',
  '/vault',
  '/jit',
  '/sessions',
  '/policy',
  '/compliance',
  '/infrastructure',
  '/vendor-access',
  '/break-glass',
  '/licensing',
  '/topology',
  // ADR-0015 11.5: the Platform Settings flip - the strangle is complete,
  // so /settings is a live route and carries no pending fallback.
  '/settings',
  // ADR-0016 11.7: Users & Credentials - F4-native (no legacy screen
  // existed), live with its batch.
  '/users',
]);

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
      { path: '/topology', element: <TopologyPage /> },
      { path: '/settings', element: <SettingsPage /> },
      { path: '/users', element: <UsersPage /> },
      // ADR-0013 invariant: a pending fallback needs a legacy URL, so a
      // nav item without one must be implemented above (the type
      // predicate keeps the compiler honest).
      ...NAV_ITEMS.filter(
        (item): item is NavItem & { legacyHref: string } =>
          !F4_LIVE_ROUTES.has(item.path) && typeof item.legacyHref === 'string',
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
