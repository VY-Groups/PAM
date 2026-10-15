import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  WHOAMI_OPEN_BODY,
  commandCenterRoutes,
  healthRoute,
  stubFetch,
  vaultRoutes,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** The i18n catalogue's sidebar labels (ADR-0010: no embedded strings). */
const NAV_LABELS = [
  'Command Center',
  'Credential Vault',
  'JIT Access & Approvals',
  'Live Session Hub',
  'Target Infrastructure',
  'Policy & Zero Trust',
  'Compliance & SOC2',
  'Licensing & Entitlements',
  'Emergency Break-Glass',
  'Vendor Access',
  'Settings',
];

describe('AppShell (F3 exit: shell renders live nav)', () => {
  it('renders one nav link per ADR-0005 route with the right hrefs', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/command-center');
    const nav = await screen.findByRole('navigation', { name: 'Primary navigation' });
    const links = Array.from(nav.querySelectorAll('a'));
    expect(links).toHaveLength(NAV_LABELS.length);
    for (const label of NAV_LABELS) {
      const link = screen.getByRole('link', { name: label });
      expect(link).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: 'Command Center' })).toHaveAttribute(
      'href',
      '/command-center',
    );
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute(
      'href',
      '/settings',
    );
  });

  it('marks the active route with aria-current=page (NavLink)', async () => {
    stubFetch(vaultRoutes());
    renderApp('/vault');
    const active = await screen.findByRole('link', { name: 'Credential Vault' });
    await waitFor(() => expect(active).toHaveAttribute('aria-current', 'page'));
  });

  it('renders the honest whoami identity chip (principal + role)', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    expect(await screen.findByText('Role: admin')).toBeInTheDocument();
    expect(screen.getByText('open')).toBeInTheDocument();
  });

  it('offers the break-glass shortcut and sign out', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    expect(await screen.findByRole('link', { name: 'Break-Glass' })).toHaveAttribute(
      'href',
      '/break-glass',
    );
    expect(screen.getByRole('button', { name: /Sign out/i })).toBeInTheDocument();
  });

  it('renders the honest F4-pending screen with its live legacy link', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/break-glass');
    expect(
      await screen.findByRole('heading', { name: /arrives at F4/ }),
    ).toBeInTheDocument();
    const legacy = screen.getByRole('link', { name: /Open the legacy screen/i });
    expect(legacy).toHaveAttribute(
      'href',
      '/screens/break_glass_emergency_protocol/code.html',
    );
  });

  it('has no axe violations', async () => {
    stubFetch(commandCenterRoutes());
    const { container } = renderApp('/command-center');
    await screen.findByRole('heading', { name: /PAM Command Center/ });
    await expectNoAxeViolations(container);
  });
});
