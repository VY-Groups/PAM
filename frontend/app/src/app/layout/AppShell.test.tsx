import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  commandCenterRoutes,
  settingsRoutes,
  stubFetch,
  vaultRoutes,
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
  'System Maps',
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

  it('renders the live Settings screen at /settings (ADR-0015 11.5 flip)', async () => {
    // The flip closed the strangler: every sidebar item is an implemented
    // route now, so /settings renders the real Platform Settings page -
    // no pending screen and no legacy link anywhere in the shell.
    stubFetch(settingsRoutes());
    renderApp('/settings');
    expect(await screen.findByTestId('settings-page')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Open the legacy screen/i })).toBeNull();
    expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute(
      'href',
      '/settings',
    );
  });

  it('has no axe violations', async () => {
    stubFetch(commandCenterRoutes());
    const { container } = renderApp('/command-center');
    await screen.findByRole('heading', { name: /PAM Command Center/ });
    await expectNoAxeViolations(container);
  });
});
