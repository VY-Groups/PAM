import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  clusterRoute,
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
  'Approvals',
  'Credential Vault',
  'JIT Access & Approvals',
  'Live Session Hub',
  'Target Infrastructure',
  'Policy & Zero Trust',
  'Compliance & SOC2',
  'Licensing & Entitlements',
  'Emergency Break-Glass',
  'Vendor Access',
  'Users & Credentials',
  'Security & MFA',
  'Settings',
  'System Maps',
];

/**
 * The five ADR-0021 job group labels. Scoped to `div.font-code-sm` so the
 * "Approvals" heading and the "Approvals" link (same text, different roles)
 * never collide in a text query.
 */
const NAV_GROUP_LABELS = ['Access', 'Approvals', 'Sessions', 'Evidence', 'Platform'];

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

  it('renders the five ADR-0021 job groups under one navigation landmark', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/command-center');
    const nav = await screen.findByRole('navigation', { name: 'Primary navigation' });
    for (const label of NAV_GROUP_LABELS) {
      expect(
        within(nav).getByText(label, { selector: 'div.font-code-sm' }),
      ).toBeInTheDocument();
    }
    // One landmark only - the groups do not each become their own nav.
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
  });

  it('marks the active route with aria-current=page (NavLink)', async () => {
    stubFetch(vaultRoutes());
    renderApp('/vault');
    const active = await screen.findByRole('link', { name: 'Credential Vault' });
    await waitFor(() => expect(active).toHaveAttribute('aria-current', 'page'));
  });

  it('renders the honest whoami identity chip in the footer (principal + role)', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    expect(await screen.findByText('Role: admin')).toBeInTheDocument();
    expect(screen.getByText('open')).toBeInTheDocument();
  });

  it('offers the break-glass shortcut in the top bar and sign out in the footer', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    expect(await screen.findByRole('link', { name: 'Break-Glass' })).toHaveAttribute(
      'href',
      '/break-glass',
    );
    expect(screen.getByRole('button', { name: /Sign out/i })).toBeInTheDocument();
  });

  it('renders the real cluster context in the footer when the contract answers', async () => {
    stubFetch([...commandCenterRoutes(), clusterRoute()]);
    renderApp('/');
    expect(await screen.findByText('pam-node-1 · active · dc')).toBeInTheDocument();
  });

  it('the skip link refocuses the routed main region', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    const skip = await screen.findByRole('link', { name: 'Skip to content' });
    fireEvent.click(skip);
    expect(document.activeElement).toBe(screen.getByRole('main'));
  });

  it('the sidebar filter narrows the nav links client-side', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/');
    const nav = await screen.findByRole('navigation', { name: 'Primary navigation' });
    const filter = screen.getByLabelText('Filter navigation');
    fireEvent.change(filter, { target: { value: 'vault' } });
    expect(within(nav).getByRole('link', { name: 'Credential Vault' })).toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Command Center' })).toBeNull();
    // Groups whose items are all filtered out disappear entirely.
    expect(within(nav).queryByText('Platform')).toBeNull();
    fireEvent.change(filter, { target: { value: 'zzz' } });
    expect(within(nav).getByText('No pages match the filter.')).toBeInTheDocument();
    fireEvent.change(filter, { target: { value: '' } });
    expect(within(nav).getByRole('link', { name: 'Command Center' })).toBeInTheDocument();
  });

  it('bounds the nav column so the sidebar actually scrolls', async () => {
    // live-testing defect: a bare overflow-y-auto on the nav grows to its
    // content height inside an unbounded parent, so the lower nav entries
    // were clipped with no scrollbar - the chain must be height-bounded
    // (h-full aside -> flex-1 min-h-0 -> flex-1 min-h-0 overflow-y-auto).
    stubFetch(commandCenterRoutes());
    renderApp('/');
    const nav = await screen.findByRole('navigation', { name: 'Primary navigation' });
    expect(nav.className).toContain('overflow-y-auto');
    expect(nav.className).toContain('flex-1');
    expect(nav.className).toContain('min-h-0');
    const container = nav.parentElement;
    expect(container?.className).toContain('flex-1');
    expect(container?.className).toContain('min-h-0');
    expect(container?.closest('#app-sidebar')).not.toBeNull();
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
