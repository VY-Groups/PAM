import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { settingsRoutes, stubFetch } from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * `window.settingsLive` (screen 11, ADR-0015 11.4) - the export in the
 * exact legacy shape (code.html:2174-2177) that the standing gate's
 * Settings block reads: type-checked at __verify_agent.mjs:361-363 (cluster)
 * and 411-413 (rbac) - `load` a function, `state` truthy - and the gate
 * AWAITS `window.settingsLive.cluster.load()` at :717 before re-reading
 * the cluster summary. This suite mirrors those gate lines exactly and
 * proves `load()` really refetches.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

async function renderedSettled() {
  stubFetch(settingsRoutes());
  renderWithProviders(<SettingsPage />);
  await screen.findByTestId('settings-cluster-summary');
  await screen.findByTestId('settings-rbac-summary');
  return window.settingsLive;
}

describe('window.settingsLive (screen 11, ADR-0015 11.4)', () => {
  it('installs the legacy-shaped export while the settings page is mounted', async () => {
    const live = await renderedSettled();

    // The gate's exact type-checks (361-363, 411-413), transcribed.
    expect(live).toBeTruthy();
    expect(typeof live?.cluster.load).toBe('function');
    expect(!!live?.cluster.state).toBe(true);
    expect(typeof live?.rbac.load).toBe('function');
    expect(!!live?.rbac.state).toBe(true);
  });

  it('cluster.state carries the settled overview (reachable, role, self)', async () => {
    const live = await renderedSettled();
    const state = live?.cluster.state;

    // The captured overview IS the state (topology fixture): the read
    // itself is the reachable proof, the role mirrors self.role.
    expect(state?.reachable).toBe(true);
    expect(state?.role).toBe('active');
    expect(state?.self?.name).toBe('pam-node-1');
  });

  it('cluster.state is the honest skeleton before any read settles', async () => {
    // The cluster read fails on this page: the pre-settle skeleton the
    // gate still type-checks (`state` truthy, like the legacy clusterLive
    // initial object) - reachable false, role unknown, no invented data.
    stubFetch(settingsRoutes().filter((route) => !route.match('/api/v1/cluster')));
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(window.settingsLive?.cluster.state).toEqual({
        reachable: false,
        role: 'unknown',
      });
    });
  });

  it('awaiting cluster.load() refetches the cluster overview (gate :717 contract)', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    await screen.findByTestId('settings-cluster-summary');
    const clusterGets = () =>
      fetchMock.mock.calls.filter(([url]) => /\/api\/v1\/cluster(\?|$)/.test(String(url)));
    const before = clusterGets().length;

    await window.settingsLive?.cluster.load();

    await waitFor(() => expect(clusterGets().length).toBeGreaterThan(before));
  });

  it('awaiting rbac.load() refetches roles AND bindings (legacy loadRbac parity)', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    await screen.findByTestId('settings-rbac-summary');
    const rbacGets = () =>
      fetchMock.mock.calls.filter(([url]) =>
        /\/api\/v1\/(roles|role-bindings)(\?|$)/.test(String(url)),
      );
    const before = rbacGets().length;

    await window.settingsLive?.rbac.load();

    await waitFor(() => expect(rbacGets().length).toBeGreaterThanOrEqual(before + 2));
  });

  it('rbac.state carries the settled rows', async () => {
    const live = await renderedSettled();
    const state = live?.rbac.state;

    expect(state?.reachable).toBe(true);
    expect(state?.roles.length).toBe(5);
    expect(state?.bindings.length).toBeGreaterThanOrEqual(1);
  });

  it('unmount removes the export (it exists exactly while the page does)', async () => {
    stubFetch(settingsRoutes());
    const { unmount } = renderWithProviders(<SettingsPage />);
    await waitFor(() => expect(window.settingsLive).toBeTruthy());

    unmount();

    expect(window.settingsLive).toBeUndefined();
  });
});
