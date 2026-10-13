import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  BYPASS_INCIDENTS_BODY,
  EVENTS_BODY,
  OVERVIEW_BODY,
  bypassIncidentsRoute,
  bypassStatsRoute,
  commandCenterRoutes,
  eventsRoute,
  healthRoute,
  overviewRoute,
  stubFetch,
  whoamiRoute,
  WHOAMI_OPEN_BODY,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('CommandCenterPage (F4 screen, live contract data only)', () => {
  it('renders posture KPIs, health strip, activity feed and bypass data from the API', async () => {
    stubFetch(commandCenterRoutes());
    renderApp('/command-center');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'PAM Command Center & Posture Overview',
      }),
    ).toBeInTheDocument();

    // Health strip: the probe's own posture, verbatim.
    expect(await screen.findByText('status: ok')).toBeInTheDocument();
    expect(screen.getByText('database: ok')).toBeInTheDocument();
    expect(screen.getByText('auth: open dev mode')).toBeInTheDocument();
    expect(screen.getByText('0 algorithms')).toBeInTheDocument();

    // Posture KPI quad: real numbers from /api/v1/overview.
    expect(await screen.findByText('62.5')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 controls passed')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument(); // posture violations
    expect(screen.getByText('rotation 100% · 0 due')).toBeInTheDocument();

    // Control posture table: real controls with PASS/FAIL evidence.
    expect(await screen.findByText('WORM audit retention')).toBeInTheDocument();
    expect(screen.getByText('worm_retention_days=2555')).toBeInTheDocument();
    expect(screen.getByText('SSO provider enforced')).toBeInTheDocument();
    expect(screen.getByText('FAIL')).toBeInTheDocument();

    // Activity feed: the audit-chain entry, not a sample row.
    expect(await screen.findByText('imported')).toBeInTheDocument();
    expect(screen.getByText('LIC-DEMO')).toBeInTheDocument();

    // Bypass section: aggregates + honest "never" stamps.
    expect(await screen.findByText('2')).toBeInTheDocument(); // signals observed
    expect(screen.getByText('1 closed of 1')).toBeInTheDocument();
    expect(screen.getByText(/Last ingest: never/)).toBeInTheDocument();
    expect(screen.getByText(/Last scan: never/)).toBeInTheDocument();
  });

  it('renders the honest empty states when the server reports no rows', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      overviewRoute({
        ...OVERVIEW_BODY,
        posture: { ...OVERVIEW_BODY.posture, score: 0, violations: 0, controls: [] },
        activity: [],
      }),
      eventsRoute({ ...EVENTS_BODY, events: [], total: 0 }),
      bypassStatsRoute(),
      bypassIncidentsRoute({ ...BYPASS_INCIDENTS_BODY, incidents: [], total: 0 }),
    ]);
    renderApp('/command-center');

    expect(await screen.findByText('No controls reported.')).toBeInTheDocument();
    expect(screen.getByText('No audit events recorded yet.')).toBeInTheDocument();
    expect(screen.getByText('No open bypass incidents.')).toBeInTheDocument();
    // No fabricated sample values behind the empty tables.
    expect(screen.queryByText('LIC-DEMO')).not.toBeInTheDocument();
  });

  it("surfaces the server's verbatim error message for a failed section", async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      overviewRoute({ error: 'overview aggregation failed' }, 500),
      eventsRoute(),
      bypassStatsRoute(),
      bypassIncidentsRoute(),
    ]);
    renderApp('/command-center');

    // ApiError retries twice (QueryProvider) - allow the full window.
    const alerts = await screen.findAllByText(
      'Section unavailable: overview aggregation failed',
      {},
      { timeout: 8000 },
    );
    expect(alerts.length).toBeGreaterThan(0);
    // The failing section never shows stale or invented posture numbers.
    expect(screen.queryByText('62.5')).not.toBeInTheDocument();
  });

  it('shows the shared backend-down banner when the API is unreachable', async () => {
    // whoami + health answer; the four screen queries reject (unmatched).
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/command-center');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/network: Unhandled fetch/)).toBeInTheDocument();
    // Brief §3.2 "not connected" chips, no sample data.
    expect(screen.getAllByText('not connected').length).toBeGreaterThan(0);
    expect(screen.queryByText('62.5')).not.toBeInTheDocument();
  });

  it('renders the sync stamp from generated_at, not a fabricated clock', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      overviewRoute({
        ...OVERVIEW_BODY,
        generated_at: '2026-10-13T11:44:00.000000',
      }),
      eventsRoute(),
      bypassStatsRoute(),
      bypassIncidentsRoute(),
    ]);
    renderApp('/command-center');

    // The sync line only shows the real stamp once /overview answers.
    expect(await screen.findByText('62.5')).toBeInTheDocument();
    const sync = screen.getByText(/^Sync:/);
    expect(sync).toHaveTextContent(/2026/);
    expect(sync).not.toHaveTextContent('—');
  });

  it('has no axe violations', async () => {
    stubFetch(commandCenterRoutes());
    const { container } = renderApp('/command-center');
    await screen.findByRole('heading', { level: 1, name: /PAM Command Center/ });
    await expectNoAxeViolations(container);
  });
});
