import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  commandCenterRoutes,
  sessionEventsRoute,
  sessionListRoute,
  stubFetch,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';
import { SESSION_EVENTS_LIVE_RESPONSE } from '../../test/sessionFixtures';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** Open the console drawer from the TopBar toggle (ADR-0020 Decision 2). */
async function openDrawer() {
  fireEvent.click(await screen.findByRole('button', { name: 'Live session console' }));
}

describe('ConsoleDrawer (ADR-0020 Decision 2: recording inspector)', () => {
  it('lists live sessions from the contract and opens a recording on click', async () => {
    stubFetch([
      ...commandCenterRoutes(),
      sessionListRoute(),
      sessionEventsRoute(8, SESSION_EVENTS_LIVE_RESPONSE),
    ]);
    renderApp('/command-center');
    await openDrawer();

    // The list renders the verbatim rig capture, not invented rows.
    expect(await screen.findByText('sess-b6fe5f73')).toBeInTheDocument();
    expect(screen.getByText('sess-cdfe9165')).toBeInTheDocument();

    // Selecting a session loads its recording (events, sequence order).
    fireEvent.click(screen.getByRole('button', { name: /sess-cdfe9165/ }));
    expect(await screen.findByText('cat /var/log/deploy.log')).toBeInTheDocument();
    expect(screen.getByText('#1')).toBeInTheDocument();
    expect(screen.getByText('#2')).toBeInTheDocument();
  });

  it('renders the honest empty state when no session exists', async () => {
    stubFetch([
      ...commandCenterRoutes(),
      sessionListRoute({
        status: 200,
        body: { items: [], total: 0, limit: 200, offset: 0 },
      }),
    ]);
    renderApp('/command-center');
    await openDrawer();

    expect(await screen.findByText('No Sessions Found')).toBeInTheDocument();
  });

  it('surfaces the verbatim error when the session list fails', async () => {
    stubFetch([
      ...commandCenterRoutes(),
      sessionListRoute({ status: 500, body: { error: 'session list exploded' } }),
    ]);
    renderApp('/command-center');
    await openDrawer();

    // Non-transport failures retry twice (QueryProvider), hence the timeout.
    const failure = await screen.findByRole('alert', {}, { timeout: 10_000 });
    expect(failure).toHaveTextContent('session list exploded');
  });

  it('has no axe violations with the drawer open', async () => {
    stubFetch([...commandCenterRoutes(), sessionListRoute()]);
    const { container } = renderApp('/command-center');
    await openDrawer();
    await screen.findByText('sess-b6fe5f73');
    await expectNoAxeViolations(container);
  });
});
