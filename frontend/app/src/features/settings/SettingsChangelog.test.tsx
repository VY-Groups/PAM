import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import { SETTINGS_AUDIT_RESPONSE, settingsRoutes, stubFetch } from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * Config Audit Changelog (screen 11, ADR-0015 11.3) - a verbatim
 * translation of the legacy `loadAudit` renderer (code.html:1774-1803).
 * The capture is the open rig's real history: the gate's own gateway
 * flips by actor `gate`, newest first - the exact lines the legacy page
 * renders.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

async function renderChangelog(overrides?: Parameters<typeof settingsRoutes>[0]) {
  stubFetch(settingsRoutes(overrides));
  const rendered = renderWithProviders(<SettingsPage />);
  return {
    ...rendered,
    list: await screen.findByTestId('settings-changelog-list'),
  };
}

describe('config audit changelog (screen 11, ADR-0015) - 11.3', () => {
  it('renders the captured history newest-first with the legacy line format', async () => {
    const { list } = await renderChangelog();

    await waitFor(() =>
      expect(list.children).toHaveLength(SETTINGS_AUDIT_RESPONSE.body.events.length),
    );
    // The capture's newest event: gate's gateway flip, field label
    // translated, action + relative time on the sub-line.
    const newest = list.children[0] as HTMLElement;
    expect(newest).toHaveTextContent('gate updated gateway — Enabled');
    expect(within(newest).getByText(/^updated · /)).toBeTruthy();
    // The newest dot wears the primary colour (legacy renderer).
    expect(newest.querySelector('div')?.className ?? '').toContain('bg-primary');
    // Every captured event rendered, in order.
    expect(list.children[19]).toHaveTextContent('updated');
  });

  it('the Full Log link opens the raw endpoint like the legacy page', async () => {
    await renderChangelog();

    const link = screen.getByRole('link', { name: 'Full Log' });
    expect(link).toHaveAttribute('href', '/api/v1/settings/audit');
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('a fresh node says so honestly (empty history)', async () => {
    const { list } = await renderChangelog({
      audit: { status: 200, body: { events: [] } },
    });
    expect(await screen.findByText('No configuration changes recorded yet.')).toBeTruthy();
    expect(list.children).toHaveLength(1);
  });

  it('an unreachable audit says so honestly - never an empty timeline', async () => {
    // A transport failure is never retried (QueryProvider ADR-0004
    // policy), so the honest unavailable line lands immediately.
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/settings\/audit(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    const { container } = renderWithProviders(<SettingsPage />);
    expect(
      await screen.findByText(
        'Audit changelog unavailable (license server not reachable).',
      ),
    ).toBeTruthy();
    // The honest one-liner, and nothing else in the timeline.
    expect(
      container.querySelectorAll('[data-testid="settings-changelog-list"] > *'),
    ).toHaveLength(1);
  });

  it('passes axe with the changelog settled', async () => {
    const { container, list } = await renderChangelog();
    await waitFor(() => expect(list.children.length).toBeGreaterThan(0));
    await expectNoAxeViolations(container);
  });
});
