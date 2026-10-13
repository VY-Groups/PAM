import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  SECRET_REVEAL_BODY,
  VAULT_EVENTS_BODY,
  VAULT_ITEMS_BODY,
  VAULT_STATS_BODY,
  healthRoute,
  stubFetch,
  vaultEventsRoute,
  vaultItemDetailRoute,
  vaultItemsRoute,
  vaultRoutes,
  vaultSecretRoute,
  vaultStatsRoute,
  whoamiRoute,
  WHOAMI_OPEN_BODY,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** Item 2 ("payments-db app") is `available` - it carries the Check out action. */
const AVAILABLE_ITEM = VAULT_ITEMS_BODY.items[1];

describe('VaultPage (F4 screen 2, live contract data only)', () => {
  it('renders posture KPIs, inventory and the audit feed from the API', async () => {
    stubFetch(vaultRoutes());
    renderApp('/vault');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Enterprise Credential Vault',
      }),
    ).toBeInTheDocument();

    // Posture KPI quad: real numbers from /api/v1/vault/stats.
    expect(await screen.findByText('2')).toBeInTheDocument(); // managed credentials
    expect(screen.getByText('100%')).toBeInTheDocument(); // rotation compliance
    expect(screen.getByText('2 secret versions at rest')).toBeInTheDocument();
    expect(screen.getByText('0 due · 0 on demand')).toBeInTheDocument();
    expect(screen.getByText('1 checkouts today · 0 rotations today')).toBeInTheDocument();

    // Inventory: contract rows, never a sample string.
    // (The credential name also appears in the audit feed - assert both.)
    expect((await screen.findAllByText('bastion-01 root')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('payments-db app').length).toBeGreaterThan(0);
    expect(screen.getByText('Primary bastion administrator')).toBeInTheDocument();
    expect(screen.getByText('bastion-01.lab')).toBeInTheDocument();
    expect(screen.getByText('svc_payments')).toBeInTheDocument();
    expect(screen.getByText('Every 1d')).toBeInTheDocument();
    expect(screen.getByText('due in 23h')).toBeInTheDocument();
    expect(screen.getByText('Tier: Tier-0')).toBeInTheDocument();
    expect(screen.getByText('checked out by j.okafor')).toBeInTheDocument();

    // Per-row lifecycle actions from the real status machine.
    expect(
      screen.getByRole('button', { name: 'Revoke: bastion-01 root' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Check out: payments-db app' }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Rotate now/ }).length).toBe(1);

    // Audit feed: the newest vault events, verbatim.
    expect(await screen.findByText('checked_out')).toBeInTheDocument();
    expect(screen.getByText('onboarded')).toBeInTheDocument();
    expect(screen.getAllByText('j.okafor').length).toBeGreaterThan(0);
  });

  it('renders the honest empty states when the vault has no items', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      vaultStatsRoute({
        ...VAULT_STATS_BODY,
        total: 0,
        by_status: {
          available: 0,
          checked_out: 0,
          failed: 0,
          rotating: 0,
          rotation_due: 0,
        },
        checked_out: 0,
        events_today: { checkouts: 0, rotations: 0 },
        secrets: { managed: 0, unmanaged: 0, versions: 0 },
      }),
      vaultItemsRoute({ ...VAULT_ITEMS_BODY, items: [], total: 0 }),
      vaultEventsRoute({ ...VAULT_EVENTS_BODY, events: [], total: 0 }),
    ]);
    renderApp('/vault');

    expect(await screen.findByText('No credentials on board yet.')).toBeInTheDocument();
    expect(screen.getByText('No vault events recorded yet.')).toBeInTheDocument();
    // No fabricated sample rows behind the empty tables.
    expect(screen.queryByText('bastion-01 root')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Check out/ })).not.toBeInTheDocument();
  });

  it("surfaces the server's verbatim error message for a failed section", async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      vaultStatsRoute(),
      vaultItemsRoute({ error: 'vault inventory failed' }, 500),
      vaultEventsRoute(),
    ]);
    renderApp('/vault');

    // ApiError retries (QueryProvider) - allow the full window.
    const alerts = await screen.findAllByText(
      'Section unavailable: vault inventory failed',
      {},
      { timeout: 8000 },
    );
    expect(alerts.length).toBeGreaterThan(0);
    // The failing inventory never shows stale rows or action buttons;
    // (the audit feed section loads independently and may name credentials).
    expect(screen.queryByRole('button', { name: /Revoke/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Check out/ })).not.toBeInTheDocument();
  });

  it('shows the shared backend-down banner when the API is unreachable', async () => {
    // whoami + health answer; the three vault queries reject (unmatched).
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/vault');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/network: Unhandled fetch/)).toBeInTheDocument();
    // Brief §3.2 "not connected" chips, no sample data.
    expect(screen.getAllByText('not connected').length).toBeGreaterThan(0);
    expect(screen.queryByText('bastion-01 root')).not.toBeInTheDocument();
  });

  it('checks out a credential and records the session principal as X-Actor', async () => {
    const fetchMock = stubFetch([
      ...vaultRoutes(),
      {
        match: (url: string) => url.endsWith('/vault/items/2/checkout'),
        respond: () =>
          new Response(
            JSON.stringify({
              item: { ...AVAILABLE_ITEM, status: 'checked_out', checked_out_by: 'open' },
              message: 'Credential checked out',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
      },
    ]);
    renderApp('/vault');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Check out: payments-db app' }),
    );

    // The server's own success message renders verbatim in the status line.
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Done: Credential checked out',
    );

    // The POST carried the real whoami principal (`open`) as X-Actor.
    const checkoutCall = fetchMock.mock.calls.find(([input]) =>
      String(input).endsWith('/vault/items/2/checkout'),
    );
    expect(checkoutCall).toBeDefined();
    const headers = new Headers((checkoutCall?.[1] as RequestInit | undefined)?.headers);
    expect(headers.get('X-Actor')).toBe('open');
  });

  it('reveals a secret once, labels its entropy and clears it on close', async () => {
    stubFetch([...vaultRoutes(), vaultItemDetailRoute(), vaultSecretRoute()]);
    renderApp('/vault');

    fireEvent.click(await screen.findByRole('button', { name: 'Reveal: payments-db app' }));
    // Explicit confirmation prompt first - no silent decryption.
    expect(
      screen.getByText(
        'Reveal the current secret version for payments-db app? The reveal is recorded in the audit trail.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('revealed-secret')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Reveal secret' }));

    // The contract's SecretReveal payload, entropy labelled honestly as ~.
    const secret = await screen.findByTestId('revealed-secret');
    expect(secret).toHaveTextContent(SECRET_REVEAL_BODY.secret);
    expect(screen.getByText('entropy ~177 bits')).toBeInTheDocument();
    expect(screen.getByText('v1 · AES-256-GCM · generated')).toBeInTheDocument();

    // Hide clears the plaintext from the document (never cached, never logged).
    fireEvent.click(screen.getByRole('button', { name: 'Hide' }));
    await waitFor(() =>
      expect(screen.queryByTestId('revealed-secret')).not.toBeInTheDocument(),
    );
  });

  it('opens the version history for a credential and closes with Escape', async () => {
    stubFetch([
      ...vaultRoutes(),
      vaultItemDetailRoute({
        item: {
          ...VAULT_ITEMS_BODY.items[0],
          events: [
            {
              action: 'rotated',
              actor: 'gate',
              created_at: '2026-10-13T23:29:30.100309',
              detail: { secret_version: 1, trigger: 'manual' },
              id: 4,
              item_id: 1,
              item_name: 'bastion-01 root',
            },
            {
              action: 'checked_out',
              actor: 'j.okafor',
              created_at: '2026-10-13T23:29:03.921539',
              detail: { reason: 'inc-4821' },
              id: 3,
              item_id: 1,
              item_name: 'bastion-01 root',
            },
          ],
        },
      }),
    ]);
    renderApp('/vault');

    fireEvent.click(
      await screen.findByRole('button', { name: 'History: bastion-01 root' }),
    );

    // The modal names the credential and lists its real audit trail.
    expect(
      await screen.findByRole('heading', { name: 'History: bastion-01 root' }),
    ).toBeInTheDocument();
    expect(await screen.findByText('rotated')).toBeInTheDocument();
    // The checkout row carries the operator's real ticket reason.
    expect(screen.getByText('inc-4821')).toBeInTheDocument();
    // Version history: the item's current version + the rotated event's.
    expect(screen.getAllByText('Secret version 1').length).toBeGreaterThan(0);

    // Keyboard-only operation: Escape closes the Radix dialog (ADR-0003).
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(
        screen.queryByRole('heading', { name: 'History: bastion-01 root' }),
      ).not.toBeInTheDocument(),
    );
  });

  it('has no axe violations', async () => {
    stubFetch(vaultRoutes());
    const { container } = renderApp('/vault');
    await screen.findByRole('heading', { level: 1, name: /Enterprise Credential Vault/ });
    await expectNoAxeViolations(container);
  });
});
