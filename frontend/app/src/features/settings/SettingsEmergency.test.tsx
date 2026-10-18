import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  EMERGENCY_GRANTS_DENIED_RESPONSE,
  EMERGENCY_GRANTS_EMPTY_RESPONSE,
  EMERGENCY_GRANTS_PENDING_RESPONSE,
  EMERGENCY_OPEN_REFUSED_RESPONSE,
  EMERGENCY_OPEN_REQUESTED_RESPONSE,
  EMERGENCY_OPEN_UNAUTHORIZED_RESPONSE,
  EMERGENCY_UNAUTHORIZED_RESPONSE,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * The sealed emergency-admin card (screen 11, ADR-0015 11.4) - the
 * legacy state machine (code.html:1311-1364) ported verbatim and
 * asserted against the verbatim rig captures. The two honest-state
 * regexes below are the standing gate's own (__verify_agent.mjs:609-612),
 * transcribed - they are the 11.5 re-point contract for the React card.
 */

// Transcribed from shots_tool/__verify_agent.mjs:609-612 (the gate contract).
const GATE_STATE =
  /^(sealed - emergency-admin (grants nothing|awaits two approvals)|window OPEN - emergency-admin)/;
const GATE_GRANTS = /^(no grants on record|\d+ grant\(s\) on record)$/;

const OPEN_BUTTON = 'Request Open Grant';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/** Render the page and wait for the card's state line to settle. */
async function settledState(overrides?: Parameters<typeof settingsRoutes>[0]) {
  stubFetch(settingsRoutes(overrides));
  renderWithProviders(<SettingsPage />);
  const state = await screen.findByTestId('settings-emergency-state');
  await waitFor(() => expect(state.textContent).not.toBe('loading...'));
  return state;
}

describe('sealed emergency card (screen 11, ADR-0015 11.4)', () => {
  it('renders the gate-legal sealed state on the pristine baseline (verbatim capture)', async () => {
    stubFetch(settingsRoutes({ emergency: EMERGENCY_GRANTS_EMPTY_RESPONSE }));
    const { container } = renderWithProviders(<SettingsPage />);

    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );
    expect(state.textContent).toMatch(GATE_STATE);

    const grants = screen.getByTestId('settings-emergency-grants');
    expect(grants.textContent).toBe('no grants on record');
    expect(grants.textContent).toMatch(GATE_GRANTS);

    // The gate requires the button present (611: `openBtn && ...`) and it
    // is enabled on the pristine baseline - no pending or open grant.
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).not.toBeDisabled();

    await expectNoAxeViolations(container);
  });

  it('renders the sealed state on the rig live baseline (1 denied grant on record)', async () => {
    const state = await settledState({ emergency: EMERGENCY_GRANTS_DENIED_RESPONSE });

    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );
    expect(state.textContent).toMatch(GATE_STATE);

    const grants = screen.getByTestId('settings-emergency-grants');
    expect(grants.textContent).toBe('1 grant(s) on record');
    expect(grants.textContent).toMatch(GATE_GRANTS);
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).not.toBeDisabled();
  });

  it('a pending grant shows the legacy line with its id and disables the button', async () => {
    const state = await settledState({ emergency: EMERGENCY_GRANTS_PENDING_RESPONSE });

    // Legacy parity text carries the grant id (code.html:1325) - richer
    // than the gate's first branch `sealed - emergency-admin awaits two
    // approvals`, which the pristine rigs can never produce (a pending
    // grant only exists after a live request). The 11.5 gate re-point
    // widens this branch to the legacy text; the page keeps it verbatim.
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - grant 1 awaits two approvals'),
    );
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).toBeDisabled();
    expect(screen.getByTestId('settings-emergency-grants').textContent).toBe(
      '1 grant(s) on record',
    );
  });

  it('an open grant shows the legacy window-OPEN line and disables the button', async () => {
    // SYNTHETIC input (NOT a fixture): opening a real window needs two
    // distinct approvals and leaves the emergency admin usable - never
    // done on a rig, so no capture exists. The rendered string is the
    // legacy template (code.html:1323-1324), asserted verbatim.
    const state = await settledState({
      emergency: {
        status: 200,
        body: {
          grants: [
            {
              approvals: [
                {
                  approver: 'approver-one',
                  created_at: '2026-10-18T11:09:10.000000',
                  decision: 'approve',
                  grant_id: 1,
                  id: 1,
                  note: '',
                },
                {
                  approver: 'approver-two',
                  created_at: '2026-10-18T11:09:11.000000',
                  decision: 'approve',
                  grant_id: 1,
                  id: 2,
                  note: '',
                },
              ],
              created_at: '2026-10-18T11:08:32.629993',
              expires_at: '2026-10-18T11:23:32.629993',
              id: 1,
              opened_at: '2026-10-18T11:09:12.000000',
              reason: 'synthetic window-OPEN arm (uncapturable on a pristine rig)',
              requested_by: 'capture-114',
              rotated_at: null,
              status: 'open',
              ticket: '',
              used_at: null,
            },
          ],
          username: 'emergency-admin',
        },
      },
    });

    await waitFor(() =>
      expect(state.textContent).toBe(
        'window OPEN - emergency-admin usable until the grant expires',
      ),
    );
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).toBeDisabled();
  });

  it('asks the legacy prompt and refuses a short reason with the verbatim 400 line', async () => {
    const fetchMock = stubFetch(
      settingsRoutes({ emergencyOpen: EMERGENCY_OPEN_REFUSED_RESPONSE }),
    );
    renderWithProviders(<SettingsPage />);
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );

    const prompt = vi.spyOn(window, 'prompt').mockReturnValue('short');
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));

    // The prompt text is the legacy's own (code.html:1346-1347).
    expect(prompt).toHaveBeenCalledWith(
      'Reason for opening the emergency admin (at least 8 characters):',
    );

    // The server's refusal IS the state line (verbatim capture).
    await waitFor(() =>
      expect(state.textContent).toBe(
        'request refused: A reason of at least 8 characters is required',
      ),
    );

    const call = fetchMock.mock.calls.find(
      ([url, init]) =>
        (init as RequestInit | undefined)?.method === 'POST' &&
        String(url).includes('/auth/emergency/open'),
    );
    expect(call, 'expected the emergency open POST').toBeTruthy();
    expect(JSON.parse(String((call?.[1] as RequestInit | undefined)?.body))).toEqual({
      reason: 'short',
    });
  });

  it('cancelling the prompt makes no call and leaves the state untouched', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );

    vi.spyOn(window, 'prompt').mockReturnValue(null);
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));

    const posts = fetchMock.mock.calls.filter(
      ([url, init]) =>
        (init as RequestInit | undefined)?.method === 'POST' &&
        String(url).includes('/auth/emergency/open'),
    );
    expect(posts).toHaveLength(0);
    expect(state.textContent).toBe('sealed - emergency-admin grants nothing');
  });

  it('a granted request clears the refusal, refetches and shows the pending state', async () => {
    stubFetch(settingsRoutes({ emergencyOpen: EMERGENCY_OPEN_REFUSED_RESPONSE }));
    renderWithProviders(<SettingsPage />);
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );

    // First attempt: the verbatim 400 refusal stands on the state line.
    vi.spyOn(window, 'prompt').mockReturnValue('too short');
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));
    await waitFor(() =>
      expect(state.textContent).toBe(
        'request refused: A reason of at least 8 characters is required',
      ),
    );

    // Second attempt against the real 201: the mutation invalidates the
    // status query, the refetch answers the captured pending grant and
    // the refusal is over - legacy `loadEmergency()` parity (1355-1357).
    stubFetch(
      settingsRoutes({
        emergency: EMERGENCY_GRANTS_PENDING_RESPONSE,
        emergencyOpen: EMERGENCY_OPEN_REQUESTED_RESPONSE,
      }),
    );
    vi.spyOn(window, 'prompt').mockReturnValue('a full dual-approved window reason');
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));

    await waitFor(() =>
      expect(state.textContent).toBe('sealed - grant 1 awaits two approvals'),
    );
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).toBeDisabled();
  });

  it('a no-token open attempt renders the 401 refusal line verbatim', async () => {
    const state = await settledState({
      emergencyOpen: EMERGENCY_OPEN_UNAUTHORIZED_RESPONSE,
    });

    vi.spyOn(window, 'prompt').mockReturnValue('a full dual-approved window reason');
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));

    await waitFor(() =>
      expect(state.textContent).toBe(
        'request refused: Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
      ),
    );
  });

  it('a dead backend on the attempt lands in the legacy catch line (Failed to fetch)', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/auth\/emergency\/open(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() =>
      expect(state.textContent).toBe('sealed - emergency-admin grants nothing'),
    );

    vi.spyOn(window, 'prompt').mockReturnValue('a full dual-approved window reason');
    fireEvent.click(screen.getByRole('button', { name: OPEN_BUTTON }));

    // Legacy catch: `request refused: ${err.message}` (code.html:1361) -
    // the transport message is the same 'Failed to fetch' the legacy
    // browser fetch throws, so the line is byte-identical parity.
    await waitFor(() => expect(state.textContent).toBe('request refused: Failed to fetch'));
  });

  it('a dead status read says unreachable and leaves the grants line at —', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/auth\/emergency(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);

    // Transport failures are never retried (QueryProvider), so the
    // honest line lands immediately - and the grants line stays the
    // legacy "—" untouched on error (code.html:1335-1338), the button
    // stays disabled (no data).
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() => expect(state.textContent).toBe('unreachable'));
    expect(screen.getByTestId('settings-emergency-grants').textContent).toBe('\u2014');
    expect(screen.getByRole('button', { name: OPEN_BUTTON })).toBeDisabled();
  });

  it('a no-token status read says unreachable (the 401 is never shown as data)', async () => {
    stubFetch(settingsRoutes({ emergency: EMERGENCY_UNAUTHORIZED_RESPONSE }));
    renderWithProviders(<SettingsPage />);

    // Non-transport failures retry twice (QueryProvider), hence the timeout.
    const state = await screen.findByTestId('settings-emergency-state');
    await waitFor(() => expect(state.textContent).toBe('unreachable'), { timeout: 10_000 });
    expect(screen.getByTestId('settings-emergency-grants').textContent).toBe('\u2014');
  });
});
