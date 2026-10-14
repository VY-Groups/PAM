import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  SESSION_DETAIL_ENDED_GATEWAY_RESPONSE,
  SESSION_DETAIL_GATEWAY_ACTIVE_RESPONSE,
  SESSION_DETAIL_LIVE_RESPONSE,
  SESSION_EVENTS_LIVE_RESPONSE,
  SESSION_IDS,
  SESSION_LINKED_GRANT_RESPONSE,
  SESSIONS_LIST_RESPONSE,
  SESSIONS_STATS_RESPONSE,
  SESSION_START_RESPONSE,
  SESSION_TERMINATE_RESPONSE,
  VAULT_ITEMS_RESPONSE,
  healthRoute,
  sessionDetailRoute,
  sessionListRoute,
  sessionsRoutes,
  stubFetch,
  whoamiRoute,
  WHOAMI_OPEN_BODY,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Live Session Hub (F4 screen 4): every assertion runs against the
 * verbatim rig captures in sessionFixtures.ts - no invented values. The
 * tests prove the KPI posture, the live/ended split, the event stream
 * (including blocked evidence and withheld input), the supervisor
 * controls with the contract's X-Actor header, the start dialog, the
 * terminate cascade, the governance quorum from the server's audit
 * trail, and all three protocol-overlay line variants.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** The recorded write call for `suffix` with the given HTTP method. */
function callWrite(fetchMock: ReturnType<typeof vi.fn>, suffix: string, method: string) {
  return fetchMock.mock.calls.find(
    ([input, init]) =>
      String(input).endsWith(suffix) &&
      ((init as RequestInit | undefined)?.method ?? 'GET') === method,
  );
}

/**
 * Assert a write reached the contract: the signed-in principal as
 * `X-Actor`, and - when given - the exact JSON body the endpoint accepts.
 */
function expectWrite(
  fetchMock: ReturnType<typeof vi.fn>,
  suffix: string,
  method: string,
  body?: unknown,
): void {
  const call = callWrite(fetchMock, suffix, method);
  expect(call).toBeDefined();
  const init = call?.[1] as RequestInit | undefined;
  expect(new Headers(init?.headers).get('X-Actor')).toBe('open');
  if (body !== undefined) {
    expect(JSON.parse(String(init?.body))).toEqual(body);
  }
}

/* ---- typed views over the captured fixtures (values are server truth) --- */

interface CapturedSession {
  id: number;
  session_ref: string;
  protocol: string;
  target: string;
  actor: string;
  status: string;
  jit_request_id: number | null;
  item_id: number | null;
  duration_seconds: number;
}

const LIST = SESSIONS_LIST_RESPONSE.body as { items: CapturedSession[] };
const STATS = SESSIONS_STATS_RESPONSE.body as {
  active: number;
  paused: number;
  locked: number;
  ended: number;
  total: number;
  events_total: number;
  events_blocked: number;
  events_withheld: number;
};

function listRow(id: number): CapturedSession {
  const row = LIST.items.find((s) => s.id === id);
  if (!row) throw new Error(`fixture session row ${id} missing`);
  return row;
}

const LIVE_STATES = ['active', 'paused', 'locked'];
const liveRows = LIST.items.filter((s) => LIVE_STATES.includes(s.status));
const endedRows = LIST.items.filter((s) => !LIVE_STATES.includes(s.status));
const liveTab = `Live streams (${liveRows.length})`;
const endedTab = `Ended (${endedRows.length})`;

describe('SessionsPage (F4 screen 4, live contract data only)', () => {
  it('renders session posture, the live/ended tabs and real cards', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Live Sessions & Recording Inspection',
      }),
    ).toBeInTheDocument();

    // Posture quad: every number and footer from /sessions/stats.
    const liveCard = ((await screen.findByText('Live now')).parentElement?.parentElement ??
      null) as HTMLElement;
    expect(liveCard).not.toBeNull();
    expect(within(liveCard).getByText(String(STATS.active))).toBeInTheDocument();
    expect(
      screen.getByText(`${STATS.paused} paused · ${STATS.locked} locked`),
    ).toBeInTheDocument();
    const endedCard = ((await screen.findByText('Ended sessions')).parentElement
      ?.parentElement ?? null) as HTMLElement;
    expect(within(endedCard).getByText(String(STATS.ended))).toBeInTheDocument();
    expect(screen.getByText(`of ${STATS.total} on record`)).toBeInTheDocument();
    const blockedCard = ((await screen.findByText('Events blocked')).parentElement
      ?.parentElement ?? null) as HTMLElement;
    expect(within(blockedCard).getByText(String(STATS.events_blocked))).toBeInTheDocument();
    expect(
      screen.getByText(`${STATS.events_withheld} withheld by policy`),
    ).toBeInTheDocument();
    const eventsCard = ((await screen.findByText('Recorded events')).parentElement
      ?.parentElement ?? null) as HTMLElement;
    expect(within(eventsCard).getByText(String(STATS.events_total))).toBeInTheDocument();

    // Tabs with the real live/ended split; the live cards carry contract
    // fields (ref, protocol, target, actor, credential posture).
    expect(await screen.findByRole('tab', { name: liveTab })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: endedTab })).toBeInTheDocument();
    expect(
      await screen.findByRole('button', {
        name: `Inspect ${listRow(SESSION_IDS.jit).session_ref}`,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', {
        name: `Inspect ${listRow(SESSION_IDS.paused).session_ref}`,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', {
        name: `Inspect ${listRow(SESSION_IDS.live).session_ref}`,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(`JIT #${SESSION_IDS.linkedGrant}`)).toBeInTheDocument();
    expect(screen.getAllByText('vault credential')).toHaveLength(2);
    expect(screen.getByText('bare session')).toBeInTheDocument();
  });

  it('auto-selects the newest live session and reports its governance facts', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const linked = listRow(SESSION_IDS.jit);
    expect(
      await screen.findByRole('heading', { name: linked.session_ref }),
    ).toBeInTheDocument();
    expect(screen.getByText(`JIT request #${SESSION_IDS.linkedGrant}`)).toBeInTheDocument();

    // Quorum from the server's audit trail: recorded approvals vs the
    // required list the requested event recorded.
    const grant = SESSION_LINKED_GRANT_RESPONSE.body as {
      request: { approvals: { manager: unknown; security: unknown } };
      events: Array<{ action: string; detail: { required_approvals?: string[] } }>;
    };
    const required =
      grant.events.find((e) => e.action === 'requested')?.detail.required_approvals
        ?.length ?? 0;
    const recorded = [
      grant.request.approvals.manager,
      grant.request.approvals.security,
    ].filter((a) => a !== null && a !== undefined).length;
    expect(
      await screen.findByText(`${recorded} of ${required} required approval(s) recorded`),
    ).toBeInTheDocument();
    expect(screen.getByText('Grant expires')).toBeInTheDocument();

    // Sub-bar chips from the contract row.
    expect(screen.getByText('LIVE MONITOR')).toBeInTheDocument();
    expect(screen.getByText('RECORDING EVENTS')).toBeInTheDocument();
  });

  it('streams the recording with command prompts, blocked evidence and withheld input', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const bare = listRow(SESSION_IDS.live);
    fireEvent.click(
      await screen.findByRole('button', { name: `Inspect ${bare.session_ref}` }),
    );

    const detail = SESSION_DETAIL_LIVE_RESPONSE.body as {
      event_count: number;
      blocked_count: number;
      watermark: { fields: { user: string } };
    };
    const stream = SESSION_EVENTS_LIVE_RESPONSE.body as {
      events: Array<{
        type: string;
        content: string | null;
        allowed: boolean;
        withheld: boolean;
      }>;
    };
    const withheld = stream.events.filter((e) => e.withheld).length;
    expect(
      await screen.findByText(
        `${detail.event_count} recorded events · ${detail.blocked_count} blocked · ${withheld} withheld by policy`,
      ),
    ).toBeInTheDocument();

    // The real command prompt and content.
    expect(
      await screen.findByText(`${bare.actor}@${bare.target.split(':')[0]}:~$`),
    ).toBeInTheDocument();
    expect(screen.getByText('cat /var/log/deploy.log')).toBeInTheDocument();
    // Blocked actions stay visible as evidence, with the server's reason.
    expect(
      screen.getByText('file_upload refused (upload_not_allowed)'),
    ).toBeInTheDocument();
    expect(screen.getAllByText('kept as evidence')).toHaveLength(2);
    expect(screen.getAllByText('BLOCKED')).toHaveLength(2);
    // Withheld keystroke says so; the logged one shows its content.
    expect(screen.getByText(/input content withheld by policy/)).toBeInTheDocument();
    expect(screen.getByText(/deploy --canary/)).toBeInTheDocument();

    // The watermark card: server-assembled fields and the rendered payload.
    expect(
      screen.getByText(new RegExp(`USER: ${detail.watermark.fields.user}`)),
    ).toBeInTheDocument();
    expect(screen.getByText(/SESSION: /)).toBeInTheDocument();
  });

  it('gates the toolbar by session state and pauses through the contract', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    // The auto-selected session is active: pause/lock/terminate offer,
    // resume disabled with its honest reason.
    expect(await screen.findByRole('button', { name: 'Pause' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Lock' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Terminate' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Resume' })).toBeDisabled();
    expect(
      screen.getByTitle('Nothing to resume in the current state.'),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    await waitFor(() => {
      expectWrite(fetchMock, `/sessions/${SESSION_IDS.jit}/pause`, 'POST');
    });
    expect(await screen.findByText('Done: Session paused')).toBeInTheDocument();
  });

  it('locks the auto-selected live session through the contract', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    fireEvent.click(await screen.findByRole('button', { name: 'Lock' }));
    await waitFor(() => {
      expectWrite(fetchMock, `/sessions/${SESSION_IDS.jit}/lock`, 'POST');
    });
    expect(await screen.findByText('Done: Session locked')).toBeInTheDocument();
  });

  it('offers resume on a paused session only', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const paused = listRow(SESSION_IDS.paused);
    fireEvent.click(
      await screen.findByRole('button', { name: `Inspect ${paused.session_ref}` }),
    );
    const resume = await screen.findByRole('button', { name: 'Resume' });
    expect(resume).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled();
    expect(screen.getByTitle('Only a live session can pause.')).toBeInTheDocument();

    fireEvent.click(resume);
    await waitFor(() => {
      expectWrite(fetchMock, `/sessions/${SESSION_IDS.paused}/resume`, 'POST');
    });
    expect(await screen.findByText('Done: Session resumed')).toBeInTheDocument();
  });

  it('terminates with a recorded reason and reports the rotation cascade', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const linked = listRow(SESSION_IDS.jit);
    fireEvent.click(await screen.findByRole('button', { name: 'Terminate' }));
    expect(
      await screen.findByRole('heading', { name: `Terminate ${linked.session_ref}?` }),
    ).toBeInTheDocument();
    // The linked-grant variant of the cascade explanation.
    expect(screen.getByText(/closes its linked JIT grant/)).toBeInTheDocument();
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(linked.target)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Reason/), {
      target: { value: 'rotation drill' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Terminate session' }));
    await waitFor(() => {
      expectWrite(fetchMock, `/sessions/${SESSION_IDS.jit}/terminate`, 'POST', {
        reason: 'rotation drill',
      });
    });

    const term = SESSION_TERMINATE_RESPONSE.body as {
      message: string;
      cascade: { secret_version: number };
    };
    expect(
      await screen.findByText(
        new RegExp(
          `${term.message} .* credential rotated to version ${term.cascade.secret_version}`,
        ),
      ),
    ).toBeInTheDocument();
  });

  it('flips a control flag through the contract and reports the audit line', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const toggle = await screen.findByRole('checkbox', { name: 'Toggle Clipboard' });
    expect(toggle).toBeChecked();
    fireEvent.click(toggle);
    await waitFor(() => {
      expectWrite(fetchMock, `/sessions/${SESSION_IDS.jit}/controls`, 'POST', {
        clipboard_allowed: false,
      });
    });
    expect(await screen.findByText('Done: Controls updated')).toBeInTheDocument();
  });

  it('reports a non-linked session as a bare grant with honest dashes', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    const bare = listRow(SESSION_IDS.live);
    fireEvent.click(
      await screen.findByRole('button', { name: `Inspect ${bare.session_ref}` }),
    );
    expect(await screen.findByText('direct (no grant)')).toBeInTheDocument();
    const governance = await screen.findByRole('region', { name: 'Governance' });
    expect(within(governance).getAllByLabelText('no data').length).toBeGreaterThan(0);
  });

  it('renders the ended-gateway overlay line and frozen controls on an ended session', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    fireEvent.mouseDown(await screen.findByRole('tab', { name: endedTab }));
    const ended = listRow(SESSION_IDS.endedGateway);
    fireEvent.click(
      await screen.findByRole('button', { name: `Inspect ${ended.session_ref}` }),
    );

    expect(await screen.findByText('PLAYBACK')).toBeInTheDocument();
    expect(screen.getByTitle('This session has ended.')).toBeInTheDocument();
    expect(screen.getByTitle('Only a live session can pause.')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Toggle Record session' })).toBeDisabled();

    // The section-27/8a overlay line for a closed gateway session.
    const gw = (
      SESSION_DETAIL_ENDED_GATEWAY_RESPONSE.body as {
        gateway: {
          state: string;
          end_reason: string | null;
          node: { name: string; state: string } | null;
        };
      }
    ).gateway;
    expect(
      screen.getByText(
        new RegExp(
          `gateway session ${gw.state} \\(${gw.end_reason}\\) via node ${gw.node?.name} \\(${gw.node?.state}\\)`,
        ),
      ),
    ).toBeInTheDocument();
  });

  it('renders the connected overlay line with the injection fact', async () => {
    stubFetch(sessionsRoutes());
    renderApp('/sessions');

    fireEvent.mouseDown(await screen.findByRole('tab', { name: endedTab }));
    const gwSession = listRow(SESSION_IDS.gatewayActive);
    fireEvent.click(
      await screen.findByRole('button', { name: `Inspect ${gwSession.session_ref}` }),
    );

    const gw = (
      SESSION_DETAIL_GATEWAY_ACTIVE_RESPONSE.body as {
        gateway: {
          state: string;
          node: { name: string; state: string } | null;
          credential_injected: boolean;
          recording: { segments: number };
        };
      }
    ).gateway;
    expect(
      await screen.findByText(
        new RegExp(
          `connected — session brokered through gateway node ${gw.node?.name} \\(${gw.node?.state}\\)`,
        ),
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /credential injected for the session only \(the user never sees it\)/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        new RegExp(`${gw.recording.segments} sealed segment\\(s\\) on disk`),
      ),
    ).toBeInTheDocument();
  });

  it('validates the start dialog client-side and starts through the contract', async () => {
    const fetchMock = stubFetch(sessionsRoutes());
    renderApp('/sessions');

    fireEvent.click(await screen.findByRole('button', { name: 'Start session' }));
    expect(
      await screen.findByRole('heading', { name: 'Start a session' }),
    ).toBeInTheDocument();
    // The credential picker lists real vault items.
    const items = (VAULT_ITEMS_RESPONSE.body as { items: Array<{ name: string }> }).items;
    expect(await screen.findByText(items[0].name)).toBeInTheDocument();

    // Empty target refuses client-side (UX only) and writes nothing.
    fireEvent.click(screen.getByRole('button', { name: 'Start' }));
    expect(
      await screen.findByText('Check the highlighted fields - limits mirror the contract.'),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/sessions', 'POST')).toBeUndefined();

    fireEvent.change(screen.getByLabelText(/Target/), {
      target: { value: 'bastion-02.lab:22' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Start' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/sessions', 'POST', {
        protocol: 'ssh',
        target: 'bastion-02.lab:22',
        record: true,
        keystroke_log: true,
        watermark: true,
        clipboard_allowed: true,
        upload_allowed: true,
        download_allowed: true,
        screenshot_allowed: true,
      });
    });

    const start = SESSION_START_RESPONSE.body as {
      message: string;
      risk: { band: string; score: number };
    };
    expect(
      await screen.findByText(
        `${start.message} - risk ${start.risk.band} (score ${start.risk.score})`,
      ),
    ).toBeInTheDocument();
  });

  it('shows the honest empty states for both tabs and no selection', async () => {
    stubFetch([
      sessionListRoute({
        status: 200,
        body: { items: [], total: 0, limit: 200, offset: 0 },
      }),
      ...sessionsRoutes(),
    ]);
    renderApp('/sessions');

    expect(
      await screen.findByText('No live sessions - start one to see it here.'),
    ).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Ended (0)' }));
    expect(await screen.findByText('No ended sessions yet.')).toBeInTheDocument();
    expect(
      screen.getByText('No session selected. Start one, or pick a card above.'),
    ).toBeInTheDocument();
  });

  it('shows a verbatim section error when the detail endpoint fails', async () => {
    stubFetch([
      sessionDetailRoute(SESSION_IDS.jit, {
        status: 500,
        body: { error: 'session detail exploded' },
      }),
      ...sessionsRoutes(),
    ]);
    renderApp('/sessions');

    // Auto-select picks the newest live session, whose detail now fails.
    const alerts = await screen.findAllByText(
      'Section unavailable: session detail exploded',
      {},
      { timeout: 8000 },
    );
    expect(alerts.length).toBeGreaterThan(0);
  });

  it('shows the shared backend-down banner when the API is unreachable', async () => {
    // whoami + health answer; every screen query rejects (unmatched).
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/sessions');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText('not connected').length).toBeGreaterThan(0);
    expect(
      screen.queryByRole('button', {
        name: `Inspect ${listRow(SESSION_IDS.jit).session_ref}`,
      }),
    ).not.toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(sessionsRoutes());
    const { container } = renderApp('/sessions');
    await screen.findByRole('heading', { level: 1, name: /Live Sessions/ });
    await waitFor(() => {
      expect(
        screen.getByRole('heading', { name: listRow(SESSION_IDS.jit).session_ref }),
      ).toBeInTheDocument();
    });
    await expectNoAxeViolations(container);
  });
});
