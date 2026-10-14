import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  healthRoute,
  jitQueueRoute,
  jitRoutes,
  jitStatsRoute,
  stubFetch,
  whoamiRoute,
  WHOAMI_OPEN_BODY,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** The recorded fetch call whose URL ends with `suffix`, if any. */
function callEndingWith(fetchMock: ReturnType<typeof vi.fn>, suffix: string) {
  return fetchMock.mock.calls.find(([input]) => String(input).endsWith(suffix));
}

/**
 * The recorded write call for `suffix` with the given HTTP method: one
 * endpoint can be called twice with different verbs (e.g. PATCH then
 * DELETE /agents/2), so the method disambiguates.
 */
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

describe('JitPage (F4 screen 3, live contract data only)', () => {
  it('renders queue posture, the request queue, broker and agent consoles', async () => {
    stubFetch(jitRoutes());
    renderApp('/jit');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Just-In-Time Access & Approvals',
      }),
    ).toBeInTheDocument();

    // Queue posture quad: every number is a /jit/stats aggregate.
    expect(await screen.findByText('Requests on record')).toBeInTheDocument();
    expect(await screen.findByText('5 closed · 3 denied')).toBeInTheDocument();
    expect(screen.getByText('0 blocked by policy')).toBeInTheDocument();
    expect(screen.getByText('expiry evaluated on every read')).toBeInTheDocument();
    expect(screen.getByText('6 high · 0 critical')).toBeInTheDocument();

    // The queue: contract rows with state-driven actions only.
    expect(await screen.findByText('#JIT-6')).toBeInTheDocument();
    expect(screen.getByText('l.dube')).toBeInTheDocument();
    expect(screen.getByText('CHG-9031')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Review: request 6' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Grant: request 7' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Close: request 8' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Detail: request 1' })).toBeInTheDocument();
    // Exactly one console-side grant: approved and not agent-bound.
    expect(screen.getAllByRole('button', { name: /Grant: request/ })).toHaveLength(1);
    expect(
      screen.queryByRole('button', { name: 'Review: request 1' }),
    ).not.toBeInTheDocument();

    // Pipeline credential broker (plan line 107).
    expect(
      await screen.findByRole('heading', { name: 'Pipeline Credential Broker' }),
    ).toBeInTheDocument();
    expect(await screen.findByText('3 active · 1 revoked')).toBeInTheDocument();
    expect(await screen.findByText('3 open credential(s)')).toBeInTheDocument();
    expect(await screen.findByText('0 released by pipeline')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Approve credential request 8' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Close credential request 7' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Revoke pipeline queue-probe' }),
    ).toBeInTheDocument();

    // AI-agent access (plan line 107).
    expect(
      await screen.findByRole('heading', { name: 'AI-Agent Access' }),
    ).toBeInTheDocument();
    expect(await screen.findByText('2 active · 1 revoked')).toBeInTheDocument();
    expect(screen.getByText('3 task scopes')).toBeInTheDocument();
    expect(screen.getByText('of 3 request(s) on record')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Tasks and detail: patch-bot' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Enable: probe-bot' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Revoke agent probe-bot' }),
    ).toBeInTheDocument();
  });

  it('filters the queue through the contract query string', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');
    await screen.findByRole('button', { name: 'Review: request 6' });

    fireEvent.change(screen.getByRole('combobox', { name: 'Status' }), {
      target: { value: 'pending' },
    });
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([input]) => String(input).includes('status=pending')),
      ).toBe(true);
    });

    fireEvent.change(screen.getByRole('textbox', { name: 'Requester' }), {
      target: { value: 'l.dube' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filter' }));
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([input]) => String(input).includes('requester=l.dube')),
      ).toBe(true);
    });
  });

  it('shows server-truth quorum, risk factors and the audit trail in the detail', async () => {
    stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(await screen.findByRole('button', { name: 'Review: request 6' }));
    expect(
      await screen.findByRole('heading', { name: 'Request #JIT-6' }),
    ).toBeInTheDocument();

    // Quorum comes from the server's `requested` event, never re-derived.
    expect(
      await screen.findByText('0 of 2 required approval(s) recorded'),
    ).toBeInTheDocument();
    expect(screen.getByText('Manager: awaiting')).toBeInTheDocument();
    expect(screen.getByText('Security: awaiting')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Approve as Manager: request 6' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Approve as Security: request 6' }),
    ).toBeInTheDocument();

    // Risk: the real score, band and factor breakdown.
    expect(screen.getByText('score 60 · High')).toBeInTheDocument();
    expect(screen.getByText('Tier-0')).toBeInTheDocument();
    expect(screen.getByText('+30 pts')).toBeInTheDocument();
    expect(screen.getByText('Wednesday 02:28 local')).toBeInTheDocument();

    // The audit trail renders the capture verbatim.
    expect(await screen.findByText('requested')).toBeInTheDocument();
    expect(screen.getByText(/by l\.dube/)).toBeInTheDocument();
  });

  it('approves with the signed-in principal and shows the server message', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(await screen.findByRole('button', { name: 'Review: request 6' }));
    await screen.findByRole('heading', { name: 'Request #JIT-6' });
    // The detail query resolves async - wait for the quorum buttons to render.
    fireEvent.click(
      await screen.findByRole('button', { name: 'Approve as Manager: request 6' }),
    );

    await waitFor(() => {
      expectWrite(fetchMock, '/jit/requests/6/approve', 'POST', { role: 'manager' });
    });
    expect((await screen.findAllByText('Done: Approval recorded')).length).toBeGreaterThan(
      0,
    );
  });

  it('denies with a recorded reason in the contract body', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(await screen.findByRole('button', { name: 'Review: request 6' }));
    await screen.findByRole('heading', { name: 'Request #JIT-6' });
    fireEvent.change(
      await screen.findByRole('textbox', { name: 'Denial reason (recorded in the trail)' }),
      { target: { value: 'Outside the change window' } },
    );
    fireEvent.click(screen.getByRole('button', { name: 'Deny request' }));

    await waitFor(() => {
      expectWrite(fetchMock, '/jit/requests/6/deny', 'POST', {
        reason: 'Outside the change window',
      });
    });
    expect((await screen.findAllByText('Done: Request denied')).length).toBeGreaterThan(0);
  });

  it('files a request through the contract form (validation first)', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(await screen.findByRole('button', { name: 'File a request' }));
    expect(
      await screen.findByRole('heading', { name: 'File an access request' }),
    ).toBeInTheDocument();

    // Client validation is UX only: the empty form never reaches the network.
    fireEvent.click(screen.getByRole('button', { name: 'File request' }));
    expect(
      await screen.findByText('Check the highlighted fields - limits mirror the contract.'),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(
        ([input, init]) =>
          String(input).endsWith('/jit/requests') &&
          (init as RequestInit | undefined)?.method === 'POST',
      ),
    ).toHaveLength(0);

    fireEvent.change(screen.getByRole('textbox', { name: 'Ticket reference' }), {
      target: { value: 'CHG-7777' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason (8-255 characters)' }), {
      target: { value: 'Elevation for the incident bridge' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'File request' }));

    await waitFor(() => {
      expectWrite(fetchMock, '/jit/requests', 'POST', {
        item_id: 1,
        reason: 'Elevation for the incident bridge',
        ticket: 'CHG-7777',
        minutes: 15,
      });
    });
    // The success line is the server's message plus the server's score.
    expect(
      await screen.findByText('Request filed - risk High (score 55)'),
    ).toBeInTheDocument();
  });

  it('grants an approved request and closes a plain grant', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(await screen.findByRole('button', { name: 'Grant: request 7' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/jit/requests/7/consume', 'POST');
    });
    expect((await screen.findAllByText('Done: Access granted')).length).toBeGreaterThan(0);

    fireEvent.click(await screen.findByRole('button', { name: 'Close: request 8' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/jit/requests/8/close', 'POST');
    });
    expect(
      (await screen.findAllByText('Done: Access closed and credential rotated')).length,
    ).toBeGreaterThan(0);
  });

  it('routes agent grant closes through the agent-access endpoint', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    // Row action on the active agent grant - never the plain JIT close.
    fireEvent.click(
      (await screen.findAllByRole('button', { name: 'Close: request 13' }))[0],
    );
    await waitFor(() => {
      expectWrite(fetchMock, '/agent-access/requests/13/close', 'POST');
    });
    expect(callEndingWith(fetchMock, '/jit/requests/13/close')).toBeUndefined();

    // The detail modal routes the same grant-end the same way.
    fireEvent.click(
      (await screen.findAllByRole('button', { name: 'Detail: request 13' }))[0],
    );
    expect(
      await screen.findByRole('heading', { name: 'Request #JIT-13' }),
    ).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Close grant 13' }));
    await waitFor(() => {
      const closes = fetchMock.mock.calls.filter(([input]) =>
        String(input).endsWith('/agent-access/requests/13/close'),
      );
      expect(closes).toHaveLength(2);
    });
    expect(
      (await screen.findAllByText('Done: Access closed and credential rotated')).length,
    ).toBeGreaterThan(0);
  });

  it('tells the agent-only truth for an approved agent request', async () => {
    stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(
      (await screen.findAllByRole('button', { name: 'Detail: request 10' }))[0],
    );
    expect(
      await screen.findByRole('heading', { name: 'Request #JIT-10' }),
    ).toBeInTheDocument();

    expect(
      await screen.findByText(
        'The agent opens this grant with its own API token - the console cannot open it.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Grant ephemeral access' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Approve as Manager' }),
    ).not.toBeInTheDocument();
  });

  it('administers the credential queue: approve, deny with reason, close', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Approve credential request 8' }),
    );
    await waitFor(() => {
      expectWrite(fetchMock, '/broker/credentials/8/approve', 'POST');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Deny credential request 6' }));
    expect(
      await screen.findByRole('heading', { name: 'Deny credential request #6' }),
    ).toBeInTheDocument();
    const denyDialog = screen.getByRole('dialog');
    fireEvent.change(
      within(denyDialog).getByRole('textbox', { name: 'Reason (recorded in the trail)' }),
      { target: { value: 'Not needed for this release' } },
    );
    fireEvent.click(within(denyDialog).getByRole('button', { name: 'Deny request' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/broker/credentials/6/deny', 'POST', {
        reason: 'Not needed for this release',
      });
    });

    // The reason modal stays open after the call (honest mutation state) -
    // close it to reach the queue rows again.
    fireEvent.click(within(denyDialog).getByRole('button', { name: 'Close dialog' }));
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    fireEvent.click(
      await screen.findByRole('button', { name: 'Close credential request 7' }),
    );
    await waitFor(() => {
      expectWrite(fetchMock, '/broker/credentials/7/close', 'POST');
    });
  });

  it('registers a pipeline identity and shows its token exactly once', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    expect(screen.queryByTestId('broker-token')).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Register pipeline' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Identity name' }), {
      target: { value: 'reg-probe' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Register identity' }));

    // Synthetic fixture token: a real rig token never enters the repo.
    expect(await screen.findByTestId('broker-token')).toHaveTextContent(
      'vypam-ci1.99.SYNTHETIC-SECRET-NOT-A-REAL-TOKEN',
    );
    await waitFor(() => {
      // The full BrokerPolicyCreate payload: form values + the split
      // targets list (empty input posts an empty array, never a string).
      expectWrite(fetchMock, '/broker/policies', 'POST', {
        name: 'reg-probe',
        ci_system: 'other',
        contact: '',
        approval_mode: 'manual',
        max_ttl_minutes: 30,
        allowed_targets: [],
      });
    });

    // Closing the modal resets the mutation: the token cannot be re-shown.
    fireEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Close dialog' }),
    );
    await waitFor(() => {
      expect(screen.queryByTestId('broker-token')).not.toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Register pipeline' }));
    await screen.findByRole('dialog');
    expect(screen.queryByTestId('broker-token')).not.toBeInTheDocument();
  });

  it('revokes a pipeline identity with a recorded reason', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Revoke pipeline queue-probe' }),
    );
    expect(
      await screen.findByRole('heading', { name: 'Revoke queue-probe?' }),
    ).toBeInTheDocument();
    const dialog = screen.getByRole('dialog');
    fireEvent.change(
      within(dialog).getByRole('textbox', { name: 'Reason (recorded in the trail)' }),
      { target: { value: 'No longer used' } },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke identity' }));

    await waitFor(() => {
      expectWrite(fetchMock, '/broker/policies/3', 'DELETE', { reason: 'No longer used' });
    });
  });

  it('enables, revokes and registers agent identities', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    // Status flip: PATCH carries only the contract's status enum.
    fireEvent.click(await screen.findByRole('button', { name: 'Enable: probe-bot' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/agents/2', 'PATCH', { status: 'active' });
    });
    expect(
      (await screen.findAllByText('Done: Agent identity probe-bot updated')).length,
    ).toBeGreaterThan(0);

    // Revoke: reason recorded, the captured message names the same identity.
    fireEvent.click(screen.getByRole('button', { name: 'Revoke agent probe-bot' }));
    expect(
      await screen.findByRole('heading', { name: 'Revoke probe-bot?' }),
    ).toBeInTheDocument();
    const revokeDialog = screen.getByRole('dialog');
    fireEvent.change(
      within(revokeDialog).getByRole('textbox', { name: 'Reason (recorded in the trail)' }),
      { target: { value: 'Token exposure drill' } },
    );
    fireEvent.click(within(revokeDialog).getByRole('button', { name: 'Revoke agent' }));
    await waitFor(() => {
      expectWrite(fetchMock, '/agents/2', 'DELETE', { reason: 'Token exposure drill' });
    });
    expect(
      (
        await screen.findAllByText(
          'Done: Agent identity probe-bot revoked (1 access request(s) closed)',
        )
      ).length,
    ).toBeGreaterThan(0);

    // The revoke modal also stays open after the call; close it first.
    fireEvent.click(within(revokeDialog).getByRole('button', { name: 'Close dialog' }));
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    // Registration: token shown once, only inside the open modal.
    fireEvent.click(screen.getByRole('button', { name: 'Register agent' }));
    const registerDialog = await screen.findByRole('dialog');
    fireEvent.change(within(registerDialog).getByRole('textbox', { name: 'Agent name' }), {
      target: { value: 'runner-bot' },
    });
    fireEvent.click(within(registerDialog).getByRole('button', { name: 'Register agent' }));
    expect(await screen.findByTestId('agent-token')).toHaveTextContent(
      'vypam-agt1.99.SYNTHETIC-SECRET-NOT-A-REAL-TOKEN',
    );
    await waitFor(() => {
      expectWrite(fetchMock, '/agents', 'POST', {
        name: 'runner-bot',
        contact: '',
        max_ttl_minutes: 15,
      });
    });
  });

  it('opens an agent detail with its declared tasks and declares one', async () => {
    const fetchMock = stubFetch(jitRoutes());
    renderApp('/jit');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Tasks and detail: patch-bot' }),
    );
    const dialog = await screen.findByRole('dialog');
    expect(
      await within(dialog).findByRole('heading', { name: 'Agent #1' }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText('nightly-patch')).toBeInTheDocument();

    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Task name' }), {
      target: { value: 'rollout-check' },
    });
    fireEvent.change(
      within(dialog).getByRole('textbox', {
        name: 'Allowed commands (one literal per line, 1-32)',
      }),
      { target: { value: 'systemctl status nginx' } },
    );
    fireEvent.change(
      within(dialog).getByRole('textbox', { name: 'Allowed targets (comma-separated)' }),
      { target: { value: 'bastion-01.lab' } },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Declare task' }));

    await waitFor(() => {
      expectWrite(fetchMock, '/agents/1/tasks', 'POST', {
        name: 'rollout-check',
        allowed_commands: ['systemctl status nginx'],
        allowed_targets: ['bastion-01.lab'],
        max_minutes: 5,
      });
    });
  });

  it('shows the honest empty queue state behind no sample rows', async () => {
    stubFetch([
      jitQueueRoute({ items: [], total: 0, limit: 20, offset: 0 }),
      ...jitRoutes(),
    ]);
    renderApp('/jit');

    expect(await screen.findByText('No requests match this filter.')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Review: request/ }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('#JIT-6')).not.toBeInTheDocument();
    // Other sections keep their own captured rows (per-query honesty).
    expect(screen.getByText('#JIT-13')).toBeInTheDocument();
  });

  it("surfaces the server's verbatim error for a failed section", async () => {
    stubFetch([jitStatsRoute({ error: 'jit stats exploded' }, 500), ...jitRoutes()]);
    renderApp('/jit');

    // ApiError retries (QueryProvider) - allow the full window.
    const alerts = await screen.findAllByText(
      'Section unavailable: jit stats exploded',
      {},
      { timeout: 8000 },
    );
    expect(alerts.length).toBeGreaterThan(0);
    expect(screen.queryByText('Requests on record')).not.toBeInTheDocument();
  });

  it('shows the shared backend-down banner when the API is unreachable', async () => {
    // whoami + health answer; every feature query rejects (unmatched).
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/jit');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/network: Unhandled fetch/)).toBeInTheDocument();
    expect(screen.getAllByText('not connected').length).toBeGreaterThan(0);
    expect(screen.queryByText('#JIT-6')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Review: request/ }),
    ).not.toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(jitRoutes());
    const { container } = renderApp('/jit');
    await screen.findByRole('heading', { level: 1, name: /Just-In-Time/ });
    await expectNoAxeViolations(container);
  });
});
