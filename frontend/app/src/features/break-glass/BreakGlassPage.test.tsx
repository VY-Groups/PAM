import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  BG_APPROVE_1_RESPONSE,
  BG_APPROVE_2_RESPONSE,
  BG_CLOSE_RESPONSE,
  BG_DENY_RESPONSE,
  BG_DUPLICATE_APPROVER_400,
  BG_EMPTY_LIST_RESPONSE,
  BG_FACTS,
  BG_OPEN_NO_CREDENTIAL_400,
  BG_OPEN_RESPONSE,
  BG_SELF_APPROVE_403,
  BG_STATS_EMPTY_RESPONSE,
  WHOAMI_OPEN_BODY,
  breakGlassFileRoute,
  breakGlassListRoute,
  breakGlassRoutes,
  breakGlassStatsRoute,
  breakGlassWriteRoute,
  healthRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Break-Glass (F4 screen 9): every assertion runs against the verbatim
 * rig captures in breakGlassFixtures.ts - no invented values. The tests
 * prove the KPI quad over the real aggregates, the lifecycle filter as
 * a real contract parameter, the selected request record (signatures
 * with notes, the recorded session, the review), the whole dual
 * approval with the acting identity recorded verbatim as X-Actor
 * (including the server's own 403 requester-signs-own and duplicate
 * refusals), the direct unseal on the honest not-configured path, the
 * close with its contract-required review note and the rotation
 * answer, the EMERGENCY-AUTHORIZE and review-note client guards (ADR-
 * 0006: client UX only, never a substitute for the server), plus the
 * honest empty / section-error / backend-down states and an axe pass.
 *
 * The MFA release dialog (section 20) is legacy-parity code driven by
 * the captured `integrations/status` factor state; this rig reports no
 * factor enrolled, so the unseal path tests the honest direct POST -
 * the dialog itself is documented in the fixtures header, not claimed.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/**
 * The recorded write call for `suffix` with the given HTTP method -
 * the LAST one, so repeated writes (the two approval signatures) each
 * assert their own call.
 */
function callWrite(fetchMock: ReturnType<typeof vi.fn>, suffix: string, method: string) {
  return [...fetchMock.mock.calls]
    .reverse()
    .find(
      ([input, init]) =>
        String(input).endsWith(suffix) &&
        ((init as RequestInit | undefined)?.method ?? 'GET') === method,
    );
}

/**
 * Assert a break-glass write carried `X-Actor` (the acting identity -
 * the signed-in principal by default, the rail's typed value when one
 * is set) and, optionally, its body.
 */
function expectWrite(
  fetchMock: ReturnType<typeof vi.fn>,
  suffix: string,
  method: string,
  opts: { actor?: string; body?: unknown } = {},
): void {
  const call = callWrite(fetchMock, suffix, method);
  expect(call).toBeDefined();
  const init = call?.[1] as RequestInit | undefined;
  expect(new Headers(init?.headers).get('X-Actor')).toBe(opts.actor ?? 'open');
  if (opts.body !== undefined) {
    expect(JSON.parse(String(init?.body))).toEqual(opts.body);
  }
}

/** Did any request carry this query-string fragment? */
function sawUrl(fetchMock: ReturnType<typeof vi.fn>, part: string): boolean {
  return fetchMock.mock.calls.some(([input]) => String(input).includes(part));
}

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/** Type a distinct acting identity into the rail input (awaits the shell). */
async function setActor(name: string): Promise<void> {
  const input = await screen.findByLabelText('Actor (X-Actor)');
  fireEvent.change(input, { target: { value: name } });
}

/** The registry row holding `ref` (the ref cell renders first). */
async function rowFor(ref: string): Promise<HTMLElement> {
  const el = await screen.findByText(ref);
  return el.closest('tr') as HTMLElement;
}

describe('Break-Glass (F4 screen 9)', () => {
  it('renders the header, the factor banner, the open-emergency chip, the KPI quad and the honest placeholder', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    expect(
      await screen.findByRole('heading', { name: 'Emergency Break-Glass' }),
    ).toBeInTheDocument();

    // The legacy critical banner and the process rail both carry the
    // LIVE factor state from integrations/status (captured: not
    // configured - the server's own gate line, twice on the page).
    expect(await screen.findByText(/EMERGENCY ACCESS/)).toBeInTheDocument();
    expect(
      screen.getAllByText(/MFA: not configured - the mfa band stays advisory/),
    ).toHaveLength(2);

    // One live emergency in the used-state registry -> the singular chip.
    expect(await screen.findByText('1 open emergency')).toBeInTheDocument();

    const total = await kpiCard('Emergency requests');
    expect(within(total).getByText('5')).toBeInTheDocument();
    expect(within(total).getByText('on record')).toBeInTheDocument();

    const pending = await kpiCard('Awaiting approval');
    expect(within(pending).getByText('1')).toBeInTheDocument();
    expect(within(pending).getByText('2 signatures outstanding')).toBeInTheDocument();

    const open = await kpiCard('Open emergencies');
    expect(within(open).getByText('1')).toBeInTheDocument();
    expect(within(open).getByText('recorded sessions running')).toBeInTheDocument();

    const lastUnseal = await kpiCard('Last unseal');
    expect(within(lastUnseal).getByText('2026-10-15T03:24:25.713187')).toBeInTheDocument();

    expect(
      screen.getByText(/Select a request to inspect its full record/),
    ).toBeInTheDocument();
  });

  it('renders the registry from the contract with legacy columns and state-gated actions', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    for (const ref of [
      BG_FACTS.ref5,
      BG_FACTS.ref4,
      BG_FACTS.ref3,
      BG_FACTS.ref2,
      BG_FACTS.ref1,
    ]) {
      expect(await screen.findByText(ref)).toBeInTheDocument();
    }
    expect(await screen.findByText('5 of 5 shown')).toBeInTheDocument();

    // The legacy table columns are all here.
    for (const name of [
      'Request',
      'Target',
      'Requested',
      'Approvals',
      'Status',
      'Session',
      'Actions',
    ]) {
      expect(screen.getByRole('columnheader', { name })).toBeInTheDocument();
    }
    expect(screen.getByText('sess #6')).toBeInTheDocument();

    // Actions are state-gated: the pending row approves and denies, the
    // used row closes with its review, the approved row unseals, the
    // terminals have no lifecycle action - and every row inspects.
    expect(screen.getAllByRole('button', { name: 'Approve' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Deny' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Close + review' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Open (unseal)' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Inspect' })).toHaveLength(5);
  });

  it('sends the lifecycle filter to the contract (server-side, never a client re-filter)', async () => {
    const fetchMock = stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    expect(await screen.findByText(BG_FACTS.ref1)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'approved' }));
    await waitFor(() => expect(sawUrl(fetchMock, 'status=approved')).toBe(true));
    expect(await screen.findByText('1 of 1 shown')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.ref3)).toBeInTheDocument();
    // A client re-filter of the stale page would still carry ref1; the
    // server's filtered answer does not.
    expect(screen.queryAllByText(BG_FACTS.ref1)).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'used' }));
    await waitFor(() => expect(sawUrl(fetchMock, 'status=used')).toBe(true));
    expect(await screen.findByText('1 of 1 shown')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.ref5)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'pending' }));
    await waitFor(() => expect(sawUrl(fetchMock, 'status=pending')).toBe(true));
    expect(await screen.findByText('1 of 1 shown')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.ref4)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'all' }));
    await waitFor(() => expect(sawUrl(fetchMock, 'status=approved')).toBe(true));
    expect(await screen.findByText('5 of 5 shown')).toBeInTheDocument();
  });

  it('renders the honest empty registry with zeroed aggregates', async () => {
    stubFetch([
      breakGlassListRoute(BG_EMPTY_LIST_RESPONSE),
      breakGlassStatsRoute(BG_STATS_EMPTY_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    expect(
      await screen.findByText('No break-glass requests on record.'),
    ).toBeInTheDocument();
    const total = await kpiCard('Emergency requests');
    expect(within(total).getByText('0')).toBeInTheDocument();
    expect(await screen.findByText('0 open emergencies')).toBeInTheDocument();
  });

  it('files an emergency only past the EMERGENCY-AUTHORIZE guard, posting the contract shape', async () => {
    const fetchMock = stubFetch([breakGlassFileRoute(), ...breakGlassRoutes()]);
    renderApp('/break-glass');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Initiate emergency break-glass' }),
    );
    const dialog = await screen.findByRole('dialog');

    // The contract defaults are preselected exactly like the server's.
    expect(within(dialog).getByLabelText('Severity')).toHaveValue('sev1');
    expect(within(dialog).getByLabelText('Session protocol')).toHaveValue('ssh');

    // Every required field blocks first; the typing guard blocks next.
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));
    await within(dialog).findByText(/Fix the highlighted fields/);
    expect(callWrite(fetchMock, '/break-glass/requests', 'POST')).toBeUndefined();

    const REASON = 'vypam synthetic capture - client guard filing';
    fireEvent.change(within(dialog).getByPlaceholderText('db-01.corp:5432'), {
      target: { value: BG_FACTS.target1 },
    });
    fireEvent.change(within(dialog).getByLabelText('Severity'), {
      target: { value: 'sev2' },
    });
    fireEvent.change(within(dialog).getByLabelText('Session protocol'), {
      target: { value: 'rdp' },
    });
    fireEvent.change(
      within(dialog).getByPlaceholderText(/Production database unreachable/),
      {
        target: { value: REASON },
      },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));
    await within(dialog).findByText(/Fix the highlighted fields/);
    expect(callWrite(fetchMock, '/break-glass/requests', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByPlaceholderText('EMERGENCY-AUTHORIZE'), {
      target: { value: 'EMERGENCY-AUTHORIZE' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));

    await waitFor(() =>
      expect(callWrite(fetchMock, '/break-glass/requests', 'POST')).toBeDefined(),
    );
    expectWrite(fetchMock, '/break-glass/requests', 'POST', {
      body: {
        target: BG_FACTS.target1,
        reason: REASON,
        severity: 'sev2',
        protocol: 'rdp',
      },
    });
    expect(await screen.findByText(BG_FACTS.fileMessage)).toBeInTheDocument();
  });

  it('renders the server 403 when the requester tries to sign their own emergency', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id4, 'approve', BG_SELF_APPROVE_403),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    // The pending request was filed by `open` (captured) and the rail
    // defaults to the signed-in principal - the server judges it.
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));

    expect(await screen.findByText(BG_FACTS.selfApprove403)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id4}/approve`, 'POST', {
      body: {},
    });
  });

  it('records the typed acting identity verbatim and renders the duplicate-signer refusal', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id4, 'approve', BG_DUPLICATE_APPROVER_400),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    await setActor(BG_FACTS.approver1);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));

    expect(await screen.findByText(BG_FACTS.duplicate400)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id4}/approve`, 'POST', {
      actor: BG_FACTS.approver1,
      body: {},
    });
  });

  it('signs the dual approval: 1/2 then 2/2 with two distinct identities', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id4, 'approve', BG_APPROVE_1_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    await setActor(BG_FACTS.approver1);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByText(BG_FACTS.approve1Message)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id4}/approve`, 'POST', {
      actor: BG_FACTS.approver1,
      body: {},
    });

    // The second signature comes from a different identity (contract rule).
    const fetchMock2 = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id4, 'approve', BG_APPROVE_2_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    expect(await screen.findByText('5 of 5 shown')).toBeInTheDocument();
    await setActor(BG_FACTS.approver2);
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    expect(await screen.findByText(BG_FACTS.approve2Message)).toBeInTheDocument();
    expectWrite(fetchMock2, `/break-glass/requests/${BG_FACTS.id4}/approve`, 'POST', {
      actor: BG_FACTS.approver2,
      body: {},
    });
  });

  it('turns a pending request down with the acting identity and shows the server message', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id4, 'deny', BG_DENY_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    await setActor(BG_FACTS.approver1);
    fireEvent.click(await screen.findByRole('button', { name: 'Deny' }));

    expect(await screen.findByText(BG_FACTS.denyMessage)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id4}/deny`, 'POST', {
      actor: BG_FACTS.approver1,
      body: {},
    });
  });

  it('releases the credential directly while no factor is enrolled (honest not-configured path)', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id3, 'open', BG_OPEN_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    // integrations/status says no factor is enrolled, so the unseal
    // posts directly with no code at all - a fake challenge is never
    // rendered.
    fireEvent.click(await screen.findByRole('button', { name: 'Open (unseal)' }));

    expect(await screen.findByText(BG_FACTS.openMessage)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id3}/open`, 'POST', {
      body: {},
    });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('renders the captured no-credential refusal on unseal', async () => {
    stubFetch([
      breakGlassWriteRoute(BG_FACTS.id3, 'open', BG_OPEN_NO_CREDENTIAL_400),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    fireEvent.click(await screen.findByRole('button', { name: 'Open (unseal)' }));

    expect(await screen.findByText(BG_FACTS.noCredential400)).toBeInTheDocument();
  });

  it('closes the emergency with the required review note and shows the rotation answer', async () => {
    const fetchMock = stubFetch([
      breakGlassWriteRoute(BG_FACTS.id5, 'close', BG_CLOSE_RESPONSE),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    fireEvent.click(await screen.findByRole('button', { name: 'Close + review' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/not closed without this note/)).toBeInTheDocument();

    const REVIEW = 'vypam synthetic capture - close flow: reviewed and rotated';
    fireEvent.change(within(dialog).getByRole('textbox'), {
      target: { value: REVIEW },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close emergency' }));

    expect(await screen.findByText(BG_FACTS.closeMessage)).toBeInTheDocument();
    expectWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id5}/close`, 'POST', {
      body: { review: REVIEW },
    });
  });

  it('requires the review note before the close POST leaves the browser', async () => {
    const fetchMock = stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(await screen.findByRole('button', { name: 'Close + review' }));
    const dialog = await screen.findByRole('dialog');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Close emergency' }));
    await within(dialog).findByText(/Fix the highlighted fields/);
    expect(
      callWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id5}/close`, 'POST'),
    ).toBeUndefined();

    // Whitespace is not a review either (the contract trims, then refuses).
    fireEvent.change(within(dialog).getByRole('textbox'), {
      target: { value: '   ' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close emergency' }));
    await within(dialog).findByText(/Fix the highlighted fields/);
    expect(
      callWrite(fetchMock, `/break-glass/requests/${BG_FACTS.id5}/close`, 'POST'),
    ).toBeUndefined();
  });

  it('inspects the pending record with its honest zero-signature state', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(
      within(await rowFor(BG_FACTS.ref4)).getByRole('button', { name: 'Inspect' }),
    );

    expect(await screen.findByText(BG_FACTS.reason4)).toBeInTheDocument();
    expect(screen.getByText('No signatures yet.')).toBeInTheDocument();
    expect(screen.getByText('mfa: not configured')).toBeInTheDocument();
    expect(screen.getByText('Dual approval (0/2 signed)')).toBeInTheDocument();
  });

  it('inspects the closed record: signatures with notes, the recorded session and the review', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(
      within(await rowFor(BG_FACTS.ref1)).getByRole('button', { name: 'Inspect' }),
    );

    expect(await screen.findByText(BG_FACTS.reason1)).toBeInTheDocument();
    expect(screen.getByText('Dual approval (2/2 signed)')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.sessionRef1)).toBeInTheDocument();
    expect(screen.getByText('recording: forced')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.review1)).toBeInTheDocument();
    expect(screen.getByText(/Closed \(post-incident review\)/)).toBeInTheDocument();
  });

  it('inspects the denied record with the server-recorded note', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(
      within(await rowFor(BG_FACTS.ref2)).getByRole('button', { name: 'Inspect' }),
    );

    expect(await screen.findByText('Denied')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.denyNote)).toBeInTheDocument();
  });

  it('inspects the used record: the live session and both signature notes', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(
      within(await rowFor(BG_FACTS.ref5)).getByRole('button', { name: 'Inspect' }),
    );

    expect(await screen.findByText(BG_FACTS.sessionRef5)).toBeInTheDocument();
    expect(screen.getByText('Recorded session')).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.approveNote1)).toBeInTheDocument();
    expect(screen.getByText(BG_FACTS.approveNote2)).toBeInTheDocument();
  });

  it('clears the selection back to the honest placeholder', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    fireEvent.click(
      within(await rowFor(BG_FACTS.ref1)).getByRole('button', { name: 'Inspect' }),
    );
    expect(await screen.findByText(BG_FACTS.reason1)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(
      await screen.findByText(/Select a request to inspect its full record/),
    ).toBeInTheDocument();
    expect(screen.queryByText(BG_FACTS.reason1)).not.toBeInTheDocument();
  });

  it('defaults the acting identity to the signed-in principal and updates the hint live', async () => {
    stubFetch(breakGlassRoutes());
    renderApp('/break-glass');

    const input = await screen.findByLabelText('Actor (X-Actor)');
    expect(input).toHaveValue('');
    expect(input).toHaveAttribute('placeholder', 'open');
    expect(screen.getByText(/currently open\)/)).toBeInTheDocument();

    await setActor('approver-night');
    expect(screen.getByText(/currently approver-night\)/)).toBeInTheDocument();
  });

  it('renders a section error verbatim without pretending the backend is down', async () => {
    stubFetch([
      breakGlassListRoute({
        status: 500,
        body: { error: 'break-glass registry exploded' },
      }),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    expect(
      await screen.findByText(
        'Section unavailable: break-glass registry exploded',
        {},
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Cannot reach the license server - live data is unavailable.'),
    ).not.toBeInTheDocument();
  });

  it('shows the honest not-connected state when the backend is down', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/break-glass');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(breakGlassRoutes());
    const { container } = renderApp('/break-glass');
    await screen.findAllByText(BG_FACTS.ref5);
    await expectNoAxeViolations(container);
  });
});

/**
 * Step 6 (ADR-0021 D3): the approver-class decisions render disabled with
 * the stated reason for the operator, who holds the file/open/close
 * operations but no approve/deny - verbatim contract operations from the
 * step-1 audit, never a role name in the logic.
 */
describe('D3 action gating (step 6)', () => {
  it('renders Approve and Deny disabled with the approver reason for the operator', async () => {
    stubFetch([
      whoamiRoute({
        ...WHOAMI_OPEN_BODY,
        mode: 'token',
        principal: 'op-1',
        role: 'operator',
        kind: 'ldap',
        operations: [
          'post /api/v1/break-glass/requests',
          'post /api/v1/break-glass/requests/{request_id}/open',
          'post /api/v1/break-glass/requests/{request_id}/close',
        ],
        operations_count: 3,
      }),
      ...breakGlassRoutes(),
    ]);
    renderApp('/break-glass');

    const approve = await screen.findByRole('button', { name: 'Approve' });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAttribute('title', 'requires approver role');

    const deny = screen.getByRole('button', { name: 'Deny' });
    expect(deny).toBeDisabled();
    expect(deny).toHaveAttribute('title', 'requires approver role');
  });
});
