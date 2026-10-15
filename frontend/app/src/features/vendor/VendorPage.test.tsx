import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  APPROVE_MISSING_RESPONSE,
  INVITE_CONFLICT_RESPONSE,
  MFA_WRONG_RESPONSE,
  REQUEST_REFUSED_RESPONSE,
  TICKET_UNCONFIGURED_RESPONSE,
  VENDORS_EMPTY_RESPONSE,
  VENDOR_DETAIL_APPROVED_RESPONSE,
  VENDOR_DETAIL_B_RESPONSE,
  VENDOR_DETAIL_INVITED_RESPONSE,
  VENDOR_FACTS,
  WHOAMI_OPEN_BODY,
  healthRoute,
  inviteVendorRoute,
  stubFetch,
  vendorDetailRoute,
  vendorRequestRoute,
  vendorRoutes,
  vendorStepRoute,
  vendorsListRoute,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Vendor Access (F4 screen 8): every assertion runs against the verbatim
 * rig captures in vendorFixtures.ts - no invented values. The tests
 * prove the registry KPI quad over the real list, the status/q contract
 * filters (server-side, never a client re-filter), the selected vendor
 * dashboard (steps, scope, grants, the 20-event trail), the whole
 * four-step chain with X-Actor on every write, the invite with its
 * one-time seed card, and every captured refusal rendered verbatim: the
 * 401 bad-TOTP, the 409 ITSM-unconfigured, the 409 missing chain steps,
 * the 403 access refusal with the server's own reason line, the invite-name
 * conflict - plus the honest empty / section-error / backend-down
 * states and an axe pass.
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

/** Assert a vendor write carried the signed-in principal as `X-Actor`. */
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

/** Did any request carry this query-string fragment? */
function sawUrl(fetchMock: ReturnType<typeof vi.fn>, part: string): boolean {
  return fetchMock.mock.calls.some(([input]) => String(input).includes(part));
}

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/**
 * The registry card containing `name`. The name can also appear in the
 * selected dashboard and the lifecycle trail, so the first match (the
 * registry renders first) is the row.
 */
async function vendorRow(name: string): Promise<HTMLElement> {
  const els = await screen.findAllByText(name);
  return els[0].parentElement?.parentElement as HTMLElement;
}

describe('Vendor Access (F4 screen 8)', () => {
  it('renders the KPI quad from the real registry and the honest placeholder', async () => {
    stubFetch(vendorRoutes());
    renderApp('/vendor-access');

    expect(
      await screen.findByRole('heading', { name: 'Vendor Access' }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('2 accounts · 0 invited · 0 approved'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Select a vendor account to open its dashboard.'),
    ).toBeInTheDocument();

    const accounts = await kpiCard('VENDOR ACCOUNTS');
    expect(within(accounts).getByText('2')).toBeInTheDocument();
    expect(within(accounts).getByText('server total · newest first')).toBeInTheDocument();

    const invited = await kpiCard('INVITED');
    expect(within(invited).getByText('0')).toBeInTheDocument();
    expect(within(invited).getByText('chain steps outstanding')).toBeInTheDocument();

    const approved = await kpiCard('APPROVED');
    expect(within(approved).getByText('0')).toBeInTheDocument();
    expect(
      within(approved).getByText('access enabled inside its scope'),
    ).toBeInTheDocument();

    const closed = await kpiCard('CLOSED');
    expect(within(closed).getByText('2')).toBeInTheDocument();
    expect(within(closed).getByText('denied · revoked · expired')).toBeInTheDocument();
  });

  it('renders every registry row with its four chain steps and honest lines', async () => {
    stubFetch(vendorRoutes());
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    within(alpha).getByText('revoked');
    within(alpha).getByText('mfa: verified');
    within(alpha).getByText('nda: signed');
    within(alpha).getByText('ticket: verified');
    within(alpha).getByText('approval: approved');
    within(alpha).getByText('any hour');
    within(alpha).getByText('1 allowed targets');
    within(alpha).getByText('no expiry set');
    within(alpha).getByRole('button', { name: 'Open' });
    within(alpha).getByRole('button', { name: 'Reinvite' });

    const beta = await vendorRow('vypam-vendor-beta.test');
    within(beta).getByText('denied');
    within(beta).getByText('approval: denied');
    within(beta).getByText(`reason: ${VENDOR_FACTS.deniedReason}`);
  });

  it('drives the status chips as real contract parameters, filtered server-side', async () => {
    const fetchMock = stubFetch(vendorRoutes());
    renderApp('/vendor-access');
    await screen.findByText('vypam-vendor-alpha.test');

    const group = screen.getByRole('group', { name: 'Filter vendors by status' });

    // The captured registry holds no invited row - the server says so.
    fireEvent.click(within(group).getByRole('button', { name: 'invited' }));
    expect(
      await screen.findByText('No vendor accounts match these filters.'),
    ).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'status=invited')).toBe(true);
    expect(screen.queryByText('vypam-vendor-alpha.test')).not.toBeInTheDocument();

    fireEvent.click(within(group).getByRole('button', { name: 'denied' }));
    expect(await screen.findByText('vypam-vendor-beta.test')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'status=denied')).toBe(true);
    expect(screen.queryByText('vypam-vendor-alpha.test')).not.toBeInTheDocument();

    fireEvent.click(within(group).getByRole('button', { name: 'all statuses' }));
    expect(await screen.findByText('vypam-vendor-alpha.test')).toBeInTheDocument();
    expect(screen.getByText('vypam-vendor-beta.test')).toBeInTheDocument();
  });

  it('sends the search as the contract `q` substring over name AND contact', async () => {
    const fetchMock = stubFetch(vendorRoutes());
    renderApp('/vendor-access');
    await screen.findByText('vypam-vendor-alpha.test');

    const search = screen.getByRole('textbox', { name: 'Search name or contact' });
    fireEvent.change(search, { target: { value: 'alpha' } });
    expect(await screen.findByText('vypam-vendor-alpha.test')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'q=alpha')).toBe(true);
    expect(screen.queryByText('vypam-vendor-beta.test')).not.toBeInTheDocument();

    // `@` never occurs in a name - this row can only match on contact.
    fireEvent.change(search, { target: { value: 'beta@example' } });
    expect(await screen.findByText('vypam-vendor-beta.test')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'q=beta')).toBe(true);
    expect(screen.queryByText('vypam-vendor-alpha.test')).not.toBeInTheDocument();
  });

  it('opens the real dashboard: ticket check verbatim, scope, grant, full trail', async () => {
    stubFetch(vendorRoutes());
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));

    expect(
      await screen.findByRole('heading', { name: 'Vendor dashboard' }),
    ).toBeInTheDocument();
    // The server's own ITSM verification detail, verbatim.
    expect(await screen.findByText('INC-23892 · HTTP 200')).toBeInTheDocument();
    expect(screen.getByText(/^NDA-2026-0043 · signed /)).toBeInTheDocument();
    expect(screen.getByText(/^approved by open · /)).toBeInTheDocument();
    // Access scope chips.
    expect(screen.getByText('10.99.8.42')).toBeInTheDocument();
    expect(screen.getByText('session recording ENABLED')).toBeInTheDocument();
    expect(screen.getAllByText('any hour').length).toBeGreaterThan(0);
    // The real scoped grant.
    expect(screen.getByText('item 1 · risk low · 30 min')).toBeInTheDocument();
    expect(
      screen.getByText('vypam-vendor-alpha.test — vypam synthetic capture request'),
    ).toBeInTheDocument();
    // The lifecycle trail (newest first, event detail preview).
    expect(screen.getByText('#45')).toBeInTheDocument();
    expect(
      screen.getAllByText(/grants_ended=\[\]\s+reason=vypam synthetic capture revoke/)
        .length,
    ).toBeGreaterThan(0);
    // A revoked account gets no lifecycle actions; Clear resets honestly:
    // the section header stays (it heads the empty state too) but the
    // selected vendor's dashboard content is gone.
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke Vendor' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(
      screen.getByText('Select a vendor account to open its dashboard.'),
    ).toBeInTheDocument();
    expect(screen.queryByText('INC-23892 · HTTP 200')).not.toBeInTheDocument();
  });

  it('offers exactly the chain actions an invited account can run', async () => {
    stubFetch([vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE), ...vendorRoutes()]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));

    expect(await screen.findByRole('button', { name: 'Verify MFA' })).toBeInTheDocument();
    screen.getByRole('button', { name: 'Record NDA' });
    screen.getByRole('button', { name: 'Verify ITSM Ticket' });
    screen.getByRole('button', { name: 'Approve' });
    screen.getByRole('button', { name: 'Deny Vendor' });
    expect(screen.queryByRole('button', { name: 'Revoke Vendor' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'File Access Request' }),
    ).not.toBeInTheDocument();
    // Four pending step lines in the dashboard (the list keeps its own states).
    expect(screen.getAllByText('mfa: pending').length).toBeGreaterThan(0);
    expect(screen.getAllByText('not yet')).toHaveLength(4);
  });

  it('verifies MFA: zod guard, real write with X-Actor, server message', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify MFA' }));
    const dialog = await screen.findByRole('dialog', { name: 'Verify vendor MFA' });

    // Empty and short codes never reach the network.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify code' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    fireEvent.change(within(dialog).getByPlaceholderText('123456'), {
      target: { value: '123' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify code' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/vendors/1/mfa', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByPlaceholderText('123456'), {
      target: { value: '123456' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify code' }));
    expect(await screen.findByText(VENDOR_FACTS.mfaMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/mfa', 'POST', { code: '123456' });
  });

  it('renders the captured 401 bad-TOTP refusal verbatim and keeps the dialog open', async () => {
    stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      vendorStepRoute(1, 'mfa', MFA_WRONG_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify MFA' }));
    const dialog = await screen.findByRole('dialog', { name: 'Verify vendor MFA' });
    fireEvent.change(within(dialog).getByPlaceholderText('123456'), {
      target: { value: '000000' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify code' }));

    expect(
      await within(dialog).findByText('TOTP code is invalid or expired'),
    ).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Verify vendor MFA' })).toBeInTheDocument();
  });

  it('records the NDA reference with X-Actor and shows the server message', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Record NDA' }));
    const dialog = await screen.findByRole('dialog', { name: 'Record NDA / agreement' });
    fireEvent.change(within(dialog).getByPlaceholderText('NDA-2026-0042'), {
      target: { value: 'NDA-2026-0042' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Record NDA' }));

    expect(await screen.findByText(VENDOR_FACTS.ndaMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/nda', 'POST', { ref: 'NDA-2026-0042' });
  });

  it('shows the honest ITSM hint, validates the ticket key, then verifies it', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify ITSM Ticket' }));
    const dialog = await screen.findByRole('dialog', { name: 'Verify ITSM ticket' });

    // The integrations status hint renders verbatim above the field.
    expect(
      within(dialog).getByText(`ITSM: ${VENDOR_FACTS.itsmUnconfigured}`),
    ).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify ticket' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    fireEvent.change(within(dialog).getByPlaceholderText('INC-23891'), {
      target: { value: 'nonsense' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify ticket' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/vendors/1/ticket', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByPlaceholderText('INC-23891'), {
      target: { value: 'INC-23891' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify ticket' }));
    expect(await screen.findByText(VENDOR_FACTS.ticketMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/ticket', 'POST', { ticket: 'INC-23891' });
  });

  it('renders the captured "itsm is not configured" 409 verbatim', async () => {
    stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      vendorStepRoute(1, 'ticket', TICKET_UNCONFIGURED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify ITSM Ticket' }));
    const dialog = await screen.findByRole('dialog', { name: 'Verify ITSM ticket' });
    fireEvent.change(within(dialog).getByPlaceholderText('INC-23891'), {
      target: { value: 'INC-23891' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify ticket' }));

    expect(await within(dialog).findByText('itsm is not configured')).toBeInTheDocument();
  });

  it('approves with X-Actor; the server names the missing steps verbatim', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByText(VENDOR_FACTS.approveMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/approve', 'POST');
  });

  it('renders the captured missing-chain-steps 409 refusal verbatim', async () => {
    stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      vendorStepRoute(1, 'approve', APPROVE_MISSING_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));

    expect(
      await screen.findByText('Every lifecycle step must be complete before approval'),
    ).toBeInTheDocument();
  });

  it('denies with an optional reason, X-Actor and the server message', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_INVITED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Deny Vendor' }));
    const dialog = await screen.findByRole('dialog', { name: 'Deny vendor' });
    fireEvent.change(within(dialog).getByLabelText('Reason (optional)'), {
      target: { value: 'vypam synthetic capture deny' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Deny vendor' }));

    expect(await screen.findByText(VENDOR_FACTS.denyMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/deny', 'POST', {
      reason: 'vypam synthetic capture deny',
    });
  });

  it('offers revoke and request on the approved state, with the window line', async () => {
    stubFetch([vendorDetailRoute(1, VENDOR_DETAIL_APPROVED_RESPONSE), ...vendorRoutes()]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));

    expect(
      await screen.findByRole('button', { name: 'Revoke Vendor' }),
    ).toBeInTheDocument();
    screen.getByRole('button', { name: 'File Access Request' });
    // Approved state has no chain actions and no grants yet.
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deny Vendor' })).not.toBeInTheDocument();
    expect(screen.getByText('No scoped requests filed yet.')).toBeInTheDocument();
    // The real agreed window from the captured approved scope.
    expect(screen.getByText('window 14:00–16:00')).toBeInTheDocument();
    expect(screen.getByText('10.66.66.0/24')).toBeInTheDocument();
    expect(screen.getByText('db-alpha.internal')).toBeInTheDocument();
  });

  it('revokes with a reason, X-Actor and the server message', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_APPROVED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke Vendor' }));
    const dialog = await screen.findByRole('dialog', { name: 'Revoke vendor' });
    fireEvent.change(within(dialog).getByLabelText('Reason (optional)'), {
      target: { value: 'certificate rotation done' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke vendor' }));

    expect(await screen.findByText(VENDOR_FACTS.revokeMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/revoke', 'POST', {
      reason: 'certificate rotation done',
    });
  });

  it('files a real scoped request: item picker, guards, contract body, X-Actor', async () => {
    const fetchMock = stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_APPROVED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'File Access Request' }));
    const dialog = await screen.findByRole('dialog', { name: 'Vendor requests access' });

    // A real item from the vault registry plus a valid reason still need
    // every field: submitting the empty form never hits the network.
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/vendors/1/requests', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByRole('combobox'), {
      target: { value: '1' },
    });
    fireEvent.change(within(dialog).getByLabelText('Reason (8-255 chars)'), {
      target: { value: 'vypam synthetic capture request' },
    });
    fireEvent.change(within(dialog).getByLabelText('Minutes (1-480)'), {
      target: { value: '30' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));

    expect(await screen.findByText(VENDOR_FACTS.requestMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors/1/requests', 'POST', {
      item_id: 1,
      reason: 'vypam synthetic capture request',
      minutes: 30,
    });
  });

  it('renders the captured 403 scope refusal with the server reason line', async () => {
    stubFetch([
      vendorDetailRoute(1, VENDOR_DETAIL_APPROVED_RESPONSE),
      vendorRequestRoute(1, REQUEST_REFUSED_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'File Access Request' }));
    const dialog = await screen.findByRole('dialog', { name: 'Vendor requests access' });
    fireEvent.change(within(dialog).getByRole('combobox'), {
      target: { value: '1' },
    });
    fireEvent.change(within(dialog).getByLabelText('Reason (8-255 chars)'), {
      target: { value: 'vypam synthetic capture request' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'File request' }));

    expect(
      await within(dialog).findByText('Vendor access refused — account is revoked'),
    ).toBeInTheDocument();
  });

  it('invites: name/window-pair guards, contract body with X-Actor, one-time seed card', async () => {
    const fetchMock = stubFetch(vendorRoutes());
    renderApp('/vendor-access');
    await screen.findByText('vypam-vendor-alpha.test');

    fireEvent.click(screen.getByRole('button', { name: 'Invite Vendor' }));
    const dialog = await screen.findByRole('dialog', { name: 'Invite vendor' });

    // A 1-char name is refused client side - nothing hits the network.
    fireEvent.change(within(dialog).getByLabelText('Name'), {
      target: { value: 'x' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Send invite' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/vendors', 'POST')).toBeUndefined();

    // The window must be a pair: a lone start is refused too.
    fireEvent.change(within(dialog).getByLabelText('Name'), {
      target: { value: 'vypam-vendor-new.test' },
    });
    fireEvent.change(within(dialog).getByLabelText('Contact'), {
      target: { value: 'ops@new.example' },
    });
    fireEvent.change(within(dialog).getByLabelText('Allowed targets (one per line)'), {
      target: { value: '10.66.66.0/24\ndb-new.internal' },
    });
    fireEvent.change(within(dialog).getByLabelText('Window start'), {
      target: { value: '14:00' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Send invite' }));
    expect(
      await within(dialog).findByText(/Fix the highlighted fields/),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/vendors', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByLabelText('Window end'), {
      target: { value: '16:00' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Send invite' }));

    expect(await screen.findByText(VENDOR_FACTS.inviteMessage)).toBeInTheDocument();
    const seed = await screen.findByTestId('vendor-seed-card');
    within(seed).getByText(VENDOR_FACTS.seedNote);
    within(seed).getByText('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');
    within(seed).getByText(/^otpauth:\/\/totp\//);
    expectWrite(fetchMock, '/vendors', 'POST', {
      name: 'vypam-vendor-new.test',
      contact: 'ops@new.example',
      allowed_targets: ['10.66.66.0/24', 'db-new.internal'],
      window_start: '14:00',
      window_end: '16:00',
      recording: true,
    });
  });

  it('renders the captured invite-name conflict 409 verbatim, with no seed', async () => {
    const fetchMock = stubFetch([
      inviteVendorRoute(INVITE_CONFLICT_RESPONSE),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Reinvite' }));

    expect(
      await screen.findByText('A vendor with this name already exists'),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('vendor-seed-card')).not.toBeInTheDocument();
    expectWrite(fetchMock, '/vendors', 'POST', { name: 'vypam-vendor-alpha.test' });
  });

  it('reinvites: same-name POST, seed card, and Hide drops it for good', async () => {
    const fetchMock = stubFetch(vendorRoutes());
    renderApp('/vendor-access');

    const alpha = await vendorRow('vypam-vendor-alpha.test');
    fireEvent.click(within(alpha).getByRole('button', { name: 'Reinvite' }));

    expect(await screen.findByText(VENDOR_FACTS.inviteMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/vendors', 'POST', { name: 'vypam-vendor-alpha.test' });
    const seed = await screen.findByTestId('vendor-seed-card');
    within(seed).getByText(VENDOR_FACTS.seedNote);

    fireEvent.click(within(seed).getByRole('button', { name: 'I stored the seed' }));
    expect(screen.queryByTestId('vendor-seed-card')).not.toBeInTheDocument();
  });

  it('opens the denied vendor on its own id and hides every lifecycle action', async () => {
    stubFetch([vendorDetailRoute(2, VENDOR_DETAIL_B_RESPONSE), ...vendorRoutes()]);
    renderApp('/vendor-access');

    const beta = await vendorRow('vypam-vendor-beta.test');
    fireEvent.click(within(beta).getByRole('button', { name: 'Open' }));

    expect(
      await screen.findByRole('heading', { name: 'Vendor dashboard' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Verify MFA' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke Vendor' })).not.toBeInTheDocument();
    // Wait for the dashboard data (its allowed-target chip): findAll only
    // waits for ONE match, and the row renders the reason on its own.
    await screen.findAllByText('10.77.77.0/24');
    expect(screen.getAllByText(`reason: ${VENDOR_FACTS.deniedReason}`)).toHaveLength(2);
    expect(screen.getAllByText('approval: denied')).toHaveLength(2);
  });

  it('renders a section error verbatim without pretending the backend is down', async () => {
    stubFetch([
      vendorsListRoute({ status: 500, body: { error: 'vendor registry exploded' } }),
      ...vendorRoutes(),
    ]);
    renderApp('/vendor-access');

    expect(
      await screen.findByText(
        'Section unavailable: vendor registry exploded',
        {},
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Cannot reach the license server - live data is unavailable.'),
    ).not.toBeInTheDocument();
  });

  it('renders the honest empty state with zeroed KPIs', async () => {
    stubFetch([vendorsListRoute(VENDORS_EMPTY_RESPONSE), ...vendorRoutes()]);
    renderApp('/vendor-access');

    expect(
      await screen.findByText('No vendor accounts match these filters.'),
    ).toBeInTheDocument();
    const accounts = await kpiCard('VENDOR ACCOUNTS');
    expect(within(accounts).getByText('0')).toBeInTheDocument();
  });

  it('shows the honest not-connected state when the backend is down', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/vendor-access');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(vendorRoutes());
    const { container } = renderApp('/vendor-access');
    await screen.findAllByText('vypam-vendor-alpha.test');
    await expectNoAxeViolations(container);
  });
});
