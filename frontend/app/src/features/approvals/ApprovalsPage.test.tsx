import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  JIT_APPROVE_RESPONSE,
  brokerCredentialsRoute,
  breakGlassListRoute,
  commandCenterRoutes,
  jitActionRoute,
  jitQueueRoute,
  stubFetch,
  vendorsListRoute,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/**
 * The approver's whoami - the five decision operations verbatim from the
 * step-1 audit (full 13-op capture: Temp/role-audit-raw.log; nav matrix:
 * RoleGate.test.tsx; contract pin: nav.test.ts).
 */
const APPROVER_WHOAMI = {
  mode: 'token',
  principal: 'aud-approver',
  role: 'approver',
  kind: 'ldap',
  operations: [
    'post /api/v1/jit/requests/{request_id}/approve',
    'post /api/v1/break-glass/requests/{request_id}/approve',
    'post /api/v1/vendors/{vendor_id}/approve',
    'post /api/v1/broker/credentials/{credential_id}/approve',
    'post /api/v1/sessions/{session_id}/events/{seq}/approve',
  ],
  operations_count: 13,
};

/** Full shell + the four inbox surfaces (my whoami first: first match wins). */
function inboxRoutes() {
  return [
    whoamiRoute(APPROVER_WHOAMI),
    ...commandCenterRoutes(),
    jitQueueRoute(),
    jitActionRoute('approve', JIT_APPROVE_RESPONSE),
    breakGlassListRoute(),
    vendorsListRoute(),
    brokerCredentialsRoute(),
  ];
}

describe('ApprovalsPage (ADR-0021 step 5 - the approver landing)', () => {
  it('renders four decision sections with API counts, context rows and named actions', async () => {
    stubFetch(inboxRoutes());
    const { container } = renderApp('/approvals');

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Approvals inbox' }),
    ).toBeInTheDocument();

    // Visible navigation for the approver: inbox + the two always-visible
    // routes only (the full role matrix lives in RoleGate.test.tsx).
    const nav = await screen.findByRole('navigation', { name: 'Primary navigation' });
    expect(within(nav).getAllByRole('link')).toHaveLength(3);

    // Four sections from the brief (JIT, break-glass, vendor, credentials).
    expect(
      screen.getByRole('heading', { name: 'JIT access requests' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Break-glass requests' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Vendor invites' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Brokered credentials' }),
    ).toBeInTheDocument();

    // Requester / ticket context on the JIT rows (the brief's row
    // contract; the fixture carries two n.adams rows - pending + closed).
    expect((await screen.findAllByText('n.adams')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('CHG-9035').length).toBeGreaterThan(0);

    // Break-glass pending row (the list route filters status=pending).
    expect(await screen.findByText('bg-ee2f15aa')).toBeInTheDocument();

    // Broker: the pending credential stays, the decided one is filtered out.
    expect(await screen.findByText('Queued second probe request')).toBeInTheDocument();
    expect(screen.queryByText('Approved probe credential request')).not.toBeInTheDocument();

    // Vendor: none invited -> the honest empty state (awaited last so all
    // four queries are settled before the count assertions below).
    expect(await screen.findByText('Nothing waiting for a decision.')).toBeInTheDocument();

    // Counts from the API: break-glass and broker each answer one pending,
    // vendors answers zero invited.
    // Counts from the API (fixture-captured totals: JIT's queue body keeps
    // its unfiltered 13, break-glass filters to one pending of five, the
    // broker queue carries two pending, no vendor is invited).
    expect(screen.getByText('13 pending')).toBeInTheDocument();
    expect(screen.getByText('1 pending')).toBeInTheDocument();
    expect(screen.getByText('2 pending')).toBeInTheDocument();
    expect(screen.getByText('0 pending')).toBeInTheDocument();
    expect(screen.getAllByText('Nothing waiting for a decision.')).toHaveLength(1);

    // Both decisions are offered with the brief's named-action a11y contract.
    expect(
      screen.getAllByRole('button', { name: /Approve as (manager|security)/ }).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByRole('button', { name: /^Deny —/ }).length).toBeGreaterThan(0);

    await expectNoAxeViolations(container);
  });

  it('sends the decision with the signed-in principal as X-Actor', async () => {
    const fetchMock = stubFetch(inboxRoutes());
    renderApp('/approvals');

    const approve = await screen.findAllByRole('button', {
      name: /Approve as (manager|security)/,
    });
    fireEvent.click(approve[0]);

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) =>
        /\/jit\/requests\/\d+\/approve/.test(String(url)),
      );
      expect(call).toBeDefined();
      const init = call?.[1] as RequestInit | undefined;
      const raw = init?.headers;
      const headers =
        raw instanceof Headers
          ? Object.fromEntries(raw.entries())
          : ((raw ?? {}) as Record<string, string>);
      expect(headers['X-Actor'] ?? headers['x-actor']).toBe('aud-approver');
    });
  });
});
