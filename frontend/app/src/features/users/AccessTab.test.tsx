import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  ASSETS_LIST_RESPONSE,
  ROLE_BINDINGS_RESPONSE,
  ROLE_BINDING_CREATE_USER_RESPONSE,
  ROLES_RESPONSE,
  USERS_LIST_RESPONSE,
  WHOAMI_OPEN_BODY,
  discoveredAssetsRoute,
  healthRoute,
  roleBindingsRoute,
  rolesRoute,
  stubFetch,
  usersRoute,
  whoamiRoute,
} from '../../test/fetchMock';
import type { CapturedResponse } from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Access tab (ADR-0017 Decision 2, batch 11.10): the human-facing
 * role-bindings view on `/users`. Every assertion runs against the verbatim
 * captures the Settings RBAC section already pins (same registry, shared
 * cache) - the tab proves the `kind: "user"` grant body, the picker +
 * free-text targets contract, the confirm-gated revoke with the server's
 * message verbatim, and the honest empty/error states.
 */

function accessTabRoutes(bindings: CapturedResponse = ROLE_BINDINGS_RESPONSE) {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    usersRoute(USERS_LIST_RESPONSE),
    rolesRoute(ROLES_RESPONSE),
    roleBindingsRoute(bindings, ROLE_BINDING_CREATE_USER_RESPONSE),
    discoveredAssetsRoute(ASSETS_LIST_RESPONSE),
  ];
}

/** Open the Access tab (the Registry tab renders first; Radix tab
 * triggers activate on mousedown - house pattern, TopologyPage.test). */
async function openAccessTab(): Promise<void> {
  const trigger = await screen.findByRole('tab', { name: 'Access' });
  fireEvent.mouseDown(trigger);
  fireEvent.click(trigger);
}

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe('Users Access tab (ADR-0017 batch 11.10, contract-shaped)', () => {
  it('renders the captured bindings with the honest Everywhere scope', async () => {
    stubFetch(accessTabRoutes());
    renderApp('/users');
    await openAccessTab();

    const row = await screen.findByText('demo-admin');
    const tr = row.closest('tr');
    expect(tr).not.toBeNull();
    expect(within(tr as HTMLElement).getByText('admin')).toBeInTheDocument();
    expect(within(tr as HTMLElement).getByText('local')).toBeInTheDocument();
    // empty scope renders "Everywhere" - never a fabricated restriction
    expect(within(tr as HTMLElement).getByText('Everywhere')).toBeInTheDocument();
  });

  it('offers the registry usernames as the principal picker', async () => {
    stubFetch(accessTabRoutes());
    renderApp('/users');
    await openAccessTab();
    await screen.findByText('demo-admin');

    const datalist = document.getElementById('users-access-principals');
    expect(datalist).not.toBeNull();
    const values = Array.from(datalist?.querySelectorAll('option') ?? []).map(
      (option) => option.value,
    );
    expect(values).toEqual(['audit.readonly', 'emergency-admin', 'ops.user']);
  });

  it('grants kind user with picker + free-text targets and answers verbatim', async () => {
    const fetchMock = stubFetch(accessTabRoutes());
    renderApp('/users');
    await openAccessTab();
    await screen.findByText('demo-admin');

    fireEvent.change(screen.getByLabelText('Console user'), {
      target: { value: 'ops.user' },
    });
    fireEvent.change(screen.getByLabelText('Target patterns'), {
      target: { value: 'db-prod-*:22' },
    });
    // the picker appends a discovered address beside the free text (contract)
    const picked = ASSETS_LIST_RESPONSE.body.assets[0].address;
    fireEvent.change(screen.getByLabelText('Add from discovered targets'), {
      target: { value: picked },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Grant access' }));

    expect(await screen.findByText('Role binding created')).toBeInTheDocument();
    const postCalls = fetchMock.mock.calls.filter(
      (call) =>
        String(call[0]).endsWith('/api/v1/role-bindings') && call[1]?.method === 'POST',
    );
    expect(postCalls).toHaveLength(1);
    const body = JSON.parse(String(postCalls[0][1]?.body));
    expect(body.kind).toBe('user');
    expect(body.principal).toBe('ops.user');
    expect(body.role).toBe('operator');
    expect(body.scope.targets).toContain('db-prod-*:22');
    expect(body.scope.targets).toContain(picked);
  });

  it('sends no scope at all when the targets stay empty (contract: everywhere)', async () => {
    const fetchMock = stubFetch(accessTabRoutes());
    renderApp('/users');
    await openAccessTab();
    await screen.findByText('demo-admin');

    fireEvent.change(screen.getByLabelText('Console user'), {
      target: { value: 'audit.readonly' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Grant access' }));

    expect(await screen.findByText('Role binding created')).toBeInTheDocument();
    const postCalls = fetchMock.mock.calls.filter(
      (call) =>
        String(call[0]).endsWith('/api/v1/role-bindings') && call[1]?.method === 'POST',
    );
    expect(JSON.parse(String(postCalls[0][1]?.body))).toEqual({
      principal: 'audit.readonly',
      role: 'operator',
      kind: 'user',
    });
  });

  it('revoke asks the captured question and answers the server message verbatim', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = stubFetch(accessTabRoutes());
    renderApp('/users');
    await openAccessTab();
    const row = await screen.findByText('demo-admin');

    fireEvent.click(
      within(row.closest('tr') as HTMLElement).getByRole('button', { name: 'Revoke' }),
    );
    expect(confirm).toHaveBeenCalledWith(
      'Revoke the admin binding for demo-admin? The token stops working immediately; the row stays as evidence.',
    );
    expect(await screen.findByText('Role binding revoked')).toBeInTheDocument();
    const deleteCalls = fetchMock.mock.calls.filter(
      (call) =>
        String(call[0]).endsWith('/role-bindings/1') && call[1]?.method === 'DELETE',
    );
    expect(deleteCalls).toHaveLength(1);
  });

  it('renders the honest empty state', async () => {
    stubFetch(accessTabRoutes({ status: 200, body: { bindings: [] } }));
    renderApp('/users');
    await openAccessTab();
    expect(await screen.findByText('No Role Bindings Found')).toBeInTheDocument();
  });

  it("renders the server's captured 500 refusal verbatim", async () => {
    stubFetch(accessTabRoutes({ status: 500, body: { error: 'bindings exploded' } }));
    renderApp('/users');
    await openAccessTab();
    // Non-transport failures retry twice (QueryProvider), hence the timeout.
    const failure = await screen.findByText(/bindings exploded/, {}, { timeout: 10_000 });
    expect(failure).toHaveAttribute('role', 'alert');
  });

  it('has no axe violations with the Access tab open', async () => {
    stubFetch(accessTabRoutes());
    const { container } = renderApp('/users');
    await openAccessTab();
    await screen.findByText('demo-admin');
    await expectNoAxeViolations(container);
  });
});
