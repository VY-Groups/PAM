import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  USER_LOCKED_ROW,
  USER_PATCH_ACTIVATE_RESPONSE,
  USER_PATCH_DEACTIVATE_RESPONSE,
  USERS_CREATE_CONFLICT_RESPONSE,
  USERS_CREATE_GENERATED_RESPONSE,
  USERS_CREATE_WEAK_RESPONSE,
  USERS_LIST_RESPONSE,
  USERS_LIST_UNAUTHORIZED_RESPONSE,
  WHOAMI_OPEN_BODY,
  healthRoute,
  stubFetch,
  userPatchRoute,
  userResetRoute,
  userSessionsRevokeRoute,
  userUnlockRoute,
  usersRoute,
  whoamiRoute,
} from '../../test/fetchMock';
import type { CapturedResponse } from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * The /users route set (whoami + health + the registry) with a custom
 * list or create answer; the detail writes keep their captured defaults
 * (`unlock`, `password-reset`, `revoke sessions`, `patch deactivate`).
 */
function usersPageRoutes(
  list: CapturedResponse = USERS_LIST_RESPONSE,
  create: CapturedResponse = USERS_CREATE_GENERATED_RESPONSE,
  patch: CapturedResponse = USER_PATCH_DEACTIVATE_RESPONSE,
) {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    usersRoute(list, create),
    userUnlockRoute(2),
    userResetRoute(2),
    userSessionsRevokeRoute(2),
    userPatchRoute(2, patch),
  ];
}

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/** The registry KPI value (KpiCard.valueDataRole, never the label card). */
function tile(container: HTMLElement, role: string): string | null {
  return container.querySelector(`[data-role="${role}"]`)?.textContent ?? null;
}

/** The `<tr>` that carries this username (waits for the row to load). */
async function rowOf(username: string): Promise<HTMLElement> {
  const cell = await screen.findByText(username);
  const tr = cell.closest('tr');
  if (tr === null) throw new Error(`no row for ${username}`);
  return tr;
}

describe('UsersPage (ADR-0016 batch 11.7, contract-shaped)', () => {
  it('renders the captured registry verbatim with derived status chips', async () => {
    stubFetch(usersPageRoutes());
    const { container } = renderApp('/users');

    expect(await screen.findByText('audit.readonly')).toBeInTheDocument();
    expect(screen.getByText('emergency-admin')).toBeInTheDocument();
    expect(screen.getByText('ops.user')).toBeInTheDocument();
    expect(screen.getByText('Emergency administrator (offline)')).toBeInTheDocument();
    expect(screen.getByText('audit.reader@example.com')).toBeInTheDocument();

    // status derivation from the captured fields
    expect(
      within(await rowOf('emergency-admin')).getByText('Emergency'),
    ).toBeInTheDocument();
    expect(
      within(await rowOf('ops.user')).getByText('Must change password'),
    ).toBeInTheDocument();
    expect(within(await rowOf('audit.readonly')).getByText('Active')).toBeInTheDocument();
    // every captured last_login_at is null -> honest "Never"
    expect(screen.getAllByText('Never')).toHaveLength(3);
    // source cells are server data, rendered as-is
    expect(
      within(await rowOf('emergency-admin')).getByText('emergency'),
    ).toBeInTheDocument();

    // registry-wide tiles from the capture: 3 users, 3 active, 0 locked, 1 must-change
    await waitFor(() => expect(tile(container, 'users-tile-total')).toBe('3'));
    expect(tile(container, 'users-tile-active')).toBe('3');
    expect(tile(container, 'users-tile-locked')).toBe('0');
    expect(tile(container, 'users-tile-must-change')).toBe('1');
  });

  it('narrows the table honestly and keeps the registry-wide tiles', async () => {
    stubFetch(usersPageRoutes());
    const { container } = renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Filter users'), { target: { value: 'zzz' } });
    expect(await screen.findByText('No users match this filter.')).toBeInTheDocument();
    expect(screen.queryByText('ops.user')).not.toBeInTheDocument();
    // the tiles read the unfiltered registry, not the filtered view
    expect(tile(container, 'users-tile-total')).toBe('3');
  });

  it('sends the source filter server-side as the contract offers it', async () => {
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'scim' } });
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some((call) => String(call[0]).includes('source=scim')),
      ).toBe(true),
    );
  });

  it('renders the captured lockout row with Unlock and clears it verbatim', async () => {
    const fetchMock = stubFetch(
      usersPageRoutes({ status: 200, body: { users: [USER_LOCKED_ROW] } }),
    );
    renderApp('/users');

    const lockedRow = await rowOf('ops.user');
    expect(await within(lockedRow).findByText('Locked')).toBeInTheDocument();
    fireEvent.click(within(lockedRow).getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText('User unlocked')).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter((call) => String(call[0]).endsWith('/users/2/unlock')),
    ).toHaveLength(1);
  });

  it('deactivate asks the captured question, PATCHes {active:false} and answers verbatim', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    const row = await rowOf('ops.user');
    await within(row).findByText('Active');

    fireEvent.click(within(row).getByRole('button', { name: 'Deactivate' }));
    expect(confirm).toHaveBeenCalledWith(
      'Deactivate ops.user? Every live session of this account is revoked.',
    );
    expect(await screen.findByText('User updated')).toBeInTheDocument();
    const patchCalls = fetchMock.mock.calls.filter(
      (call) => String(call[0]).includes('/users/2') && call[1]?.method === 'PATCH',
    );
    expect(patchCalls).toHaveLength(1);
    expect(JSON.parse(String(patchCalls[0][1]?.body))).toEqual({ active: false });
  });

  it('cancel on deactivate does nothing (no request)', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    const row = await rowOf('ops.user');
    await within(row).findByText('Active');

    fireEvent.click(within(row).getByRole('button', { name: 'Deactivate' }));
    expect(
      fetchMock.mock.calls.filter(
        (call) => String(call[0]).includes('/users/2') && call[1]?.method === 'PATCH',
      ),
    ).toHaveLength(0);
    expect(screen.queryByText('User updated')).not.toBeInTheDocument();
  });

  it('activate on an inactive row PATCHes {active:true} and answers verbatim', async () => {
    const inactiveOps = { ...USERS_LIST_RESPONSE.body.users[2], is_active: false };
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = stubFetch(
      usersPageRoutes(
        { status: 200, body: { users: [inactiveOps] } },
        USERS_CREATE_GENERATED_RESPONSE,
        USER_PATCH_ACTIVATE_RESPONSE,
      ),
    );
    renderApp('/users');

    const row = await rowOf('ops.user');
    fireEvent.click(await within(row).findByRole('button', { name: 'Activate' }));
    expect(await screen.findByText('User updated')).toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
    const patchCalls = fetchMock.mock.calls.filter(
      (call) => String(call[0]).includes('/users/2') && call[1]?.method === 'PATCH',
    );
    expect(JSON.parse(String(patchCalls[0][1]?.body))).toEqual({ active: true });
  });

  it('password reset shows the one-time secret, copies it and answers verbatim', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    stubFetch(usersPageRoutes());
    renderApp('/users');
    const row = await rowOf('ops.user');
    await within(row).findByText('Active');

    fireEvent.click(within(row).getByRole('button', { name: 'Reset password' }));
    expect(
      await screen.findByText('Password reset - every session revoked'),
    ).toBeInTheDocument();
    const reveal = screen.getByTestId('user-secret');
    expect(
      within(reveal).getByText('New password for ops.user - shown once'),
    ).toBeInTheDocument();
    expect(within(reveal).getByText('fixture-ResetOnce-0000')).toBeInTheDocument();

    fireEvent.click(within(reveal).getByRole('button', { name: 'Copy' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('fixture-ResetOnce-0000'));
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('revoke sessions asks the captured question and answers the captured count', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    const row = await rowOf('ops.user');
    await within(row).findByText('Active');

    fireEvent.click(within(row).getByRole('button', { name: 'Revoke sessions' }));
    expect(confirm).toHaveBeenCalledWith('Revoke every live session of ops.user?');
    expect(await screen.findByText('0 session(s) revoked')).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(
        (call) =>
          String(call[0]).endsWith('/users/2/sessions') && call[1]?.method === 'DELETE',
      ),
    ).toHaveLength(1);
  });

  it('create without a password reveals the generated secret once (captured)', async () => {
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'new.user' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));

    expect(await screen.findByText('User created')).toBeInTheDocument();
    const reveal = screen.getByTestId('user-secret');
    // the reveal mirrors the SERVER's answer (the verbatim capture created
    // ops.user on the rig), not the typed value - the POST body below
    // proves the typed username went out
    expect(
      within(reveal).getByText('Generated password for ops.user - shown once'),
    ).toBeInTheDocument();
    expect(within(reveal).getByText('fixture-GeneratedOnce-0000')).toBeInTheDocument();
    const createCalls = fetchMock.mock.calls.filter(
      (call) => String(call[0]).endsWith('/api/v1/users') && call[1]?.method === 'POST',
    );
    expect(createCalls).toHaveLength(1);
    expect(JSON.parse(String(createCalls[0][1]?.body))).toEqual({ username: 'new.user' });
    // the form resets after the successful create
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('');
  });

  it("renders the server's captured 409 refusal verbatim", async () => {
    stubFetch(usersPageRoutes(USERS_LIST_RESPONSE, USERS_CREATE_CONFLICT_RESPONSE));
    renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ops.user' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(await screen.findByText("User 'ops.user' already exists")).toBeInTheDocument();
  });

  it("renders the server's captured NIST refusal verbatim when the server knows better", async () => {
    stubFetch(usersPageRoutes(USERS_LIST_RESPONSE, USERS_CREATE_WEAK_RESPONSE));
    renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: 'common.pass.user' },
    });
    fireEvent.change(screen.getByLabelText('Initial password (optional)'), {
      // 16 chars: passes the client mirror; the server stays authoritative
      target: { value: 'commonpassword12' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(
      await screen.findByText(
        'Password must be at least 14 characters (NIST: length over complexity)',
      ),
    ).toBeInTheDocument();
  });

  it('mirrors the captured password policy client-side when the form is short', async () => {
    const fetchMock = stubFetch(usersPageRoutes());
    renderApp('/users');
    await screen.findByText('audit.readonly');

    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: 'short.pass' },
    });
    fireEvent.change(screen.getByLabelText('Initial password (optional)'), {
      target: { value: 'TooShort12' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
    expect(
      await screen.findByText('The initial password must be at least 14 characters.'),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(
        (call) => String(call[0]).endsWith('/api/v1/users') && call[1]?.method === 'POST',
      ),
    ).toHaveLength(0);
  });

  it('renders the captured 401 refusal verbatim with honest dash tiles', async () => {
    stubFetch(usersPageRoutes(USERS_LIST_UNAUTHORIZED_RESPONSE));
    const { container } = renderApp('/users');
    // the alert wraps the server's message in the i18n prefix (states.error);
    // the query client retries non-transport failures twice before settling
    expect(
      await screen.findByText(
        /Admin token required \(Authorization: Bearer <token> or X-Admin-Token\)/,
        {},
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
    expect(tile(container, 'users-tile-total')).toBe('—');
  });

  it('has no axe violations', async () => {
    stubFetch(usersPageRoutes());
    const { container } = renderApp('/users');
    await screen.findByText('audit.readonly');
    await expectNoAxeViolations(container);
  });
});
