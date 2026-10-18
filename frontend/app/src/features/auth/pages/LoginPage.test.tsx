import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../../test/axe';
import {
  RECOVERY_RESET_OK_RESPONSE,
  RECOVERY_RESET_REFUSED_RESPONSE,
  RECOVERY_START_RESPONSE,
  RECOVERY_START_UNKNOWN_RESPONSE,
  UNAUTHENTICATED_BODY,
  WHOAMI_OPEN_BODY,
  bypassIncidentsRoute,
  bypassStatsRoute,
  eventsRoute,
  healthRoute,
  jsonResponse,
  overviewRoute,
  stubFetch,
  whoamiRoute,
} from '../../../test/fetchMock';
import { renderApp } from '../../../test/renderApp';

function loginRoute(respond: (init?: RequestInit) => Response | Promise<Response>) {
  return {
    match: (url: string) => url.includes('/auth/login'),
    respond,
  };
}

const MINT_200 = { session_token: 'tok-1', csrf_token: 'csrf-1' };

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('LoginPage (F3 login flow, contract-shaped)', () => {
  it('shows the honest required-fields message on an empty submit', async () => {
    stubFetch([whoamiRoute(UNAUTHENTICATED_BODY, 401), healthRoute()]);
    renderApp('/login');
    fireEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect(
      await screen.findByText('Username and password are required.'),
    ).toBeInTheDocument();
  });

  it('logs in with valid credentials, stores the legacy twins and enters the shell', async () => {
    let whoamiAnswered = false;
    stubFetch([
      {
        match: (url: string) => url.includes('/auth/whoami'),
        respond: () => {
          if (!whoamiAnswered) {
            whoamiAnswered = true;
            return jsonResponse(401, UNAUTHENTICATED_BODY);
          }
          return jsonResponse(200, WHOAMI_OPEN_BODY);
        },
      },
      loginRoute(() => jsonResponse(200, MINT_200)),
      healthRoute(),
      overviewRoute(),
      eventsRoute(),
      bypassStatsRoute(),
      bypassIncidentsRoute(),
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(
      await screen.findByRole('heading', { name: /PAM Command Center/ }),
    ).toBeInTheDocument();
    expect(sessionStorage.getItem('aegispam_admin_token')).toBe('tok-1');
    expect(sessionStorage.getItem('aegispam_admin_csrf')).toBe('csrf-1');
  });

  it('continues the 403 mfa_required challenge with the TOTP code (contract shape)', async () => {
    let whoamiAnswered = false;
    const fetchMock = stubFetch([
      {
        match: (url: string) => url.includes('/auth/whoami'),
        respond: () => {
          if (!whoamiAnswered) {
            whoamiAnswered = true;
            return jsonResponse(401, UNAUTHENTICATED_BODY);
          }
          return jsonResponse(200, WHOAMI_OPEN_BODY);
        },
      },
      loginRoute((init) => {
        const body = init?.body
          ? (JSON.parse(String(init.body)) as Record<string, unknown>)
          : {};
        if (body.login_challenge === 'vypam-mfa1.c.s' && body.totp_code === '123456') {
          return jsonResponse(200, { session_token: 'tok-2', csrf_token: 'csrf-2' });
        }
        return jsonResponse(403, {
          error: 'MFA required',
          status: 'mfa_required',
          challenge: 'vypam-mfa1.c.s',
        });
      }),
      healthRoute(),
      overviewRoute(),
      eventsRoute(),
      bypassStatsRoute(),
      bypassIncidentsRoute(),
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    const code = await screen.findByLabelText('Verification code');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(
      await screen.findByRole('heading', { name: /PAM Command Center/ }),
    ).toBeInTheDocument();

    const loginCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/auth/login'),
    );
    const retry = JSON.parse(
      String((loginCalls[1] as unknown as [string, RequestInit])[1].body),
    );
    expect(retry).toMatchObject({
      username: 'admin',
      login_challenge: 'vypam-mfa1.c.s',
      totp_code: '123456',
    });
  });

  it('shows the fail-closed enrolment message with the offered methods', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      loginRoute(() =>
        jsonResponse(403, {
          error: 'No factor enrolled',
          status: 'enrolment_required',
          methods_allowed: ['totp', 'webauthn'],
        }),
      ),
      healthRoute(),
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(
      await screen.findByText(/not yet enrolled \(totp, webauthn\)/),
    ).toBeInTheDocument();
  });

  it("surfaces the server's honest 401 refusal text", async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      loginRoute(() => jsonResponse(401, { error: 'Invalid credentials' })),
      healthRoute(),
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument();
  });

  it('shows the honest backend-down message when the server cannot be reached', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      loginRoute(() => Promise.reject(new TypeError('Failed to fetch'))),
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(
      await screen.findByText('Cannot reach the license server: Failed to fetch'),
    ).toBeInTheDocument();
    expect(screen.getByText(/License server: not connected/)).toBeInTheDocument();
  });

  it('redirects an already-authenticated visitor away from login', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      overviewRoute(),
      eventsRoute(),
      bypassStatsRoute(),
      bypassIncidentsRoute(),
    ]);
    renderApp('/login');
    expect(
      await screen.findByRole('heading', { name: /PAM Command Center/ }),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch([whoamiRoute(UNAUTHENTICATED_BODY, 401), healthRoute()]);
    const { container } = renderApp('/login');
    await screen.findByLabelText('Username');
    await expectNoAxeViolations(container);
  });
});

/** ADR-0016 batch 11.6 - the forgot-password flow on the login card. */
function recoveryStartRoute(
  capture: { status: number; body: unknown } = RECOVERY_START_RESPONSE,
) {
  return {
    match: (url: string) => url.includes('/auth/recovery/start'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

function recoveryResetRoute(
  capture: { status: number; body: unknown } = RECOVERY_RESET_REFUSED_RESPONSE,
) {
  return {
    match: (url: string) => url.includes('/auth/recovery/reset'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

describe('LoginPage recovery (ADR-0016 batch 11.6, contract-shaped)', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  /** Step 1: username -> the generic 202 -> step 2. Returns once step 2 shows. */
  async function reachRecoveryStep2(username: string): Promise<void> {
    renderApp('/login');
    fireEvent.click(await screen.findByRole('button', { name: 'Forgot password?' }));
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: username },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send code' }));
    await screen.findByText(/has an account, a one-time code was sent/);
  }

  it('requests the code and shows the generic anti-enumeration answer verbatim', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(),
    ]);
    await reachRecoveryStep2('admin');
    expect(
      screen.getByText(
        'If admin has an account, a one-time code was sent to its registered e-mail.',
      ),
    ).toBeInTheDocument();
    const startCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/auth/recovery/start'),
    );
    expect(startCalls).toHaveLength(1);
    expect(
      JSON.parse(String((startCalls[0] as unknown as [string, RequestInit])[1].body)),
    ).toEqual({
      username: 'admin',
    });
  });

  it('answers unknown usernames with the same shape and the same copy (no enumeration)', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(RECOVERY_START_UNKNOWN_RESPONSE),
    ]);
    await reachRecoveryStep2('nobody.here');
    expect(
      screen.getByText(
        'If nobody.here has an account, a one-time code was sent to its registered e-mail.',
      ),
    ).toBeInTheDocument();
  });

  it('renders the refused code verbatim and keeps the challenge open', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(),
      recoveryResetRoute(RECOVERY_RESET_REFUSED_RESPONSE),
    ]);
    await reachRecoveryStep2('ops.user');
    fireEvent.change(screen.getByLabelText('One-time code'), {
      target: { value: '000000' },
    });
    fireEvent.change(screen.getByLabelText('New password'), {
      target: { value: 'New-Pass-9921-Zz!' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }));

    expect(await screen.findByText('One-time code invalid or expired')).toBeInTheDocument();
    // still on step 2 - the challenge stays open for another attempt
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeInTheDocument();
    const resetCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/auth/recovery/reset'),
    );
    expect(resetCalls).toHaveLength(1);
    expect(
      JSON.parse(String((resetCalls[0] as unknown as [string, RequestInit])[1].body)),
    ).toEqual({
      username: 'ops.user',
      challenge_id: '4c27cc0058a3ec853ace76153ef03e5b',
      code: '000000',
      new_password: 'New-Pass-9921-Zz!',
    });
  });

  it('shows the server success message verbatim and returns to sign-in', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(),
      recoveryResetRoute(RECOVERY_RESET_OK_RESPONSE),
    ]);
    await reachRecoveryStep2('ops.user');
    fireEvent.change(screen.getByLabelText('One-time code'), {
      target: { value: '48190273' },
    });
    fireEvent.change(screen.getByLabelText('New password'), {
      target: { value: 'New-Pass-9921-Zz!' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }));

    expect(await screen.findByText('Password reset - sign in again')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('ops.user');
  });

  it('mirrors the captured password policy client-side (min 14) without a request', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(),
      recoveryResetRoute(),
    ]);
    await reachRecoveryStep2('ops.user');
    fireEvent.change(screen.getByLabelText('One-time code'), {
      target: { value: '48190273' },
    });
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'short' } });
    fireEvent.click(screen.getByRole('button', { name: 'Set new password' }));
    expect(
      await screen.findByText(
        'Enter the code and a new password of at least 14 characters.',
      ),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter((call) =>
        String(call[0]).includes('/auth/recovery/reset'),
      ),
    ).toHaveLength(0);
  });

  it('shows the honest backend-down line when the recovery start cannot reach the server', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      {
        match: (url: string) => url.includes('/auth/recovery/start'),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
    ]);
    renderApp('/login');
    fireEvent.click(await screen.findByRole('button', { name: 'Forgot password?' }));
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send code' }));
    expect(
      await screen.findByText('Cannot reach the license server: Failed to fetch'),
    ).toBeInTheDocument();
  });

  it('has no axe violations on both recovery steps', async () => {
    stubFetch([
      whoamiRoute(UNAUTHENTICATED_BODY, 401),
      healthRoute(),
      recoveryStartRoute(),
    ]);
    const { container } = renderApp('/login');
    fireEvent.click(await screen.findByRole('button', { name: 'Forgot password?' }));
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    await expectNoAxeViolations(container);
    fireEvent.click(screen.getByRole('button', { name: 'Send code' }));
    await screen.findByText(/has an account, a one-time code was sent/);
    await expectNoAxeViolations(container);
  });
});
