import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../../test/axe';
import {
  UNAUTHENTICATED_BODY,
  WHOAMI_OPEN_BODY,
  healthRoute,
  jsonResponse,
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
    ]);
    renderApp('/login');
    fireEvent.change(await screen.findByLabelText('Username'), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(
      await screen.findByRole('heading', { name: /arrives at F4/ }),
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
      await screen.findByRole('heading', { name: /arrives at F4/ }),
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
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/login');
    expect(
      await screen.findByRole('heading', { name: /arrives at F4/ }),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch([whoamiRoute(UNAUTHENTICATED_BODY, 401), healthRoute()]);
    const { container } = renderApp('/login');
    await screen.findByLabelText('Username');
    await expectNoAxeViolations(container);
  });
});
