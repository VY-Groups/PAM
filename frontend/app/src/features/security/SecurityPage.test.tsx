import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  BACKUP_CODES_RESPONSE,
  DELETE_FACTOR_OK_RESPONSE,
  DELETE_LAST_FACTOR_RESPONSE,
  ENROLL_EMAIL_NO_ADDRESS_RESPONSE,
  ENROLL_EMAIL_VERIFY_BAD_RESPONSE,
  ENROLL_EMAIL_VERIFY_OK_RESPONSE,
  ENROLL_RADIUS_OK_RESPONSE,
  ENROLL_RADIUS_UNCONFIGURED_RESPONSE,
  ENROLL_TOTP_RESPONSE,
  ENROLL_TOTP_VERIFY_OK_RESPONSE,
  ENROLL_TOTP_VERIFY_WRONG_RESPONSE,
  MFA_ASSERTION_FAILED_RESPONSE,
  MFA_FACTORS_EMPTY_RESPONSE,
  MFA_FACTORS_NO_SESSION_RESPONSE,
  MFA_FACTORS_RESPONSE,
  STEPUP_REQUIRED_RESPONSE,
  WHOAMI_OPEN_BODY,
  healthRoute,
  jsonResponse,
  mfaBackupCodesRoute,
  mfaEnrollEmailRoute,
  mfaEnrollEmailVerifyRoute,
  mfaEnrollRadiusRoute,
  mfaEnrollTotpRoute,
  mfaEnrollTotpVerifyRoute,
  mfaFactorsRoute,
  mfaStepupRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import type { CapturedResponse } from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * The /security route set (whoami + health + the mfa surface) with
 * per-endpoint captured overrides; everything not overridden keeps its
 * verbatim rig default.
 */
function securityPageRoutes(
  overrides: Partial<{
    list: CapturedResponse;
    remove: CapturedResponse;
    backup: CapturedResponse;
    totpEnrol: CapturedResponse;
    totpVerify: CapturedResponse;
    email: CapturedResponse;
    emailVerify: CapturedResponse;
    radius: CapturedResponse;
    stepup: CapturedResponse;
  }> = {},
) {
  return [
    whoamiRoute(WHOAMI_OPEN_BODY),
    healthRoute(),
    mfaFactorsRoute(overrides.list ?? MFA_FACTORS_RESPONSE, overrides.remove),
    mfaBackupCodesRoute(overrides.backup),
    mfaEnrollTotpRoute(overrides.totpEnrol ?? ENROLL_TOTP_RESPONSE),
    mfaEnrollTotpVerifyRoute(overrides.totpVerify),
    mfaEnrollEmailRoute(overrides.email),
    mfaEnrollEmailVerifyRoute(overrides.emailVerify),
    mfaEnrollRadiusRoute(overrides.radius),
    mfaStepupRoute(overrides.stepup),
  ];
}

/**
 * A route whose answers advance per request (the step-up retry-once flow:
 * refuse, then accept after the refresh).
 */
function sequenceRoute(match: (url: string) => boolean, bodies: CapturedResponse[]) {
  let i = 0;
  return {
    match,
    respond: () => {
      const capture = bodies[Math.min(i, bodies.length - 1)];
      i += 1;
      return jsonResponse(capture.status, capture.body);
    },
  };
}

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/**
 * The `<tr>` that carries this label. "Authenticator app" also names the
 * TOTP section heading (which renders before the async list lands), so the
 * label must resolve inside a table row - waitFor keeps polling until the
 * row exists.
 */
async function rowOf(label: string): Promise<HTMLElement> {
  return await waitFor(() => {
    const cells = screen.getAllByText(label);
    for (const cell of cells) {
      const tr = cell.closest('tr');
      if (tr !== null) return tr;
    }
    throw new Error(`no table row for ${label}`);
  });
}

describe('SecurityPage (ADR-0017 batch 11.8, contract-shaped)', () => {
  it('renders the captured factor row verbatim (kind, label, chip, last use)', async () => {
    stubFetch(securityPageRoutes());
    renderApp('/security');

    const row = await rowOf('Authenticator app');
    expect(within(row).getByText('totp')).toBeInTheDocument();
    expect(within(row).getByText('Active')).toBeInTheDocument();
    // the capture carries a real last_used_at, so the honest Never is absent
    expect(within(row).queryByText('Never')).toBeNull();
  });

  it('shows the honest empty state when no factors exist', async () => {
    stubFetch(securityPageRoutes({ list: MFA_FACTORS_EMPTY_RESPONSE }));
    renderApp('/security');
    expect(
      await screen.findByText(/No factors yet - enrol an authenticator app below/),
    ).toBeInTheDocument();
  });

  it('renders the captured no-session 401 verbatim', async () => {
    stubFetch(securityPageRoutes({ list: MFA_FACTORS_NO_SESSION_RESPONSE }));
    renderApp('/security');
    // the shared client retries non-transport failures before the error
    // state lands (QueryProvider), hence the raised waitFor timeout
    expect(
      await screen.findByText(
        'Cannot load factors: Console session required',
        {},
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
  });

  it('shows the honest backend-down notice when factors cannot load', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      {
        match: (url: string) => /\/auth\/mfa\/factors(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
    ]);
    renderApp('/security');
    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
  });

  it('refuses factor removal with the captured last-factor 403 verbatim', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    stubFetch(securityPageRoutes({ remove: DELETE_LAST_FACTOR_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    expect(confirm).toHaveBeenCalledWith(
      'Remove the Authenticator app factor? Sign-in keeps working while another factor remains.',
    );
    expect(
      await screen.findByText(
        "This is the user's last factor and mfa_required is on - request a two-admin recovery instead (POST /api/v1/auth/factor-recovery/request)",
      ),
    ).toBeInTheDocument();
    // the row survives - the server refused, the table re-read shows it
    expect((await screen.findAllByText('Authenticator app')).length).toBeGreaterThan(0);
  });

  it("removes a factor and renders the server's own answer verbatim", async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    stubFetch(securityPageRoutes({ remove: DELETE_FACTOR_OK_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    expect(await screen.findByText('Factor removed')).toBeInTheDocument();
  });

  it('enrols TOTP: the shown-once secret box, then the captured invalid-code 401 verbatim', async () => {
    stubFetch(securityPageRoutes({ totpVerify: ENROLL_TOTP_VERIFY_WRONG_RESPONSE }));
    renderApp('/security');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Set up authenticator app' }),
    );
    const box = await screen.findByTestId('totp-secret');
    expect(within(box).getByText('fixture-TotpSecret-0000')).toBeInTheDocument();
    expect(
      within(box).getByText(/otpauth:\/\/totp\/VY-PAM%3Asec\.user/),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Current code from the app'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify and activate' }));
    expect(await screen.findByText('TOTP code invalid')).toBeInTheDocument();
    // the secret stays on screen for another attempt
    expect(screen.getByTestId('totp-secret')).toBeInTheDocument();
  });

  it('verifies TOTP with a live code and clears the secret box', async () => {
    stubFetch(securityPageRoutes({ totpVerify: ENROLL_TOTP_VERIFY_OK_RESPONSE }));
    renderApp('/security');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Set up authenticator app' }),
    );
    await screen.findByTestId('totp-secret');
    fireEvent.change(screen.getByLabelText('Current code from the app'), {
      target: { value: '48190273' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify and activate' }));

    expect(
      await screen.findByText('Authenticator app verified (totp).'),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('totp-secret')).toBeNull();
  });

  it('generates backup codes and renders the server shown-once message verbatim', async () => {
    stubFetch(securityPageRoutes());
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Generate backup codes' }));
    const box = await screen.findByTestId('backup-codes');
    expect(
      within(box).getByText('Shown once - store them now; they cannot be recovered.'),
    ).toBeInTheDocument();
    expect(within(box).getByText('0001-0001-0001-0001')).toBeInTheDocument();
  });

  it('pauses on the captured step-up 403 and retries the action exactly once', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      mfaFactorsRoute(),
      sequenceRoute(
        (url) => url.endsWith('/auth/mfa/backup-codes'),
        [STEPUP_REQUIRED_RESPONSE, BACKUP_CODES_RESPONSE],
      ),
      mfaStepupRoute(),
    ]);
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Generate backup codes' }));
    // the refusal pauses into the step-up card - no scary alert
    await screen.findByTestId('stepup-card');
    expect(screen.queryByRole('alert')).toBeNull();

    fireEvent.change(screen.getByLabelText('Verification code'), {
      target: { value: '48190273' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify step-up' }));

    expect(await screen.findByText('Step-up verified (totp).')).toBeInTheDocument();
    await screen.findByTestId('backup-codes');
    const backupCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/auth/mfa/backup-codes'),
    );
    expect(backupCalls).toHaveLength(2); // refused once, retried once
    expect(screen.queryByTestId('stepup-card')).toBeNull();
  });

  it('renders a second step-up refusal verbatim instead of pausing again', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      mfaFactorsRoute(),
      mfaBackupCodesRoute(STEPUP_REQUIRED_RESPONSE), // refuses again after the refresh
      mfaStepupRoute(),
    ]);
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Generate backup codes' }));
    await screen.findByTestId('stepup-card');
    fireEvent.change(screen.getByLabelText('Verification code'), {
      target: { value: '48190273' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify step-up' }));

    expect(
      await screen.findByText(
        'Step-up MFA required for this action (POST /api/v1/auth/mfa/stepup within 1 min)',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('stepup-card')).toBeNull();
  });

  it('verifies a step-up refusal with the captured 401 verbatim', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      mfaFactorsRoute(),
      mfaBackupCodesRoute(STEPUP_REQUIRED_RESPONSE),
      mfaStepupRoute(MFA_ASSERTION_FAILED_RESPONSE),
    ]);
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Generate backup codes' }));
    await screen.findByTestId('stepup-card');
    fireEvent.change(screen.getByLabelText('Verification code'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify step-up' }));

    expect(await screen.findByText('MFA assertion failed')).toBeInTheDocument();
    // a wrong step-up code must NOT consume the paused action: the card
    // stays open for a fresh code, with the server's refusal verbatim
    expect(screen.getByTestId('stepup-card')).toBeInTheDocument();
  });

  it('enrols e-mail: generic 202 copy, then the captured invalid-code 401 verbatim', async () => {
    stubFetch(securityPageRoutes({ emailVerify: ENROLL_EMAIL_VERIFY_BAD_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'E-mail me a code' }));
    expect(
      await screen.findByText(
        'If your account has a registered mailbox, a one-time code was sent to it.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/No mail server configured yet\?/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('One-time code'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify e-mail factor' }));
    expect(await screen.findByText('One-time code invalid or expired')).toBeInTheDocument();
  });

  it('enrols e-mail with a live code (source-verified success answer)', async () => {
    stubFetch(securityPageRoutes({ emailVerify: ENROLL_EMAIL_VERIFY_OK_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'E-mail me a code' }));
    await screen.findByText(
      'If your account has a registered mailbox, a one-time code was sent to it.',
    );
    fireEvent.change(screen.getByLabelText('One-time code'), {
      target: { value: '48190273' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify e-mail factor' }));

    expect(await screen.findByText('E-mail factor enrolled.')).toBeInTheDocument();
    expect(screen.queryByText('Verify e-mail factor')).toBeNull();
  });

  it('renders the captured no-address 400 verbatim and never opens the verify form', async () => {
    stubFetch(securityPageRoutes({ email: ENROLL_EMAIL_NO_ADDRESS_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'E-mail me a code' }));
    expect(
      await screen.findByText(
        'This account has no e-mail address - an admin sets it first (PATCH /api/v1/users/{user_id})',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText('One-time code')).toBeNull();
  });

  it('renders the captured unconfigured-RADIUS 503 verbatim', async () => {
    stubFetch(securityPageRoutes({ radius: ENROLL_RADIUS_UNCONFIGURED_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Enrol RADIUS factor' }));
    expect(
      await screen.findByText(
        'RADIUS is not configured - set host, port and the shared secret in the `radius` settings group and enable it first',
      ),
    ).toBeInTheDocument();
  });

  it('enrols RADIUS on a configured deployment (source-verified 201 answer)', async () => {
    stubFetch(securityPageRoutes({ radius: ENROLL_RADIUS_OK_RESPONSE }));
    renderApp('/security');

    fireEvent.click(await screen.findByRole('button', { name: 'Enrol RADIUS factor' }));
    expect(await screen.findByText('RADIUS factor enrolled.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('has no axe violations', async () => {
    stubFetch(securityPageRoutes());
    const { container } = renderApp('/security');
    await screen.findByTestId('security-page');
    await screen.findAllByText('Authenticator app');
    await expectNoAxeViolations(container);
  });
});
