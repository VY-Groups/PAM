import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  ITSM_VERIFY_INVALID_TICKET_RESPONSE,
  ITSM_VERIFY_UNAUTHORIZED_RESPONSE,
  ITSM_VERIFY_UNCONFIGURED_RESPONSE,
  LDAP_BIND_INVALID_RESPONSE,
  LDAP_BIND_UNCONFIGURED_RESPONSE,
  MFA_ENROLL_UNAUTHORIZED_RESPONSE,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * The Enterprise Integrations 11.4 slice (screen 11, ADR-0015 + its 11.4
 * amendment): the four live connector note lines (legacy
 * `mfaGateNote`/`itsmNote`/`siemNote`/`ldapNote`, code.html:1283-1306),
 * the legacy-wired MFA enroll action (1702-1729), and the two NEW
 * actions no legacy button calls (ITSM verify, LDAP bind - ADR 11.4
 * inventory note). Every answer below is a verbatim rig capture; the
 * CONNECTED note branches and the LDAP 200 arms are contract-driven
 * only (no capture exists - pristine rigs are unconfigured), exactly
 * like the 11.3 SMTP 200 arm.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

const ITSM_NOTE = 'not connected - set itsm.base_url';

/** Render the page and wait for the integrations status read to settle. */
async function settledIntegrations(overrides?: Parameters<typeof settingsRoutes>[0]) {
  const fetchMock = stubFetch(settingsRoutes(overrides));
  renderWithProviders(<SettingsPage />);
  await screen.findByText(ITSM_NOTE);
  return fetchMock;
}

function postCall(fetchMock: ReturnType<typeof stubFetch>, stem: string) {
  return fetchMock.mock.calls.find(
    ([url, init]) =>
      (init as RequestInit | undefined)?.method === 'POST' && String(url).includes(stem),
  );
}

describe('connector note lines (screen 11, ADR-0015 11.4)', () => {
  it('renders the four legacy note lines verbatim and no static descriptions', async () => {
    stubFetch(settingsRoutes());
    const { container } = renderWithProviders(<SettingsPage />);

    // Each note is the legacy template's server-data arm, verbatim from
    // the captured pristine status read (code.html:1283-1297): the mfa
    // gate statement is live data, the others are the honest gaps.
    expect(
      await screen.findByText('not configured - the mfa band stays advisory'),
    ).toBeTruthy();
    expect(screen.getByTestId('settings-note-itsm').textContent).toBe(ITSM_NOTE);
    expect(screen.getByTestId('settings-note-siem').textContent).toBe(
      'not connected - set siem.webhook_url, a signing secret and enabled=true',
    );
    expect(screen.getByTestId('settings-note-ldap').textContent).toBe(
      'not connected - set ldap.server and ldap.user_bind_template',
    );

    // The note REPLACES the static description on the four connector
    // cards (legacy: note line, no description paragraph).
    expect(
      screen.queryByText(
        'The TOTP factor state - enrolled by its own endpoint, read-only here.',
      ),
    ).toBeNull();
    expect(
      screen.queryByText(
        'Ticket verification against the vendor API - endpoint, credentials and timeout.',
      ),
    ).toBeNull();
    expect(
      screen.queryByText(
        'Outbound audit push: webhook destination, signing secret and timeout.',
      ),
    ).toBeNull();
    expect(
      screen.queryByText('Directory bind: server, port, TLS and the user bind template.'),
    ).toBeNull();

    await expectNoAxeViolations(container);
  });

  it('a dead status read puts the legacy catch lines on all four notes', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/integrations\/status(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);

    // Verbatim catch texts (code.html:1303-1306) - the notes never claim
    // a connector state the server could not confirm. `findByText` waits
    // for the transport failure to settle (no retry for backend-down).
    expect(
      await screen.findByText('MFA gate status: \u2014 (license server not reachable)'),
    ).toBeTruthy();
    expect(
      await screen.findByText('ITSM status: \u2014 (license server not reachable)'),
    ).toBeTruthy();
    expect(
      await screen.findByText('SIEM status: \u2014 (license server not reachable)'),
    ).toBeTruthy();
    expect(
      await screen.findByText('LDAP status: \u2014 (license server not reachable)'),
    ).toBeTruthy();
  });
});

describe('MFA enroll (screen 11, ADR-0015 11.4 - the legacy-wired action)', () => {
  it('mints the factor and shows the secret box exactly once (verbatim 201)', async () => {
    const fetchMock = await settledIntegrations();

    // The one-time box is NOT in the DOM before the answer.
    expect(screen.queryByTestId('settings-mfa-secret-once')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Enroll MFA Factor' }));

    // The box, the server's own success message, and the documented
    // redaction stand-ins for the rig-minted material (house rule: real
    // secrets never enter the repo - the fixture says so on its face).
    const box = await screen.findByTestId('settings-mfa-secret-once');
    const codes = box.querySelectorAll('code');
    expect(codes[0].textContent).toBe('<redacted-shown-once>');
    expect(codes[1].textContent).toBe('<redacted-shown-once>');
    expect(
      await screen.findByText(
        'Factor enrolled - add it to your authenticator app; the secret is shown once',
      ),
    ).toBeTruthy();

    // The legacy enrolls with an empty JSON body (code.html:1707-1710).
    const call = postCall(fetchMock, '/mfa/enroll');
    expect(call, 'expected the mfa enroll POST').toBeTruthy();
    expect(JSON.parse(String((call?.[1] as RequestInit | undefined)?.body))).toEqual({});
  });

  it('a no-token enroll renders the 401 line verbatim and mints nothing', async () => {
    await settledIntegrations({ mfaEnroll: MFA_ENROLL_UNAUTHORIZED_RESPONSE });

    fireEvent.click(screen.getByRole('button', { name: 'Enroll MFA Factor' }));

    expect(
      await screen.findByText(
        'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
      ),
    ).toBeTruthy();
    expect(screen.queryByTestId('settings-mfa-secret-once')).toBeNull();
  });

  it('a dead enroll endpoint says no factor was enrolled (honest down line)', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/mfa\/enroll(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);
    await screen.findByText(ITSM_NOTE);

    fireEvent.click(screen.getByRole('button', { name: 'Enroll MFA Factor' }));

    expect(
      await screen.findByText(
        'Could not reach the license server - no factor was enrolled.',
      ),
    ).toBeTruthy();
    expect(screen.queryByTestId('settings-mfa-secret-once')).toBeNull();
  });

  it('the minted secret is kept on a failed re-enroll (legacy parity)', async () => {
    await settledIntegrations();

    fireEvent.click(screen.getByRole('button', { name: 'Enroll MFA Factor' }));
    await screen.findByTestId('settings-mfa-secret-once');

    // The re-enroll fails (this time the transport is dead): the box
    // keeps what was already given - the factor stays enrolled, the
    // legacy keeps its box (code.html:1721-1726 only hides on success's
    // own reload path, never on error).
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/mfa\/enroll(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    fireEvent.click(screen.getByRole('button', { name: 'Enroll MFA Factor' }));

    expect(
      await screen.findByText(
        'Could not reach the license server - no factor was enrolled.',
      ),
    ).toBeTruthy();
    expect(screen.getByTestId('settings-mfa-secret-once')).toBeTruthy();
  });
});

describe('ITSM verify (11.4 NEW action - no legacy button calls it)', () => {
  it('sends the ticket and renders the pristine rig 409 refusal verbatim', async () => {
    const fetchMock = await settledIntegrations({
      itsmVerify: ITSM_VERIFY_UNCONFIGURED_RESPONSE,
    });

    fireEvent.change(screen.getByLabelText('Ticket reference'), {
      target: { value: 'INC0012345' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verify Ticket' }));

    // The configured check refuses BEFORE any vendor call and that
    // refusal IS the feedback (verbatim capture).
    expect(await screen.findByText('ITSM is not configured')).toBeTruthy();

    const call = postCall(fetchMock, '/itsm/verify');
    expect(call, 'expected the itsm verify POST').toBeTruthy();
    expect(JSON.parse(String((call?.[1] as RequestInit | undefined)?.body))).toEqual({
      ticket: 'INC0012345',
    });
  });

  it('an empty ticket surfaces the server 400 validation line verbatim', async () => {
    await settledIntegrations({ itsmVerify: ITSM_VERIFY_INVALID_TICKET_RESPONSE });

    fireEvent.click(screen.getByRole('button', { name: 'Verify Ticket' }));

    expect(await screen.findByText("'ticket' is required")).toBeTruthy();
  });

  it('a no-token verify renders the 401 line verbatim', async () => {
    await settledIntegrations({ itsmVerify: ITSM_VERIFY_UNAUTHORIZED_RESPONSE });

    fireEvent.click(screen.getByRole('button', { name: 'Verify Ticket' }));

    expect(
      await screen.findByText(
        'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
      ),
    ).toBeTruthy();
  });

  it('a dead backend renders the shared honest down line', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/itsm\/verify(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);
    await screen.findByText(ITSM_NOTE);

    fireEvent.click(screen.getByRole('button', { name: 'Verify Ticket' }));

    expect(
      await screen.findByText(
        'Could not reach the license server - the action did not run.',
      ),
    ).toBeTruthy();
  });
});

describe('LDAP bind (11.4 NEW action - no legacy button calls it)', () => {
  it('sends the bind attempt, renders the pristine rig 409, never echoes the password', async () => {
    const fetchMock = await settledIntegrations({
      ldapBind: LDAP_BIND_UNCONFIGURED_RESPONSE,
    });
    const password = 'bind-secret-capture-standin';

    fireEvent.change(screen.getByLabelText('Bind username'), {
      target: { value: 'svc-directory' },
    });
    const passwordInput = screen.getByLabelText('Bind password');
    expect(passwordInput).toHaveAttribute('type', 'password');
    fireEvent.change(passwordInput, { target: { value: password } });
    fireEvent.click(screen.getByRole('button', { name: 'Test LDAP Bind' }));

    // The configured check runs before any bind (service.py:1879) - the
    // refusal is the feedback and the password never left the request.
    expect(await screen.findByText('LDAP is not configured')).toBeTruthy();
    expect(document.body.textContent).not.toContain(password);
    expect(screen.queryByTestId('settings-ldap-ticket-once')).toBeNull();

    const call = postCall(fetchMock, '/auth/ldap');
    expect(call, 'expected the ldap bind POST').toBeTruthy();
    expect(JSON.parse(String((call?.[1] as RequestInit | undefined)?.body))).toEqual({
      password,
      username: 'svc-directory',
    });
  });

  it('an empty password surfaces the server 400 validation line verbatim', async () => {
    await settledIntegrations({ ldapBind: LDAP_BIND_INVALID_RESPONSE });

    fireEvent.change(screen.getByLabelText('Bind username'), {
      target: { value: 'svc-directory' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Test LDAP Bind' }));

    expect(await screen.findByText("'password' is required")).toBeTruthy();
  });

  it('a dead backend renders the shared honest down line and mints no ticket', async () => {
    stubFetch([
      {
        match: (url: string) => /\/api\/v1\/auth\/ldap(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ]);
    renderWithProviders(<SettingsPage />);
    await screen.findByText(ITSM_NOTE);

    fireEvent.change(screen.getByLabelText('Bind username'), {
      target: { value: 'svc-directory' },
    });
    fireEvent.change(screen.getByLabelText('Bind password'), {
      target: { value: 'bind-secret-capture-standin' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Test LDAP Bind' }));

    expect(
      await screen.findByText(
        'Could not reach the license server - the action did not run.',
      ),
    ).toBeTruthy();
    expect(screen.queryByTestId('settings-ldap-ticket-once')).toBeNull();
  });
});
