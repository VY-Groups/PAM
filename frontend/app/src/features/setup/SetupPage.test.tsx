import { screen } from '@testing-library/react';
import { fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  SETUP_STATE_OPEN_BODY,
  WHOAMI_OPEN_BODY,
  healthRoute,
  jsonResponse,
  setupStateRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import type { CapturedResponse } from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * The /setup route set: the public state plus the write routes this test
 * answers with contract-shaped bodies (the fresh state after a profile
 * save, the completion message, and the uniform 401 refusal).
 */
const PROFILE_SAVED_BODY = {
  ...SETUP_STATE_OPEN_BODY,
  company_name: 'Acme Industrial',
  contact_email: 'ops@acme.example',
};
const COMPLETE_OK_BODY = { message: 'Setup completed - sign in with your company admins' };
const COMPLETE_REFUSED_BODY = { error: 'Invalid username or password' };

function setupProfileRoute(
  capture: CapturedResponse = { status: 200, body: PROFILE_SAVED_BODY },
) {
  return {
    match: (url: string) => url.endsWith('/setup/profile'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

function setupCompleteRoute(capture: CapturedResponse) {
  return {
    match: (url: string) => url.endsWith('/setup/complete'),
    respond: () => jsonResponse(capture.status, capture.body),
  };
}

/** The JSON body this mock call carried, or null when it sent none. */
function sentBody(
  fetchMock: ReturnType<typeof stubFetch>,
  needle: string,
): Record<string, unknown> | null {
  const call = fetchMock.mock.calls.find(([input]) => String(input).includes(needle));
  const init = call?.[1] as RequestInit | undefined;
  return typeof init?.body === 'string'
    ? (JSON.parse(init.body) as Record<string, unknown>)
    : null;
}

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe('SetupPage (ADR-0018 batch 11.11, contract-shaped)', () => {
  it('renders the whole wizard on a virgin install with both officer names', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute(), setupStateRoute()]);
    const { container } = renderApp('/setup');

    expect(await screen.findByText('Company profile')).toBeInTheDocument();
    expect(screen.getByText('Mail server')).toBeInTheDocument();
    expect(screen.getByText('Company admins')).toBeInTheDocument();
    expect(screen.getByText('Finish setup')).toBeInTheDocument();
    // the bootstrap officer names the state carries render verbatim
    expect(screen.getByText(/vypam-maker \(maker\)/)).toBeInTheDocument();
    expect(screen.getByText(/vypam-checker \(checker\)/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('answers the honest already-completed panel once the stamp is set', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      setupStateRoute({
        ...SETUP_STATE_OPEN_BODY,
        configured: true,
        company_name: 'Acme Industrial',
      }),
    ]);
    const { container } = renderApp('/setup');

    expect(await screen.findByText('Setup already completed')).toBeInTheDocument();
    expect(
      screen.getByText('This instance is configured. Sign in with a company account.'),
    ).toBeInTheDocument();
    expect(screen.queryByText('Company profile')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('saves the profile through PUT /setup/profile and shows the fresh state', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      setupStateRoute(),
      setupProfileRoute(),
    ]);
    renderApp('/setup');

    fireEvent.change(await screen.findByLabelText('Company name'), {
      target: { value: 'Acme Industrial' },
    });
    fireEvent.change(screen.getByLabelText('Contact e-mail'), {
      target: { value: 'ops@acme.example' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(await screen.findByText('Profile stored.')).toBeInTheDocument();
    const body = sentBody(fetchMock, '/setup/profile');
    expect(body).toMatchObject({
      company_name: 'Acme Industrial',
      contact_email: 'ops@acme.example',
      logo_data_uri: '',
    });
  });

  it('renders the officer-gate refusal verbatim when someone else saves', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      setupStateRoute(),
      setupProfileRoute({
        status: 403,
        body: {
          error:
            'Setup is still running - only the VY-PAM bootstrap officers may configure this instance',
          details: { phase: 'first-run', officers: ['vypam-maker', 'vypam-checker'] },
        },
      }),
    ]);
    renderApp('/setup');

    fireEvent.change(await screen.findByLabelText('Company name'), {
      target: { value: 'Not Yours Inc' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(
      await screen.findByText(
        'Setup is still running - only the VY-PAM bootstrap officers may configure this instance',
      ),
    ).toBeInTheDocument();
  });

  it('attests with both passwords and renders the server message verbatim', async () => {
    const fetchMock = stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      setupStateRoute(),
      setupCompleteRoute({ status: 200, body: COMPLETE_OK_BODY }),
    ]);
    renderApp('/setup');

    fireEvent.change(await screen.findByLabelText('Maker password'), {
      target: { value: 'foundry-copper-passphrase' },
    });
    fireEvent.change(screen.getByLabelText('Checker password'), {
      target: { value: 'granite-orchard-passphrase' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Complete setup' }));

    expect(await screen.findByText(COMPLETE_OK_BODY.message)).toBeInTheDocument();
    expect(sentBody(fetchMock, '/setup/complete')).toMatchObject({
      maker_password: 'foundry-copper-passphrase',
      checker_password: 'granite-orchard-passphrase',
    });
  });

  it('shows the uniform 401 refusal when either password is wrong', async () => {
    stubFetch([
      whoamiRoute(WHOAMI_OPEN_BODY),
      healthRoute(),
      setupStateRoute(),
      setupCompleteRoute({ status: 401, body: COMPLETE_REFUSED_BODY }),
    ]);
    renderApp('/setup');

    fireEvent.change(await screen.findByLabelText('Maker password'), {
      target: { value: 'wrong-maker-phrase-1' },
    });
    fireEvent.change(screen.getByLabelText('Checker password'), {
      target: { value: 'right-checker-phrase' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Complete setup' }));

    // the same bytes on both failures - the page never guesses which one
    expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();
    expect(screen.queryByText('Setup already completed')).not.toBeInTheDocument();
  });

  it('keeps the wizard honest when the state read is unreachable', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/setup');

    expect(await screen.findByText('License server unreachable')).toBeInTheDocument();
  });
});
