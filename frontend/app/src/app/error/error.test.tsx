import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import { WHOAMI_OPEN_BODY, stubFetch, whoamiRoute } from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { ErrorBoundary } from './ErrorBoundary';
import { NotFound } from './NotFound';
import { PendingScreen } from '../PendingScreen';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('NotFound (real client 404, ADR-0005)', () => {
  it('renders the honest 404 with a way back', () => {
    stubFetch([]);
    renderWithProviders(<NotFound />);
    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to Command Center' })).toHaveAttribute(
      'href',
      '/',
    );
  });

  it('has no axe violations', async () => {
    stubFetch([]);
    const { container } = renderWithProviders(<NotFound />);
    await expectNoAxeViolations(container);
  });
});

describe('ErrorBoundary (app crash guard)', () => {
  it('shows the honest crash state and recovers on retry', async () => {
    stubFetch([]);
    let shouldThrow = true;
    function Bomb(): React.ReactElement {
      if (shouldThrow) throw new Error('boom');
      return <p>Recovered view</p>;
    }
    renderWithProviders(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Something went wrong');
    shouldThrow = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Recovered view')).toBeInTheDocument();
  });
});

describe('PendingScreen (honest F4 strangler state)', () => {
  it('names the feature, the phase and links the live legacy screen', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY)]);
    renderWithProviders(
      <PendingScreen
        titleKey="nav.vault"
        legacyHref="/screens/credential_vault_secrets_inventory/code.html"
      />,
    );
    expect(
      await screen.findByRole('heading', { name: 'Credential Vault arrives at F4' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open the legacy screen/i })).toHaveAttribute(
      'href',
      '/screens/credential_vault_secrets_inventory/code.html',
    );
  });
});
