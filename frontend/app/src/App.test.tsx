import { render, screen } from '@testing-library/react';
import { createMemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { routes } from './app/router';
import { App } from './App';
import { HEALTH_OK_BODY, jsonResponse, stubFetch } from './test/fetchMock';

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderApp(initialPath = '/') {
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  return render(<App router={router} />);
}

describe('App (F3 shell)', () => {
  it('renders the VY-PAM brand - unauthenticated visitors land on login', async () => {
    stubFetch([
      {
        match: (url) => url.includes('/auth/whoami'),
        respond: () => jsonResponse(401, { error: 'Not authenticated' }),
      },
      {
        match: (url) => url.includes('/health'),
        respond: () => jsonResponse(200, HEALTH_OK_BODY),
      },
    ]);
    renderApp();
    const heading = await screen.findByRole('heading', { level: 1, name: /VY-PAM/i });
    expect(heading).toBeInTheDocument();
  });

  it('contains no sample-brand strings (F0 invariant)', async () => {
    stubFetch([
      {
        match: (url) => url.includes('/auth/whoami'),
        respond: () => jsonResponse(401, { error: 'Not authenticated' }),
      },
      {
        match: (url) => url.includes('/health'),
        respond: () => jsonResponse(200, HEALTH_OK_BODY),
      },
    ]);
    const { container } = renderApp();
    await screen.findByRole('heading', { level: 1 });
    expect(container.textContent).not.toMatch(/Aegis|Stitch/i);
  });
});
