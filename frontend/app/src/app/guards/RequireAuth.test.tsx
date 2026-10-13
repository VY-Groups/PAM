import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { WHOAMI_OPEN_BODY, stubFetch, whoamiRoute } from '../../test/fetchMock';
import { renderWithRoutes } from '../../test/renderApp';
import { RequireAuth } from './RequireAuth';
import { RequireRole } from './RequireRole';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

const guardRoutes = [
  { path: '/login', element: <div>Login page</div> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <div>Secret area</div>
      </RequireAuth>
    ),
  },
];

describe('RequireAuth', () => {
  it('redirects an unauthenticated caller (whoami 401) to login', async () => {
    stubFetch([whoamiRoute({ error: 'Not authenticated' }, 401)]);
    renderWithRoutes(guardRoutes, '/');
    expect(await screen.findByText('Login page')).toBeInTheDocument();
    expect(screen.queryByText('Secret area')).not.toBeInTheDocument();
  });

  it('lets an authenticated caller through (whoami 200)', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY)]);
    renderWithRoutes(guardRoutes, '/');
    expect(await screen.findByText('Secret area')).toBeInTheDocument();
  });

  it('shows the honest backend-down state instead of a fake login wall', async () => {
    stubFetch([
      {
        match: (url) => url.includes('/auth/whoami'),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
    ]);
    renderWithRoutes(guardRoutes, '/');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Cannot reach the license server');
    expect(alert).toHaveTextContent('network: Failed to fetch');
    expect(screen.queryByText('Login page')).not.toBeInTheDocument();
    expect(screen.queryByText('Secret area')).not.toBeInTheDocument();
  });
});

describe('RequireRole (explicit allow-list, no invented hierarchy)', () => {
  it('refuses a role outside the allow-list with an honest notice', async () => {
    stubFetch([whoamiRoute({ ...WHOAMI_OPEN_BODY, role: 'auditor', principal: 'ann' })]);
    renderWithRoutes(
      [
        {
          path: '*',
          element: (
            <RequireRole roles={['admin']}>
              <div>Admin area</div>
            </RequireRole>
          ),
        },
      ],
      '/',
    );
    expect(
      await screen.findByRole('heading', { name: /not available for your role/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Your role \(auditor\)/)).toBeInTheDocument();
    expect(screen.queryByText('Admin area')).not.toBeInTheDocument();
  });

  it('lets a listed role through', async () => {
    stubFetch([whoamiRoute({ ...WHOAMI_OPEN_BODY, role: 'admin' })]);
    renderWithRoutes(
      [
        {
          path: '*',
          element: (
            <RequireRole roles={['admin']}>
              <div>Admin area</div>
            </RequireRole>
          ),
        },
      ],
      '/',
    );
    expect(await screen.findByText('Admin area')).toBeInTheDocument();
  });
});
