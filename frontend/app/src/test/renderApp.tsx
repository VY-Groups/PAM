import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { RouterProvider, createMemoryRouter } from 'react-router';
import type { RouteObject } from 'react-router';

import { App } from '../App';
import { routes } from '../app/router';
import { AuthProvider } from '../app/providers/AuthProvider';
import { I18nProvider } from '../app/providers/I18nProvider';
import { QueryProvider } from '../app/providers/QueryProvider';

/** Render the real app (real route table) at a given client path. */
export function renderApp(initialPath = '/') {
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  return render(<App router={router} />);
}

/** Render an element inside the full provider stack with ad-hoc routes. */
export function renderWithProviders(element: ReactElement, initialPath = '/') {
  return renderWithRoutes([{ path: '*', element }], initialPath);
}

/** Render ad-hoc routes inside the full provider stack (guards tests). */
export function renderWithRoutes(testRoutes: RouteObject[], initialPath = '/') {
  const router = createMemoryRouter(testRoutes, { initialEntries: [initialPath] });
  return render(
    <I18nProvider>
      <QueryProvider>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryProvider>
    </I18nProvider>,
  );
}
