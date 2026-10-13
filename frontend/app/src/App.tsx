import { RouterProvider } from 'react-router';
import type { DataRouter } from 'react-router';

import { ErrorBoundary } from './app/error/ErrorBoundary';
import { AuthProvider } from './app/providers/AuthProvider';
import { I18nProvider } from './app/providers/I18nProvider';
import { QueryProvider } from './app/providers/QueryProvider';
import { createAppRouter } from './app/router';

const defaultRouter = createAppRouter();

/**
 * Provider stack (plan §3 `app/`): i18n -> query -> auth -> crash guard
 * -> router. Tests inject a memory router via the `router` prop.
 */
export function App({ router = defaultRouter }: { router?: DataRouter }) {
  return (
    <I18nProvider>
      <QueryProvider>
        <AuthProvider>
          <ErrorBoundary>
            <RouterProvider router={router} />
          </ErrorBoundary>
        </AuthProvider>
      </QueryProvider>
    </I18nProvider>
  );
}
