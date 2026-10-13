import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import type { ReactNode } from 'react';

import { isBackendDown } from '../../api/http';

/**
 * ADR-0004: TanStack Query wraps every call. Backend-down must surface
 * immediately and honestly (plan §5), so transport failures are never
 * retried into a slow blank UI - other failures get one retry. The client
 * is per-provider instance so tests stay isolated.
 */
function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (failureCount, error) => !isBackendDown(error) && failureCount < 2,
        refetchOnWindowFocus: false,
        staleTime: 30_000,
      },
    },
  });
}

export function QueryProvider({ children }: { children: ReactNode }) {
  const [queryClient] = useState(createQueryClient);
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
