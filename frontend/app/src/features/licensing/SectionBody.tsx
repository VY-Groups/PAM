import { useTranslation } from 'react-i18next';
import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import { isBackendDown } from '../../api/http';
import { NotConnected } from '../../components';

/**
 * One honest state machine for every Licensing section (F4 per-screen
 * DoD): loading line, verbatim section error, the brief §3.2 "not
 * connected" chip for transport failures (the shared banner sits
 * above), and the real content once the contract answers. Feature-local
 * on purpose - features never import each other (plan §3 rule 2); each
 * screen keeps its own copy until a deliberate design-system promotion.
 */
export function SectionBody<T>({
  query,
  children,
}: {
  query: UseQueryResult<T>;
  children: (data: T) => ReactNode;
}) {
  const { t } = useTranslation();
  if (query.isPending) {
    return (
      <p className="p-space-md font-body-sm text-body-sm text-outline">
        {t('licensing.states.loading')}
      </p>
    );
  }
  if (query.isError) {
    if (isBackendDown(query.error)) {
      return <NotConnected />;
    }
    return (
      <p role="alert" className="p-space-md font-body-sm text-body-sm text-error">
        {t('licensing.states.error', {
          message: query.error instanceof Error ? query.error.message : String(query.error),
        })}
      </p>
    );
  }
  return <>{children(query.data)}</>;
}
