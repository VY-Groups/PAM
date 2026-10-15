import { useTranslation } from 'react-i18next';
import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import { isBackendDown } from '../../api/http';
import { NotConnected } from '../../components';

/**
 * One honest state machine for every Vendor Access section (F4
 * per-screen DoD): loading line, verbatim section error, the brief §3.2
 * "not connected" chip for transport failures (the shared banner sits
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
        {t('vendor.states.loading')}
      </p>
    );
  }
  if (query.error !== null && query.error !== undefined) {
    if (isBackendDown(query.error)) return <NotConnected />;
    const message =
      query.error instanceof Error ? query.error.message : String(query.error);
    return (
      <p role="alert" className="p-space-md font-body-sm text-body-sm text-error">
        {t('vendor.states.sectionError', { message })}
      </p>
    );
  }
  if (query.data === undefined) return null;
  return <>{children(query.data)}</>;
}
