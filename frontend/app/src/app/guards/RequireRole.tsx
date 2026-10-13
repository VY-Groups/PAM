import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import type { WhoAmIRole } from '../../api/generated/models/whoAmIRole';
import { useAuth } from '../providers/useAuth';

/**
 * Role guard (plan §3 `app/guards/`). `roles` is an explicit allow-list -
 * the component invents no hierarchy: backend `role_allows` decides
 * per-operation (architecture §10), and each screen's allowed roles are
 * wired with its F4 replacement, not guessed here. Renders an honest
 * refusal (never a fake redirect) when the whoami role is not listed.
 */
export function RequireRole({
  roles,
  children,
}: {
  roles: WhoAmIRole[];
  children: ReactNode;
}) {
  const { whoami } = useAuth();
  const { t } = useTranslation();

  if (whoami && !roles.includes(whoami.role)) {
    return (
      <section
        role="alert"
        className="max-w-xl mx-auto mt-space-xl flex flex-col gap-space-md p-space-xl rounded-xl bg-surface-container-lowest border border-outline-variant/30"
      >
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          {t('errors.roleForbiddenTitle')}
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          {t('errors.roleForbiddenBody', { role: whoami.role })}
        </p>
      </section>
    );
  }
  return <>{children}</>;
}
