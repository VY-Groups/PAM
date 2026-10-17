import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader, StatusDot } from '../../components';
import { FRONTEND_ROUTES } from './topology.generated';

/**
 * View 1 - Frontend (ADR-0013): the sidebar and router tables joined
 * with each feature's real imports of the generated client, resolved
 * to contract operations by the extractor. Pure extracted data - if a
 * route, a component name or a client call changes, the CI drift step
 * fails until this map is regenerated.
 */
export function FrontendMapSection() {
  const { t } = useTranslation();
  const live = FRONTEND_ROUTES.filter((r) => r.state === 'live').length;
  const pending = FRONTEND_ROUTES.length - live;
  return (
    <section aria-label={t('topology.frontend.title')} className="space-y-space-md">
      <SectionHeader
        title={t('topology.frontend.title')}
        subtitle={t('topology.frontend.subtitle')}
      />
      <div className="flex items-center gap-space-sm">
        <Chip>
          {live} {t('topology.frontend.liveCount')}
        </Chip>
        <Chip tone="inactive">
          {pending} {t('topology.frontend.pendingCount')}
        </Chip>
      </div>
      <ol className="space-y-space-sm">
        {FRONTEND_ROUTES.map((route) => (
          <li
            key={route.path}
            className="rounded-lg border border-outline-variant/30 p-space-md"
            data-state={route.state}
          >
            <div className="flex flex-wrap items-center gap-space-sm">
              <StatusDot state={route.state === 'live' ? 'ok' : 'muted'} />
              {route.icon && (
                <span
                  className={`material-symbols-outlined text-[20px]${route.danger ? ' text-error' : ''}`}
                  aria-hidden="true"
                >
                  {route.icon}
                </span>
              )}
              <span className="font-title-md text-title-md text-on-surface">
                {route.labelKey ? t(route.labelKey) : route.path}
              </span>
              <code className="font-code-sm text-code-sm text-on-surface-variant">
                {route.path}
              </code>
              <Chip tone={route.state === 'live' ? 'info' : 'inactive'}>
                {route.state === 'live'
                  ? t('topology.frontend.stateLive')
                  : t('topology.frontend.statePending')}
              </Chip>
            </div>
            <div className="mt-space-sm pl-space-lg">
              {route.state === 'live' ? (
                <div className="space-y-space-xs">
                  <div className="flex flex-wrap items-center gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
                    <span aria-hidden="true">→</span>
                    <code className="font-code-sm text-code-sm text-on-surface">
                      {route.component}
                    </code>
                    <span aria-hidden="true">·</span>
                    <code className="font-code-sm text-code-sm">{route.feature}/</code>
                  </div>
                  {route.clientFunctions.length > 0 ? (
                    <div className="flex flex-wrap gap-space-xs">
                      {route.endpoints.map((endpoint) => (
                        <code
                          key={endpoint}
                          className="rounded bg-surface-container px-space-xs font-code-sm text-code-sm text-on-surface"
                        >
                          {endpoint}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <p className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('topology.frontend.noCalls')}
                    </p>
                  )}
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
                  <a
                    className="text-primary underline underline-offset-2"
                    href={route.legacyHref ?? undefined}
                  >
                    {t('topology.frontend.legacyScreen')}
                  </a>
                  <span>{t('topology.frontend.pendingNote')}</span>
                </div>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
