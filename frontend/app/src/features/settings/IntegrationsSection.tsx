import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader, StatusDot } from '../../components';
import { useIntegrationsStatus } from './queries';

/**
 * Enterprise Integrations chips (screen 11, ADR-0015): MFA, ITSM, SIEM
 * and LDAP, straight from `GET /api/v1/integrations/status`. The same
 * four chips the legacy `platform_settings_center` page carries -
 * `configured` reads honest, never optimistically green.
 *
 * A dead backend renders the "not connected" rail; it does NOT claim the
 * connectors are unconfigured, which the server would be the only
 * authority to state.
 */
export function IntegrationsSection() {
  const { t } = useTranslation();
  const integrations = useIntegrationsStatus();
  const data = integrations.isError ? undefined : integrations.data;

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-integrations">
      <SectionHeader
        subtitle={t('settings.integrations.subtitle')}
        title={t('settings.integrations.title')}
      />

      {integrations.isError ? (
        <p
          role="alert"
          className="font-body-sm text-body-sm text-error"
          data-testid="settings-integrations-error"
        >
          {t('settings.integrations.unreachable')}
        </p>
      ) : (
        <div
          aria-label={t('settings.integrations.chipsLabel')}
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
        >
          {(
            [
              { key: 'mfa', on: data?.mfa?.configured ?? false },
              { key: 'itsm', on: data?.itsm?.configured ?? false },
              { key: 'siem', on: data?.siem?.configured ?? false },
              { key: 'ldap', on: data?.ldap?.configured ?? false },
            ] as const
          ).map((row) => (
            <Chip className="gap-1.5" key={row.key}>
              <StatusDot state={data ? (row.on ? 'ok' : 'muted') : 'muted'} />
              {data
                ? t(row.on ? 'settings.integrations.on' : 'settings.integrations.off', {
                    name: t(`settings.integrations.names.${row.key}`),
                  })
                : ''}
            </Chip>
          ))}
        </div>
      )}
    </section>
  );
}
