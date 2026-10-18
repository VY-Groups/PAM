/**
 * Config Audit Changelog (screen 11, ADR-0015 11.3) - a verbatim
 * translation of the legacy `loadAudit` renderer (code.html:1774-1803):
 * `GET /api/v1/settings/audit?limit=20` as a timeline, each row
 * `<actor> updated <group> — <changed fields>` with the
 * `<action> · <ago>` sub-line, the newest dot in the primary colour,
 * the honest empty line on a fresh node and the honest unavailable
 * line on a dead backend. The `Full Log` link opens the raw endpoint,
 * like the legacy `auditLogLink`.
 */
import { useTranslation } from 'react-i18next';

import { settingsAgo } from './ago';
import { useSettingsAudit } from './queries';
import type { TFunction } from 'i18next';
import type { SettingsAuditResponseEventsItem } from '../../api/generated/models';

/** Legacy detail line: the changed fields' labels, else the action word. */
function changelogDetail(event: SettingsAuditResponseEventsItem, t: TFunction): string {
  const fields = Object.keys(event.changes ?? {});
  return fields.length
    ? fields
        .map((field) => t(`settings.forms.fieldLabels.${event.group}.${field}`))
        .join(', ')
    : event.action;
}

export function ChangelogSection() {
  const { t } = useTranslation();
  const audit = useSettingsAudit();
  const events = audit.isError ? null : (audit.data?.events ?? null);

  return (
    <section className="flex flex-col" data-testid="settings-changelog">
      <div className="flex items-center justify-between pb-space-sm mb-space-md border-b border-surface-container">
        <h2 className="font-headline-sm text-headline-sm text-on-surface">
          {t('settings.changelog.title')}
        </h2>
        <a
          className="font-label-md text-label-md text-primary font-semibold hover:underline"
          href="/api/v1/settings/audit"
          rel="noopener noreferrer"
          target="_blank"
        >
          {t('settings.changelog.fullLog')}
        </a>
      </div>
      <div className="space-y-space-md" data-testid="settings-changelog-list">
        {audit.isError ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('settings.changelog.unavailable')}
          </p>
        ) : events === null ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('settings.forms.loading')}
          </p>
        ) : events.length === 0 ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('settings.changelog.empty')}
          </p>
        ) : (
          events.map((event, index) => (
            <div className="relative pl-6" key={event.id}>
              <div
                className={`absolute left-1.5 top-1.5 w-2.5 h-2.5 rounded-full -translate-x-1/2 ${
                  index === 0 ? 'bg-primary' : 'bg-surface-container-highest'
                }`}
              />
              <p className="font-body-sm text-body-sm text-on-surface font-medium leading-snug">
                {t('settings.changelog.itemLine', {
                  actor: event.actor,
                  detail: changelogDetail(event, t),
                  group: event.group,
                })}
              </p>
              <p className="font-code-sm text-code-sm text-on-surface-variant mt-0.5">
                {t('settings.changelog.itemSub', {
                  action: event.action,
                  ago: settingsAgo(event.created_at, t),
                })}
              </p>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
