/**
 * A group card (screen 11, ADR-0015 11.3) - the bordered sub-block the
 * legacy page uses for the four connector forms inside Enterprise
 * Integrations (code.html:538-575), the six identity forms (589-642)
 * and the gateway form (671-677): `<h3>` title, the meta span on the
 * right, a description line, the `data-settings-group` grid, and an
 * optional footer slot (the actions - SMTP test, SCIM rotate, and the
 * 11.4 ITSM verify / LDAP bind).
 *
 * 11.4: the `note` slot replaces the static description when present -
 * the legacy connector cards carry a LIVE status note instead of prose
 * (code.html:544, 553, 562, 571), so a card with `note` renders that
 * line and no description.
 */
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { GroupMeta, SettingsGroupFields } from './SettingsGroupFields';

export function SettingsGroupCard({
  footer,
  group,
  note,
}: {
  footer?: ReactNode;
  group: string;
  note?: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className="p-space-sm rounded-lg bg-surface-container-low border border-outline-variant/30 flex flex-col gap-space-sm">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-headline-sm text-[14px] text-on-surface font-semibold">
          {t(`settings.forms.cards.${group}.title`)}
        </h3>
        <GroupMeta group={group} />
      </div>
      {note ?? (
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t(`settings.forms.cards.${group}.description`)}
        </p>
      )}
      <SettingsGroupFields group={group} />
      {footer}
    </div>
  );
}
