/**
 * A group card (screen 11, ADR-0015 11.3) - the bordered sub-block the
 * legacy page uses for the four connector forms inside Enterprise
 * Integrations (code.html:538-575), the six identity forms (589-642)
 * and the gateway form (671-677): `<h3>` title, the meta span on the
 * right, a description line, the `data-settings-group` grid, and an
 * optional footer slot (the 11.3 actions - SMTP test, SCIM rotate).
 */
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { GroupMeta, SettingsGroupFields } from './SettingsGroupFields';

export function SettingsGroupCard({
  footer,
  group,
}: {
  footer?: ReactNode;
  group: string;
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
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t(`settings.forms.cards.${group}.description`)}
      </p>
      <SettingsGroupFields group={group} />
      {footer}
    </div>
  );
}
