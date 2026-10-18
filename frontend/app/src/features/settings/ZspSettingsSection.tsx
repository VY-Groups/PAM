/**
 * Global Zero-Standing Privilege & Session Defaults (screen 11,
 * ADR-0015 11.3). The legacy page renders this card as a HARD-CODED
 * block (code.html:347-406: fixed labels, per-field help, select-based
 * TTLs); the strangler renders it schema-driven like every other group,
 * so the labels come from the field names and an int is a number input -
 * the ADR-approved divergence, noted in the 11.3 amendment.
 */
import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { StoredConfigurationBlock } from './SettingsGroupFields';

export function ZspSettingsSection() {
  const { t } = useTranslation();
  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-zsp">
      <SectionHeader
        subtitle={t('settings.zsp.subtitle')}
        title={t('settings.zsp.title')}
      />
      <StoredConfigurationBlock group="zsp" />
    </section>
  );
}
