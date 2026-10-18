/**
 * Immutable WORM Audit Ledger Destination (screen 11, ADR-0015 11.3).
 * The legacy page's section carries a decorative ledger visual
 * (code.html:455-487) that is display chrome, not form state - out of
 * 11.3 scope (no ADR row owns it); this slice ships the section header
 * and the schema-driven `worm` group with its stored-configuration
 * meta, like every other group.
 */
import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { StoredConfigurationBlock } from './SettingsGroupFields';

export function WormSettingsSection() {
  const { t } = useTranslation();
  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-worm">
      <SectionHeader
        subtitle={t('settings.worm.subtitle')}
        title={t('settings.worm.title')}
      />
      <StoredConfigurationBlock group="worm" />
    </section>
  );
}
