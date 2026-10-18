/**
 * Session Gateway & Recording, phase 8a (screen 11, ADR-0015 11.3):
 * the schema-driven `gateway` group under the legacy section's heading
 * (code.html:662-677). The node registration UI that shares this
 * section is 11.4 scope; the standing gate's gateway checks (meta line
 * not loading + field counts) are satisfied by this block.
 */
import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { SettingsGroupCard } from './SettingsGroupCard';

export function GatewaySettingsSection() {
  const { t } = useTranslation();
  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-gateway">
      <SectionHeader
        subtitle={t('settings.gateway.subtitle')}
        title={t('settings.gateway.title')}
      />
      <SettingsGroupCard group="gateway" />
    </section>
  );
}
