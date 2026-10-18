/**
 * Identity & Login Security, Addendum C (screen 11, ADR-0015 11.3):
 * the six identity group cards in the legacy page's grid order (auth,
 * webauthn, smtp, sms, radius, scim - code.html:587-642), with the 11.3
 * actions riding in their cards' footers (SMTP test, SCIM rotate). The
 * 11.4 emergency-card slice appends here.
 */
import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { ScimRotateAction, SmtpTestAction } from './SettingsGroupActions';
import { SettingsGroupCard } from './SettingsGroupCard';

export function IdentitySettingsSection() {
  const { t } = useTranslation();
  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-identity">
      <SectionHeader
        subtitle={t('settings.identity.subtitle')}
        title={t('settings.identity.title')}
      />
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-space-md">
        <SettingsGroupCard group="auth" />
        <SettingsGroupCard group="webauthn" />
        <SettingsGroupCard footer={<SmtpTestAction />} group="smtp" />
        <SettingsGroupCard group="sms" />
        <SettingsGroupCard group="radius" />
        <SettingsGroupCard footer={<ScimRotateAction />} group="scim" />
      </div>
    </section>
  );
}
