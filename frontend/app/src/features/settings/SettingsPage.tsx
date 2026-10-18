import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { ClusterPostureSection } from './ClusterPostureSection';
import { HsmStatusSection } from './HsmStatusSection';
import { IntegrationsSection } from './IntegrationsSection';
import { SsoStatusSection } from './SsoStatusSection';

/**
 * Platform Settings (screen 11, ADR-0015) - the React successor of
 * `platform_settings_center/code.html`, the page the server actually
 * serves for `/settings` (the strangler target; `platform_settings_idp_
 * hsm_configuration` is only its design spec).
 *
 * This 11.1 slice is the read-only posture shell: SSO federation, HSM
 * custody, the enterprise integrations chips and the HA/DC/DR cluster
 * view. The route stays `pending` (nav keeps its legacyHref) until the
 * 11.5 flip, so nothing here claims to be served yet - the interim
 * verification is Vitest + axe against the verbatim rig captures, and
 * e2e joins at the flip per ADR-0015.
 *
 * Sections stack in the legacy page's order; 11.2-11.4 add the RBAC
 * directory, the 15 schema group forms and the identity/emergency/
 * gateway actions below these.
 */
export function SettingsPage() {
  const { t } = useTranslation();

  return (
    <div className="flex flex-col gap-space-lg" data-testid="settings-page">
      <SectionHeader
        subtitle={t('settings.page.subtitle')}
        title={t('settings.page.title')}
      />
      <SsoStatusSection />
      <HsmStatusSection />
      <IntegrationsSection />
      <ClusterPostureSection />
    </div>
  );
}
