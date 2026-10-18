import { useTranslation } from 'react-i18next';

import { Button, SectionHeader } from '../../components';
import { ChangelogSection } from './ChangelogSection';
import { ClusterPostureSection } from './ClusterPostureSection';
import { ConnectorNote } from './ConnectorNote';
import { GatewaySettingsSection } from './GatewaySettingsSection';
import { HsmStatusSection } from './HsmStatusSection';
import { IdentitySettingsSection } from './IdentitySettingsSection';
import { IntegrationsSection } from './IntegrationsSection';
import { RbacSection } from './RbacSection';
import { SettingsFormProvider } from './SettingsFormProvider';
import { useSettingsForm } from './settingsFormContext';
import { ItsmVerifyAction, LdapBindAction } from './SettingsGroupActions';
import { SettingsGroupCard } from './SettingsGroupCard';
import { useSettingsLiveExport } from './settingsLive';
import { SsoStatusSection } from './SsoStatusSection';
import { StoredConfigurationBlock } from './SettingsGroupFields';
import { WormSettingsSection } from './WormSettingsSection';
import { ZspSettingsSection } from './ZspSettingsSection';
import type { SettingsBanner } from './settingsFormContext';

/**
 * Platform Settings (screen 11, ADR-0015) - the React successor of
 * `platform_settings_center/code.html`, the page the server actually
 * serves for `/settings` (the strangler target; `platform_settings_idp_
 * hsm_configuration` is only its design spec).
 *
 * 11.1 built the read-only posture shell (SSO, HSM, integrations,
 * cluster), 11.2 added the RBAC/ABAC directory, 11.3 adds the 15
 * schema-driven group forms with the page-level Save/Export and the
 * config-audit changelog, and 11.4 adds the sealed emergency-admin card
 * (legacy state machine ported verbatim), the live connector note lines,
 * the legacy MFA enroll action and the ITSM/LDAP NEW actions - plus the
 * legacy-shaped `window.settingsLive` export the standing gate reads.
 * 11.5 flipped it (ADR-0015): this page IS the served Platform Settings
 * screen - the router mounts it at /settings, the server redirects the
 * old URL here and the legacy `platform_settings_center/code.html` is
 * deleted; the standing gate reads this page (e2e from the flip on).
 *
 * Section order IS the legacy page's document order (code.html: SSO,
 * HSM, ZSP, WORM, integrations + its four connector cards, identity,
 * gateway, HA/DC/DR cluster, RBAC, changelog last) - the strangler
 * interleaves the forms into those sections exactly where the legacy
 * page renders them: the sso/hsm forms inside their posture sections,
 * the four connector cards inside integrations. The gate's 6b
 * `belowCluster` contract (RBAC below the cluster section) holds.
 */
export function SettingsPage() {
  return (
    <SettingsFormProvider>
      <SettingsPageBody />
    </SettingsFormProvider>
  );
}

function SettingsPageBody() {
  const { t } = useTranslation();
  const { banner, dirtyCount, exportJson, loadFailed, save, saving, toast } =
    useSettingsForm();
  // The legacy-shaped window export the standing gate's Settings block
  // reads (settingsLive.ts) - installed while this page is mounted.
  useSettingsLiveExport();

  return (
    <div className="flex flex-col gap-space-lg" data-testid="settings-page">
      <SectionHeader
        actions={
          <>
            <Button icon="download" onClick={exportJson} variant="secondary">
              {t('settings.forms.export')}
            </Button>
            <Button disabled={saving} icon="save" onClick={save}>
              {saving
                ? t('settings.forms.saving')
                : dirtyCount > 0
                  ? t('settings.forms.saveCount', { count: dirtyCount })
                  : t('settings.forms.save')}
            </Button>
          </>
        }
        subtitle={t('settings.page.subtitle')}
        title={t('settings.page.title')}
      />

      {/* An unreachable settings read is a load-time alert of its own; a
          save attempt renders its own banner below (never conflated). */}
      {loadFailed ? (
        <p
          className="rounded-lg border border-error bg-error-container px-space-md py-2.5 font-body-sm text-body-sm text-on-error-container"
          data-testid="settings-load-error"
          role="alert"
        >
          {t('settings.forms.unreachable')}
        </p>
      ) : null}

      {banner ? (
        <p
          aria-live="polite"
          className={bannerClassName(banner)}
          data-testid="settings-banner"
          role="alert"
        >
          {banner.text}
        </p>
      ) : null}

      <SsoStatusSection>
        <StoredConfigurationBlock group="sso" />
      </SsoStatusSection>
      <HsmStatusSection>
        <StoredConfigurationBlock group="hsm" />
      </HsmStatusSection>
      <ZspSettingsSection />
      <WormSettingsSection />
      <IntegrationsSection>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-space-md">
          <SettingsGroupCard group="mfa" note={<ConnectorNote group="mfa" />} />
          <SettingsGroupCard
            footer={<ItsmVerifyAction />}
            group="itsm"
            note={<ConnectorNote group="itsm" />}
          />
          <SettingsGroupCard group="siem" note={<ConnectorNote group="siem" />} />
          <SettingsGroupCard
            footer={<LdapBindAction />}
            group="ldap"
            note={<ConnectorNote group="ldap" />}
          />
        </div>
      </IntegrationsSection>
      <IdentitySettingsSection />
      <GatewaySettingsSection />
      <ClusterPostureSection />
      <RbacSection />
      <ChangelogSection />

      {/* The legacy `#toast-notification`: title + the changed-fields
          line, auto-hiding after 4s (set in the provider). */}
      {toast ? (
        <div
          className="fixed bottom-14 right-8 z-50 max-w-sm rounded-lg border border-outline-variant/30 bg-surface-container-lowest p-space-md shadow-xl"
          data-testid="settings-toast"
        >
          <p className="font-label-md text-label-md font-semibold text-on-surface">
            {toast.title}
          </p>
          <p className="mt-1 font-body-sm text-body-sm text-on-surface-variant">
            {toast.desc}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function bannerClassName(banner: SettingsBanner): string {
  const base = 'rounded-lg px-space-md py-2.5 font-body-sm text-body-sm';
  if (banner.tone === 'error')
    return `${base} border border-error bg-error-container text-on-error-container`;
  if (banner.tone === 'ok')
    return `${base} border border-primary/30 bg-primary/5 text-on-surface`;
  return `${base} border border-outline-variant/30 bg-surface-container-lowest text-on-surface-variant`;
}
