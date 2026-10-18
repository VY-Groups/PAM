import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader, StatusDot } from '../../components';
import { useSsoStatus } from './queries';

/**
 * Single Sign-On & Identity Provider Federation posture (screen 11,
 * ADR-0015). The live line and the three chips carry the SAME words the
 * legacy `platform_settings_center` page writes - the gate's 6c parity
 * regexes (`/^enforce sso: (on|off)$/`, the sessions/no-idp form, the
 * "not loading..." line) are the contract, so this is a verbatim
 * carry-over of the legacy format, not a re-design.
 *
 * No `id=` and no `aria-labelledby` (the React DoD bans ids and the
 * sections are not landmarks); the `data-testid` hooks are what the
 * flip-time gate re-points at.
 *
 * An unreachable backend renders the honest "not connected" rail - never
 * a zeroed posture that would read as "no SSO is configured", which is a
 * different (and false) claim.
 */
export function SsoStatusSection() {
  const { t } = useTranslation();
  const sso = useSsoStatus();
  const data = sso.isError ? undefined : sso.data;

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-sso">
      <SectionHeader
        subtitle={t('settings.sso.subtitle')}
        title={t('settings.sso.title')}
      />

      {/* The live line: real data when settled, honest em-dash while the
          first read is in flight (never a lingering "loading..."). */}
      <p
        className="font-body-sm text-body-sm text-on-surface-variant"
        data-testid="settings-sso-line"
      >
        {sso.isError
          ? t('settings.sso.unreachable')
          : !data
            ? '\u2014'
            : data.configured
              ? t('settings.sso.lineConfigured', {
                  lastLogin: data.last_login_at ?? t('settings.never'),
                  ttl: data.session_ttl_minutes,
                  jit: t(data.jit_provisioning ? 'settings.on' : 'settings.off'),
                })
              : t('settings.sso.lineNoIdp')}
      </p>

      <div
        aria-label={t('settings.sso.chipsLabel')}
        className="flex flex-wrap items-center gap-space-sm"
        role="group"
      >
        <Chip className="gap-1.5">
          <StatusDot state={data ? (data.enforce_sso ? 'ok' : 'muted') : 'muted'} />
          {data
            ? t(data.enforce_sso ? 'settings.sso.enforceOn' : 'settings.sso.enforceOff')
            : ''}
        </Chip>
        <Chip className="gap-1.5">
          <StatusDot state={data ? (data.require_mfa ? 'ok' : 'muted') : 'muted'} />
          {data
            ? t(data.require_mfa ? 'settings.sso.mfaRequired' : 'settings.sso.mfaOptional')
            : ''}
        </Chip>
        <Chip className="gap-1.5">
          <StatusDot state={data ? (data.configured ? 'ok' : 'muted') : 'muted'} />
          {data
            ? data.configured
              ? t('settings.sso.sessions', {
                  active: data.sessions_active,
                  subjects: data.subjects,
                  total: data.sessions_total,
                })
              : t('settings.sso.noIdp')
            : ''}
        </Chip>
      </div>
    </section>
  );
}
