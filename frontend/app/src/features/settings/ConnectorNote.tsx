/**
 * The live connector note line (screen 11, ADR-0015 11.4) - the four
 * legacy spans `mfaGateNote` / `itsmNote` / `siemNote` / `ldapNote`
 * (code.html:544, 553, 562, 571) filled by `loadIntegrations`
 * (1283-1297), ported verbatim and derived from the SAME
 * `GET /api/v1/integrations/status` read the chips use:
 *
 * - mfa: the server's `gate` enforcement statement (live data with no
 *   other home on the page).
 * - itsm/ldap: the configured line (vendor at URL / server:port + bind
 *   template) or the server's honest `detail` gap.
 * - siem: state + last-push ledger, or the honest `detail` gap.
 * - pre-settle shows the legacy "status: —" line; a failed read shows
 *   the legacy catch text (code.html:1303-1306).
 *
 * The CONNECTED branches of itsm/siem/ldap are contract-driven only: no
 * capture exists (the pristine rigs answer `configured: false`), noted
 * here exactly like the un-capturable SMTP 200 arm - tests assert the
 * pristine gap + unreachable lines only.
 */
import { useTranslation } from 'react-i18next';

import type { IntegrationsStatus } from '../../api/generated/models';
import { useIntegrationsStatus } from './queries';

export type ConnectorGroup = 'itsm' | 'ldap' | 'mfa' | 'siem';

type Translate = (key: string, options?: Record<string, unknown>) => string;

function noteText(group: ConnectorGroup, data: IntegrationsStatus, t: Translate): string {
  if (group === 'mfa') return data.mfa.gate || t('settings.forms.notes.mfa.gateFallback');
  if (group === 'itsm') {
    const itsm = data.itsm;
    return itsm.configured
      ? t('settings.forms.notes.itsm.connected', {
          credentials: t(
            itsm.credentials_configured
              ? 'settings.forms.notes.credentialsStored'
              : 'settings.forms.notes.credentialsMissing',
          ),
          url: itsm.base_url,
          vendor: itsm.vendor,
        })
      : itsm.detail || t('settings.integrations.notConnected');
  }
  if (group === 'ldap') {
    const ldap = data.ldap;
    return ldap.configured
      ? t('settings.forms.notes.ldap.connected', {
          port: ldap.port,
          server: ldap.server,
          template: ldap.user_bind_template,
          ttl: ldap.ticket_ttl_seconds,
        })
      : ldap.detail || t('settings.integrations.notConnected');
  }
  const siem = data.siem;
  if (!siem.configured) return siem.detail || t('settings.integrations.notConnected');
  const push = siem.last_push;
  const base = t('settings.forms.notes.siem.connected', {
    state: siem.state,
    status: push.last_push_status || t('settings.never'),
  });
  const records = push.records_pushed
    ? t('settings.forms.notes.siem.recordsSuffix', { count: push.records_pushed })
    : '';
  const batches = push.batches_failed
    ? t('settings.forms.notes.siem.batchesSuffix', { count: push.batches_failed })
    : '';
  return base + records + batches;
}

/** Renders one card's note; every card shares the single status query. */
export function ConnectorNote({ group }: { group: ConnectorGroup }) {
  const { t } = useTranslation();
  const integrations = useIntegrationsStatus();
  // A failed read wins over stale data, exactly like the chips above
  // (IntegrationsSection) and the legacy catch (1303-1306).
  const data = integrations.isError ? undefined : integrations.data;

  const text = data
    ? noteText(group, data, t)
    : integrations.isError
      ? t(`settings.forms.notes.${group}.unreachable`)
      : t(`settings.forms.notes.${group}.initial`);

  return (
    <p
      className="font-body-sm text-body-sm text-on-surface-variant"
      data-testid={`settings-note-${group}`}
    >
      {text}
    </p>
  );
}
