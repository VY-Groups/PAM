import type { ReactNode } from 'react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader, StatusDot } from '../../components';
import { isBackendDown } from '../../api/http';
import { FeedbackLine } from './SettingsGroupActions';
import { useIntegrationsStatus, useMfaEnroll } from './queries';

/**
 * Enterprise Integrations chips (screen 11, ADR-0015): MFA, ITSM, SIEM
 * and LDAP, straight from `GET /api/v1/integrations/status`. The same
 * four chips the legacy `platform_settings_center` page carries -
 * `configured` reads honest, never optimistically green.
 *
 * A dead backend renders the "not connected" rail; it does NOT claim the
 * connectors are unconfigured, which the server would be the only
 * authority to state.
 *
 * 11.3: the trailing `children` slot hosts the four connector group
 * cards (mfa, itsm, siem, ldap) below the chips, the legacy page's
 * layout.
 *
 * 11.4 (ADR amendment): the header carries the legacy `Enroll MFA
 * Factor` button (code.html:507-511) - `POST /api/v1/mfa/enroll` is the
 * ONE legacy-wired mutating action on this page (code.html:1702-1729).
 * A 201 mints the TOTP secret, shown exactly once in the box below the
 * chips (legacy 531-536); not in the DOM before the answer arrives. The
 * minted secret is kept on a failed re-enroll, like the legacy (the
 * factor stays enrolled; the box keeps showing what was already given).
 */
export function IntegrationsSection({ children }: { children?: ReactNode }) {
  const { t } = useTranslation();
  const integrations = useIntegrationsStatus();
  const data = integrations.isError ? undefined : integrations.data;
  const enroll = useMfaEnroll();
  const [minted, setMinted] = useState<{ secret: string; uri: string } | null>(null);
  const [feedback, setFeedback] = useState<{ tone: 'error' | 'ok'; text: string } | null>(
    null,
  );

  const onEnroll = () => {
    setFeedback(null);
    enroll.mutate(undefined, {
      onError: (error) =>
        setFeedback({
          tone: 'error',
          text: isBackendDown(error)
            ? t('settings.integrations.enrollUnreachable')
            : error instanceof Error
              ? error.message
              : t('settings.integrations.enrollUnreachable'),
        }),
      // The contract requires secret/otpauth_uri/message on a 201, so no
      // fallback copy: what is shown is what the server minted.
      onSuccess: (mint) => {
        setMinted({ secret: mint.secret, uri: mint.otpauth_uri });
        setFeedback({ tone: 'ok', text: mint.message });
      },
    });
  };

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-integrations">
      <SectionHeader
        actions={
          <div className="flex flex-col items-end gap-1">
            <Button
              data-testid="settings-mfa-enroll"
              disabled={enroll.isPending}
              icon="phonelink_lock"
              onClick={onEnroll}
            >
              {t('settings.integrations.enrollButton')}
            </Button>
            <FeedbackLine feedback={feedback} />
          </div>
        }
        subtitle={t('settings.integrations.subtitle')}
        title={t('settings.integrations.title')}
      />

      {integrations.isError ? (
        <p
          role="alert"
          className="font-body-sm text-body-sm text-error"
          data-testid="settings-integrations-error"
        >
          {t('settings.integrations.unreachable')}
        </p>
      ) : (
        <div
          aria-label={t('settings.integrations.chipsLabel')}
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
        >
          {(
            [
              { key: 'mfa', on: data?.mfa?.configured ?? false },
              { key: 'itsm', on: data?.itsm?.configured ?? false },
              { key: 'siem', on: data?.siem?.configured ?? false },
              { key: 'ldap', on: data?.ldap?.configured ?? false },
            ] as const
          ).map((row) => (
            <Chip className="gap-1.5" key={row.key}>
              <StatusDot state={data ? (row.on ? 'ok' : 'muted') : 'muted'} />
              {data
                ? t(row.on ? 'settings.integrations.on' : 'settings.integrations.off', {
                    name: t(`settings.integrations.names.${row.key}`),
                  })
                : ''}
            </Chip>
          ))}
        </div>
      )}

      {/*
        The one-time secret box (legacy code.html:531-536): not in the DOM
        until the enroll actually answered 201 - the secret exists exactly
        once, in this response.
      */}
      {minted ? (
        <div
          className="rounded-lg bg-tertiary/10 border border-tertiary/40 p-space-sm"
          data-testid="settings-mfa-secret-once"
        >
          <span className="font-label-badge text-label-badge text-tertiary font-semibold">
            {t('settings.integrations.mfaSecretTitle')}
          </span>
          <code className="block mt-1 px-3 py-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface break-all">
            {minted.secret}
          </code>
          <code className="block px-3 py-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface-variant break-all">
            {minted.uri}
          </code>
        </div>
      ) : null}

      {children}
    </section>
  );
}
