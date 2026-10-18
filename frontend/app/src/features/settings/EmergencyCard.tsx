/**
 * The sealed emergency-admin card (screen 11, ADR-0015 11.4) - legacy
 * parity for code.html:643-657 plus the `loadEmergency` /
 * `requestEmergencyOpen` state machine (1311-1364), ported verbatim:
 *
 * - state line (legacy order): `window OPEN - {user} usable until the
 *   grant expires` > `sealed - grant {id} awaits two approvals` >
 *   `sealed - {user} grants nothing`; a failed read says `unreachable`
 *   and leaves the grants line untouched; a refused open attempt
 *   replaces the state with `request refused: {message}` until the next
 *   successful read (the mutation's invalidation re-reads on success).
 * - grants line: `{n} grant(s) on record` / `no grants on record`, the
 *   legacy "—" until the read settles.
 * - the button is disabled while a grant is pending or open - and before
 *   the first read settles (the legacy starts it `disabled`).
 * - the reason is asked through `window.prompt` exactly like the legacy
 *   (user-approved 2026-10-18); cancelling makes no call. Transport
 *   failures land in the same `request refused: {message}` line the
 *   legacy's catch renders (`err.message`, code.html:1361).
 *
 * The gate's two honest-state regexes (__verify_agent.mjs:609-612) are
 * asserted in SettingsEmergency.test.tsx against the verbatim captures
 * (pristine + denied baseline) - that is the 11.5 re-point contract.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '../../components';
import { useEmergencyOpen, useEmergencyStatus } from './queries';

export function EmergencyCard() {
  const { t } = useTranslation();
  const status = useEmergencyStatus();
  const open = useEmergencyOpen();
  const [refusal, setRefusal] = useState<{
    line: string;
    /** The data the refusal was rendered against; a fresh read clears it. */
    snapshot: typeof status.data;
  } | null>(null);

  const data = status.data;
  const grants = data?.grants ?? [];
  const pending = grants.filter((grant) => grant.status === 'pending');
  const openGrants = grants.filter((grant) => grant.status === 'open');

  // The refusal stands until a NEW successful read lands (legacy:
  // `loadEmergency()` overwrites the line after a granted request,
  // code.html:1355-1357, and a later loadAll cycle after a save) - keyed
  // to the read's data object, no effect needed. Note: a failed READ
  // after a refusal keeps the refusal line here (the legacy's next
  // loadAll cycle would replace it with `unreachable`; React Query has
  // no polling cycle, and the refusal stays a true statement).
  const refusalLine = refusal && refusal.snapshot === data ? refusal.line : null;

  const stateLine = refusalLine
    ? refusalLine
    : status.isError
      ? t('settings.emergency.stateUnreachable')
      : data
        ? openGrants.length > 0
          ? t('settings.emergency.stateOpen', { username: data.username })
          : pending.length > 0
            ? t('settings.emergency.statePending', { id: pending[0].id })
            : t('settings.emergency.stateSealed', { username: data.username })
        : t('settings.forms.loading');

  const grantsLine = data
    ? grants.length > 0
      ? t('settings.emergency.grantsSome', { count: grants.length })
      : t('settings.emergency.grantsNone')
    : t('settings.emergency.grantsInitial');

  const disabled = !data || pending.length > 0 || openGrants.length > 0;

  const requestOpen = () => {
    const reason = window.prompt(t('settings.emergency.prompt'));
    if (reason === null) return;
    open.mutate(
      { reason },
      {
        onError: (error) =>
          setRefusal({
            line: t('settings.emergency.stateRefused', {
              message: error instanceof Error ? error.message : String(error),
            }),
            snapshot: data,
          }),
        onSuccess: () => setRefusal(null),
      },
    );
  };

  return (
    <div
      className="mt-space-md p-space-sm rounded-lg bg-surface-container-low border border-outline-variant/30 flex flex-col gap-space-sm"
      data-role="emergency-card"
      data-testid="settings-emergency-card"
    >
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-headline-sm text-[14px] text-on-surface font-semibold">
          {t('settings.emergency.title')}
        </h3>
        <span
          className="font-code-sm text-code-sm text-on-surface-variant"
          data-role="emergency-state"
          data-testid="settings-emergency-state"
        >
          {stateLine}
        </span>
      </div>
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('settings.emergency.description')}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          data-role="emergency-open"
          data-testid="settings-emergency-open"
          disabled={disabled}
          icon="emergency_home"
          onClick={requestOpen}
          type="button"
        >
          {t('settings.emergency.openButton')}
        </Button>
        <span
          className="font-code-sm text-code-sm text-on-surface-variant"
          data-role="emergency-grants"
          data-testid="settings-emergency-grants"
        >
          {grantsLine}
        </span>
      </div>
    </div>
  );
}
