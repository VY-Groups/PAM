import { useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError, isBackendDown } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { Button, Chip, DataTable, SectionHeader, Value } from '../../components';
import type { DataTableColumn } from '../../components';
import { settingsAgo } from '../settings/ago';
import {
  deleteFactor,
  enrollEmail,
  enrollRadius,
  enrollTotp,
  generateBackupCodes,
  stepUp,
  useFactors,
  verifyEmailEnrol,
  verifyTotpEnrol,
} from './queries';
import type {
  BackupCodesBody,
  EnrollEmailBody,
  EnrollTotpBody,
  MfaFactorRow,
  StepUpBody,
  TotpVerifyBody,
} from './types';

/**
 * Security & MFA (ADR-0017 batch 11.8) - the self-service surface for
 * `GET /auth/mfa/factors` + the factor writes. F4-native (no legacy screen
 * existed), live with its batch: factors list with the captured replay
 * state and last use, TOTP enrolment (shown-once secret + otpauth URI +
 * live-code verify), backup codes (shown once), e-mail enrolment with the
 * honest refusals, and factor removal behind a confirm (the contract has
 * no delete-user).
 *
 * Truth rules: every write renders the server's own answer verbatim
 * (`Factor removed`, `MFA assertion failed`, `TOTP code invalid`, the
 * last-factor refusal, the no-address 400) or an i18n line where the
 * server sent no message (`{status: "verified"}`). A captured
 * `stepup_required` 403 pauses the action, one code refreshes the window
 * and the action retries exactly once (retry-once, never a loop); a
 * second refusal renders verbatim. Shown-once material (secret, backup
 * codes) lives only in component state and is never stored.
 */
export function SecurityPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const [totp, setTotp] = useState<EnrollTotpBody | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [backup, setBackup] = useState<BackupCodesBody | null>(null);
  const [email, setEmail] = useState<EnrollEmailBody | null>(null);
  const [emailCode, setEmailCode] = useState('');
  const [stepupOpen, setStepupOpen] = useState(false);
  const [stepupCode, setStepupCode] = useState('');
  /** The one paused action: re-run at most once after a fresh step-up. */
  const pendingRef = useRef<(() => Promise<void>) | null>(null);

  const factors = useFactors();

  const mutationError = (err: unknown): void => {
    setError(err instanceof Error ? err.message : String(err));
  };

  const startAction = (): void => {
    setStatus(null);
    setError(null);
  };

  const isStepupRequired = (err: unknown): boolean =>
    err instanceof ApiError &&
    err.status === 403 &&
    (err.details as { reason?: string } | null)?.reason === 'stepup_required';

  /**
   * Run a write; the captured step-up 403 pauses it (the card appears,
   * no scary error) and `pendingRef` keeps it for exactly one retry.
   */
  const withStepup = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true);
    try {
      await action();
    } catch (err) {
      if (isStepupRequired(err)) {
        pendingRef.current = action;
        setStepupOpen(true);
        return;
      }
      mutationError(err);
    } finally {
      setBusy(false);
    }
  };

  const onEnrollTotp = (): void => {
    startAction();
    void withStepup(async () => {
      const data: EnrollTotpBody = await enrollTotp();
      setTotp(data);
      setCopyState('idle');
    });
  };

  const onVerifyTotp = (): void => {
    const code = totpCode.trim();
    if (code === '') {
      setError(t('security.totp.codeRequired'));
      return;
    }
    startAction();
    void withStepup(async () => {
      const data: TotpVerifyBody = await verifyTotpEnrol(code);
      setTotp(null);
      setTotpCode('');
      setStatus(t('security.totp.verified', { method: data.method }));
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityFactors });
    });
  };

  const onBackupCodes = (): void => {
    startAction();
    void withStepup(async () => {
      setBackup(await generateBackupCodes());
    });
  };

  const onEnrollEmail = (): void => {
    startAction();
    void withStepup(async () => {
      setEmail(await enrollEmail());
      setEmailCode('');
    });
  };

  const onVerifyEmail = (): void => {
    if (email === null) return;
    const code = emailCode.trim();
    if (code === '') {
      setError(t('security.email.codeRequired'));
      return;
    }
    startAction();
    void withStepup(async () => {
      await verifyEmailEnrol(email.challenge_id, code);
      setEmail(null);
      setEmailCode('');
      setStatus(t('security.email.verified'));
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityFactors });
    });
  };

  /**
   * RADIUS: an unconfigured deployment answers the captured honest 503
   * (the `radius` settings group) which renders verbatim below; a
   * configured one returns 201 and the factor list refreshes.
   */
  const onEnrollRadius = (): void => {
    startAction();
    void withStepup(async () => {
      await enrollRadius();
      setStatus(t('security.radius.verified'));
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityFactors });
    });
  };

  const onRemove = (factor: MfaFactorRow): void => {
    const question = t('security.actions.confirmRemove', { label: factor.name });
    if (!window.confirm(question)) return;
    startAction();
    void withStepup(async () => {
      const data = await deleteFactor(factor.id);
      setStatus(data.message); // the server's own answer, verbatim
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityFactors });
    });
  };

  /** Refresh the window once, then re-run the paused action exactly once. */
  const onStepupSubmit = (): void => {
    const code = stepupCode.trim();
    if (code === '') {
      setError(t('security.stepup.codeRequired'));
      return;
    }
    const retry = pendingRef.current;
    startAction();
    setBusy(true);
    void (async () => {
      try {
        const data: StepUpBody = await stepUp(code);
        // only a FRESH assertion consumes the paused action: a wrong code
        // leaves both the card and the pending action in place for re-entry
        pendingRef.current = null;
        setStepupOpen(false);
        setStepupCode('');
        setStatus(t('security.stepup.verified', { method: data.method }));
        // the retried action runs raw: a second step-up refusal surfaces
        // verbatim instead of pausing again (retry once, never a loop)
        if (retry) await retry();
      } catch (err) {
        mutationError(err);
      } finally {
        setBusy(false);
      }
    })();
  };

  const copySecret = async (): Promise<void> => {
    if (totp === null) return;
    try {
      await navigator.clipboard.writeText(totp.secret);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    }
  };

  const inputClass =
    'px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

  const columns: DataTableColumn<MfaFactorRow>[] = [
    {
      key: 'kind',
      header: t('security.columns.factor'),
      render: (factor) => <code className="font-code-md text-code-md">{factor.kind}</code>,
    },
    {
      key: 'name',
      header: t('security.columns.label'),
      render: (factor) => <Value value={factor.name}>{factor.name}</Value>,
    },
    {
      key: 'status',
      header: t('security.columns.status'),
      render: (factor) =>
        factor.active ? (
          <Chip tone="info">{t('security.statusChips.active')}</Chip>
        ) : (
          <Chip tone="inactive">{t('security.statusChips.inactive')}</Chip>
        ),
    },
    {
      key: 'lastUsed',
      header: t('security.columns.lastUsed'),
      render: (factor) =>
        factor.last_used_at !== null ? (
          <span>{settingsAgo(factor.last_used_at, t)}</span>
        ) : (
          <span>{t('security.statusChips.never')}</span>
        ),
    },
    {
      key: 'actions',
      header: t('security.columns.actions'),
      render: (factor) => (
        <Button type="button" variant="destructive" onClick={() => onRemove(factor)}>
          {t('security.actions.remove')}
        </Button>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-space-lg" data-testid="security-page">
      <SectionHeader
        title={t('security.page.title')}
        subtitle={t('security.page.subtitle')}
      />

      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-body-sm text-body-sm text-on-surface"
      >
        {status}
      </p>
      {error !== null ? (
        <p role="alert" className="min-h-5 font-body-sm text-body-sm text-error">
          {error}
        </p>
      ) : null}

      {/* Step-up: a paused action waits here for one fresh assertion. */}
      {stepupOpen ? (
        <section
          data-testid="stepup-card"
          className="flex flex-col gap-space-md rounded-lg border border-outline-variant/40 bg-surface-container-low p-space-md"
        >
          <div className="flex flex-col">
            <h3 className="font-title-sm text-title-sm text-on-surface">
              {t('security.stepup.title')}
            </h3>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('security.stepup.subtitle')}
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-space-md">
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('security.stepup.code')}
              </span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={stepupCode}
                onChange={(event) => setStepupCode(event.target.value)}
                placeholder={t('login.mfaPlaceholder')}
                className={`${inputClass} font-code-md text-code-md tracking-widest`}
              />
            </label>
            <Button type="button" disabled={busy} onClick={onStepupSubmit}>
              {t('security.stepup.verify')}
            </Button>
          </div>
        </section>
      ) : null}

      {factors.isPending ? (
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('security.states.loading')}
        </p>
      ) : factors.isError ? (
        isBackendDown(factors.error) ? (
          <BackendDownNotice body={t('errors.backendDown')} error={factors.error} />
        ) : (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('security.states.error', {
              message:
                factors.error instanceof Error
                  ? factors.error.message
                  : String(factors.error),
            })}
          </p>
        )
      ) : (
        <DataTable
          columns={columns}
          rows={factors.data.factors}
          rowKey={(factor) => String(factor.id)}
          caption={t('security.page.title')}
          emptyMessage={t('security.states.empty')}
          bodyDataRole="security-factors"
        />
      )}

      {/* TOTP enrolment: shown-once secret + otpauth URI + live verify. */}
      <section className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
        <div className="flex flex-col">
          <h3 className="font-title-sm text-title-sm text-on-surface">
            {t('security.totp.title')}
          </h3>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('security.totp.subtitle')}
          </p>
        </div>
        {totp === null ? (
          <div>
            <Button type="button" disabled={busy} onClick={onEnrollTotp}>
              {t('security.totp.enrol')}
            </Button>
          </div>
        ) : (
          <div
            role="status"
            data-testid="totp-secret"
            className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/40 bg-surface-container-low p-space-md"
          >
            <p className="font-label-md text-label-md text-on-surface">
              {t('security.totp.secretTitle')}
            </p>
            <div className="flex flex-wrap items-center gap-space-sm">
              <span className="font-label-sm text-label-sm text-on-surface-variant">
                {t('security.totp.secretLabel')}
              </span>
              <code className="font-code-md text-code-md tracking-wider text-on-surface select-all">
                {totp.secret}
              </code>
              <Button type="button" variant="secondary" onClick={() => void copySecret()}>
                {t('security.totp.copy')}
              </Button>
            </div>
            <p
              aria-live="polite"
              className="font-body-sm text-body-sm text-on-surface-variant"
            >
              {copyState === 'copied'
                ? t('security.totp.copied')
                : copyState === 'failed'
                  ? t('security.totp.copyFailed')
                  : ''}
            </p>
            <div className="flex flex-col gap-1">
              <span className="font-label-sm text-label-sm text-on-surface-variant">
                {t('security.totp.uriLabel')}
              </span>
              <code className="font-code-sm text-code-sm break-all text-on-surface select-all">
                {totp.otpauth_uri}
              </code>
            </div>
            <div className="flex flex-wrap items-end gap-space-md">
              <label className="flex flex-col gap-1">
                <span className="font-label-md text-label-md text-on-surface-variant">
                  {t('security.totp.code')}
                </span>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={totpCode}
                  onChange={(event) => setTotpCode(event.target.value)}
                  placeholder={t('login.mfaPlaceholder')}
                  className={`${inputClass} font-code-md text-code-md tracking-widest`}
                />
              </label>
              <Button type="button" disabled={busy} onClick={onVerifyTotp}>
                {t('security.totp.verify')}
              </Button>
            </div>
          </div>
        )}
      </section>

      {/* Backup codes: the server's own shown-once message renders verbatim. */}
      <section className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
        <div className="flex flex-col">
          <h3 className="font-title-sm text-title-sm text-on-surface">
            {t('security.backup.title')}
          </h3>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('security.backup.subtitle')}
          </p>
        </div>
        <div>
          <Button type="button" disabled={busy} onClick={onBackupCodes}>
            {t('security.backup.generate')}
          </Button>
        </div>
        {backup !== null ? (
          <div
            role="status"
            data-testid="backup-codes"
            className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/40 bg-surface-container-low p-space-md"
          >
            <p className="font-label-md text-label-md text-on-surface">{backup.message}</p>
            <ul className="flex flex-wrap gap-space-sm">
              {backup.codes.map((code) => (
                <li key={code}>
                  <code className="font-code-md text-code-md tracking-wider text-on-surface select-all">
                    {code}
                  </code>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      {/* E-mail factor: generic 202 + the honest refusals (captured). */}
      <section className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
        <div className="flex flex-col">
          <h3 className="font-title-sm text-title-sm text-on-surface">
            {t('security.email.title')}
          </h3>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('security.email.subtitle')}
          </p>
        </div>
        <div>
          <Button type="button" disabled={busy} onClick={onEnrollEmail}>
            {t('security.email.send')}
          </Button>
        </div>
        {email !== null ? (
          <div className="flex flex-col gap-space-md">
            <p className="font-body-sm text-body-sm text-on-surface">
              {t('security.email.sent')}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('security.email.smtpNote')}
            </p>
            <div className="flex flex-wrap items-end gap-space-md">
              <label className="flex flex-col gap-1">
                <span className="font-label-md text-label-md text-on-surface-variant">
                  {t('security.email.code')}
                </span>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={emailCode}
                  onChange={(event) => setEmailCode(event.target.value)}
                  placeholder={t('login.mfaPlaceholder')}
                  className={`${inputClass} font-code-md text-code-md tracking-widest`}
                />
              </label>
              <Button type="button" disabled={busy} onClick={onVerifyEmail}>
                {t('security.email.verify')}
              </Button>
            </div>
          </div>
        ) : null}
      </section>

      {/* RADIUS: the honest unconfigured 503 is the server's own message. */}
      <section className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
        <div className="flex flex-col">
          <h3 className="font-title-sm text-title-sm text-on-surface">
            {t('security.radius.title')}
          </h3>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('security.radius.subtitle')}
          </p>
        </div>
        <div>
          <Button type="button" disabled={busy} onClick={onEnrollRadius}>
            {t('security.radius.enrol')}
          </Button>
        </div>
      </section>
    </div>
  );
}
