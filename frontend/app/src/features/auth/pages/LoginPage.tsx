import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate } from 'react-router';

import { ApiError, expectOk, isBackendDown } from '../../../api/http';
import {
  getHealth,
  postApiV1AuthRecoveryReset,
  postApiV1AuthRecoveryStart,
} from '../../../api/generated';
import { queryKeys } from '../../../api/queryKeys';
import { useAuth } from '../../../app/providers/useAuth';
import {
  loginSchema,
  mfaSchema,
  recoveryResetSchema,
  recoveryStartSchema,
} from '../schemas';
import type {
  LoginFormValues,
  MfaFormValues,
  RecoveryResetFormValues,
  RecoveryStartFormValues,
} from '../schemas';

/**
 * Console login (plan F3: "login screen once identity work exists").
 * Flow mirrors the contract and the legacy screen exactly: password ->
 * session, 403 `mfa_required` -> TOTP step, 403 `enrolment_required` ->
 * honest fail-closed message, network failure -> honest backend-down.
 * Fields validated client-side (ADR-0006), server always authoritative;
 * submit disables in-flight (duplicate-submission protection).
 *
 * ADR-0016 batch 11.6 adds password recovery on the same card:
 * `POST /auth/recovery/start` answers the identical generic 202 for every
 * syntactically valid username (no enumeration, captured verbatim), then
 * `POST /auth/recovery/reset` applies the code + new password - the server's
 * own messages render verbatim ("Password reset - sign in again" on success,
 * "One-time code invalid or expired" on 401), transport failure shows the
 * shared honest backend-down line. Step 2's back re-enters step 1, where a
 * re-send under the cooldown returns the SAME challenge id (otp.py contract).
 */
export function LoginPage() {
  const { t } = useTranslation();
  const { status, login } = useAuth();
  const navigate = useNavigate();

  const [challenge, setChallenge] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<
    null | { step: 1 } | { step: 2; username: string; challengeId: string }
  >(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [creds, setCreds] = useState<{ username: string; password: string } | null>(null);

  const userForm = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    mode: 'onSubmit',
  });
  const mfaForm = useForm<MfaFormValues>({
    resolver: zodResolver(mfaSchema),
    mode: 'onSubmit',
  });
  const recoveryStartForm = useForm<RecoveryStartFormValues>({
    resolver: zodResolver(recoveryStartSchema),
    mode: 'onSubmit',
  });
  const recoveryResetForm = useForm<RecoveryResetFormValues>({
    resolver: zodResolver(recoveryResetSchema),
    mode: 'onSubmit',
  });

  // The footer's honest server state: /health is unauthenticated.
  const health = useQuery({
    queryKey: queryKeys.health,
    queryFn: () => getHealth(),
    retry: (failureCount, err) => !isBackendDown(err) && failureCount < 1,
    staleTime: 15_000,
  });
  const serverState = health.isPending
    ? '-'
    : health.error || health.data === undefined || health.data.status !== 200
      ? t('login.serverNotConnected')
      : health.data.data.status === 'ok'
        ? t('login.serverHealthy')
        : t('login.serverUnreachable');

  /** Map a recovery-flow failure to the shared honest render rules. */
  const recoveryFailure = (err: unknown): void => {
    if (isBackendDown(err)) {
      setError(t('auth.backendDownLogin', { message: err.message }));
    } else if (err instanceof ApiError && err.body?.error) {
      setError(err.body.error); // the server's own message, verbatim
    } else if (err instanceof ApiError) {
      setError(t('login.refused', { status: err.status }));
    } else {
      setError(t('errors.unexpectedBody'));
    }
  };

  const doLogin = async (
    username: string,
    password: string,
    extra?: { login_challenge?: string; totp_code?: string },
  ): Promise<void> => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const outcome = await login(username, password, extra);
      if (outcome.kind === 'ok') {
        navigate('/', { replace: true });
      } else {
        setCreds({ username, password });
        setChallenge(outcome.challenge);
      }
    } catch (err) {
      if (isBackendDown(err)) {
        setError(t('auth.backendDownLogin', { message: err.message }));
      } else if (err instanceof ApiError) {
        if (err.statusField === 'enrolment_required') {
          setError(
            t('login.enrolmentRequired', {
              methods: err.body?.methods_allowed?.join(', ') ?? '',
            }),
          );
        } else if (err.body?.error) {
          setError(err.body.error);
        } else {
          setError(t('login.refused', { status: err.status }));
        }
      } else {
        setError(t('errors.unexpectedBody'));
      }
    } finally {
      setBusy(false);
    }
  };

  if (status === 'authenticated') return <Navigate to="/" replace />;

  const onUserValid = (values: LoginFormValues): void => {
    void doLogin(values.username, values.password);
  };
  const onUserInvalid = (): void => setError(t('login.required'));
  const onMfaValid = (values: MfaFormValues): void => {
    if (creds) {
      void doLogin(creds.username, creds.password, {
        login_challenge: challenge ?? undefined,
        totp_code: values.code,
      });
    }
  };
  const onMfaInvalid = (): void => setError(t('login.enterCode'));

  /** Enter recovery step 1, carrying over a username already typed. */
  const startRecovery = (): void => {
    setError('');
    setNotice('');
    recoveryStartForm.setValue('username', userForm.getValues('username'));
    setRecovery({ step: 1 });
  };

  const onRecoveryStartValid = (values: RecoveryStartFormValues): void => {
    void (async () => {
      setBusy(true);
      setError('');
      setNotice('');
      try {
        const res = expectOk(
          await postApiV1AuthRecoveryStart({ username: values.username }),
        );
        const challengeId = (res.data as { challenge_id?: unknown }).challenge_id;
        if (typeof challengeId !== 'string' || challengeId === '') {
          setError(t('errors.unexpectedBody'));
          return;
        }
        setRecovery({ step: 2, username: values.username, challengeId });
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };
  const onRecoveryStartInvalid = (): void => setError(t('login.recoveryUsernameRequired'));

  const onRecoveryResetValid = (values: RecoveryResetFormValues): void => {
    if (recovery === null || recovery.step !== 2) return;
    const username = recovery.username;
    void (async () => {
      setBusy(true);
      setError('');
      setNotice('');
      try {
        const res = expectOk(
          await postApiV1AuthRecoveryReset({
            username,
            challenge_id: recovery.challengeId,
            code: values.code,
            new_password: values.new_password,
          }),
        );
        const message = (res.data as { message?: unknown }).message;
        setNotice(
          typeof message === 'string' && message !== ''
            ? message
            : t('errors.unexpectedBody'),
        );
        setRecovery(null);
        userForm.setValue('username', username);
        recoveryResetForm.reset();
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };
  const onRecoveryResetInvalid = (): void => setError(t('login.recoveryEnterAll'));

  const inputClass =
    'w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

  return (
    <div className="min-h-screen flex items-center justify-center px-space-xl bg-surface font-body-md text-body-md">
      <div className="w-full max-w-md bg-surface-container-lowest rounded-xl shadow-sm border border-outline-variant/30 p-space-xl flex flex-col gap-space-lg">
        <div className="flex items-center gap-3">
          <span
            className="material-symbols-outlined text-primary text-[28px]"
            aria-hidden="true"
          >
            shield_lock
          </span>
          <div className="flex flex-col">
            <h1 className="font-headline-sm text-headline-sm text-on-surface">
              {t('app.title')}
            </h1>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.subtitle')}
            </p>
          </div>
        </div>

        {challenge !== null ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={mfaForm.handleSubmit(onMfaValid, onMfaInvalid)}
            noValidate
          >
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.mfaPrompt')}
            </p>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.mfaCode')}
              </span>
              <input
                {...mfaForm.register('code')}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder={t('login.mfaPlaceholder')}
                className={`${inputClass} font-code-md text-code-md tracking-widest`}
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.verify')}
            </button>
            <button
              type="button"
              onClick={() => {
                setChallenge(null);
                setError('');
              }}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors"
            >
              {t('login.back')}
            </button>
          </form>
        ) : recovery === null ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={userForm.handleSubmit(onUserValid, onUserInvalid)}
            noValidate
          >
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.username')}
              </span>
              <input
                {...userForm.register('username')}
                autoComplete="username"
                type="text"
                className={inputClass}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.password')}
              </span>
              <input
                {...userForm.register('password')}
                autoComplete="current-password"
                type="password"
                className={inputClass}
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.signIn')}
            </button>
            <button
              type="button"
              onClick={startRecovery}
              className="self-center font-label-md text-label-md text-primary hover:underline"
            >
              {t('login.forgotPassword')}
            </button>
          </form>
        ) : recovery.step === 1 ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={recoveryStartForm.handleSubmit(
              onRecoveryStartValid,
              onRecoveryStartInvalid,
            )}
            noValidate
          >
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.recoveryTitle')}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.recoveryStartHint')}
            </p>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.username')}
              </span>
              <input
                {...recoveryStartForm.register('username')}
                autoComplete="username"
                type="text"
                className={inputClass}
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.recoverySendCode')}
            </button>
            <button
              type="button"
              onClick={() => {
                setRecovery(null);
                setError('');
              }}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors"
            >
              {t('login.back')}
            </button>
          </form>
        ) : (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={recoveryResetForm.handleSubmit(
              onRecoveryResetValid,
              onRecoveryResetInvalid,
            )}
            noValidate
          >
            <p role="status" className="font-body-sm text-body-sm text-on-surface">
              {t('login.recoverySent', { username: recovery.username })}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.recoverySmtpNote')}
            </p>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.recoveryCode')}
              </span>
              <input
                {...recoveryResetForm.register('code')}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder={t('login.mfaPlaceholder')}
                className={`${inputClass} font-code-md text-code-md tracking-widest`}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.recoveryNewPassword')}
              </span>
              <input
                {...recoveryResetForm.register('new_password')}
                autoComplete="new-password"
                type="password"
                className={inputClass}
              />
            </label>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.recoveryPolicy')}
            </p>
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.recoverySubmit')}
            </button>
            <button
              type="button"
              onClick={() => {
                recoveryStartForm.setValue('username', recovery.username);
                setRecovery({ step: 1 });
                setError('');
              }}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors"
            >
              {t('login.back')}
            </button>
          </form>
        )}

        {notice ? (
          <div role="status" className="font-body-sm text-body-sm text-tertiary">
            {notice}
          </div>
        ) : null}

        {error ? (
          <div role="alert" className="font-body-sm text-body-sm text-error">
            {error}
          </div>
        ) : null}

        <div className="flex items-center gap-1.5 font-body-sm text-body-sm text-on-surface-variant border-t border-outline-variant/20 pt-space-md">
          <span
            className={`w-2 h-2 rounded-full ${serverState === t('login.serverHealthy') ? 'bg-tertiary' : 'bg-outline'}`}
            aria-hidden="true"
          />
          <span>{t('login.serverFooter', { state: serverState })}</span>
        </div>
      </div>
    </div>
  );
}
