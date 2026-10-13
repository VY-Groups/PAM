import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate } from 'react-router';

import { ApiError, isBackendDown } from '../../../api/http';
import { getHealth } from '../../../api/generated';
import { queryKeys } from '../../../api/queryKeys';
import { useAuth } from '../../../app/providers/useAuth';
import { loginSchema, mfaSchema } from '../schemas';
import type { LoginFormValues, MfaFormValues } from '../schemas';

/**
 * Console login (plan F3: "login screen once identity work exists").
 * Flow mirrors the contract and the legacy screen exactly: password ->
 * session, 403 `mfa_required` -> TOTP step, 403 `enrolment_required` ->
 * honest fail-closed message, network failure -> honest backend-down.
 * Fields validated client-side (ADR-0006), server always authoritative;
 * submit disables in-flight (duplicate-submission protection).
 */
export function LoginPage() {
  const { t } = useTranslation();
  const { status, login } = useAuth();
  const navigate = useNavigate();

  const [challenge, setChallenge] = useState<string | null>(null);
  const [error, setError] = useState('');
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

  const doLogin = async (
    username: string,
    password: string,
    extra?: { login_challenge?: string; totp_code?: string },
  ): Promise<void> => {
    setBusy(true);
    setError('');
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

        {challenge === null ? (
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
                className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
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
                className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.signIn')}
            </button>
          </form>
        ) : (
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
                className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-md text-code-md tracking-widest border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
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
        )}

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
