import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Navigate, useNavigate } from 'react-router';

import { ApiError, expectOk, isBackendDown } from '../../../api/http';
import {
  getHealth,
  postApiV1AuthMfaEnrollTotp,
  postApiV1AuthMfaEnrollTotpVerify,
  postApiV1AuthOtpStart,
  postApiV1AuthPassword,
  postApiV1AuthRecoveryReset,
  postApiV1AuthRecoveryStart,
} from '../../../api/generated';
import { storeSession } from '../../../api/session';
import { queryKeys } from '../../../api/queryKeys';
import { useAuth } from '../../../app/providers/useAuth';
import {
  changePasswordSchema,
  enrolSchema,
  loginSchema,
  mfaSchema,
  recoveryResetSchema,
  recoveryStartSchema,
} from '../schemas';
import type {
  ChangePasswordFormValues,
  EnrolFormValues,
  LoginFormValues,
  MfaFormValues,
  RecoveryResetFormValues,
  RecoveryStartFormValues,
} from '../schemas';
import { useSetupState } from '../../setup/queries';

/**
 * Console login (plan F3: "login screen once identity work exists").
 * Flow mirrors the contract and the legacy screen exactly: password ->
 * session, 403 `mfa_required` -> TOTP step, 403 `enrolment_required` ->
 * the enrolment arm (ADR-0018 batch 11.11: the 403's own ticket enrols
 * TOTP and the verify mints the session - without it the first-run
 * officers could never sign in on a default MFA-required install),
 * network failure -> honest backend-down.
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
  const { status, login, refresh } = useAuth();
  const navigate = useNavigate();
  // ADR-0018 batch 11.11: the login card carries the instance branding
  // (company name / logo from the public setup state) - absent on a
  // virgin install, the exact VY-PAM card as before.
  const setup = useSetupState();

  const [challenge, setChallenge] = useState<string | null>(null);
  const [changeUser, setChangeUser] = useState<string | null>(null);
  const [otpChallenge, setOtpChallenge] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<
    null | { step: 1 } | { step: 2; username: string; challengeId: string }
  >(null);
  // ADR-0018 batch 11.11: the forced-enrolment arm - the login 403's own
  // ticket authorises the TOTP enrolment; the verify mints the session.
  const [enrol, setEnrol] = useState<{ ticket: string; methods: string[] } | null>(null);
  const [enrolSeed, setEnrolSeed] = useState<{
    secret: string;
    otpauth_uri: string;
  } | null>(null);
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
  const changeForm = useForm<ChangePasswordFormValues>({
    resolver: zodResolver(changePasswordSchema),
    mode: 'onSubmit',
  });
  const enrolForm = useForm<EnrolFormValues>({
    resolver: zodResolver(enrolSchema),
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
    extra?: {
      login_challenge?: string;
      totp_code?: string;
      otp_challenge_id?: string;
      otp_code?: string;
    },
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
        setOtpChallenge(null);
        setChallenge(outcome.challenge);
      }
    } catch (err) {
      if (isBackendDown(err)) {
        setError(t('auth.backendDownLogin', { message: err.message }));
      } else if (err instanceof ApiError) {
        if (err.statusField === 'enrolment_required') {
          // The same 403 carries the enrol ticket - open the arm that
          // enrols TOTP against it (fail-closed until a factor exists).
          const ticket = err.body?.enrol_ticket ?? '';
          if (ticket !== '') {
            setCreds({ username, password });
            setEnrolSeed(null);
            setEnrol({ ticket, methods: err.body?.methods_allowed ?? [] });
            setError('');
          } else {
            setError(
              t('login.enrolmentRequired', {
                methods: err.body?.methods_allowed?.join(', ') ?? '',
              }),
            );
          }
        } else if (
          err.status === 403 &&
          (err.details as { reason?: string } | null)?.reason === 'password-change-required'
        ) {
          // captured 403 {details: {reason: "password-change-required"}} -
          // the server refuses sign-in until POST /auth/password runs
          setChallenge(null);
          setChangeUser(username);
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
      if (otpChallenge !== null) {
        // e-mail OTP arm: the challenge id + code travel inline at login
        // (openapi /auth/login otp_challenge_id, otp_code)
        void doLogin(creds.username, creds.password, {
          otp_challenge_id: otpChallenge,
          otp_code: values.code,
        });
      } else {
        void doLogin(creds.username, creds.password, {
          login_challenge: challenge ?? undefined,
          totp_code: values.code,
        });
      }
    }
  };
  const onMfaInvalid = (): void => setError(t('login.enterCode'));

  /**
   * Start the e-mail OTP login challenge: the captured generic 202
   * ({status, challenge_id}) is byte-identical for every username - the
   * same anti-enumeration contract as the recovery flow (ADR-0016).
   */
  const sendLoginOtp = (): void => {
    if (!creds) return;
    void (async () => {
      setBusy(true);
      setError('');
      setNotice('');
      try {
        const res = expectOk(
          await postApiV1AuthOtpStart({ username: creds.username, purpose: 'login' }),
        );
        const id = (res.data as { challenge_id?: unknown }).challenge_id;
        if (typeof id !== 'string' || id === '') {
          setError(t('errors.unexpectedBody'));
          return;
        }
        setOtpChallenge(id);
        setNotice(t('login.otpSent'));
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };

  /** POST /auth/password - the captured forced-change path (ADR-0017 D1). */
  const onChangeValid = (values: ChangePasswordFormValues): void => {
    if (changeUser === null) return;
    const username = changeUser;
    void (async () => {
      setBusy(true);
      setError('');
      setNotice('');
      try {
        const res = expectOk(
          await postApiV1AuthPassword({
            username,
            old_password: values.old_password,
            new_password: values.new_password,
          }),
        );
        const message = (res.data as { message?: unknown }).message;
        // the server's own answer renders verbatim ("Password changed")
        setNotice(
          typeof message === 'string' && message !== ''
            ? message
            : t('errors.unexpectedBody'),
        );
        setChangeUser(null);
        userForm.setValue('username', username);
        changeForm.reset();
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };
  const onChangeInvalid = (): void => setError(t('login.changeEnterAll'));

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

  /** Mint the TOTP seed against the enrol ticket (shown exactly once). */
  const startEnrol = (): void => {
    if (enrol === null) return;
    setBusy(true);
    setError('');
    (async () => {
      try {
        const reply = expectOk(
          await postApiV1AuthMfaEnrollTotp({ enrol_ticket: enrol.ticket }),
        );
        const data = reply.data as unknown as { secret: string; otpauth_uri: string };
        setEnrolSeed({ secret: data.secret, otpauth_uri: data.otpauth_uri });
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };

  /** Verify the first live code: the ticket is consumed and the session
   * is minted by the same reply (routes.py: the enrolment-mint arm). */
  const onEnrolValid = (values: EnrolFormValues): void => {
    if (enrol === null) return;
    setBusy(true);
    setError('');
    (async () => {
      try {
        const mint = expectOk(
          await postApiV1AuthMfaEnrollTotpVerify({
            enrol_ticket: enrol.ticket,
            code: values.code,
          }),
        ).data;
        if (!mint.session_token) {
          // Honest refusal: a 200 without a minted session is a contract
          // violation - never store half a login (AuthProvider rule).
          throw new ApiError(200, 'Enrolment reply carried no session token.');
        }
        storeSession(mint.session_token, mint.csrf_token);
        await refresh();
        navigate('/', { replace: true });
      } catch (err) {
        recoveryFailure(err);
      } finally {
        setBusy(false);
      }
    })();
  };
  const onEnrolInvalid = (): void => setError(t('login.mfaPrompt'));

  const inputClass =
    'w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

  return (
    <div className="min-h-screen flex items-center justify-center px-space-xl bg-surface font-body-md text-body-md">
      <div className="w-full max-w-md bg-surface-container-lowest rounded-xl shadow-sm border border-outline-variant/30 p-space-xl flex flex-col gap-space-lg">
        <div className="flex items-center gap-3">
          {setup.data?.logo_data_uri ? (
            <img
              alt={
                setup.data.company_name !== ''
                  ? `${setup.data.company_name} logo`
                  : 'Instance logo'
              }
              className="h-8 w-8 shrink-0 rounded object-contain"
              src={setup.data.logo_data_uri}
            />
          ) : (
            <span
              className="material-symbols-outlined text-primary text-[28px]"
              aria-hidden="true"
            >
              shield_lock
            </span>
          )}
          <div className="flex flex-col">
            <h1 className="font-headline-sm text-headline-sm text-on-surface">
              {setup.data?.company_name ? setup.data.company_name : t('app.title')}
            </h1>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.subtitle')}
            </p>
          </div>
        </div>

        {enrol !== null ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={enrolForm.handleSubmit(onEnrolValid, onEnrolInvalid)}
            noValidate
          >
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.enrolTitle')}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.enrolMethods', { methods: enrol.methods.join(', ') })}
            </p>
            {enrolSeed === null ? (
              <button
                type="button"
                disabled={busy}
                onClick={startEnrol}
                className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {t('login.enrolSetUp')}
              </button>
            ) : (
              <>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('login.enrolSeedHint')}
                </p>
                <p
                  className="font-code-sm text-code-sm text-on-surface break-all select-all bg-surface-container rounded p-2"
                  data-testid="enrol-secret"
                >
                  {enrolSeed.secret}
                </p>
                <label className="flex flex-col gap-1">
                  <span className="font-label-md text-label-md text-on-surface-variant">
                    {t('login.mfaCode')}
                  </span>
                  <input
                    {...enrolForm.register('code')}
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
              </>
            )}
            <button
              type="button"
              onClick={() => {
                setEnrol(null);
                setEnrolSeed(null);
                setCreds(null);
                setError('');
                enrolForm.reset();
              }}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors"
            >
              {t('login.back')}
            </button>
          </form>
        ) : changeUser !== null ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={changeForm.handleSubmit(onChangeValid, onChangeInvalid)}
            noValidate
          >
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.changeTitle')}
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('login.changeHint')}
            </p>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.changeCurrent')}
              </span>
              <input
                {...changeForm.register('old_password')}
                autoComplete="current-password"
                type="password"
                className={inputClass}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="font-label-md text-label-md text-on-surface-variant">
                {t('login.changeNew')}
              </span>
              <input
                {...changeForm.register('new_password')}
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
              {t('login.changeSubmit')}
            </button>
            <button
              type="button"
              onClick={() => {
                setChangeUser(null);
                setError('');
                setNotice('');
              }}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors"
            >
              {t('login.back')}
            </button>
          </form>
        ) : challenge !== null ? (
          <form
            className="flex flex-col gap-space-md"
            onSubmit={mfaForm.handleSubmit(onMfaValid, onMfaInvalid)}
            noValidate
          >
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t(otpChallenge !== null ? 'login.otpPrompt' : 'login.mfaPrompt')}
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
              disabled={busy}
              onClick={sendLoginOtp}
              className="w-full py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md text-label-md font-semibold hover:bg-surface-container-high transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('login.sendEmailCode')}
            </button>
            <button
              type="button"
              onClick={() => {
                setChallenge(null);
                setOtpChallenge(null);
                setError('');
                setNotice('');
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
