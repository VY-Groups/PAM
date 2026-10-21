import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import mark from '../../assets/vy-pam-mark.svg';
import { isBackendDown } from '../../api/http';
import { useCreateRoleBinding, usePutSettingsGroup } from '../settings/queries';
import { useCreateUser } from '../users/queries';
import { useCompleteSetup, useSetupState, useUpdateSetupProfile } from './queries';
import {
  setupAdminSchema,
  setupAttestationSchema,
  setupProfileSchema,
  setupSmtpSchema,
} from './schemas';
import type {
  SetupAdminFormValues,
  SetupAttestationFormValues,
  SetupProfileFormValues,
  SetupSmtpFormValues,
} from './schemas';

/** The backend's logo bound (ADR-0018): PNG/JPEG data URI, 64 KB decoded. */
const MAX_LOGO_BYTES = 64 * 1024;

/**
 * First-run setup wizard (ADR-0018 batch 11.11, route `/setup` beside
 * `/login`). Four ordered sections on one page - company profile, SMTP,
 * company admins, and the maker-checker attestation that finishes setup.
 * Each save renders the server's refusal verbatim (house rule); the page
 * itself is public, the officer's console session is the key the profile
 * step turns (the backend refuses everyone else while setup runs).
 */
export function SetupPage() {
  const { t } = useTranslation();
  const state = useSetupState();
  const profile = useUpdateSetupProfile();
  const complete = useCompleteSetup();
  const [logoDataUri, setLogoDataUri] = useState('');
  const [logoError, setLogoError] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [generated, setGenerated] = useState<{ username: string; password: string } | null>(
    null,
  );
  const [done, setDone] = useState('');

  const profileForm = useForm<SetupProfileFormValues>({
    resolver: zodResolver(setupProfileSchema),
    mode: 'onSubmit',
  });

  /** Mutation failures render the server's message verbatim (house rule). */
  const mutationError = (err: unknown): void => {
    if (isBackendDown(err)) {
      setError(t('shell.backendDownTitle'));
      return;
    }
    setError(err instanceof Error ? err.message : String(err));
  };
  const startAction = (): void => {
    setStatus('');
    setError('');
  };

  const onLogoFile = (file: File | undefined): void => {
    setLogoError('');
    if (file === undefined) return;
    if (file.type !== 'image/png' && file.type !== 'image/jpeg') {
      setLogoError(t('setup.logoTypeError'));
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setLogoError(t('setup.logoSizeError', { max: 64 }));
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setLogoDataUri(String(reader.result ?? ''));
    reader.onerror = () => setLogoError(t('setup.logoReadError'));
    reader.readAsDataURL(file);
  };

  const doProfile = (values: SetupProfileFormValues): void => {
    startAction();
    profile.mutate(
      {
        company_name: values.company_name,
        contact_email: values.contact_email ?? '',
        logo_data_uri: logoDataUri,
      },
      {
        onSuccess: (data) => {
          setStatus(t('setup.profileSaved'));
          setLogoDataUri(data.logo_data_uri);
        },
        onError: mutationError,
      },
    );
  };

  if (state.isLoading) {
    return (
      <main className="min-h-screen bg-surface flex items-center justify-center font-body-md text-body-md text-on-surface-variant">
        {t('shell.checkingSession')}
      </main>
    );
  }

  if (state.isError || state.data === undefined) {
    return (
      <main className="min-h-screen bg-surface flex flex-col items-center justify-center gap-space-md font-body-md text-body-md">
        <p className="text-on-surface">{t('shell.backendDownTitle')}</p>
        <Link className="text-primary underline" to="/login">
          {t('login.signIn')}
        </Link>
      </main>
    );
  }

  const data = state.data;

  if (data.configured || done !== '') {
    return (
      <main className="min-h-screen bg-surface flex items-center justify-center px-space-xl font-body-md text-body-md">
        <section className="w-full max-w-md bg-surface-container-lowest rounded-xl shadow-sm border border-outline-variant/30 p-space-xl flex flex-col gap-space-md">
          <h1 className="font-headline-sm text-headline-sm text-on-surface">
            {t('setup.completedTitle')}
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {done !== '' ? done : t('setup.completedBody')}
          </p>
          <Link
            className="w-full py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold text-center hover:bg-primary-container transition-colors"
            to="/login"
          >
            {t('login.signIn')}
          </Link>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-surface px-space-xl py-space-2xl flex justify-center font-body-md text-body-md">
      <div className="w-full max-w-2xl flex flex-col gap-space-xl">
        <header className="flex items-center gap-space-md">
          {logoDataUri !== '' || data.logo_data_uri !== '' ? (
            <img
              alt={
                data.company_name !== ''
                  ? t('setup.brandLogoAlt', { company: data.company_name })
                  : t('setup.brandLogoAltAnon')
              }
              className="h-10 w-10 shrink-0 rounded object-contain bg-surface-container-lowest"
              src={logoDataUri !== '' ? logoDataUri : data.logo_data_uri}
            />
          ) : (
            <img alt="VY-PAM logo" className="h-10 w-10 shrink-0" src={mark} />
          )}
          <div className="flex flex-col">
            <h1 className="font-headline-sm text-headline-sm text-on-surface">
              {data.company_name !== '' ? data.company_name : t('app.title')}
            </h1>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('setup.subtitle')}
            </p>
          </div>
        </header>

        <section
          aria-label={t('setup.signInHintTitle')}
          className="bg-surface-container rounded-lg border border-outline-variant/30 p-space-md font-body-sm text-body-sm text-on-surface-variant"
        >
          <p>{t('setup.signInHint')}</p>
          <p className="font-code-sm text-code-sm text-on-surface">
            {t('setup.officersLine', {
              maker: data.bootstrap.maker,
              checker: data.bootstrap.checker,
            })}
          </p>
          <Link className="text-primary underline" to="/login">
            {t('login.signIn')}
          </Link>
        </section>

        {error !== '' ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {error}
          </p>
        ) : null}
        {status !== '' ? (
          <p role="status" className="font-body-sm text-body-sm text-on-surface">
            {status}
          </p>
        ) : null}

        <ProfileSection
          form={profileForm}
          onSave={doProfile}
          busy={profile.isPending}
          logoDataUri={logoDataUri !== '' ? logoDataUri : data.logo_data_uri}
          logoError={logoError}
          onLogoFile={onLogoFile}
        />

        <SmtpSection
          onActionError={mutationError}
          onStart={startAction}
          onStatus={setStatus}
        />

        <AdminSection
          onActionError={mutationError}
          onStart={startAction}
          generated={generated}
          onGenerated={setGenerated}
          onStatus={setStatus}
        />

        <AttestationSection
          complete={complete}
          onSave={(values) => {
            startAction();
            complete.mutate(values, {
              onSuccess: (reply) => setDone(reply.message),
              onError: mutationError,
            });
          }}
        />
      </div>
    </main>
  );
}

function SectionCard({
  titleKey,
  descKey,
  children,
}: {
  titleKey: string;
  descKey: string;
  children: React.ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <section className="bg-surface-container-lowest rounded-xl shadow-sm border border-outline-variant/30 p-space-lg flex flex-col gap-space-md">
      <div className="flex flex-col gap-1">
        <h2 className="font-title-md text-title-md text-on-surface">{t(titleKey)}</h2>
        <p className="font-body-sm text-body-sm text-on-surface-variant">{t(descKey)}</p>
      </div>
      {children}
    </section>
  );
}

const inputClass =
  'w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';
const labelClass = 'flex flex-col gap-1';
const spanClass = 'font-label-md text-label-md text-on-surface-variant';
const submitClass =
  'self-start px-space-lg py-2 rounded-lg bg-primary text-on-primary font-label-md text-label-md font-semibold hover:bg-primary-container transition-colors disabled:opacity-50 disabled:cursor-not-allowed';

/** Step 1 - company profile: name, logo, contact (ADR-0018 Decision 2). */
function ProfileSection({
  form,
  onSave,
  busy,
  logoDataUri,
  logoError,
  onLogoFile,
}: {
  form: ReturnType<typeof useForm<SetupProfileFormValues>>;
  onSave: (values: SetupProfileFormValues) => void;
  busy: boolean;
  logoDataUri: string;
  logoError: string;
  onLogoFile: (file: File | undefined) => void;
}) {
  const { t } = useTranslation();
  return (
    <SectionCard titleKey="setup.profileTitle" descKey="setup.profileDesc">
      <form
        className="flex flex-col gap-space-md"
        onSubmit={form.handleSubmit(onSave)}
        noValidate
      >
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.companyName')}</span>
          <input className={inputClass} type="text" {...form.register('company_name')} />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.logo')}</span>
          <input
            accept="image/png,image/jpeg"
            className={inputClass}
            type="file"
            onChange={(event) => onLogoFile(event.target.files?.[0])}
          />
          <span className="font-body-sm text-body-sm text-on-surface-variant">
            {t('setup.logoHint', { max: 64 })}
          </span>
        </label>
        {logoError !== '' ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {logoError}
          </p>
        ) : null}
        {logoDataUri !== '' ? (
          <img
            alt={t('setup.logoPreviewAlt')}
            className="h-16 w-16 rounded object-contain bg-surface-container border border-outline-variant/30"
            src={logoDataUri}
          />
        ) : null}
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.contactEmail')}</span>
          <input className={inputClass} type="email" {...form.register('contact_email')} />
        </label>
        <button className={submitClass} disabled={busy} type="submit">
          {t('setup.saveProfile')}
        </button>
      </form>
    </SectionCard>
  );
}

/** Step 2 - SMTP, through the ordinary settings write (ADR-0018 D4). */
function SmtpSection({
  onStart,
  onActionError,
  onStatus,
}: {
  onStart: () => void;
  onActionError: (err: unknown) => void;
  onStatus: (message: string) => void;
}) {
  const { t } = useTranslation();
  const smtpForm = useForm<SetupSmtpFormValues>({
    resolver: zodResolver(setupSmtpSchema),
    mode: 'onSubmit',
    defaultValues: {
      enabled: false,
      host: '',
      port: 587,
      username: '',
      password: '',
      from_address: '',
      use_tls: true,
    },
  });
  const putSettings = usePutSettingsGroup();

  const doSave = (values: SetupSmtpFormValues): void => {
    onStart();
    putSettings.mutate(
      {
        group: 'smtp',
        body: {
          enabled: values.enabled,
          host: values.host,
          port: values.port,
          use_tls: values.use_tls,
          username: values.username,
          from_address: values.from_address,
          // an empty secret means "clear" server side: only send it when
          // the officer really typed one (never wipe a set password blind)
          ...(values.password !== '' ? { password: values.password } : {}),
        },
      },
      { onSuccess: () => onStatus(t('setup.smtpSaved')), onError: onActionError },
    );
  };

  return (
    <SectionCard titleKey="setup.smtpTitle" descKey="setup.smtpDesc">
      <form
        className="flex flex-col gap-space-md"
        onSubmit={smtpForm.handleSubmit(doSave)}
        noValidate
      >
        <label className="flex items-center gap-space-sm">
          <input type="checkbox" {...smtpForm.register('enabled')} />
          <span className={spanClass}>{t('setup.smtpEnabled')}</span>
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.smtpHost')}</span>
          <input className={inputClass} type="text" {...smtpForm.register('host')} />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.smtpPort')}</span>
          <input
            className={inputClass}
            type="number"
            {...smtpForm.register('port', { valueAsNumber: true })}
          />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.smtpUsername')}</span>
          <input className={inputClass} type="text" {...smtpForm.register('username')} />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.smtpPassword')}</span>
          <input
            autoComplete="new-password"
            className={inputClass}
            type="password"
            {...smtpForm.register('password')}
          />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.smtpFrom')}</span>
          <input
            className={inputClass}
            type="email"
            {...smtpForm.register('from_address')}
          />
        </label>
        <label className="flex items-center gap-space-sm">
          <input type="checkbox" {...smtpForm.register('use_tls')} />
          <span className={spanClass}>{t('setup.smtpTls')}</span>
        </label>
        <button className={submitClass} disabled={putSettings.isPending} type="submit">
          {t('setup.saveSmtp')}
        </button>
      </form>
    </SectionCard>
  );
}

/**
 * Step 3 - the company's first admins: create the account (generated
 * password shown once when none given) and bind the admin role through
 * the ordinary kind:user path, exactly like the Access tab does.
 */
function AdminSection({
  onStart,
  onActionError,
  generated,
  onGenerated,
  onStatus,
}: {
  onStart: () => void;
  onActionError: (err: unknown) => void;
  generated: { username: string; password: string } | null;
  onGenerated: (next: { username: string; password: string } | null) => void;
  onStatus: (message: string) => void;
}) {
  const { t } = useTranslation();
  const adminForm = useForm<SetupAdminFormValues>({
    resolver: zodResolver(setupAdminSchema),
    mode: 'onSubmit',
  });
  const createUser = useCreateUser();
  const createBinding = useCreateRoleBinding();

  const doSave = (values: SetupAdminFormValues): void => {
    onStart();
    onGenerated(null);
    createUser.mutate(
      {
        username: values.username,
        ...(values.password !== undefined && values.password !== ''
          ? { password: values.password }
          : {}),
      },
      {
        onSuccess: (created) => {
          const secret = (created as { generated_password?: string }).generated_password;
          if (typeof secret === 'string' && secret !== '') {
            onGenerated({ username: values.username, password: secret });
          }
          createBinding.mutate(
            { principal: values.username, role: 'admin', kind: 'user' },
            {
              onSuccess: () =>
                onStatus(t('setup.adminCreated', { username: values.username })),
              onError: onActionError,
            },
          );
        },
        onError: onActionError,
      },
    );
  };

  return (
    <SectionCard titleKey="setup.adminsTitle" descKey="setup.adminsDesc">
      <form
        className="flex flex-col gap-space-md"
        onSubmit={adminForm.handleSubmit(doSave)}
        noValidate
      >
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.adminUsername')}</span>
          <input className={inputClass} type="text" {...adminForm.register('username')} />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.adminPassword')}</span>
          <input
            autoComplete="new-password"
            className={inputClass}
            type="password"
            {...adminForm.register('password')}
          />
          <span className="font-body-sm text-body-sm text-on-surface-variant">
            {t('setup.adminPasswordHint')}
          </span>
        </label>
        <button
          className={submitClass}
          disabled={createUser.isPending || createBinding.isPending}
          type="submit"
        >
          {t('setup.saveAdmin')}
        </button>
      </form>
      {generated !== null ? (
        <div className="bg-surface-container rounded-lg border border-outline-variant/40 p-space-md flex flex-col gap-space-sm">
          <p className="font-label-md text-label-md text-error">
            {t('setup.passwordOnce')}
          </p>
          <p className="font-code-sm text-code-sm text-on-surface break-all">
            {generated.username}: {generated.password}
          </p>
          <button
            className="self-start text-primary underline font-body-sm text-body-sm"
            type="button"
            onClick={() => onGenerated(null)}
          >
            {t('common.close')}
          </button>
        </div>
      ) : null}
    </SectionCard>
  );
}

/** Step 4 - the maker-checker attestation that ends setup (one-way). */
function AttestationSection({
  complete,
  onSave,
}: {
  complete: ReturnType<typeof useCompleteSetup>;
  onSave: (values: SetupAttestationFormValues) => void;
}) {
  const { t } = useTranslation();
  const attestationForm = useForm<SetupAttestationFormValues>({
    resolver: zodResolver(setupAttestationSchema),
    mode: 'onSubmit',
  });
  return (
    <SectionCard titleKey="setup.completeTitle" descKey="setup.completeDesc">
      <form
        className="flex flex-col gap-space-md"
        onSubmit={attestationForm.handleSubmit(onSave)}
        noValidate
      >
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.makerPassword')}</span>
          <input
            autoComplete="current-password"
            className={inputClass}
            type="password"
            {...attestationForm.register('maker_password')}
          />
        </label>
        <label className={labelClass}>
          <span className={spanClass}>{t('setup.checkerPassword')}</span>
          <input
            autoComplete="current-password"
            className={inputClass}
            type="password"
            {...attestationForm.register('checker_password')}
          />
        </label>
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('setup.completeHint')}
        </p>
        <button className={submitClass} disabled={complete.isPending} type="submit">
          {t('setup.completeSubmit')}
        </button>
      </form>
    </SectionCard>
  );
}
