import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import {
  Button,
  Chip,
  DataTable,
  KpiCard,
  SectionHeader,
  Tabs,
  Value,
} from '../../components';
import type { DataTableColumn } from '../../components';
import { GetApiV1UsersSource } from '../../api/generated/models';
import { settingsAgo } from '../settings/ago';
import { AccessTab } from './AccessTab';
import { isLocked } from './lockState';
import { usersCreateSchema } from './schemas';
import type { UsersCreateFormValues } from './schemas';
import {
  useCreateUser,
  useResetPassword,
  useUnlockUser,
  useUpdateUser,
  useRevokeUserSessions,
  useUsersList,
} from './queries';
import type { ConsoleUser } from './types';

/** A one-time password the server generated (create or admin reset). */
interface SecretReveal {
  username: string;
  value: string;
  kind: 'generated' | 'reset';
}

/**
 * Users & Credentials (ADR-0016 batch 11.7) - the console surface for
 * `GET/POST /users` + the four admin writes. First F4-native screen after
 * `/topology`: no legacy page ever existed for user administration, so the
 * nav item carries no legacyHref and the route ships live with this batch.
 *
 * Truth rules: every row is the captured `GET /users` shape; every write
 * renders the server's own message verbatim (`User updated`,
 * `User unlocked`, `Password reset - every session revoked`, `N session(s)
 * revoked`, `User created`); refusals render the captured error text
 * verbatim (401 admin-token required, 409 exists, the NIST length
 * refusal). A generated password appears once in the reveal box and is
 * never stored beyond that state. Deactivate (not delete - the contract
 * has no delete) and session revocation are `window.confirm`-gated.
 */
export function UsersPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: every user write is administrator-class; the auditor who can list
  // users sees them disabled with the stated reason, never a 403.
  const canUpdate = canOperate(ACTION_OPS.userUpdate, whoami);
  const canUnlock = canOperate(ACTION_OPS.userUnlock, whoami);
  const canReset = canOperate(ACTION_OPS.userPasswordReset, whoami);
  const canRevoke = canOperate(ACTION_OPS.userSessionsRevoke, whoami);
  const canCreate = canOperate(ACTION_OPS.userCreate, whoami);

  const [source, setSource] = useState<GetApiV1UsersSource | ''>('');
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<SecretReveal | null>(null);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const list = useUsersList(source);
  const create = useCreateUser();
  const update = useUpdateUser();
  const unlock = useUnlockUser();
  const reset = useResetPassword();
  const revoke = useRevokeUserSessions();

  const createForm = useForm<UsersCreateFormValues>({
    resolver: zodResolver(usersCreateSchema),
    mode: 'onSubmit',
  });

  /** Mutation failures render the server's message verbatim (house rule). */
  const mutationError = (err: unknown): void => {
    setError(err instanceof Error ? err.message : String(err));
  };

  const revealSecret = (
    username: string,
    value: string,
    kind: SecretReveal['kind'],
  ): void => {
    setSecret({ username, value, kind });
    setCopyState('idle');
  };

  const copySecret = async (): Promise<void> => {
    if (secret === null) return;
    try {
      await navigator.clipboard.writeText(secret.value);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    }
  };

  const startAction = (): void => {
    setStatus(null);
    setError(null);
  };

  const doActivate = (user: ConsoleUser, active: boolean): void => {
    if (!active) {
      const question = t('users.actions.confirmDeactivate', { username: user.username });
      if (!window.confirm(question)) return;
    }
    startAction();
    update.mutate(
      { userId: user.id, body: { active } },
      { onSuccess: (data) => setStatus(data.message), onError: mutationError },
    );
  };

  const doUnlock = (user: ConsoleUser): void => {
    startAction();
    unlock.mutate(user.id, {
      onSuccess: (data) => setStatus(data.message),
      onError: mutationError,
    });
  };

  const doReset = (user: ConsoleUser): void => {
    startAction();
    reset.mutate(
      { userId: user.id },
      {
        onSuccess: (data) => {
          setStatus(data.message);
          if (data.generated_password !== undefined && data.generated_password !== '') {
            revealSecret(user.username, data.generated_password, 'reset');
          }
        },
        onError: mutationError,
      },
    );
  };

  const doRevoke = (user: ConsoleUser): void => {
    const question = t('users.actions.confirmRevoke', { username: user.username });
    if (!window.confirm(question)) return;
    startAction();
    revoke.mutate(user.id, {
      onSuccess: (data) => setStatus(data.message),
      onError: mutationError,
    });
  };

  const doRequireChange = (user: ConsoleUser): void => {
    const question = t('users.actions.confirmRequireChange', {
      username: user.username,
    });
    if (!window.confirm(question)) return;
    startAction();
    update.mutate(
      { userId: user.id, body: { must_change_password: true } },
      { onSuccess: (data) => setStatus(data.message), onError: mutationError },
    );
  };

  const doClearChange = (user: ConsoleUser): void => {
    const question = t('users.actions.confirmClearChange', {
      username: user.username,
    });
    if (!window.confirm(question)) return;
    startAction();
    update.mutate(
      { userId: user.id, body: { must_change_password: false } },
      { onSuccess: (data) => setStatus(data.message), onError: mutationError },
    );
  };

  const onCreateValid = (values: UsersCreateFormValues): void => {
    startAction();
    create.mutate(
      {
        username: values.username,
        email: values.email !== undefined && values.email !== '' ? values.email : undefined,
        display_name:
          values.display_name !== undefined && values.display_name !== ''
            ? values.display_name
            : undefined,
        password:
          values.password !== undefined && values.password !== ''
            ? values.password
            : undefined,
      },
      {
        onSuccess: (data) => {
          setStatus(data.message);
          if (data.generated_password !== undefined && data.generated_password !== '') {
            revealSecret(data.user.username, data.generated_password, 'generated');
          }
          createForm.reset();
        },
        onError: mutationError,
      },
    );
  };
  const onCreateInvalid = (): void => {
    const errs = createForm.formState.errors;
    setError(
      errs.username !== undefined
        ? t('users.create.usernameRequired')
        : t('users.create.passwordTooShort'),
    );
  };

  const all = list.data?.users ?? [];
  const needle = q.trim().toLowerCase();
  const rows =
    needle === ''
      ? all
      : all.filter(
          (user) =>
            user.username.toLowerCase().includes(needle) ||
            user.display_name.toLowerCase().includes(needle) ||
            user.email.toLowerCase().includes(needle),
        );

  const inputClass =
    'px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

  const columns: DataTableColumn<ConsoleUser>[] = [
    {
      key: 'username',
      header: t('users.columns.username'),
      render: (user) => <span className="font-code-md text-code-md">{user.username}</span>,
    },
    {
      key: 'displayName',
      header: t('users.columns.displayName'),
      render: (user) => <Value value={user.display_name}>{user.display_name}</Value>,
    },
    {
      key: 'email',
      header: t('users.columns.email'),
      render: (user) => <Value value={user.email}>{user.email}</Value>,
    },
    {
      key: 'source',
      header: t('users.columns.source'),
      render: (user) => <span className="text-on-surface-variant">{user.source}</span>,
    },
    {
      key: 'status',
      header: t('users.columns.status'),
      render: (user) => (
        <span className="flex flex-wrap gap-1.5">
          {!user.is_active ? (
            <Chip tone="inactive">{t('users.statusChips.inactive')}</Chip>
          ) : isLocked(user) ? (
            <Chip tone="inactive">{t('users.statusChips.locked')}</Chip>
          ) : (
            <Chip tone="info">{t('users.statusChips.active')}</Chip>
          )}
          {user.must_change_password ? (
            <Chip tone="info">{t('users.statusChips.mustChange')}</Chip>
          ) : null}
          {user.is_emergency ? (
            <Chip tone="inactive">{t('users.statusChips.emergency')}</Chip>
          ) : null}
        </span>
      ),
    },
    {
      key: 'lastLogin',
      header: t('users.columns.lastLogin'),
      render: (user) =>
        user.last_login_at !== null ? (
          <span>{settingsAgo(user.last_login_at, t)}</span>
        ) : (
          <span>{t('users.statusChips.never')}</span>
        ),
    },
    {
      key: 'actions',
      header: t('users.columns.actions'),
      render: (user) => (
        <span className="flex flex-wrap gap-1.5">
          <Button
            type="button"
            variant={user.is_active ? 'destructive' : 'secondary'}
            disabled={!canUpdate}
            title={canUpdate ? undefined : t('roleReasons.administrator')}
            onClick={() => doActivate(user, !user.is_active)}
          >
            {user.is_active ? t('users.actions.deactivate') : t('users.actions.activate')}
          </Button>
          {isLocked(user) ? (
            <Button
              type="button"
              variant="secondary"
              disabled={!canUnlock}
              title={canUnlock ? undefined : t('roleReasons.administrator')}
              onClick={() => doUnlock(user)}
            >
              {t('users.actions.unlock')}
            </Button>
          ) : null}
          <Button
            type="button"
            variant="secondary"
            disabled={!canReset}
            title={canReset ? undefined : t('roleReasons.administrator')}
            onClick={() => doReset(user)}
          >
            {t('users.actions.resetPassword')}
          </Button>
          {user.must_change_password ? (
            <Button
              type="button"
              variant="secondary"
              disabled={!canUpdate}
              title={canUpdate ? undefined : t('roleReasons.administrator')}
              onClick={() => doClearChange(user)}
            >
              {t('users.actions.clearChange')}
            </Button>
          ) : (
            <Button
              type="button"
              variant="secondary"
              disabled={!canUpdate}
              title={canUpdate ? undefined : t('roleReasons.administrator')}
              onClick={() => doRequireChange(user)}
            >
              {t('users.actions.requireChange')}
            </Button>
          )}
          <Button
            type="button"
            variant="destructive"
            disabled={!canRevoke}
            title={canRevoke ? undefined : t('roleReasons.administrator')}
            onClick={() => doRevoke(user)}
          >
            {t('users.actions.revokeSessions')}
          </Button>
        </span>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-space-lg" data-testid="users-page">
      <SectionHeader title={t('users.page.title')} subtitle={t('users.page.subtitle')} />

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

      <Tabs
        label={t('users.tabs.label')}
        tabs={[
          {
            value: 'registry',
            label: t('users.tabs.registry'),
            content: (
              <div className="flex flex-col gap-space-lg">
                {/* One-time reveal: the generated password is shown once, here only. */}
                {secret !== null ? (
                  <div
                    role="status"
                    data-testid="user-secret"
                    className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/40 bg-surface-container-low p-space-md"
                  >
                    <p className="font-label-md text-label-md text-on-surface">
                      {t(
                        secret.kind === 'generated'
                          ? 'users.secret.generatedTitle'
                          : 'users.secret.resetTitle',
                        {
                          username: secret.username,
                        },
                      )}
                    </p>
                    <div className="flex flex-wrap items-center gap-space-sm">
                      <code className="font-code-md text-code-md tracking-wider text-on-surface select-all">
                        {secret.value}
                      </code>
                      <Button
                        type="button"
                        variant="secondary"
                        onClick={() => void copySecret()}
                      >
                        {t('users.secret.copy')}
                      </Button>
                    </div>
                    <p
                      aria-live="polite"
                      className="font-body-sm text-body-sm text-on-surface-variant"
                    >
                      {copyState === 'copied'
                        ? t('users.secret.copied')
                        : copyState === 'failed'
                          ? t('users.secret.copyFailed')
                          : ''}
                    </p>
                  </div>
                ) : null}

                {/* KPI quad: registry-wide counts (the filter only narrows the table). */}
                <div className="grid gap-space-md sm:grid-cols-2 lg:grid-cols-4">
                  <KpiCard
                    label={t('users.kpi.total')}
                    value={list.data ? String(all.length) : '—'}
                    valueDataRole="users-tile-total"
                  />
                  <KpiCard
                    label={t('users.kpi.active')}
                    value={
                      list.data ? String(all.filter((user) => user.is_active).length) : '—'
                    }
                    valueDataRole="users-tile-active"
                  />
                  <KpiCard
                    label={t('users.kpi.locked')}
                    value={list.data ? String(all.filter(isLocked).length) : '—'}
                    valueDataRole="users-tile-locked"
                  />
                  <KpiCard
                    label={t('users.kpi.mustChange')}
                    value={
                      list.data
                        ? String(all.filter((user) => user.must_change_password).length)
                        : '—'
                    }
                    valueDataRole="users-tile-must-change"
                  />
                </div>

                {list.isPending ? (
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    {t('users.states.loading')}
                  </p>
                ) : list.isError ? (
                  isBackendDown(list.error) ? (
                    <BackendDownNotice body={t('errors.backendDown')} error={list.error} />
                  ) : (
                    <p role="alert" className="font-body-sm text-body-sm text-error">
                      {t('users.states.error', {
                        message:
                          list.error instanceof Error
                            ? list.error.message
                            : String(list.error),
                      })}
                    </p>
                  )
                ) : (
                  <>
                    <div className="flex flex-wrap items-end gap-space-md">
                      <label className="flex flex-col gap-1">
                        <span className="font-label-md text-label-md text-on-surface-variant">
                          {t('users.filter.label')}
                        </span>
                        <input
                          type="search"
                          value={q}
                          onChange={(event) => setQ(event.target.value)}
                          placeholder={t('users.filter.placeholder')}
                          className={`${inputClass} min-w-64`}
                        />
                      </label>
                      <label className="flex flex-col gap-1">
                        <span className="font-label-md text-label-md text-on-surface-variant">
                          {t('users.filter.sourceLabel')}
                        </span>
                        <select
                          value={source}
                          onChange={(event) =>
                            setSource(event.target.value as GetApiV1UsersSource | '')
                          }
                          className={inputClass}
                        >
                          <option value="">{t('users.filter.sourceAll')}</option>
                          <option value={GetApiV1UsersSource.local}>
                            {GetApiV1UsersSource.local}
                          </option>
                          <option value={GetApiV1UsersSource.scim}>
                            {GetApiV1UsersSource.scim}
                          </option>
                          <option value={GetApiV1UsersSource.emergency}>
                            {GetApiV1UsersSource.emergency}
                          </option>
                        </select>
                      </label>
                    </div>

                    <DataTable
                      columns={columns}
                      rows={rows}
                      rowKey={(user) => String(user.id)}
                      caption={t('users.caption')}
                      emptyMessage={t('users.empty')}
                      bodyDataRole="users-body"
                    />
                  </>
                )}

                <section className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
                  <div className="flex flex-col">
                    <h3 className="font-title-sm text-title-sm text-on-surface">
                      {t('users.create.title')}
                    </h3>
                    <p className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('users.create.subtitle')}
                    </p>
                  </div>
                  <form
                    data-testid="create-user-form"
                    className="grid gap-space-md sm:grid-cols-2"
                    onSubmit={createForm.handleSubmit(onCreateValid, onCreateInvalid)}
                    noValidate
                  >
                    <label className="flex flex-col gap-1">
                      <span className="font-label-md text-label-md text-on-surface-variant">
                        {t('users.create.username')}
                      </span>
                      <input
                        {...createForm.register('username')}
                        autoComplete="off"
                        type="text"
                        className={inputClass}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="font-label-md text-label-md text-on-surface-variant">
                        {t('users.create.displayName')}
                      </span>
                      <input
                        {...createForm.register('display_name')}
                        autoComplete="off"
                        type="text"
                        className={inputClass}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="font-label-md text-label-md text-on-surface-variant">
                        {t('users.create.email')}
                      </span>
                      <input
                        {...createForm.register('email')}
                        autoComplete="off"
                        type="email"
                        className={inputClass}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="font-label-md text-label-md text-on-surface-variant">
                        {t('users.create.password')}
                      </span>
                      <input
                        {...createForm.register('password')}
                        autoComplete="new-password"
                        type="password"
                        className={inputClass}
                      />
                    </label>
                    <p className="sm:col-span-2 font-body-sm text-body-sm text-on-surface-variant">
                      {t('users.create.passwordHint')}
                    </p>
                    <div className="sm:col-span-2">
                      <Button
                        type="submit"
                        disabled={create.isPending || !canCreate}
                        title={canCreate ? undefined : t('roleReasons.administrator')}
                      >
                        {t('users.create.submit')}
                      </Button>
                    </div>
                  </form>
                </section>
              </div>
            ),
          },
          {
            value: 'access',
            label: t('users.tabs.access'),
            content: <AccessTab usernames={all.map((user) => user.username)} />,
          },
        ]}
      />
    </div>
  );
}
