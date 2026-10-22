import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import { Button, DataTable, SectionHeader } from '../../components';
import type { RoleBinding, RoleBindingCreateRole } from '../../api/generated/models';
import { isBackendDown } from '../../api/http';
import { useDiscoveryAssets } from '../infrastructure/queries';
import { settingsAgo } from '../settings/ago';
import {
  useCreateRoleBinding,
  useRevokeRoleBinding,
  useRoleBindings,
  useRoles,
} from '../settings/queries';

type TFunction = ReturnType<typeof useTranslation>['t'];

/**
 * Access tab (ADR-0017 Decision 2, batch 11.10): the human-facing view of
 * the role-bindings surface on `/users`. The create always sends
 * `kind: "user"` (a console user's grant - no token is minted, so there is
 * no once-reveal box); the machine-facing one-time-token flow stays in the
 * Settings RBAC section untouched. All reads/writes reuse the settings
 * query hooks, so this tab and the Settings section are one cache view of
 * the same registry and can never disagree.
 *
 * Honest states (house rule): the list renders loading / backend-down /
 * verbatim-error instead of an empty table that would read as "nobody has
 * access"; every write renders the server's own message verbatim.
 */

/** Targets and vault items, else the honest "everywhere". */
function scopeSummary(binding: RoleBinding, t: TFunction): string {
  const scope = binding.scope ?? {};
  const parts: string[] = [];
  if (scope.targets?.length) parts.push(scope.targets.join(', '));
  if (scope.vault_items?.length) {
    parts.push(t('users.access.scopeItems', { items: scope.vault_items.join(', ') }));
  }
  return parts.length ? parts.join(' \u00b7 ') : t('users.access.everywhere');
}

/** The comma-list parser the grant form applies (same as the Settings form). */
function splitList(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

const inputClass =
  'px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

export function AccessTab({ usernames }: { usernames: string[] }) {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: granting/revoking a binding is administrator-class; the auditor
  // who can list bindings sees them disabled with the stated reason.
  const canGrant = canOperate(ACTION_OPS.bindingCreate, whoami);
  const canRevoke = canOperate(ACTION_OPS.bindingRevoke, whoami);
  const roles = useRoles();
  const bindings = useRoleBindings();
  const create = useCreateRoleBinding();
  const revoke = useRevokeRoleBinding();
  const assets = useDiscoveryAssets({ q: '' });

  const [principal, setPrincipal] = useState('');
  const [roleName, setRoleName] = useState('operator');
  const [targets, setTargets] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const roleRows = roles.data?.roles;
  const bindingRows = bindings.data?.bindings;

  /** Mutation failures render the server's message verbatim (house rule). */
  const mutationError = (err: unknown): void => {
    setError(err instanceof Error ? err.message : String(err));
  };

  const startAction = (): void => {
    setStatus(null);
    setError(null);
  };

  const handleGrant = (): void => {
    const trimmed = principal.trim();
    if (trimmed === '') {
      setError(t('users.access.form.principalRequired'));
      return;
    }
    const targetList = splitList(targets);
    startAction();
    create.mutate(
      {
        principal: trimmed,
        role: roleName as RoleBindingCreateRole,
        kind: 'user',
        ...(targetList.length ? { scope: { targets: targetList } } : {}),
      },
      {
        onSuccess: (data) => {
          setStatus(data.message);
          setPrincipal('');
          setTargets('');
        },
        onError: mutationError,
      },
    );
  };

  const handleRevoke = (binding: RoleBinding): void => {
    const question = t('users.access.confirmRevoke', {
      principal: binding.principal,
      role: binding.role,
    });
    if (!window.confirm(question)) return;
    startAction();
    revoke.mutate(binding.id, {
      onSuccess: (data) => setStatus(data.message),
      onError: mutationError,
    });
  };

  /** The picker appends an address the admin has not added yet. */
  const appendTarget = (address: string): void => {
    const current = splitList(targets);
    if (!current.includes(address)) setTargets([...current, address].join(', '));
  };

  return (
    <section className="flex flex-col gap-space-md" data-testid="users-access">
      <SectionHeader
        title={t('users.access.title')}
        subtitle={t('users.access.subtitle')}
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

      {/* Grant form: kind is always `user` (this tab is the human-facing view). */}
      <div className="flex flex-wrap items-end gap-space-md rounded-lg border border-outline-variant/30 p-space-md">
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('users.access.form.principal')}
          </span>
          <input
            list="users-access-principals"
            autoComplete="off"
            type="text"
            value={principal}
            onChange={(event) => setPrincipal(event.target.value)}
            placeholder={t('users.access.form.principalPlaceholder')}
            className={`${inputClass} min-w-48`}
          />
          <datalist id="users-access-principals">
            {usernames.map((name) => (
              <option key={name} value={name} />
            ))}
          </datalist>
        </label>
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('users.access.form.role')}
          </span>
          <select
            value={roleName}
            onChange={(event) => setRoleName(event.target.value)}
            className={inputClass}
          >
            {(roleRows ?? []).map((role) => (
              <option key={role.name} value={role.name}>
                {role.name}
              </option>
            ))}
          </select>
        </label>
        <div className="flex flex-col gap-1 grow min-w-64">
          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('users.access.form.targets')}
            </span>
            <input
              type="text"
              value={targets}
              onChange={(event) => setTargets(event.target.value)}
              placeholder={t('users.access.form.targetsPlaceholder')}
              className={inputClass}
            />
          </label>
          <span className="font-body-sm text-body-sm text-on-surface-variant">
            {t('users.access.form.targetsHint')}
          </span>
        </div>
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('users.access.form.pickerLabel')}
          </span>
          <select
            value=""
            onChange={(event) => {
              if (event.target.value !== '') appendTarget(event.target.value);
            }}
            className={inputClass}
          >
            <option value="">{t('users.access.form.pickerEmpty')}</option>
            {(assets.data?.assets ?? []).map((asset) => (
              <option key={asset.id} value={asset.address}>
                {asset.address}
              </option>
            ))}
          </select>
        </label>
        <Button
          type="button"
          onClick={handleGrant}
          disabled={create.isPending || !canGrant}
          title={canGrant ? undefined : t('roleReasons.administrator')}
        >
          {t('users.access.form.submit')}
        </Button>
      </div>

      {bindings.isPending ? (
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('users.access.loading')}
        </p>
      ) : bindings.isError ? (
        isBackendDown(bindings.error) ? (
          <BackendDownNotice body={t('errors.backendDown')} error={bindings.error} />
        ) : (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('users.access.error', {
              message:
                bindings.error instanceof Error
                  ? bindings.error.message
                  : String(bindings.error),
            })}
          </p>
        )
      ) : (
        <DataTable
          columns={[
            {
              key: 'principal',
              header: t('users.access.columns.principal'),
              render: (row: RoleBinding) => (
                <span className="font-code-md text-code-md">{row.principal}</span>
              ),
            },
            {
              key: 'role',
              header: t('users.access.columns.role'),
              render: (row: RoleBinding) => row.role,
            },
            {
              key: 'kind',
              header: t('users.access.columns.kind'),
              render: (row: RoleBinding) => row.kind,
            },
            {
              key: 'scope',
              header: t('users.access.columns.scope'),
              render: (row: RoleBinding) => scopeSummary(row, t),
            },
            {
              key: 'created',
              header: t('users.access.columns.created'),
              render: (row: RoleBinding) => settingsAgo(row.created_at, t),
            },
            {
              key: 'actions',
              header: t('users.access.columns.actions'),
              render: (row: RoleBinding) => (
                <Button
                  type="button"
                  variant="destructive"
                  disabled={!canRevoke}
                  title={canRevoke ? undefined : t('roleReasons.administrator')}
                  onClick={() => handleRevoke(row)}
                >
                  {t('users.access.revoke')}
                </Button>
              ),
            },
          ]}
          rows={bindingRows ?? []}
          rowKey={(row: RoleBinding) => String(row.id)}
          caption={t('users.access.caption')}
          emptyMessage={t('users.access.empty')}
          bodyDataRole="users-access-bindings"
        />
      )}
    </section>
  );
}
