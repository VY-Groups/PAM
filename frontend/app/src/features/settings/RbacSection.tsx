import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, DataTable, KpiCard, SectionHeader } from '../../components';
import type {
  Role,
  RoleBinding,
  RoleBindingCreate,
  RoleBindingCreateKind,
  RoleBindingCreateRole,
} from '../../api/generated/models';
import { ApiError, isBackendDown, isUnauthorized } from '../../api/http';
import {
  useCreateRoleBinding,
  useRevokeRoleBinding,
  useRoleBindings,
  useRoles,
} from './queries';

type TFunction = ReturnType<typeof useTranslation>['t'];

/**
 * RBAC / ABAC (screen 11, ADR-0015, the 11.2 slice). A verbatim
 * carry-over of the legacy `platform_settings_center` RBAC block: the
 * summary composer, the two posture tiles, the five-role directory, the
 * grant form, the one-time token box and the binding table with revoke.
 *
 * The parity contract is the standing gate's 6b block
 * (shots_tool/__verify_agent.mjs, lines 416-432 + the kind-select check
 * at 477): the summary regex `^\d+ roles \u00b7 \d+ active bindings?$
 * parens`, the seeded-five role tile and row count, the binding rows,
 * the token box starting `hidden`, and NO `id=` anywhere in the section
 * (the one place the legacy page used `id="rbac-token-value"` the React
 * DoD bans ids, so this section carries none and the flip-time gate
 * re-points at the `data-testid`/`data-role` hooks).
 *
 * Honest states, proven in RbacSection.test.tsx and never assumed:
 * - the summary reads the server's own counts (a role list of five is
 *   five because the server seeded five, not because the page says so);
 * - an unreachable server says so verbatim instead of rendering a zero
 *   registry that would read as "no access is granted";
 * - a 401 (token-mode rig, no admin token) says the admin token is
 *   required - a different and more actionable truth than "unreachable";
 * - the grant form's token box appears ONLY on a 201 that actually
 *   carries a token (a `local` principal); an `ldap`/`sso`/`user`
 *   grant answers without one and the box stays hidden.
 *
 * Divergences from the legacy page, each deliberate and each tested:
 * - the role `<select>` derives its options from the same
 *   `GET /api/v1/roles` the directory table renders, so the two can
 *   never disagree (the legacy page hardcodes five `<option>`s);
 * - feedback uses an inline `role="status"`/`role="alert"` line instead
 *   of the legacy page-level banner/toast chrome (the React app has no
 *   such chrome yet); the copy is verbatim either way.
 */

/** Legacy `rbacRoleChip` tone mapping, classes verbatim. */
function roleChipClasses(name: string): string {
  if (name === 'admin') return 'bg-error/10 text-error';
  if (name === 'operator') return 'bg-tertiary/10 text-tertiary';
  return 'bg-primary/10 text-primary';
}

function RoleChip({ name }: { name: string }) {
  return (
    <span
      className={`inline-flex px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold ${roleChipClasses(name)}`}
    >
      {name}
    </span>
  );
}

/** Legacy `rbacScopeSummary`: targets and vault items, else the honest unscoped. */
function scopeSummary(binding: RoleBinding, t: TFunction): string {
  const scope = binding.scope ?? {};
  const parts: string[] = [];
  if (scope.targets && scope.targets.length) {
    parts.push(t('settings.rbac.scopeTargets', { targets: scope.targets.join(', ') }));
  }
  if (scope.vault_items && scope.vault_items.length) {
    parts.push(t('settings.rbac.scopeItems', { items: scope.vault_items.join(', ') }));
  }
  return parts.length ? parts.join(' \u00b7 ') : t('settings.rbac.scopeUnscoped');
}

/** Legacy `ago`: relative last-use, "never" when the row never ran. */
function ago(iso: string | null | undefined, t: TFunction): string {
  if (!iso) return t('settings.never');
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return iso;
  const seconds = Math.max(0, (Date.now() - then.getTime()) / 1000);
  if (seconds < 60) return t('settings.rbac.agoJustNow');
  if (seconds < 3600)
    return t('settings.rbac.agoMinutes', { count: Math.floor(seconds / 60) });
  if (seconds < 86400)
    return t('settings.rbac.agoHours', { count: Math.floor(seconds / 3600) });
  const days = Math.floor(seconds / 86400);
  return days === 1
    ? t('settings.rbac.agoYesterday')
    : t('settings.rbac.agoDays', { count: days });
}

/** Legacy `rbacAction` error words: server error verbatim, honest fallbacks. */
function actionErrorMessage(error: unknown, t: TFunction): string {
  if (isBackendDown(error)) return t('settings.rbac.unreachableAction');
  if (error instanceof ApiError) {
    return error.body?.error ?? t('settings.rbac.actionFailed', { status: error.status });
  }
  return error instanceof Error ? error.message : String(error);
}

/** The comma-list parser the legacy grant form applies, verbatim. */
function splitList(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

interface Feedback {
  tone: 'created' | 'revoked' | 'error';
  text: string;
}

export function RbacSection() {
  const { t } = useTranslation();
  const roles = useRoles();
  const bindings = useRoleBindings();
  const create = useCreateRoleBinding();
  const revoke = useRevokeRoleBinding();

  const [principal, setPrincipal] = useState('');
  const [roleName, setRoleName] = useState('operator');
  const [kind, setKind] = useState<RoleBindingCreateKind>('local');
  const [targets, setTargets] = useState('');
  const [items, setItems] = useState('');
  const [tokenOnce, setTokenOnce] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const roleRows = roles.data?.roles;
  const bindingRows = bindings.data?.bindings;

  // Legacy `renderRbac`'s kind line: local, sso, then the rest counted
  // as directory - and the summary singularises on exactly one binding.
  const local = (bindingRows ?? []).filter((row) => row.kind === 'local').length;
  const sso = (bindingRows ?? []).filter((row) => row.kind === 'sso').length;
  const ldap = (bindingRows ?? []).length - local - sso;
  const kindLine = sso
    ? t('settings.rbac.kindLineSso', { ldap, local, sso })
    : t('settings.rbac.kindLine', { ldap, local });

  let summary: string;
  if (roles.isError && isUnauthorized(roles.error)) {
    summary = t('settings.rbac.tokenNeeded');
  } else if (roles.isError || bindings.isError) {
    summary = t('settings.rbac.unreachable');
  } else if (!roleRows || !bindingRows) {
    summary = t('settings.rbac.loading');
  } else {
    summary = t('settings.rbac.summary', {
      bindingWord: t(
        bindingRows.length === 1 ? 'settings.rbac.bindingOne' : 'settings.rbac.bindingMany',
      ),
      bindings: bindingRows.length,
      kind: kindLine,
      roles: roleRows.length,
    });
  }

  async function handleGrant() {
    const trimmed = principal.trim();
    if (!trimmed) {
      setFeedback({ tone: 'error', text: t('settings.rbac.form.principalRequired') });
      return;
    }
    const targetList = splitList(targets);
    const itemList = splitList(items);
    const payload: RoleBindingCreate = {
      principal: trimmed,
      role: roleName as RoleBindingCreateRole,
      kind,
    };
    if (targetList.length || itemList.length) {
      payload.scope = {};
      if (targetList.length) payload.scope.targets = targetList;
      if (itemList.length) payload.scope.vault_items = itemList.map((p) => parseInt(p, 10));
    }
    try {
      const body = await create.mutateAsync(payload);
      setPrincipal('');
      setTargets('');
      setItems('');
      if (body.token) setTokenOnce(body.token);
      setFeedback({
        tone: 'created',
        text: body.token
          ? t('settings.rbac.createdToken', {
              principal: body.binding.principal,
              role: body.binding.role,
            })
          : t('settings.rbac.createdDirectory', {
              principal: body.binding.principal,
              role: body.binding.role,
            }),
      });
    } catch (error) {
      setFeedback({ tone: 'error', text: actionErrorMessage(error, t) });
    }
  }

  function handleRevoke(binding: RoleBinding) {
    const confirmed = window.confirm(
      t('settings.rbac.revokeConfirm', { principal: binding.principal }),
    );
    if (!confirmed) return;
    revoke.mutate(binding.id, {
      onSuccess: () =>
        setFeedback({
          tone: 'revoked',
          text: t('settings.rbac.revokedLine', {
            principal: binding.principal,
            role: binding.role,
          }),
        }),
      onError: (error) =>
        setFeedback({ tone: 'error', text: actionErrorMessage(error, t) }),
    });
  }

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-rbac">
      <SectionHeader
        subtitle={t('settings.rbac.subtitle')}
        title={t('settings.rbac.title')}
      />

      <p
        className="font-code-sm text-code-sm text-on-surface-variant"
        data-testid="settings-rbac-summary"
      >
        {summary}
      </p>

      <div className="grid grid-cols-2 gap-space-sm">
        <KpiCard
          footer={t('settings.rbac.tileRolesSub')}
          label={t('settings.rbac.tileRoles')}
          value={roleRows ? String(roleRows.length) : null}
          valueDataRole="rbac-tile-roles"
        />
        <KpiCard
          footer={bindingRows ? kindLine : '\u2014'}
          label={t('settings.rbac.tileBindings')}
          value={bindingRows ? String(bindingRows.length) : null}
          valueDataRole="rbac-tile-bindings"
        />
      </div>

      <DataTable
        bodyDataRole="rbac-role-rows"
        caption={t('settings.rbac.rolesCaption')}
        columns={[
          {
            key: 'name',
            header: t('settings.rbac.columns.role'),
            render: (row: Role) => <RoleChip name={row.name} />,
          },
          {
            key: 'description',
            header: t('settings.rbac.columns.description'),
            render: (row: Role) => row.description,
          },
          {
            key: 'operations',
            header: t('settings.rbac.columns.operations'),
            render: (row: Role) => String(row.operations),
          },
        ]}
        emptyMessage={t('settings.rbac.rolesEmpty')}
        rows={roleRows ?? []}
        rowKey={(row: Role) => String(row.id)}
      />

      <div className="flex flex-wrap items-end gap-space-sm rounded-lg bg-surface-container-low border border-outline-variant/30 p-space-sm">
        <label className="flex flex-col gap-1 font-headline-sm text-[13px] text-on-surface font-medium">
          {t('settings.rbac.form.principal')}
          <input
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary-container"
            onChange={(event) => setPrincipal(event.target.value)}
            placeholder={t('settings.rbac.form.principalPlaceholder')}
            type="text"
            value={principal}
          />
        </label>
        <label className="flex flex-col gap-1 font-headline-sm text-[13px] text-on-surface font-medium">
          {t('settings.rbac.form.role')}
          <select
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary-container"
            onChange={(event) => setRoleName(event.target.value)}
            value={roleName}
          >
            {(roleRows ?? []).map((role) => (
              <option key={role.name} value={role.name}>
                {role.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 font-headline-sm text-[13px] text-on-surface font-medium">
          {t('settings.rbac.form.kind')}
          <select
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary-container"
            data-testid="settings-rbac-input-kind"
            onChange={(event) => setKind(event.target.value as RoleBindingCreateKind)}
            value={kind}
          >
            <option value="local">{t('settings.rbac.kindLocal')}</option>
            <option value="ldap">{t('settings.rbac.kindLdap')}</option>
            <option value="sso">{t('settings.rbac.kindSso')}</option>
            <option value="user">{t('settings.rbac.kindUser')}</option>
          </select>
        </label>
        <label className="flex flex-col grow min-w-[180px] gap-1 font-headline-sm text-[13px] text-on-surface font-medium">
          {t('settings.rbac.form.targets')}
          <input
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary-container"
            onChange={(event) => setTargets(event.target.value)}
            placeholder={t('settings.rbac.form.targetsPlaceholder')}
            type="text"
            value={targets}
          />
        </label>
        <label className="flex flex-col grow min-w-[160px] gap-1 font-headline-sm text-[13px] text-on-surface font-medium">
          {t('settings.rbac.form.items')}
          <input
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary-container"
            onChange={(event) => setItems(event.target.value)}
            placeholder={t('settings.rbac.form.itemsPlaceholder')}
            type="text"
            value={items}
          />
        </label>
        <Button onClick={() => void handleGrant()}>{t('settings.rbac.form.submit')}</Button>
      </div>

      {/*
        The one-time token box: present in the DOM but `hidden` until a
        201 actually returns a token (the gate's `tokenBoxHidden` check,
        line 428). A directory grant answers without a token and the box
        stays hidden - the legacy page's exact behaviour.
      */}
      <div
        className={`${tokenOnce === null ? 'hidden' : ''} rounded-lg bg-primary/5 border border-primary/30 p-space-sm`}
        data-testid="settings-rbac-token-once"
      >
        <span className="font-label-badge text-label-badge text-primary">
          {t('settings.rbac.tokenOnceLabel')}
        </span>
        <code className="block mt-1 px-3 py-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface break-all">
          {tokenOnce ?? ''}
        </code>
      </div>

      {feedback ? (
        <p
          aria-live="polite"
          className={
            feedback.tone === 'error'
              ? 'font-body-sm text-body-sm text-error'
              : 'font-body-sm text-body-sm text-on-surface-variant'
          }
          data-testid="settings-rbac-status"
          role={feedback.tone === 'error' ? 'alert' : 'status'}
        >
          {feedback.text}
        </p>
      ) : null}

      <DataTable
        bodyDataRole="rbac-binding-rows"
        caption={t('settings.rbac.bindingsCaption')}
        columns={[
          {
            key: 'principal',
            header: t('settings.rbac.columns.principal'),
            render: (row: RoleBinding) => (
              <span className="font-code-sm text-code-sm text-on-surface font-medium whitespace-nowrap">
                {row.principal}
              </span>
            ),
          },
          {
            key: 'role',
            header: t('settings.rbac.columns.role'),
            render: (row: RoleBinding) => <RoleChip name={row.role} />,
          },
          {
            key: 'kind',
            header: t('settings.rbac.columns.kind'),
            render: (row: RoleBinding) => (
              <>
                {row.kind}
                {row.has_token ? (
                  <span className="font-code-sm text-code-sm text-outline">
                    {' '}
                    {row.token_prefix}
                  </span>
                ) : null}
              </>
            ),
          },
          {
            key: 'scope',
            header: t('settings.rbac.columns.scope'),
            render: (row: RoleBinding) => scopeSummary(row, t),
          },
          {
            key: 'lastUsed',
            header: t('settings.rbac.columns.lastUsed'),
            render: (row: RoleBinding) => ago(row.last_used_at, t),
          },
          {
            key: 'actions',
            header: t('settings.rbac.columns.actions'),
            render: (row: RoleBinding) => (
              <Button onClick={() => handleRevoke(row)} variant="destructive">
                {t('settings.rbac.revoke')}
              </Button>
            ),
          },
        ]}
        emptyMessage={t('settings.rbac.bindingsEmpty')}
        rows={bindingRows ?? []}
        rowKey={(row: RoleBinding) => String(row.id)}
      />
    </section>
  );
}
