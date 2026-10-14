import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import {
  Button,
  Chip,
  DataTable,
  KpiCard,
  Modal,
  SectionHeader,
  StatusDot,
  Value,
} from '../../components';
import type { DataTableColumn, DotState } from '../../components';
import type {
  BrokerCredential,
  BrokerPolicy,
  BrokerPolicyList,
  BrokerStats,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import {
  useBrokerCredentialAction,
  useBrokerPolicies,
  useBrokerCredentials,
  useBrokerStats,
  useRegisterPolicy,
  useRevokePolicy,
} from './queries';
import {
  policySchema,
  reasonSchema,
  splitCommaList,
  type PolicyForm,
  type PolicyValues,
  type ReasonValues,
} from './schemas';
import { SectionBody } from './SectionBody';

/**
 * Pipeline Credential Broker (plan §4 line 107): no static secret ever
 * lives in a pipeline - it authenticates with its broker API token
 * (shown once, stored as a sha256 hash) and requests vault credentials
 * through this queue. The console registers identities, watches the
 * queue and admin-approves/denies/closes; `release` is deliberately
 * absent from this UI because the contract authenticates it with the
 * pipeline's own token (the decrypted value exists only in that
 * response, never in a console session).
 */
export function BrokerSection({ actor }: { actor: string }) {
  const { t } = useTranslation();
  const stats = useBrokerStats();
  const policies = useBrokerPolicies();
  const credentials = useBrokerCredentials();
  const register = useRegisterPolicy();
  const revoke = useRevokePolicy();
  const credentialAction = useBrokerCredentialAction();

  const [registering, setRegistering] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<BrokerPolicy | null>(null);
  const [denyTarget, setDenyTarget] = useState<BrokerCredential | null>(null);

  function closeRegister(open: boolean) {
    if (!open) {
      register.reset(); // the once-shown token must not outlive the modal
      setRegistering(false);
    }
  }

  return (
    <section className="flex flex-col gap-space-sm">
      <SectionHeader title={t('jit.broker.heading')} subtitle={t('jit.broker.subtitle')} />

      <SectionBody query={stats}>{(data) => <BrokerKpis stats={data} />}</SectionBody>

      {/* Mutation feedback: the server's own message, verbatim. */}
      {revoke.isSuccess ? (
        <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
          {t('jit.states.actionDone', { message: revoke.data.message })}
        </p>
      ) : null}
      {revoke.isError ? (
        <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(revoke.error)
              ? t('errors.backendDown')
              : revoke.error.message,
          })}
        </p>
      ) : null}
      {credentialAction.isSuccess ? (
        <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
          {t('jit.states.actionDone', { message: credentialAction.data.message })}
        </p>
      ) : null}
      {credentialAction.isError ? (
        <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(credentialAction.error)
              ? t('errors.backendDown')
              : credentialAction.error.message,
          })}
        </p>
      ) : null}

      {/* Pipeline identities. */}
      <div className="mt-space-md">
        <div className="flex items-center justify-between gap-space-md">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.broker.policiesHeading')}
          </span>
          <Button icon="add" onClick={() => setRegistering(true)}>
            {t('jit.broker.register')}
          </Button>
        </div>
        <div className="mt-space-sm overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={policies}>
            {(data: BrokerPolicyList) => (
              <PoliciesTable
                policies={data.policies}
                busy={revoke.isPending}
                onRevoke={(policy) => setRevokeTarget(policy)}
              />
            )}
          </SectionBody>
        </div>
      </div>

      {/* The credential approval queue (rows record only that a secret
          was released - `secret_released`, never the value). */}
      <div className="mt-space-md">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.broker.credentialsHeading')}
        </span>
        <div className="mt-space-sm overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={credentials}>
            {(data) => (
              <CredentialsTable
                rows={data.credentials}
                busy={credentialAction.isPending}
                onApprove={(row) =>
                  credentialAction.mutate({ kind: 'approve', credentialId: row.id, actor })
                }
                onDeny={(row) => setDenyTarget(row)}
                onClose={(row) =>
                  credentialAction.mutate({ kind: 'close', credentialId: row.id, actor })
                }
              />
            )}
          </SectionBody>
        </div>
      </div>

      {/* Register a pipeline identity: the API token is shown once. */}
      <Modal
        open={registering}
        onOpenChange={closeRegister}
        title={t('jit.broker.registerTitle')}
        closeLabel={t('common.close')}
      >
        <RegisterPolicyBody actor={actor} register={register} />
      </Modal>

      {/* Revoke an identity: reason recorded, open credentials end first. */}
      <ReasonModal
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        title={t('jit.broker.revokeTitle', { name: revokeTarget?.name ?? '' })}
        confirmLabel={t('jit.broker.revokeConfirm')}
        busy={revoke.isPending}
        onSubmit={(reason) => {
          if (revokeTarget !== null) {
            revoke.mutate({ policyId: revokeTarget.id, actor, reason });
          }
        }}
      />

      {/* Deny a queued credential with its recorded reason. */}
      <ReasonModal
        open={denyTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDenyTarget(null);
        }}
        title={t('jit.broker.denyTitle', { id: denyTarget?.id ?? 0 })}
        confirmLabel={t('jit.broker.denyConfirm')}
        busy={credentialAction.isPending}
        onSubmit={(reason) => {
          if (denyTarget !== null) {
            credentialAction.mutate({
              kind: 'deny',
              credentialId: denyTarget.id,
              actor,
              reason,
            });
          }
        }}
      />
    </section>
  );
}

/** Broker posture KPIs: identities, queued approvals, live grants, trail. */
function BrokerKpis({ stats }: { stats: BrokerStats }) {
  const { t } = useTranslation();
  return (
    <div className="mt-space-md grid grid-cols-1 gap-space-lg sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('jit.broker.kpis.policies')}
        value={stats.policies.total}
        accent="primary"
        footer={t('jit.broker.kpis.policiesFooter', {
          active: stats.policies.by_status.active ?? 0,
          revoked: stats.policies.by_status.revoked ?? 0,
        })}
      />
      <KpiCard
        label={t('jit.broker.kpis.pending')}
        value={stats.credentials.by_status.pending ?? 0}
        accent={(stats.credentials.by_status.pending ?? 0) > 0 ? 'tertiary' : 'primary'}
        footer={t('jit.broker.kpis.pendingFooter', { open: stats.credentials.open })}
      />
      <KpiCard
        label={t('jit.broker.kpis.open')}
        value={stats.credentials.open}
        accent={stats.credentials.open > 0 ? 'primary-container' : 'primary'}
        footer={t('jit.broker.kpis.openFooter', {
          released: stats.credentials.by_status.released ?? 0,
        })}
      />
      <KpiCard
        label={t('jit.broker.kpis.events')}
        value={stats.events}
        accent="primary-container"
        footer={t('jit.broker.kpis.eventsFooter')}
      />
    </div>
  );
}

const POLICY_STATUS_DOT: Record<string, DotState> = {
  active: 'ok',
  expired: 'muted',
  revoked: 'error',
};

/** Pipeline identities table: identity, CI system, policy, scope, actions. */
function PoliciesTable({
  policies,
  busy,
  onRevoke,
}: {
  policies: BrokerPolicy[];
  busy: boolean;
  onRevoke: (policy: BrokerPolicy) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<BrokerPolicy>[] = [
    {
      key: 'identity',
      header: t('jit.broker.columns.identity'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-md text-code-md text-on-surface font-semibold">
            {row.name}
          </span>
          <Value value={row.contact} />
        </div>
      ),
    },
    {
      key: 'ci',
      header: t('jit.broker.columns.ci'),
      render: (row) => <Chip>{row.ci_system}</Chip>,
    },
    {
      key: 'approval',
      header: t('jit.broker.columns.approval'),
      render: (row) => (
        <span className="font-body-sm text-body-sm">
          {row.approval_mode === 'auto'
            ? t('jit.broker.autoApproval')
            : t('jit.broker.manualApproval')}
        </span>
      ),
    },
    {
      key: 'scope',
      header: t('jit.broker.columns.scope'),
      render: (row) => {
        const targets = row.allowed_targets ?? [];
        return (
          <div className="flex flex-col gap-1">
            <span className="font-code-sm text-code-sm">
              {t('jit.broker.ttlCap', { minutes: row.max_ttl_minutes })}
            </span>
            <span className="font-body-sm text-body-sm text-outline">
              {targets.length === 0 ? t('jit.broker.anyTargets') : targets.join(', ')}
            </span>
          </div>
        );
      },
    },
    {
      key: 'lastUsed',
      header: t('jit.broker.columns.lastUsed'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <Value value={row.last_used_at === null ? null : formatTime(row.last_used_at)} />
          <span className="font-body-sm text-body-sm text-outline">
            {t('jit.broker.useCount', { count: row.use_count })}
          </span>
        </div>
      ),
    },
    {
      key: 'state',
      header: t('jit.broker.columns.state'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={POLICY_STATUS_DOT[row.status] ?? 'muted'} />
            {t(`jit.broker.status.${row.status}`)}
          </span>
          {row.revoked_reason !== null ? (
            <span className="font-body-sm text-body-sm text-error">
              {row.revoked_reason}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('jit.broker.columns.actions'),
      render: (row) =>
        row.status === 'active' ? (
          <Button
            variant="destructive"
            icon="block"
            ariaLabel={t('jit.broker.actionsUi.revokeNamed', { name: row.name })}
            disabled={busy}
            onClick={() => onRevoke(row)}
          >
            {t('jit.broker.actionsUi.revoke')}
          </Button>
        ) : (
          <Value value={null} />
        ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={policies}
      rowKey={(row) => String(row.id)}
      caption={t('jit.broker.policiesCaption')}
      emptyMessage={t('jit.broker.policiesEmpty')}
    />
  );
}

const CREDENTIAL_STATUS_DOT: Record<string, DotState> = {
  pending: 'live',
  approved: 'live',
  released: 'ok',
  denied: 'error',
  closed: 'muted',
  expired: 'muted',
};

/** Credential queue: request, window, state (secret never here), actions. */
function CredentialsTable({
  rows,
  busy,
  onApprove,
  onDeny,
  onClose,
}: {
  rows: BrokerCredential[];
  busy: boolean;
  onApprove: (row: BrokerCredential) => void;
  onDeny: (row: BrokerCredential) => void;
  onClose: (row: BrokerCredential) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<BrokerCredential>[] = [
    {
      key: 'credential',
      header: t('jit.broker.columns.credential'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-md text-code-md text-primary font-bold">
            {t('jit.broker.credPrefix', { id: row.id })}
          </span>
          <span className="font-body-sm text-body-sm text-outline">
            {t('jit.broker.pipelineId', { policyId: row.policy_id, itemId: row.item_id })}
          </span>
        </div>
      ),
    },
    {
      key: 'reason',
      header: t('jit.broker.columns.reason'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-body-sm text-body-sm text-on-surface">{row.ticket}</span>
          <span className="font-body-sm text-body-sm text-on-surface-variant line-clamp-2">
            {row.reason}
          </span>
          {row.build_ref ? (
            <span className="font-code-sm text-code-sm text-outline line-clamp-1">
              {row.build_ref}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'window',
      header: t('jit.broker.columns.window'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-body-sm text-body-sm">
            {t('jit.queue.windowMinutes', { minutes: row.minutes })}
          </span>
          {row.minutes_left !== null && row.minutes_left !== undefined ? (
            <span className="font-body-sm text-body-sm text-outline">
              {t('jit.queue.windowLeft', { minutes: row.minutes_left })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'state',
      header: t('jit.broker.columns.state'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={CREDENTIAL_STATUS_DOT[row.status] ?? 'muted'} />
            {t(`jit.broker.credStatus.${row.status}`)}
          </span>
          {row.secret_released ? (
            <span className="font-body-sm text-body-sm text-tertiary">
              {t('jit.broker.secretReleased')}
            </span>
          ) : null}
          {row.denied_reason !== null ? (
            <span className="font-body-sm text-body-sm text-error">
              {row.denied_reason}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('jit.broker.columns.actions'),
      render: (row) => (
        <div className="flex flex-wrap items-center gap-space-xs">
          {row.status === 'pending' ? (
            <>
              <Button
                icon="how_to_reg"
                ariaLabel={t('jit.broker.actionsUi.approveNamed', { id: row.id })}
                disabled={busy}
                onClick={() => onApprove(row)}
              >
                {t('jit.broker.actionsUi.approve')}
              </Button>
              <Button
                variant="destructive"
                icon="block"
                ariaLabel={t('jit.broker.actionsUi.denyNamed', { id: row.id })}
                disabled={busy}
                onClick={() => onDeny(row)}
              >
                {t('jit.broker.actionsUi.deny')}
              </Button>
            </>
          ) : row.status === 'approved' || row.status === 'released' ? (
            <Button
              variant="destructive"
              icon="stop_circle"
              ariaLabel={t('jit.broker.actionsUi.closeNamed', { id: row.id })}
              disabled={busy}
              onClick={() => onClose(row)}
            >
              {t('jit.broker.actionsUi.close')}
            </Button>
          ) : (
            <Value value={null} />
          )}
        </div>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(row) => String(row.id)}
      caption={t('jit.broker.credentialsCaption')}
      emptyMessage={t('jit.broker.credentialsEmpty')}
    />
  );
}

/** Register pipeline form + the once-shown API token panel. */
function RegisterPolicyBody({
  actor,
  register,
}: {
  actor: string;
  register: ReturnType<typeof useRegisterPolicy>;
}) {
  const { t } = useTranslation();
  const form = useForm<PolicyForm, unknown, PolicyValues>({
    resolver: zodResolver(policySchema),
    mode: 'onSubmit',
    defaultValues: {
      name: '',
      ci_system: 'other',
      contact: '',
      approval_mode: 'manual',
      max_ttl_minutes: 30,
      allowed_targets: '',
    },
  });

  if (register.data !== undefined) {
    return (
      <div className="flex flex-col gap-space-md">
        <p className="font-headline-sm text-headline-sm text-on-surface font-semibold">
          {t('jit.broker.tokenOnce')}
        </p>
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('jit.broker.tokenOnceHint')}
        </p>
        <p
          className="rounded-lg bg-surface-container-high p-space-md font-code-sm text-code-sm break-all select-all"
          data-testid="broker-token"
        >
          {register.data.token}
        </p>
        <p className="font-body-sm text-body-sm text-tertiary">{register.data.message}</p>
      </div>
    );
  }

  return (
    <form
      className="flex flex-col gap-space-md"
      onSubmit={form.handleSubmit((values) => {
        register.mutate({
          name: values.name,
          ci_system: values.ci_system,
          contact: values.contact,
          approval_mode: values.approval_mode,
          max_ttl_minutes: values.max_ttl_minutes,
          allowed_targets: splitCommaList(values.allowed_targets),
          actor,
        });
      })}
      noValidate
    >
      {register.isError ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(register.error)
              ? t('errors.backendDown')
              : register.error.message,
          })}
        </p>
      ) : null}

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.broker.form.name')}
        </span>
        <input
          type="text"
          maxLength={128}
          {...form.register('name')}
          className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>

      <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.broker.form.ciSystem')}
          </span>
          <select
            {...form.register('ci_system')}
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          >
            {[
              'jenkins',
              'gitlab',
              'github',
              'azure_devops',
              'terraform',
              'ansible',
              'argocd',
              'docker',
              'other',
            ].map((system) => (
              <option key={system} value={system}>
                {system}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.broker.form.approvalMode')}
          </span>
          <select
            {...form.register('approval_mode')}
            className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          >
            <option value="manual">{t('jit.broker.manualApproval')}</option>
            <option value="auto">{t('jit.broker.autoApproval')}</option>
          </select>
        </label>
      </div>

      <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.broker.form.ttl')}
          </span>
          <input
            type="number"
            min={1}
            max={480}
            {...form.register('max_ttl_minutes')}
            className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-md text-code-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.broker.form.contact')}
          </span>
          <input
            type="text"
            maxLength={160}
            {...form.register('contact')}
            className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </label>
      </div>

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.broker.form.targets')}
        </span>
        <input
          type="text"
          maxLength={1024}
          placeholder={t('jit.broker.form.targetsPlaceholder')}
          {...form.register('allowed_targets')}
          className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-sm text-code-sm border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>

      {Object.keys(form.formState.errors).length > 0 ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.broker.form.invalid')}
        </p>
      ) : null}

      <div className="flex justify-end gap-space-sm">
        <Button type="submit" icon="app_registration" disabled={register.isPending}>
          {t('jit.broker.registerConfirm')}
        </Button>
      </div>
    </form>
  );
}

/**
 * A small RHF+Zod reason dialog shared by deny and revoke (ADR-0006):
 * the optional `reason` is recorded on the server's trail verbatim.
 */
export function ReasonModal({
  open,
  onOpenChange,
  title,
  confirmLabel,
  busy,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  confirmLabel: string;
  busy: boolean;
  onSubmit: (reason: string) => void;
}) {
  const { t } = useTranslation();
  const form = useForm<ReasonValues>({
    resolver: zodResolver(reasonSchema),
    mode: 'onSubmit',
    defaultValues: { reason: '' },
  });
  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) form.reset({ reason: '' });
        onOpenChange(next);
      }}
      title={title}
      closeLabel={t('common.close')}
    >
      <form
        className="flex flex-col gap-space-md"
        onSubmit={form.handleSubmit((values) => {
          onSubmit(values.reason.trim());
          form.reset({ reason: '' });
        })}
        noValidate
      >
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.reason.label')}
          </span>
          <input
            type="text"
            maxLength={255}
            {...form.register('reason')}
            className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </label>
        <div className="flex justify-end gap-space-sm">
          <Button type="submit" variant="destructive" disabled={busy}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
