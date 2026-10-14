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
  AgentIdentity,
  AgentStats,
  AgentTaskScope,
  JitRequest,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import { ReasonModal } from './BrokerSection';
import {
  useAgentAccessRequests,
  useAgentAccessStats,
  useAgentAction,
  useAgentDetail,
  useAgents,
  useCloseAgentAccess,
  useDeclareTask,
  useRegisterAgent,
} from './queries';
import {
  agentSchema,
  splitLineList,
  splitCommaList,
  taskSchema,
  type AgentForm,
  type AgentValues,
  type TaskForm,
  type TaskValues,
} from './schemas';
import { SectionBody } from './SectionBody';

/**
 * AI-Agent Access (plan §4 line 107): an agent never holds a standing
 * credential - its API token (shown once, stored as a sha256 hash) files
 * access requests against declared task allow-lists, and this console
 * watches identities, declares tasks, disables/revokes identities and
 * ends grants. `open` is deliberately absent: the contract authenticates
 * it with the agent's own token, so the console never fakes an action it
 * cannot perform (same rule as the broker's `release`).
 *
 * Pending access rows ARE JIT requests, so "Review" opens the shared
 * detail modal owned by JitPage - one truth for quorum and events.
 */
export function AgentSection({
  actor,
  onReviewRequest,
}: {
  actor: string;
  onReviewRequest: (requestId: number) => void;
}) {
  const { t } = useTranslation();
  const stats = useAgentAccessStats();
  const agents = useAgents();
  const requests = useAgentAccessRequests();
  const register = useRegisterAgent();
  const agentAction = useAgentAction();
  const closeAgentAccess = useCloseAgentAccess();

  const [registering, setRegistering] = useState(false);
  const [manageId, setManageId] = useState<number | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<AgentIdentity | null>(null);

  function closeRegister(open: boolean) {
    if (!open) {
      register.reset(); // the once-shown token must not outlive the modal
      setRegistering(false);
    }
  }

  return (
    <section className="flex flex-col gap-space-sm">
      <SectionHeader title={t('jit.agents.heading')} subtitle={t('jit.agents.subtitle')} />

      <SectionBody query={stats}>{(data) => <AgentKpis stats={data} />}</SectionBody>

      {/* Mutation feedback: the server's own message, verbatim. */}
      {agentAction.isSuccess ? (
        <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
          {t('jit.states.actionDone', { message: agentAction.data.message })}
        </p>
      ) : null}
      {agentAction.isError ? (
        <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(agentAction.error)
              ? t('errors.backendDown')
              : agentAction.error.message,
          })}
        </p>
      ) : null}
      {closeAgentAccess.isSuccess ? (
        <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
          {t('jit.states.actionDone', { message: closeAgentAccess.data.message })}
        </p>
      ) : null}
      {closeAgentAccess.isError ? (
        <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(closeAgentAccess.error)
              ? t('errors.backendDown')
              : closeAgentAccess.error.message,
          })}
        </p>
      ) : null}

      {/* Agent identities. */}
      <div className="mt-space-md">
        <div className="flex items-center justify-between gap-space-md">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.agents.identitiesHeading')}
          </span>
          <Button icon="add" onClick={() => setRegistering(true)}>
            {t('jit.agents.register')}
          </Button>
        </div>
        <div className="mt-space-sm overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={agents}>
            {(data) => (
              <AgentsTable
                agents={data.agents}
                busy={agentAction.isPending}
                onManage={(agent) => setManageId(agent.id)}
                onToggle={(agent) =>
                  agentAction.mutate({
                    kind: agent.status === 'active' ? 'disable' : 'enable',
                    agentId: agent.id,
                    actor,
                  })
                }
                onRevoke={(agent) => setRevokeTarget(agent)}
              />
            )}
          </SectionBody>
        </div>
      </div>

      {/* The access request queue (rows shared with the JIT queue). */}
      <div className="mt-space-md">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.agents.requestsHeading')}
        </span>
        <div className="mt-space-sm overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={requests}>
            {(data) => (
              <AccessRequestsTable
                rows={data.items}
                busy={closeAgentAccess.isPending}
                onReview={(row) => onReviewRequest(row.id)}
                onClose={(row) => closeAgentAccess.mutate({ requestId: row.id, actor })}
              />
            )}
          </SectionBody>
        </div>
      </div>

      {/* Register an agent identity: its API token is shown once. */}
      <Modal
        open={registering}
        onOpenChange={closeRegister}
        title={t('jit.agents.registerTitle')}
        closeLabel={t('common.close')}
      >
        <RegisterAgentBody actor={actor} register={register} />
      </Modal>

      {/* Agent facts, declared tasks and the section-16 trail. */}
      <Modal
        open={manageId !== null}
        onOpenChange={(open) => {
          if (!open) setManageId(null);
        }}
        title={t('jit.agents.detailTitle', { id: manageId ?? 0 })}
        closeLabel={t('common.close')}
      >
        <AgentDetailBody agentId={manageId} actor={actor} />
      </Modal>

      {/* Revoke an identity: reason recorded, open grants end first. */}
      <ReasonModal
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        title={t('jit.agents.revokeTitle', { name: revokeTarget?.name ?? '' })}
        confirmLabel={t('jit.agents.revokeConfirm')}
        busy={agentAction.isPending}
        onSubmit={(reason) => {
          if (revokeTarget !== null) {
            agentAction.mutate({ kind: 'revoke', agentId: revokeTarget.id, actor, reason });
          }
        }}
      />
    </section>
  );
}

/** Agent posture KPIs: identities, live queue, open grants, trail. */
function AgentKpis({ stats }: { stats: AgentStats }) {
  const { t } = useTranslation();
  const identities = stats.identities;
  return (
    <div className="mt-space-md grid grid-cols-1 gap-space-lg sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('jit.agents.kpis.identities')}
        value={identities.total}
        accent="primary"
        footer={t('jit.agents.kpis.identitiesFooter', {
          active: identities.by_status.active ?? 0,
          revoked: identities.by_status.revoked ?? 0,
        })}
      />
      <KpiCard
        label={t('jit.agents.kpis.open')}
        value={stats.requests.open}
        accent={stats.requests.open > 0 ? 'primary-container' : 'primary'}
        footer={t('jit.agents.kpis.openFooter', { tasks: stats.tasks })}
      />
      <KpiCard
        label={t('jit.agents.kpis.pending')}
        value={stats.requests.by_status.pending ?? 0}
        accent={(stats.requests.by_status.pending ?? 0) > 0 ? 'tertiary' : 'primary'}
        footer={t('jit.agents.kpis.pendingFooter', { total: stats.requests.total })}
      />
      <KpiCard
        label={t('jit.agents.kpis.events')}
        value={stats.events}
        accent="primary-container"
        footer={t('jit.agents.kpis.eventsFooter')}
      />
    </div>
  );
}

const AGENT_STATUS_DOT: Record<string, DotState> = {
  active: 'ok',
  disabled: 'muted',
  revoked: 'error',
};

/** Identity table: window cap, last use, state and lifecycle actions. */
function AgentsTable({
  agents,
  busy,
  onManage,
  onToggle,
  onRevoke,
}: {
  agents: AgentIdentity[];
  busy: boolean;
  onManage: (agent: AgentIdentity) => void;
  onToggle: (agent: AgentIdentity) => void;
  onRevoke: (agent: AgentIdentity) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<AgentIdentity>[] = [
    {
      key: 'identity',
      header: t('jit.agents.columns.identity'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-md text-code-md text-on-surface font-semibold">
            {row.name}
          </span>
          <Value value={row.contact} />
          <span className="font-body-sm text-body-sm text-outline line-clamp-2">
            {row.description ?? ''}
          </span>
        </div>
      ),
    },
    {
      key: 'window',
      header: t('jit.agents.columns.window'),
      render: (row) => (
        <span className="font-code-sm text-code-sm">
          {t('jit.broker.ttlCap', { minutes: row.max_ttl_minutes })}
        </span>
      ),
    },
    {
      key: 'lastUsed',
      header: t('jit.agents.columns.lastUsed'),
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
      header: t('jit.agents.columns.state'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={AGENT_STATUS_DOT[row.status] ?? 'muted'} />
            {t(`jit.agents.status.${row.status}`)}
          </span>
          <span className="font-code-sm text-code-sm text-outline">{row.token_hash}</span>
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('jit.agents.columns.actions'),
      render: (row) => (
        <div className="flex flex-wrap items-center gap-space-xs">
          <Button
            icon="playlist_add"
            ariaLabel={t('jit.agents.actionsUi.manageNamed', { name: row.name })}
            onClick={() => onManage(row)}
          >
            {t('jit.agents.actionsUi.manage')}
          </Button>
          {row.status === 'revoked' ? null : (
            <Button
              variant="secondary"
              icon={row.status === 'active' ? 'person_off' : 'person_check'}
              ariaLabel={t('jit.agents.actionsUi.toggleNamed', {
                action:
                  row.status === 'active'
                    ? t('jit.agents.actionsUi.disable')
                    : t('jit.agents.actionsUi.enable'),
                name: row.name,
              })}
              disabled={busy}
              onClick={() => onToggle(row)}
            >
              {row.status === 'active'
                ? t('jit.agents.actionsUi.disable')
                : t('jit.agents.actionsUi.enable')}
            </Button>
          )}
          {row.status === 'revoked' ? null : (
            <Button
              variant="destructive"
              icon="block"
              ariaLabel={t('jit.agents.actionsUi.revokeNamed', { name: row.name })}
              disabled={busy}
              onClick={() => onRevoke(row)}
            >
              {t('jit.agents.actionsUi.revoke')}
            </Button>
          )}
        </div>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={agents}
      rowKey={(row) => String(row.id)}
      caption={t('jit.agents.identitiesCaption')}
      emptyMessage={t('jit.agents.identitiesEmpty')}
    />
  );
}

const ACCESS_STATUS_DOT: Record<string, DotState> = {
  pending: 'live',
  approved: 'live',
  active: 'ok',
  closed: 'muted',
  expired: 'muted',
  denied: 'error',
  blocked: 'error',
};

/** Access request queue: agent/task binding, risk, state, actions. */
function AccessRequestsTable({
  rows,
  busy,
  onReview,
  onClose,
}: {
  rows: JitRequest[];
  busy: boolean;
  onReview: (row: JitRequest) => void;
  onClose: (row: JitRequest) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<JitRequest>[] = [
    {
      key: 'request',
      header: t('jit.agents.columns.request'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-md text-code-md text-primary font-bold">
            {t('jit.queue.idPrefix', { id: row.id })}
          </span>
          <span className="font-body-sm text-body-sm text-outline">
            <Value value={formatTime(row.created_at)} />
          </span>
        </div>
      ),
    },
    {
      key: 'agent',
      header: t('jit.agents.columns.agentTask'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm text-on-surface">
            {row.agent_binding?.agent_name ?? row.requester}
          </span>
          <span className="font-body-sm text-body-sm text-tertiary">
            {row.agent_binding?.task ?? t('jit.agents.noTask')}
          </span>
        </div>
      ),
    },
    {
      key: 'reason',
      header: t('jit.agents.columns.reason'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm text-primary font-semibold">
            {row.ticket}
          </span>
          <span className="font-body-sm text-body-sm text-on-surface-variant line-clamp-2">
            {row.reason}
          </span>
        </div>
      ),
    },
    {
      key: 'risk',
      header: t('jit.queue.columns.risk'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span
            className={`font-code-md text-code-md font-bold ${
              row.risk.level === 'high' || row.risk.level === 'critical'
                ? 'text-error'
                : 'text-on-surface'
            }`}
          >
            {t('jit.queue.riskScore', { score: row.risk.score })}
          </span>
          <Chip>{t(`jit.risk.${row.risk.level}`)}</Chip>
        </div>
      ),
    },
    {
      key: 'state',
      header: t('jit.agents.columns.state'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={ACCESS_STATUS_DOT[row.status] ?? 'muted'} />
            {t(`jit.status.${row.status}`)}
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
      key: 'actions',
      header: t('jit.agents.columns.actions'),
      render: (row) => (
        <div className="flex flex-wrap items-center gap-space-xs">
          {row.status === 'pending' || row.status === 'blocked' ? (
            <Button
              icon="rule"
              ariaLabel={t('jit.queue.actionsUi.named', {
                action: t('jit.queue.actionsUi.review'),
                id: row.id,
              })}
              onClick={() => onReview(row)}
            >
              {t('jit.queue.actionsUi.review')}
            </Button>
          ) : null}
          {row.status === 'active' ? (
            <Button
              variant="destructive"
              icon="stop_circle"
              ariaLabel={t('jit.queue.actionsUi.named', {
                action: t('jit.queue.actionsUi.close'),
                id: row.id,
              })}
              disabled={busy}
              onClick={() => onClose(row)}
            >
              {t('jit.queue.actionsUi.close')}
            </Button>
          ) : null}
          <Button
            variant="secondary"
            icon="visibility"
            ariaLabel={t('jit.queue.actionsUi.named', {
              action: t('jit.queue.actionsUi.detail'),
              id: row.id,
            })}
            onClick={() => onReview(row)}
          >
            {t('jit.queue.actionsUi.detail')}
          </Button>
        </div>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(row) => String(row.id)}
      caption={t('jit.agents.requestsCaption')}
      emptyMessage={t('jit.agents.requestsEmpty')}
    />
  );
}

/** Register-agent form + the once-shown API token panel. */
function RegisterAgentBody({
  actor,
  register,
}: {
  actor: string;
  register: ReturnType<typeof useRegisterAgent>;
}) {
  const { t } = useTranslation();
  const form = useForm<AgentForm, unknown, AgentValues>({
    resolver: zodResolver(agentSchema),
    mode: 'onSubmit',
    defaultValues: { name: '', contact: '', max_ttl_minutes: 15 },
  });

  if (register.data !== undefined) {
    return (
      <div className="flex flex-col gap-space-md">
        <p className="font-headline-sm text-headline-sm text-on-surface font-semibold">
          {t('jit.agents.tokenOnce')}
        </p>
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('jit.agents.tokenOnceHint')}
        </p>
        <p
          className="rounded-lg bg-surface-container-high p-space-md font-code-sm text-code-sm break-all select-all"
          data-testid="agent-token"
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
        register.mutate({ ...values, actor });
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
          {t('jit.agents.form.name')}
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
            {t('jit.agents.form.contact')}
          </span>
          <input
            type="text"
            maxLength={160}
            {...form.register('contact')}
            className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.agents.form.ttl')}
          </span>
          <input
            type="number"
            min={1}
            max={480}
            {...form.register('max_ttl_minutes')}
            className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-md text-code-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </label>
      </div>

      {Object.keys(form.formState.errors).length > 0 ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.agents.form.invalid')}
        </p>
      ) : null}

      <div className="flex justify-end gap-space-sm">
        <Button type="submit" icon="app_registration" disabled={register.isPending}>
          {t('jit.agents.registerConfirm')}
        </Button>
      </div>
    </form>
  );
}

/** Agent detail body: facts, declared tasks, declare form, trail. */
function AgentDetailBody({ agentId, actor }: { agentId: number | null; actor: string }) {
  const { t } = useTranslation();
  const detail = useAgentDetail(agentId);
  const declareTask = useDeclareTask();
  const form = useForm<TaskForm, unknown, TaskValues>({
    resolver: zodResolver(taskSchema),
    mode: 'onSubmit',
    defaultValues: {
      name: '',
      allowed_commands: '',
      allowed_targets: '',
      max_minutes: 5,
    },
  });

  if (agentId === null) return null;
  if (detail.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-outline">{t('jit.states.loading')}</p>
    );
  }
  if (detail.error !== null && detail.error !== undefined) {
    const message = isBackendDown(detail.error)
      ? t('errors.backendDown')
      : detail.error.message;
    return (
      <p role="alert" className="font-body-sm text-body-sm text-error">
        {t('jit.states.sectionError', { message })}
      </p>
    );
  }
  const data = detail.data;
  if (data === undefined) return null;
  const { agent, tasks, open_grants, events } = data;

  return (
    <div className="flex flex-col gap-space-md">
      {/* Identity facts (the token itself never exists server-side). */}
      <div className="rounded-lg bg-surface-container-low p-space-md font-body-sm text-body-sm text-on-surface">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={AGENT_STATUS_DOT[agent.status] ?? 'muted'} />
            {t(`jit.agents.status.${agent.status}`)}
          </span>
          <span className="font-code-sm text-code-sm text-outline">{agent.token_hash}</span>
        </div>
        <dl className="mt-space-sm grid grid-cols-1 gap-space-sm sm:grid-cols-2">
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.detail.contact')}
            </dt>
            <dd>
              <Value value={agent.contact} />
            </dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.detail.window')}
            </dt>
            <dd className="font-code-sm text-code-sm">
              {t('jit.broker.ttlCap', { minutes: agent.max_ttl_minutes })}
            </dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.detail.createdBy')}
            </dt>
            <dd className="font-code-sm text-code-sm">{agent.created_by}</dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.detail.lastUsed')}
            </dt>
            <dd>
              <Value
                value={agent.last_used_at === null ? null : formatTime(agent.last_used_at)}
              />
            </dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.detail.openGrants')}
            </dt>
            <dd className="font-code-sm text-code-sm">
              {t('jit.agents.detail.openGrantsValue', { count: open_grants })}
            </dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.reason')}
            </dt>
            <dd>{agent.description ?? '—'}</dd>
          </div>
        </dl>
      </div>

      {/* Declared task allow-lists (commands are literal, default-deny). */}
      <div>
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.agents.detail.tasks')}
        </span>
        <ul className="mt-1 flex flex-col gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
          {tasks.length === 0 ? (
            <li>{t('jit.agents.detail.tasksEmpty')}</li>
          ) : (
            tasks.map((task) => <TaskItem key={task.id} task={task} />)
          )}
        </ul>
      </div>

      {/* Declare a new task allow-list (contract: minItems 1, maxItems 32). */}
      {agent.status === 'revoked' ? null : (
        <form
          className="flex flex-col gap-space-md rounded-lg bg-surface-container-low p-space-md"
          onSubmit={form.handleSubmit((values) => {
            declareTask.mutate({
              agentId: agent.id,
              actor,
              payload: {
                name: values.name,
                allowed_commands: splitLineList(values.allowed_commands),
                allowed_targets: splitCommaList(values.allowed_targets),
                max_minutes: values.max_minutes,
              },
            });
            form.reset({
              name: '',
              allowed_commands: '',
              allowed_targets: '',
              max_minutes: 5,
            });
          })}
          noValidate
        >
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.agents.taskForm.heading')}
          </span>
          {declareTask.isSuccess ? (
            <p role="status" className="font-body-sm text-body-sm text-tertiary">
              {t('jit.states.actionDone', { message: declareTask.data.message })}
            </p>
          ) : null}
          {declareTask.isError ? (
            <p role="alert" className="font-body-sm text-body-sm text-error">
              {t('jit.states.actionFailed', {
                message: isBackendDown(declareTask.error)
                  ? t('errors.backendDown')
                  : declareTask.error.message,
              })}
            </p>
          ) : null}

          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.taskForm.name')}
            </span>
            <input
              type="text"
              maxLength={128}
              {...form.register('name')}
              className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.taskForm.commands')}
            </span>
            <textarea
              rows={3}
              maxLength={8192}
              placeholder={t('jit.agents.taskForm.commandsPlaceholder')}
              {...form.register('allowed_commands')}
              className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-sm text-code-sm border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.taskForm.targets')}
            </span>
            <input
              type="text"
              maxLength={1024}
              placeholder={t('jit.agents.taskForm.targetsPlaceholder')}
              {...form.register('allowed_targets')}
              className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-sm text-code-sm border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.agents.taskForm.maxMinutes')}
            </span>
            <input
              type="number"
              min={1}
              max={480}
              {...form.register('max_minutes')}
              className="w-32 px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-md text-code-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
            />
          </label>

          {Object.keys(form.formState.errors).length > 0 ? (
            <p role="alert" className="font-body-sm text-body-sm text-error">
              {t('jit.agents.taskForm.invalid')}
            </p>
          ) : null}

          <div className="flex justify-end">
            <Button type="submit" icon="add_task" disabled={declareTask.isPending}>
              {t('jit.agents.taskForm.submit')}
            </Button>
          </div>
        </form>
      )}

      {/* The agent trail (contract: the token never enters `detail`). */}
      <div>
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.agents.detail.events')}
        </span>
        <ul className="mt-1 flex flex-col gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
          {events.length === 0 ? (
            <li>{t('jit.agents.detail.eventsEmpty')}</li>
          ) : (
            events.map((event) => (
              <li
                key={event.id}
                className="flex flex-col gap-0.5 border-b border-outline-variant/20 pb-1"
              >
                <span className="flex items-center justify-between gap-2">
                  <Chip>{event.action}</Chip>
                  <span className="font-code-sm text-code-sm text-outline">
                    <Value value={formatTime(event.created_at)} />
                  </span>
                </span>
                <span>
                  {t('jit.detail.eventActor', { actor: event.actor })}
                  {' · '}
                  {agentEventText(event.detail)}
                </span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}

/** One declared task scope: name, literal command allow-list, targets. */
function TaskItem({ task }: { task: AgentTaskScope }) {
  const { t } = useTranslation();
  return (
    <li className="flex flex-col gap-0.5 border-b border-outline-variant/20 pb-1">
      <span className="flex items-center justify-between gap-2">
        <span className="font-code-sm text-code-sm text-on-surface font-semibold">
          {task.name}
        </span>
        <span className="font-code-sm text-code-sm text-outline">
          {t('jit.queue.windowMinutes', { minutes: task.max_minutes })}
        </span>
      </span>
      <span className="font-code-sm text-code-sm">{task.allowed_commands.join(' · ')}</span>
      <span className="font-body-sm text-body-sm text-outline">
        {task.allowed_targets.length === 0
          ? t('jit.broker.anyTargets')
          : task.allowed_targets.join(', ')}
      </span>
    </li>
  );
}

/**
 * Render a server event detail object as readable `key: value` pairs -
 * contract field names verbatim, arrays joined, token material never
 * present (the backend refuses it by construction).
 */
function agentEventText(detail: unknown): string {
  if (detail === null || typeof detail !== 'object') return '';
  const record = detail as Record<string, unknown>;
  const parts: string[] = [];
  for (const [key, value] of Object.entries(record)) {
    if (value === null || value === undefined) continue;
    if (Array.isArray(value)) {
      if (value.length > 0 && value.every((entry) => typeof entry === 'string')) {
        parts.push(`${key}: ${value.join(', ')}`);
      }
      continue;
    }
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      parts.push(`${key}: ${String(value)}`);
    }
  }
  return parts.join(' · ');
}
