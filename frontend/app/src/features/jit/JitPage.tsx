import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import type { UseFormReturn } from 'react-hook-form';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
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
  JitRequest,
  JitRequestDetail,
  JitStats,
  VaultItemList,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import {
  useCloseAgentAccess,
  useFileJitRequest,
  useJitAction,
  useJitQueue,
  useJitRequestDetail,
  useJitStats,
  useJitTargets,
  type JitActionKind,
  type JitQueueFilter,
  type JitStatus,
} from './queries';
import {
  fileRequestSchema,
  reasonSchema,
  type FileRequestForm,
  type FileRequestValues,
  type ReasonValues,
} from './schemas';
import { SectionBody } from './SectionBody';
import { BrokerSection } from './BrokerSection';
import { AgentSection } from './AgentSection';

/**
 * The detail modal can end a grant two ways: `close` (the plain JIT
 * endpoint) and `close-agent` - the same grant-end through the
 * contract's agent-access endpoint, which additionally writes the
 * section-16 agent trail event (the backend wraps `close_jit_request`).
 */
type PageActionKind = JitActionKind | 'close-agent';

/**
 * The F4 JIT Access screen (plan §4 line 107): the request queue with
 * approvals and ephemeral grants, then the pipeline broker and the
 * agent-access consoles below it - live data only, honest loading /
 * error / empty / not-connected / backend-down states (F4 per-screen
 * DoD). Design-system components and generated hooks only; every write
 * carries the signed-in principal as the contract's `X-Actor`.
 *
 * Quorum is the server's rule (low auto-approves, medium needs manager,
 * high needs manager + security, critical is blocked): the screen reads
 * `required_approvals` from the server's own `requested` event and never
 * re-derives it, so the UI cannot drift from the backend.
 */
export function JitPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const stats = useJitStats();
  const [filter, setFilter] = useState<JitQueueFilter>({ status: 'all', requester: '' });
  const queue = useJitQueue(filter);
  const fileRequest = useFileJitRequest();
  const action = useJitAction();

  const [detailId, setDetailId] = useState<number | null>(null);
  const [filing, setFiling] = useState(false);
  const closeAgentAccess = useCloseAgentAccess();

  const backendDownError = [stats.error, queue.error].find(
    (error) => error !== null && error !== undefined && isBackendDown(error),
  );

  /** Who acts: the real session principal (open mode reports `open`). */
  const actor = whoami?.principal ?? 'console';

  function runAction(kind: PageActionKind, requestId: number, reason?: string) {
    if (kind === 'close-agent') {
      closeAgentAccess.mutate({ requestId, actor });
      return;
    }
    action.mutate({ kind, requestId, actor, reason });
  }

  const busy = action.isPending || closeAgentAccess.isPending;
  const successMessage = action.isSuccess
    ? action.data.message
    : closeAgentAccess.isSuccess
      ? closeAgentAccess.data.message
      : null;
  const failedMutation = action.isError
    ? action.error
    : closeAgentAccess.isError
      ? closeAgentAccess.error
      : null;

  return (
    <div className="flex w-full flex-col gap-space-xl pt-space-xl">
      <section className="flex flex-col gap-space-sm">
        <Chip>{t('jit.kicker')}</Chip>
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          {t('jit.title')}
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          {t('jit.subtitle')}
        </p>
      </section>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {/* Queue posture KPIs: server-computed aggregates, absent = em-dash. */}
      <section>
        <SectionHeader title={t('jit.kpis.heading')} />
        <SectionBody query={stats}>{(data) => <JitStatsKpis stats={data} />}</SectionBody>
      </section>

      {/* The request queue: filters from the contract, actions per state. */}
      <section>
        <SectionHeader title={t('jit.queue.heading')} subtitle={t('jit.queue.subtitle')} />
        <QueueFilters filter={filter} onApply={setFilter} />
        {/* Mutation feedback: the server's own message, verbatim. */}
        {successMessage !== null ? (
          <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
            {t('jit.states.actionDone', { message: successMessage })}
          </p>
        ) : null}
        {failedMutation !== null ? (
          <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
            {t('jit.states.actionFailed', {
              message: isBackendDown(failedMutation)
                ? t('errors.backendDown')
                : failedMutation.message,
            })}
          </p>
        ) : null}
        <div className="mt-space-md overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={queue}>
            {(data) => (
              <QueueTable
                rows={data.items}
                busy={busy}
                onReview={(row) => setDetailId(row.id)}
                onDetail={(row) => setDetailId(row.id)}
                onGrant={(row) => runAction('grant', row.id)}
                onClose={(row) =>
                  runAction(row.agent_binding !== null ? 'close-agent' : 'close', row.id)
                }
              />
            )}
          </SectionBody>
        </div>
        <div className="mt-space-md">
          <Button icon="add" onClick={() => setFiling(true)}>
            {t('jit.queue.fileRequest')}
          </Button>
        </div>
      </section>

      {/* Request detail modal: risk, quorum (server truth), events, actions. */}
      <Modal
        open={detailId !== null}
        onOpenChange={(open) => {
          if (!open) setDetailId(null);
        }}
        title={t('jit.detail.title', { id: detailId ?? 0 })}
        closeLabel={t('common.close')}
      >
        <RequestDetailBody
          requestId={detailId}
          actor={actor}
          busy={busy}
          successMessage={successMessage}
          failedMutation={failedMutation}
          onAction={(kind, requestId, reason) => runAction(kind, requestId, reason)}
        />
      </Modal>

      {/* File-a-request modal: contract fields, risk computed server-side. */}
      <Modal
        open={filing}
        onOpenChange={(open) => {
          if (!open) {
            fileRequest.reset();
            setFiling(false);
          }
        }}
        title={t('jit.file.title')}
        closeLabel={t('common.close')}
      >
        <FileRequestBody actor={actor} fileRequest={fileRequest} />
      </Modal>

      {/* Pipeline Credential Broker (plan line 107: "pipeline broker"). */}
      <BrokerSection actor={actor} />

      {/* AI-Agent access (plan line 107: "agent access"). */}
      <AgentSection actor={actor} onReviewRequest={(id) => setDetailId(id)} />
    </div>
  );
}

/** Queue posture KPI quad: total, pending, active, high-risk on record. */
function JitStatsKpis({ stats }: { stats: JitStats }) {
  const { t } = useTranslation();
  const atRisk = (stats.by_risk.high ?? 0) + (stats.by_risk.critical ?? 0);
  return (
    <div className="mt-space-md grid grid-cols-1 gap-space-lg sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('jit.kpis.total')}
        value={stats.total}
        accent="primary"
        footer={t('jit.kpis.totalFooter', {
          closed: stats.by_status.closed ?? 0,
          denied: stats.by_status.denied ?? 0,
        })}
      />
      <KpiCard
        label={t('jit.kpis.pending')}
        value={stats.pending}
        accent={stats.pending > 0 ? 'tertiary' : 'primary'}
        footer={t('jit.kpis.pendingFooter', {
          blocked: stats.by_status.blocked ?? 0,
        })}
      />
      <KpiCard
        label={t('jit.kpis.active')}
        value={stats.active}
        accent={stats.active > 0 ? 'primary-container' : 'primary'}
        footer={t('jit.kpis.activeFooter')}
      />
      <KpiCard
        label={t('jit.kpis.atRisk')}
        value={atRisk}
        accent={atRisk > 0 ? 'error' : 'primary-container'}
        footer={t('jit.kpis.atRiskFooter', {
          high: stats.by_risk.high ?? 0,
          critical: stats.by_risk.critical ?? 0,
        })}
      />
    </div>
  );
}

/** Status filter (contract enum) + requester substring search. */
function QueueFilters({
  filter,
  onApply,
}: {
  filter: JitQueueFilter;
  onApply: (next: JitQueueFilter) => void;
}) {
  const { t } = useTranslation();
  const [search, setSearch] = useState(filter.requester);
  const statuses: Array<JitStatus | 'all'> = [
    'all',
    'pending',
    'approved',
    'active',
    'closed',
    'expired',
    'denied',
    'blocked',
  ];
  return (
    <form
      className="mt-space-md flex flex-wrap items-end gap-space-md"
      onSubmit={(event) => {
        event.preventDefault();
        onApply({ status: filter.status, requester: search });
      }}
    >
      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.queue.filters.status')}
        </span>
        <select
          value={filter.status}
          onChange={(event) =>
            onApply({
              status: event.target.value as JitStatus | 'all',
              requester: filter.requester,
            })
          }
          className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        >
          {statuses.map((status) => (
            <option key={status} value={status}>
              {status === 'all'
                ? t('jit.queue.filters.allStatuses')
                : t(`jit.status.${status}`)}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.queue.filters.requester')}
        </span>
        <input
          type="text"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder={t('jit.queue.filters.requesterPlaceholder')}
          className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>
      <Button type="submit" variant="secondary">
        {t('jit.queue.filters.apply')}
      </Button>
      <span className="font-code-sm text-code-sm text-outline">
        {t('jit.queue.filters.order')}
      </span>
    </form>
  );
}

/** Server status -> the as-built dot state (the label always renders too). */
const STATUS_DOT: Record<JitStatus, DotState> = {
  pending: 'live',
  approved: 'live',
  active: 'ok',
  closed: 'muted',
  expired: 'muted',
  denied: 'error',
  blocked: 'error',
};

/** The queue table: request, risk, window, quorum facts and actions. */
function QueueTable({
  rows,
  busy,
  onReview,
  onDetail,
  onGrant,
  onClose,
}: {
  rows: JitRequest[];
  busy: boolean;
  onReview: (row: JitRequest) => void;
  onDetail: (row: JitRequest) => void;
  onGrant: (row: JitRequest) => void;
  onClose: (row: JitRequest) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<JitRequest>[] = [
    {
      key: 'request',
      header: t('jit.queue.columns.request'),
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
      key: 'requester',
      header: t('jit.queue.columns.requester'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-body-md text-body-md text-on-surface">{row.requester}</span>
          {row.agent_binding ? (
            <span className="font-code-sm text-code-sm text-tertiary">
              {t('jit.queue.agentBinding', {
                agent: row.agent_binding.agent_name,
                task: row.agent_binding.task,
              })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'ticket',
      header: t('jit.queue.columns.ticket'),
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
      key: 'window',
      header: t('jit.queue.columns.window'),
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
      key: 'status',
      header: t('jit.queue.columns.status'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={STATUS_DOT[row.status]} />
            {t(`jit.status.${row.status}`)}
          </span>
          <span className="font-body-sm text-body-sm text-outline">
            {t('jit.queue.quorumRecorded', {
              manager: row.approvals.manager?.actor ?? '—',
              security: row.approvals.security?.actor ?? '—',
            })}
          </span>
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('jit.queue.columns.actions'),
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
          {row.status === 'approved' && row.agent_binding === null ? (
            <Button
              icon="lock_open"
              ariaLabel={t('jit.queue.actionsUi.named', {
                action: t('jit.queue.actionsUi.grant'),
                id: row.id,
              })}
              disabled={busy}
              onClick={() => onGrant(row)}
            >
              {t('jit.queue.actionsUi.grant')}
            </Button>
          ) : null}
          {row.status === 'active' ? (
            <Button
              icon="stop_circle"
              variant="destructive"
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
          {row.status === 'pending' || row.status === 'blocked' ? null : (
            <Button
              variant="secondary"
              icon="visibility"
              ariaLabel={t('jit.queue.actionsUi.named', {
                action: t('jit.queue.actionsUi.detail'),
                id: row.id,
              })}
              onClick={() => onDetail(row)}
            >
              {t('jit.queue.actionsUi.detail')}
            </Button>
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
      caption={t('jit.queue.caption')}
      emptyMessage={t('jit.queue.empty')}
    />
  );
}

/**
 * Required approvals come from the server's `requested` event payload -
 * the same value the backend enforced when it filed the request. The
 * frontend never re-derives quorum from the risk band.
 */
function requiredApprovalsFromEvents(detail: JitRequestDetail | undefined): string[] {
  const requested = detail?.events.find((event) => event.action === 'requested');
  const value = (requested?.detail as { required_approvals?: unknown } | undefined)
    ?.required_approvals;
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : [];
}

/** Detail modal body: facts, risk factors, quorum, events and actions. */
function RequestDetailBody({
  requestId,
  actor,
  busy,
  successMessage,
  failedMutation,
  onAction,
}: {
  requestId: number | null;
  actor: string;
  busy: boolean;
  successMessage: string | null;
  failedMutation: Error | null;
  onAction: (kind: PageActionKind, requestId: number, reason?: string) => void;
}) {
  const { t } = useTranslation();
  const detail = useJitRequestDetail(requestId);
  const denyForm = useForm<ReasonValues>({
    resolver: zodResolver(reasonSchema),
    mode: 'onSubmit',
    defaultValues: { reason: '' },
  });

  if (requestId === null) return null;
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
  const { request, events } = data;
  const required = requiredApprovalsFromEvents(data);
  const recorded: Record<string, ApprovalSlot> = {
    manager: request.approvals.manager,
    security: request.approvals.security,
  };
  const openRoles = required.filter((role) => approvalActor(recorded[role]) === null);
  const selfApproval = actor === request.requester;

  return (
    <div className="flex flex-col gap-space-md">
      {/* Mutation feedback inside the modal: the server's own message. */}
      {successMessage !== null ? (
        <p role="status" className="font-body-sm text-body-sm text-tertiary">
          {t('jit.states.actionDone', { message: successMessage })}
        </p>
      ) : null}
      {failedMutation !== null ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(failedMutation)
              ? t('errors.backendDown')
              : failedMutation.message,
          })}
        </p>
      ) : null}

      {/* Identity & window facts. */}
      <div className="rounded-lg bg-surface-container-low p-space-md font-body-sm text-body-sm text-on-surface">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={STATUS_DOT[request.status]} />
            {t(`jit.status.${request.status}`)}
          </span>
          <span className="font-code-sm text-code-sm text-outline">
            {t('jit.queue.idPrefix', { id: request.id })}
          </span>
        </div>
        <dl className="mt-space-sm grid grid-cols-1 gap-space-sm sm:grid-cols-2">
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.requester')}
            </dt>
            <dd className="font-code-sm text-code-sm">{request.requester}</dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.queue.columns.ticket')}
            </dt>
            <dd className="font-code-sm text-code-sm">{request.ticket}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.reason')}
            </dt>
            <dd className="font-body-sm text-body-sm">{request.reason}</dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.target')}
            </dt>
            <dd className="font-code-sm text-code-sm">
              {t('jit.detail.itemId', { id: request.item_id })}
            </dd>
          </div>
          <div>
            <dt className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.window')}
            </dt>
            <dd className="font-code-sm text-code-sm">
              {request.minutes_left !== null && request.minutes_left !== undefined
                ? t('jit.queue.windowLeft', { minutes: request.minutes_left })
                : t('jit.queue.windowMinutes', { minutes: request.minutes })}
            </dd>
          </div>
          {request.session_ref ? (
            <div>
              <dt className="font-label-md text-label-md text-on-surface-variant">
                {t('jit.detail.sessionRef')}
              </dt>
              <dd className="font-code-sm text-code-sm">{request.session_ref}</dd>
            </div>
          ) : null}
          {request.expires_at ? (
            <div>
              <dt className="font-label-md text-label-md text-on-surface-variant">
                {t('jit.detail.expiresAt')}
              </dt>
              <dd className="font-code-sm text-code-sm">
                <Value value={formatTime(request.expires_at)} />
              </dd>
            </div>
          ) : null}
        </dl>
      </div>

      {/* Risk evaluation: score, band and every real factor. */}
      <div className="rounded-lg bg-surface-container-low p-space-md">
        <div className="flex items-center justify-between">
          <span className="font-label-md text-label-md text-on-surface-variant">
            {t('jit.detail.risk')}
          </span>
          <span className="font-code-md text-code-md font-bold text-on-surface">
            {t('jit.queue.riskScore', { score: request.risk.score })} ·{' '}
            {t(`jit.risk.${request.risk.level}`)}
          </span>
        </div>
        <ul className="mt-space-sm flex flex-col gap-1 font-body-sm text-body-sm text-on-surface-variant">
          {request.risk.factors.map((factor) => (
            <li key={factor.factor} className="flex items-center justify-between gap-2">
              <span>{factor.detail}</span>
              <span className="font-code-sm text-code-sm text-outline">
                {t('jit.detail.factorPoints', { points: factor.points })}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {/* Quorum: server-truth required roles vs the recorded approvals. */}
      <div className="rounded-lg bg-surface-container-low p-space-md">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.detail.quorum')}
        </span>
        <p className="mt-1 font-body-sm text-body-sm text-on-surface">
          {t('jit.detail.quorumState', {
            required: required.length,
            recorded: required.filter((role) => approvalActor(recorded[role]) !== null)
              .length,
          })}
        </p>
        <ul className="mt-1 flex flex-col gap-1 font-code-sm text-code-sm text-on-surface-variant">
          {required.length === 0 ? (
            <li>{t('jit.detail.quorumNone')}</li>
          ) : (
            required.map((role) => (
              <li key={role}>
                {t(`jit.detail.role.${role}`)}:{' '}
                {approvalActor(recorded[role]) ?? t('jit.detail.roleAwaiting')}
              </li>
            ))
          )}
        </ul>
        {request.status === 'blocked' ? (
          <p role="status" className="mt-2 font-body-sm text-body-sm text-error">
            {t('jit.detail.blockedNotice')}
          </p>
        ) : null}
        {selfApproval && request.status === 'pending' ? (
          <p className="mt-2 font-body-sm text-body-sm text-on-surface-variant">
            {t('jit.detail.selfApproval')}
          </p>
        ) : null}
      </div>

      {/* Actions for this state - only roles the server still expects. */}
      {request.status === 'pending' ? (
        <div className="flex flex-wrap items-center gap-space-sm">
          {openRoles.map((role) => (
            <Button
              key={role}
              icon="how_to_reg"
              disabled={busyOr(busy, selfApproval)}
              ariaLabel={t('jit.detail.actionsUi.approveNamed', {
                role: t(`jit.detail.role.${role}`),
                id: request.id,
              })}
              onClick={() =>
                onAction(
                  role === 'manager' ? 'approve-manager' : 'approve-security',
                  request.id,
                )
              }
            >
              {t('jit.detail.actionsUi.approveRole', {
                role: t(`jit.detail.role.${role}`),
              })}
            </Button>
          ))}
        </div>
      ) : null}
      {request.status === 'pending' || request.status === 'blocked' ? (
        <form
          className="flex flex-col gap-space-sm"
          onSubmit={denyForm.handleSubmit((values) => {
            onAction(
              'deny',
              request.id,
              values.reason.trim() === '' ? undefined : values.reason,
            );
            denyForm.reset({ reason: '' });
          })}
        >
          <label className="flex flex-col gap-1">
            <span className="font-label-md text-label-md text-on-surface-variant">
              {t('jit.detail.denyReason')}
            </span>
            <input
              type="text"
              maxLength={255}
              {...denyForm.register('reason')}
              className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
            />
          </label>
          <div>
            <Button type="submit" variant="destructive" icon="block" disabled={busy}>
              {t('jit.detail.actionsUi.deny')}
            </Button>
          </div>
        </form>
      ) : null}
      {request.status === 'approved' ? (
        request.agent_binding !== null ? (
          /* An agent grant opens only through the agent's own token
             (contract: /agent-access/{id}/open is agentToken-only) - the
             console never fakes a grant it cannot perform. */
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('jit.detail.agentOpensGrant')}
          </p>
        ) : (
          <div>
            <Button
              icon="lock_open"
              disabled={busy}
              ariaLabel={t('jit.detail.actionsUi.approveGrant', { id: request.id })}
              onClick={() => onAction('grant', request.id)}
            >
              {t('jit.detail.actionsUi.grant')}
            </Button>
          </div>
        )
      ) : null}
      {request.status === 'active' ? (
        <div>
          <Button
            variant="destructive"
            icon="stop_circle"
            disabled={busy}
            ariaLabel={t('jit.detail.actionsUi.closeNamed', { id: request.id })}
            onClick={() =>
              onAction(request.agent_binding !== null ? 'close-agent' : 'close', request.id)
            }
          >
            {t('jit.detail.actionsUi.close')}
          </Button>
        </div>
      ) : null}

      {/* The audit trail for this request, newest event first. */}
      <div>
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.detail.events')}
        </span>
        <ul className="mt-1 flex flex-col gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
          {events.length === 0 ? (
            <li>{t('jit.detail.eventsEmpty')}</li>
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
                  {eventText(event.detail)}
                </span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}

/** Busy gate for quorum buttons (self-approval is refused server-side). */
function busyOr(busy: boolean, selfApproval: boolean): boolean {
  return busy || selfApproval;
}

/** Render the interesting server event details as readable text. */
function eventText(detail: unknown): string {
  if (detail === null || typeof detail !== 'object') return '';
  const record = recordOf(detail);
  const parts: string[] = [];
  if (typeof record.reason === 'string') parts.push(record.reason);
  if (typeof record.role === 'string') parts.push(String(record.role));
  if (typeof record.minutes === 'number') parts.push(`${record.minutes}m`);
  if (typeof record.risk_score === 'number') parts.push(`risk ${record.risk_score}`);
  if (typeof record.session_ref === 'string') parts.push(record.session_ref);
  return parts.length > 0 ? ` · ${parts.join(' · ')}` : '';
}

function recordOf(value: object): Record<string, unknown> {
  return value as Record<string, unknown>;
}

/** One approval slot: the contract's open object, or absent (`null`). */
type ApprovalSlot = Record<string, unknown> | null | undefined;

/**
 * The approving principal when the slot is filled contract-shaped; null
 * while the role is still awaiting its approval (an honest guard - the
 * generated model types the slot as an open object, not `{actor}`).
 */
function approvalActor(slot: ApprovalSlot): string | null {
  if (slot === null || slot === undefined) return null;
  return typeof slot.actor === 'string' ? slot.actor : null;
}

/** File-a-request modal body: contract fields, honest states, feedback. */
function FileRequestBody({
  actor,
  fileRequest,
}: {
  actor: string;
  fileRequest: ReturnType<typeof useFileJitRequest>;
}) {
  const { t } = useTranslation();
  const targets = useJitTargets();
  const form = useForm<FileRequestForm, unknown, FileRequestValues>({
    resolver: zodResolver(fileRequestSchema),
    mode: 'onSubmit',
    defaultValues: { item_id: 1, reason: '', ticket: '', minutes: 15 },
  });

  return (
    <form
      className="flex flex-col gap-space-md"
      onSubmit={form.handleSubmit((values) => {
        fileRequest.mutate({ ...values, actor });
      })}
      noValidate
    >
      {fileRequest.isSuccess ? (
        <p role="status" className="font-body-sm text-body-sm text-tertiary">
          {t('jit.file.filed', {
            message: fileRequest.data.message,
            risk: t(`jit.risk.${fileRequest.data.request.risk.level}`),
            score: fileRequest.data.request.risk.score,
          })}
        </p>
      ) : null}
      {fileRequest.isError ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.states.actionFailed', {
            message: isBackendDown(fileRequest.error)
              ? t('errors.backendDown')
              : fileRequest.error.message,
          })}
        </p>
      ) : null}

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.file.target')}
        </span>
        <SectionBody query={targets}>
          {(data: VaultItemList) => <TargetSelect form={form} targets={data} />}
        </SectionBody>
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.file.ticket')}
        </span>
        <input
          type="text"
          maxLength={64}
          placeholder={t('jit.file.ticketPlaceholder')}
          {...form.register('ticket')}
          className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.file.reason')}
        </span>
        <textarea
          rows={3}
          maxLength={255}
          {...form.register('reason')}
          className="w-full px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="font-label-md text-label-md text-on-surface-variant">
          {t('jit.file.minutes')}
        </span>
        <input
          type="number"
          min={1}
          max={480}
          {...form.register('minutes')}
          className="w-32 px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-code-md text-code-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
        />
      </label>

      {Object.keys(form.formState.errors).length > 0 ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('jit.file.invalid')}
        </p>
      ) : null}

      <div className="flex justify-end gap-space-sm">
        <Button type="submit" icon="send" disabled={fileRequest.isPending}>
          {t('jit.file.submit')}
        </Button>
      </div>
    </form>
  );
}

/** The vault target picker (server inventory, never a sample list). */
function TargetSelect({
  form,
  targets,
}: {
  form: UseFormReturn<FileRequestForm, unknown, FileRequestValues>;
  targets: VaultItemList;
}) {
  const { t } = useTranslation();
  if (targets.items.length === 0) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('jit.file.noTargets')}
      </p>
    );
  }
  return (
    <>
      <select
        {...form.register('item_id')}
        className="px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-md text-body-md border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
      >
        {targets.items.map((item) => (
          <option key={item.id} value={item.id}>
            {item.name} ({item.target})
          </option>
        ))}
      </select>
      {form.formState.errors.item_id ? (
        <span className="font-body-sm text-body-sm text-error">
          {t('jit.file.invalidTarget')}
        </span>
      ) : null}
    </>
  );
}
