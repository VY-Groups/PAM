import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import {
  Button,
  Chip,
  KpiCard,
  Modal,
  SectionHeader,
  StatusDot,
  Tabs,
  Value,
} from '../../components';
import type { TabItem } from '../../components';
import type {
  Session,
  SessionDetail,
  SessionEndResponse,
  SessionList,
  SessionStartRequest,
  SessionStats,
  SessionControlsUpdate,
} from '../../api/generated/models';
import { formatDuration, formatTime } from '../../lib/format';
import { SectionBody } from './SectionBody';
import { EventStream } from './EventStream';
import { WatermarkCard } from './WatermarkCard';
import {
  sessionProtocols,
  startSessionSchema,
  terminateSchema,
  type StartSessionForm,
  type StartSessionValues,
  type TerminateValues,
} from './schemas';
import {
  useSessionDetail,
  useSessionEvents,
  useSessionGrant,
  useSessionLifecycle,
  useSessionList,
  useSessionStats,
  useStartCredentials,
  useStartSession,
  useTerminateSession,
  useUpdateControls,
} from './queries';

/**
 * Live Session Hub (F4 screen 4, plan §4 line 108): the session list with
 * its live/ended split, the supervisor controls, the recorded event
 * stream, the control flags and the section-12/27 watermark overlay. All
 * data is contract-served; every absent value renders the honest em-dash
 * or an explicit empty state, and the live player stays out of scope
 * ("live player later" - plan §4 line 108).
 */

const LIVE_STATES: readonly Session['status'][] = ['active', 'paused', 'locked'];
const ENDED_STATES: readonly Session['status'][] = ['terminated', 'completed'];

const isLive = (s: Session): boolean => LIVE_STATES.includes(s.status);
const isEnded = (s: Session): boolean => ENDED_STATES.includes(s.status);
const isSuspended = (s: Session): boolean => s.status === 'paused' || s.status === 'locked';

/** The seven `SessionControls` flags, in contract order. */
const CONTROL_FLAGS = [
  'record',
  'keystroke_log',
  'watermark',
  'clipboard_allowed',
  'upload_allowed',
  'download_allowed',
  'screenshot_allowed',
] as const;

export function SessionsPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const actor = whoami?.principal ?? 'console';

  const stats = useSessionStats();
  const list = useSessionList();
  const [pickedId, setPickedId] = useState<number | null>(null);

  // Auto-selection is derived during render (no effect): keep the user's
  // pick while the server still reports it, otherwise the first live
  // session (else the first row) - legacy `ensureSelection` parity, and
  // the detail pane can never show a row the server no longer reports.
  const items = list.data?.items;
  const selectedId =
    pickedId !== null && items?.some((s) => s.id === pickedId)
      ? pickedId
      : items
        ? (items.find(isLive)?.id ?? items[0]?.id ?? null)
        : null;

  const detail = useSessionDetail(selectedId);
  const events = useSessionEvents(selectedId);
  const session = detail.data?.session ?? null;
  const grant = useSessionGrant(session?.jit_request_id ?? null);

  const start = useStartSession();
  const lifecycle = useSessionLifecycle();
  const terminate = useTerminateSession();
  const controls = useUpdateControls();

  const [starting, setStarting] = useState(false);
  const [terminating, setTerminating] = useState(false);

  const backendDownError = [stats, list, detail, events].find(
    (q) => q.error !== null && q.error !== undefined && isBackendDown(q.error),
  )?.error;

  const startForm = useForm<StartSessionForm, unknown, StartSessionValues>({
    resolver: zodResolver(startSessionSchema),
    defaultValues: {
      protocol: 'ssh',
      target: '',
      item: '',
      record: true,
      keystroke_log: true,
      watermark: true,
      clipboard_allowed: true,
      upload_allowed: true,
      download_allowed: true,
      screenshot_allowed: true,
    },
  });
  const terminateForm = useForm<TerminateValues>({
    resolver: zodResolver(terminateSchema),
    defaultValues: { reason: '' },
  });

  const onStartSubmit = startForm.handleSubmit((values) => {
    const payload: SessionStartRequest = {
      protocol: values.protocol,
      target: values.target,
      record: values.record,
      keystroke_log: values.keystroke_log,
      watermark: values.watermark,
      clipboard_allowed: values.clipboard_allowed,
      upload_allowed: values.upload_allowed,
      download_allowed: values.download_allowed,
      screenshot_allowed: values.screenshot_allowed,
      ...(values.item === '' ? {} : { item_id: Number(values.item) }),
    };
    start.mutate(
      { ...payload, actor },
      { onSuccess: (data) => setPickedId(data.session.id) },
    );
  });

  const onTerminateSubmit = terminateForm.handleSubmit((values) => {
    if (session === null) return;
    terminate.mutate(
      { sessionId: session.id, actor, reason: values.reason },
      {
        onSuccess: () => {
          setTerminating(false);
          terminateForm.reset();
        },
      },
    );
  });

  return (
    <div className="flex w-full flex-col gap-space-xl pt-space-xl">
      <section className="flex items-start justify-between gap-space-lg">
        <div className="flex flex-col gap-space-sm">
          <Chip>{t('sessions.kicker')}</Chip>
          <h1 className="font-headline-lg text-headline-lg text-on-surface">
            {t('sessions.title')}
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {t('sessions.subtitle')}
          </p>
        </div>
        <Button type="button" onClick={() => setStarting(true)}>
          {t('sessions.list.start')}
        </Button>
      </section>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      <KpiRow stats={stats.data} />

      <SectionBody query={list}>
        {(data) => (
          <Tabs
            label={t('sessions.tabs.label')}
            defaultValue="live"
            tabs={sessionTabs(data, selectedId, setPickedId, t)}
          />
        )}
      </SectionBody>

      {selectedId === null ? (
        <p className="rounded-xl bg-surface-container-lowest p-space-md font-body-sm text-body-sm text-on-surface-variant shadow-sm">
          {t('sessions.detail.none')}
        </p>
      ) : (
        <SectionBody query={detail}>
          {(data) => (
            <DetailPane
              data={data}
              eventsQuery={events}
              grant={grant}
              actor={actor}
              lifecycle={lifecycle}
              terminate={terminate}
              controls={controls}
              onTerminate={() => setTerminating(true)}
              listHasSession={
                items !== undefined && items.some((s) => s.id === data.session.id)
              }
            />
          )}
        </SectionBody>
      )}

      <StartDialog
        open={starting}
        onOpenChange={(open) => {
          setStarting(open);
          if (!open) {
            start.reset();
            startForm.reset();
          }
        }}
        form={startForm}
        onSubmit={onStartSubmit}
        start={start}
      />
      <TerminateDialog
        open={terminating}
        onOpenChange={(open) => {
          setTerminating(open);
          if (!open) terminate.reset();
        }}
        session={session}
        grantLinked={
          session?.jit_request_id !== null && session?.jit_request_id !== undefined
        }
        form={terminateForm}
        onSubmit={onTerminateSubmit}
        terminate={terminate}
      />
    </div>
  );
}

/* --------------------------------------------------------------- KPI strip */

function KpiRow({ stats }: { stats: SessionStats | undefined }) {
  const { t } = useTranslation();
  return (
    <section
      aria-label={t('sessions.kpis.heading')}
      className="grid grid-cols-1 gap-space-md sm:grid-cols-2 xl:grid-cols-4"
    >
      <KpiCard
        label={t('sessions.kpis.live')}
        value={stats?.active}
        footer={
          stats
            ? t('sessions.kpis.liveFooter', {
                paused: stats.paused,
                locked: stats.locked,
              })
            : undefined
        }
      />
      <KpiCard
        label={t('sessions.kpis.ended')}
        value={stats?.ended}
        footer={stats ? t('sessions.kpis.endedFooter', { total: stats.total }) : undefined}
      />
      <KpiCard
        label={t('sessions.kpis.blocked')}
        value={stats?.events_blocked}
        footer={
          stats
            ? t('sessions.kpis.blockedFooter', {
                withheld: stats.events_withheld,
              })
            : undefined
        }
      />
      <KpiCard
        label={t('sessions.kpis.events')}
        value={stats?.events_total}
        footer={t('sessions.kpis.eventsFooter')}
      />
    </section>
  );
}

/* ------------------------------------------------------------- list + tabs */

function sessionTabs(
  data: SessionList,
  selectedId: number | null,
  onSelect: (id: number) => void,
  t: (key: string, options?: Record<string, unknown>) => string,
): TabItem[] {
  const live = data.items.filter(isLive);
  const ended = data.items.filter(isEnded);
  return [
    {
      value: 'live',
      label: t('sessions.tabs.liveWithCount', { count: live.length }),
      content: (
        <SessionCards
          rows={live}
          selectedId={selectedId}
          onSelect={onSelect}
          emptyKey="sessions.list.emptyLive"
          t={t}
        />
      ),
    },
    {
      value: 'ended',
      label: t('sessions.tabs.endedWithCount', { count: ended.length }),
      content: (
        <SessionCards
          rows={ended}
          selectedId={selectedId}
          onSelect={onSelect}
          emptyKey="sessions.list.emptyEnded"
          t={t}
        />
      ),
    },
  ];
}

function SessionCards({
  rows,
  selectedId,
  onSelect,
  emptyKey,
  t,
}: {
  rows: Session[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  emptyKey: string;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  if (rows.length === 0) {
    return (
      <p className="rounded-xl bg-surface-container-lowest p-space-md font-body-sm text-body-sm text-on-surface-variant shadow-sm">
        {t(emptyKey)}
      </p>
    );
  }
  return (
    <ul className="grid grid-cols-1 gap-space-sm md:grid-cols-2 xl:grid-cols-3">
      {rows.map((s) => {
        const selected = s.id === selectedId;
        return (
          <li key={s.id}>
            <button
              type="button"
              onClick={() => onSelect(s.id)}
              aria-pressed={selected}
              aria-label={t('sessions.list.inspect', { ref: s.session_ref })}
              className={`flex w-full flex-col gap-space-sm rounded-xl p-space-md text-left shadow-sm transition-colors ${
                selected
                  ? 'bg-primary/5 ring-1 ring-primary/40'
                  : 'bg-surface-container-lowest hover:bg-surface-container-low'
              }`}
            >
              <div className="flex items-center justify-between gap-space-sm">
                <span className="flex items-center gap-space-xs">
                  <Chip>{s.protocol}</Chip>
                  <code className="font-code-sm text-code-sm text-on-surface">
                    {s.session_ref}
                  </code>
                </span>
                <Chip tone={isLive(s) && s.status === 'active' ? 'info' : 'inactive'}>
                  {s.status}
                </Chip>
              </div>
              <span className="truncate font-body-sm text-body-sm text-on-surface-variant">
                {s.target}
              </span>
              <div className="flex flex-wrap items-center gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
                <StatusDot state={isLive(s) ? 'live' : 'muted'} />
                <span>{s.actor}</span>
                <Value value={formatDuration(s.duration_seconds)} />
                {s.jit_request_id !== null && s.jit_request_id !== undefined ? (
                  <Chip tone="inactive">
                    {t('sessions.list.jitPrefix', { id: s.jit_request_id })}
                  </Chip>
                ) : null}
                <Chip tone="inactive">
                  {s.item_id !== null && s.item_id !== undefined
                    ? t('sessions.list.vault')
                    : t('sessions.list.bare')}
                </Chip>
              </div>
              <span className="font-label-badge text-label-badge uppercase tracking-wider text-primary">
                {t('sessions.list.inspect', { ref: s.session_ref })}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/* ------------------------------------------------------------ detail pane */

function DetailPane({
  data,
  eventsQuery,
  grant,
  actor,
  lifecycle,
  terminate,
  controls,
  onTerminate,
  listHasSession,
}: {
  data: SessionDetail;
  eventsQuery: ReturnType<typeof useSessionEvents>;
  grant: ReturnType<typeof useSessionGrant>;
  actor: string;
  lifecycle: ReturnType<typeof useSessionLifecycle>;
  terminate: ReturnType<typeof useTerminateSession>;
  controls: ReturnType<typeof useUpdateControls>;
  onTerminate: () => void;
  listHasSession: boolean;
}) {
  const { t } = useTranslation();
  const s = data.session;
  const host = s.target.split(':')[0];
  const ended = isEnded(s);
  const live = s.status === 'active';
  const suspended = isSuspended(s);

  const canPause = live;
  const canResume = suspended;
  const canLock = live || s.status === 'paused';
  const canTerminate = !ended;

  const disabledReason = (enabled: boolean, reason: string) => (enabled ? '' : reason);

  const noticeError = [lifecycle, terminate, controls].find((m) => m.isError)?.error;
  const noticeMessage =
    terminate.data !== undefined && terminate.isSuccess
      ? terminate.data.message
      : lifecycle.data?.message && lifecycle.isSuccess
        ? lifecycle.data.message
        : controls.data?.message && controls.isSuccess
          ? controls.data.message
          : null;

  return (
    <div className="flex flex-col gap-space-lg">
      <section
        className="flex flex-col gap-space-md rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
        aria-label={t('sessions.detail.heading')}
      >
        <SectionHeader
          title={s.session_ref}
          subtitle={`${s.actor}@${host} · ${s.protocol} · ${s.target}`}
          actions={
            <div className="flex flex-wrap items-center gap-space-sm">
              <Button
                type="button"
                variant="secondary"
                disabled={!canPause || lifecycle.isPending}
                title={disabledReason(canPause, t('sessions.detail.pauseDisabled'))}
                onClick={() => lifecycle.mutate({ kind: 'pause', sessionId: s.id, actor })}
              >
                {t('sessions.detail.pause')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canResume || lifecycle.isPending}
                title={disabledReason(canResume, t('sessions.detail.resumeDisabled'))}
                onClick={() => lifecycle.mutate({ kind: 'resume', sessionId: s.id, actor })}
              >
                {t('sessions.detail.resume')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!canLock || lifecycle.isPending}
                title={disabledReason(canLock, t('sessions.detail.lockDisabled'))}
                onClick={() => lifecycle.mutate({ kind: 'lock', sessionId: s.id, actor })}
              >
                {t('sessions.detail.lock')}
              </Button>
              <Button
                type="button"
                variant="destructive"
                disabled={!canTerminate || terminate.isPending}
                title={disabledReason(canTerminate, t('sessions.detail.endedDisabled'))}
                onClick={onTerminate}
              >
                {t('sessions.detail.terminate')}
              </Button>
            </div>
          }
        />
        <div className="flex flex-wrap items-center gap-space-sm">
          <Chip tone={live || suspended ? 'info' : 'inactive'}>
            {live || suspended
              ? t('sessions.detail.monitor')
              : t('sessions.detail.playback')}
          </Chip>
          <Chip tone={s.controls.record ? 'info' : 'inactive'}>
            {s.controls.record
              ? t('sessions.detail.recordingOn')
              : t('sessions.detail.recordingOff')}
          </Chip>
          <Chip tone="inactive">
            {t('sessions.detail.eventCount', { count: data.event_count })}
          </Chip>
          <Chip tone="inactive">
            {t('sessions.detail.blockedCount', { count: data.blocked_count })}
          </Chip>
          <Chip tone="inactive">
            {t('sessions.detail.replay', {
              duration: formatDuration(s.duration_seconds) ?? '—',
              count: data.event_count,
            })}
          </Chip>
          <Chip tone="inactive">
            {ended
              ? t('sessions.detail.ttlEnded', {
                  state: s.status,
                  duration: formatDuration(s.duration_seconds) ?? '—',
                })
              : t('sessions.detail.ttlElapsed', {
                  duration: formatDuration(s.duration_seconds) ?? '—',
                })}
          </Chip>
        </div>
        {noticeError !== undefined ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('sessions.detail.failed', {
              message:
                noticeError instanceof Error ? noticeError.message : String(noticeError),
            })}
          </p>
        ) : null}
        {noticeMessage !== null ? (
          <p className="font-body-sm text-body-sm text-primary">
            {t('sessions.detail.done', { message: noticeMessage })}
            {terminate.data?.cascade !== undefined &&
            terminate.data.cascade !== null &&
            terminate.isSuccess
              ? ` · ${cascadeLine(terminate.data, t)}`
              : ''}
          </p>
        ) : null}
        {!listHasSession ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('sessions.detail.notInList')}
          </p>
        ) : null}
      </section>

      <div className="grid grid-cols-1 gap-space-lg xl:grid-cols-2">
        <SectionBody query={eventsQuery}>
          {(data2) => (
            <EventStream
              session={s}
              events={data2.events}
              eventCount={data.event_count}
              blockedCount={data.blocked_count}
            />
          )}
        </SectionBody>

        <div className="flex flex-col gap-space-lg">
          <WatermarkCard watermark={data.watermark} gateway={data.gateway ?? null} loaded />
          <GovernancePanel session={s} grant={grant} />
          <ControlsPanel session={s} actor={actor} controls={controls} />
          <ViolationsPanel
            recorded={data.event_count}
            blocked={data.blocked_count}
            withheld={(eventsQuery.data?.events ?? []).filter((e) => e.withheld).length}
          />
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------- governance */

function GovernancePanel({
  session,
  grant,
}: {
  session: Session;
  grant: ReturnType<typeof useSessionGrant>;
}) {
  const { t } = useTranslation();
  const linked = session.jit_request_id !== null && session.jit_request_id !== undefined;

  let quorum: string | null = null;
  if (linked && grant.data !== undefined) {
    const requested = grant.data.events.find((e) => e.action === 'requested');
    const detail = requested?.detail as { required_approvals?: unknown } | undefined;
    const required = Array.isArray(detail?.required_approvals)
      ? (detail.required_approvals as unknown[]).length
      : null;
    const approvals = grant.data.request.approvals;
    const recorded = [approvals?.manager, approvals?.security].filter(
      (a) => a !== null && a !== undefined,
    ).length;
    quorum =
      required === null
        ? t('sessions.governance.quorumUnknown', { recorded })
        : t('sessions.governance.quorumState', { recorded, required });
  }

  return (
    <section
      className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
      aria-label={t('sessions.governance.heading')}
    >
      <SectionHeader title={t('sessions.governance.heading')} />
      <dl className="grid grid-cols-1 gap-space-sm sm:grid-cols-2">
        <div>
          <dt className="font-label-badge text-label-badge uppercase text-outline">
            {t('sessions.governance.source')}
          </dt>
          <dd className="m-0 font-body-sm text-body-sm text-on-surface">
            {linked
              ? t('sessions.governance.jit', { id: session.jit_request_id })
              : t('sessions.governance.direct')}
          </dd>
        </div>
        <div>
          <dt className="font-label-badge text-label-badge uppercase text-outline">
            {t('sessions.governance.quorum')}
          </dt>
          <dd className="m-0 font-body-sm text-body-sm text-on-surface">
            <Value value={quorum} />
          </dd>
        </div>
        <div>
          <dt className="font-label-badge text-label-badge uppercase text-outline">
            {t('sessions.governance.started')}
          </dt>
          <dd className="m-0 font-body-sm text-body-sm text-on-surface">
            <Value value={formatTime(session.started_at)} />
          </dd>
        </div>
        <div>
          <dt className="font-label-badge text-label-badge uppercase text-outline">
            {t('sessions.governance.expires')}
          </dt>
          <dd className="m-0 font-body-sm text-body-sm text-on-surface">
            <Value
              value={
                linked && grant.data !== undefined
                  ? formatTime(grant.data.request.expires_at ?? null)
                  : null
              }
            />
          </dd>
        </div>
      </dl>
      {linked && grant.isPending ? (
        <p className="font-body-sm text-body-sm text-outline">
          {t('sessions.states.loading')}
        </p>
      ) : null}
      {linked && grant.error ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('sessions.states.sectionError', {
            message:
              grant.error instanceof Error ? grant.error.message : String(grant.error),
          })}
        </p>
      ) : null}
    </section>
  );
}

/* ------------------------------------------------------------- controls */

function ControlsPanel({
  session,
  actor,
  controls,
}: {
  session: Session;
  actor: string;
  controls: ReturnType<typeof useUpdateControls>;
}) {
  const { t } = useTranslation();
  const ended = isEnded(session);

  return (
    <section
      className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
      aria-label={t('sessions.controls.heading')}
    >
      <SectionHeader
        title={t('sessions.controls.heading')}
        subtitle={t('sessions.controls.subtitle')}
      />
      <ul className="flex flex-col gap-space-xs">
        {CONTROL_FLAGS.map((flag) => (
          <li
            key={flag}
            className="flex items-center justify-between gap-space-sm rounded-lg bg-surface-container-low p-space-sm"
          >
            <span className="font-body-sm text-body-sm text-on-surface">
              {t(`sessions.controls.flags.${flag}`)}
            </span>
            <span className="flex items-center gap-space-sm">
              <Chip tone={session.controls[flag] ? 'info' : 'inactive'}>
                {session.controls[flag]
                  ? t('sessions.controls.on')
                  : t('sessions.controls.off')}
              </Chip>
              <input
                type="checkbox"
                checked={session.controls[flag]}
                disabled={ended || controls.isPending}
                title={ended ? t('sessions.controls.ended') : ''}
                aria-label={t('sessions.controls.toggleAria', {
                  name: t(`sessions.controls.flags.${flag}`),
                })}
                onChange={(e) => {
                  const update: SessionControlsUpdate = {
                    [flag]: e.target.checked,
                  };
                  controls.mutate({
                    sessionId: session.id,
                    actor,
                    update,
                  });
                }}
              />
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/* ----------------------------------------------------------- violations */

function ViolationsPanel({
  recorded,
  blocked,
  withheld,
}: {
  recorded: number;
  blocked: number;
  withheld: number;
}) {
  const { t } = useTranslation();
  return (
    <section
      className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
      aria-label={t('sessions.violations.heading')}
    >
      <SectionHeader
        title={t('sessions.violations.heading')}
        actions={
          <Chip tone={blocked > 0 ? 'info' : 'inactive'}>{`${blocked} BLOCKED`}</Chip>
        }
      />
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {blocked > 0 ? t('sessions.violations.some') : t('sessions.violations.none')}
      </p>
      <dl className="grid grid-cols-3 gap-space-sm">
        <ViolationStat label={t('sessions.violations.recorded')} value={recorded} />
        <ViolationStat label={t('sessions.violations.blockedLabel')} value={blocked} />
        <ViolationStat label={t('sessions.violations.withheldLabel')} value={withheld} />
      </dl>
    </section>
  );
}

function ViolationStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg bg-surface-container-low p-space-sm">
      <dt className="font-label-badge text-label-badge uppercase text-outline">{label}</dt>
      <dd className="m-0 font-body-sm text-body-sm text-on-surface">
        <Value value={value} />
      </dd>
    </div>
  );
}

/* --------------------------------------------------------------- dialogs */

function StartDialog({
  open,
  onOpenChange,
  form,
  onSubmit,
  start,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  form: ReturnType<typeof useForm<StartSessionForm, unknown, StartSessionValues>>;
  onSubmit: () => void;
  start: ReturnType<typeof useStartSession>;
}) {
  const { t } = useTranslation();
  const credentials = useStartCredentials();
  const {
    register,
    formState: { errors },
  } = form;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t('sessions.start.title')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('sessions.start.cancel')}
          </Button>
          <Button type="submit" form="start-session-form" disabled={start.isPending}>
            {start.isPending ? t('sessions.start.submitting') : t('sessions.start.submit')}
          </Button>
        </>
      }
    >
      <form
        id="start-session-form"
        onSubmit={onSubmit}
        className="flex flex-col gap-space-md"
        noValidate
      >
        <label className="flex flex-col gap-space-xs font-body-sm text-body-sm text-on-surface">
          {t('sessions.start.protocol')}
          <select
            className="rounded-lg border border-outline bg-surface p-space-sm font-body-sm text-body-sm"
            {...register('protocol')}
          >
            {sessionProtocols.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-space-xs font-body-sm text-body-sm text-on-surface">
          {t('sessions.start.target')}
          <input
            type="text"
            className="rounded-lg border border-outline bg-surface p-space-sm font-body-sm text-body-sm"
            placeholder={t('sessions.start.targetPlaceholder')}
            {...register('target')}
          />
          {errors.target ? (
            <span role="alert" className="text-error">
              {t('sessions.start.invalid')}
            </span>
          ) : null}
        </label>
        <label className="flex flex-col gap-space-xs font-body-sm text-body-sm text-on-surface">
          {t('sessions.start.credential')}
          <select
            className="rounded-lg border border-outline bg-surface p-space-sm font-body-sm text-body-sm"
            {...register('item')}
          >
            <option value="">{t('sessions.start.noCredential')}</option>
            {credentials.data?.items.map((i) => (
              <option key={i.id} value={String(i.id)}>
                {i.name}
              </option>
            ))}
          </select>
        </label>
        <fieldset className="flex flex-col gap-space-xs">
          <legend className="font-label-badge text-label-badge uppercase text-outline">
            {t('sessions.start.controls')}
          </legend>
          <div className="grid grid-cols-2 gap-space-xs">
            {CONTROL_FLAGS.map((flag) => (
              <label
                key={flag}
                className="flex items-center gap-space-xs font-body-sm text-body-sm text-on-surface"
              >
                <input type="checkbox" {...register(flag)} />
                {t(`sessions.controls.flags.${flag}`)}
              </label>
            ))}
          </div>
        </fieldset>
        {start.error ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('sessions.start.failed', {
              message:
                start.error instanceof Error ? start.error.message : String(start.error),
            })}
          </p>
        ) : null}
        {start.isSuccess ? (
          <p className="font-body-sm text-body-sm text-primary">
            {start.data.risk !== undefined && start.data.risk !== null
              ? t('sessions.start.startedWithRisk', {
                  message: start.data.message,
                  risk: start.data.risk.band,
                  score: start.data.risk.score,
                })
              : t('sessions.start.started', { message: start.data.message })}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}

function TerminateDialog({
  open,
  onOpenChange,
  session,
  grantLinked,
  form,
  onSubmit,
  terminate,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  session: Session | null;
  grantLinked: boolean;
  form: ReturnType<typeof useForm<TerminateValues>>;
  onSubmit: () => void;
  terminate: ReturnType<typeof useTerminateSession>;
}) {
  const { t } = useTranslation();
  const {
    register,
    formState: { errors },
  } = form;
  if (session === null) return null;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t('sessions.terminate.title', { ref: session.session_ref })}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('sessions.start.cancel')}
          </Button>
          <Button
            type="submit"
            form="terminate-session-form"
            variant="destructive"
            disabled={terminate.isPending}
          >
            {terminate.isPending
              ? t('sessions.terminate.submitting')
              : t('sessions.terminate.submit')}
          </Button>
        </>
      }
    >
      <form
        id="terminate-session-form"
        onSubmit={onSubmit}
        className="flex flex-col gap-space-md"
        noValidate
      >
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {grantLinked ? t('sessions.terminate.bodyLinked') : t('sessions.terminate.body')}
        </p>
        <dl className="grid grid-cols-2 gap-space-sm">
          <TerminateFact
            label={t('sessions.terminate.session')}
            value={session.session_ref}
          />
          <TerminateFact label={t('sessions.terminate.target')} value={session.target} />
          <TerminateFact label={t('sessions.terminate.actor')} value={session.actor} />
          <TerminateFact
            label={t('sessions.terminate.started')}
            value={formatTime(session.started_at) ?? '—'}
          />
        </dl>
        <label className="flex flex-col gap-space-xs font-body-sm text-body-sm text-on-surface">
          {t('sessions.terminate.reason')}
          <input
            type="text"
            className="rounded-lg border border-outline bg-surface p-space-sm font-body-sm text-body-sm"
            placeholder={t('sessions.terminate.reasonPlaceholder')}
            {...register('reason')}
          />
          {errors.reason ? (
            <span role="alert" className="text-error">
              {errors.reason.message}
            </span>
          ) : null}
        </label>
        {terminate.error ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('sessions.terminate.failed', {
              message:
                terminate.error instanceof Error
                  ? terminate.error.message
                  : String(terminate.error),
            })}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}

function TerminateFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-surface-container-low p-space-sm">
      <dt className="font-label-badge text-label-badge uppercase text-outline">{label}</dt>
      <dd className="m-0 font-body-sm text-body-sm text-on-surface">{value}</dd>
    </div>
  );
}

/* ---------------------------------------------------------------- helpers */

/**
 * The release-and-rotate cascade the terminate response reports (plan §3
 * gate 3e): rotation outcome verbatim - the rotated version, an honest
 * "no rotation configured", or the rotation error itself.
 */
function cascadeLine(
  data: SessionEndResponse,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  const cascade = data.cascade as Record<string, unknown> | undefined;
  if (cascade === undefined || cascade === null) return '';
  if (typeof cascade.rotation_error === 'string' && cascade.rotation_error !== '') {
    return t('sessions.terminate.cascadeError', {
      error: cascade.rotation_error,
    });
  }
  if (cascade.rotated === true) {
    return t('sessions.terminate.cascadeRotated', {
      version:
        typeof cascade.secret_version === 'number'
          ? String(cascade.secret_version)
          : typeof cascade.secret_version === 'string'
            ? cascade.secret_version
            : '—',
    });
  }
  if (cascade.checkout_released === true) {
    return t('sessions.terminate.cascadeReleased');
  }
  return '';
}
