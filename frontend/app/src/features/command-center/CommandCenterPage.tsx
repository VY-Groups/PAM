import { useTranslation } from 'react-i18next';
import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import {
  Chip,
  DataTable,
  KpiCard,
  NotConnected,
  SectionHeader,
  StatusDot,
  Value,
} from '../../components';
import type { DataTableColumn } from '../../components';
import type {
  BypassIncident,
  BypassStats,
  Health,
  Overview,
  OverviewPostureControlsItem,
  UnifiedEvent,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import {
  useActivityFeed,
  useBypassStats,
  useHealth,
  useOpenBypassIncidents,
  useOverview,
} from './queries';

/**
 * The F4 Command Center (plan §4 line 105): posture KPIs, health strip,
 * activity feed and the bypass-detection section - live data only, honest
 * loading / error / empty / not-connected / backend-down states (plan F4
 * per-screen DoD). Design-system components and generated query hooks only.
 */
export function CommandCenterPage() {
  const { t } = useTranslation();
  const overview = useOverview();
  const health = useHealth();
  const events = useActivityFeed();
  const bypassStats = useBypassStats();
  const incidents = useOpenBypassIncidents();

  const backendDownError = [
    overview.error,
    health.error,
    events.error,
    bypassStats.error,
    incidents.error,
  ].find((error) => error !== null && isBackendDown(error));

  return (
    <div className="flex w-full flex-col gap-space-xl pt-space-xl">
      <section className="flex flex-col gap-space-sm">
        <Chip>{t('commandCenter.kicker')}</Chip>
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          {t('commandCenter.title')}
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          {t('commandCenter.subtitle')}
        </p>
        <p className="font-code-sm text-code-sm text-outline">
          {t('commandCenter.sync', {
            time: formatTime(overview.data?.generated_at) ?? '—',
          })}
        </p>
      </section>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {/* Health strip: the server's own probe state, never assumed. */}
      <section>
        <SectionHeader title={t('commandCenter.health.heading')} />
        <div className="mt-space-md rounded-xl bg-surface-container-lowest p-space-md shadow-sm">
          <SectionBody query={health}>
            {(data) => <HealthStrip health={data} />}
          </SectionBody>
        </div>
      </section>

      {/* Posture KPIs: server-computed posture aggregate, absent = em-dash. */}
      <section>
        <SectionHeader title={t('commandCenter.kpis.heading')} />
        <SectionBody query={overview}>
          {(data) => <PostureKpis overview={data} />}
        </SectionBody>
      </section>

      {/* Per-control evidence table. */}
      <section>
        <SectionHeader
          title={t('commandCenter.controls.heading')}
          subtitle={t('commandCenter.controls.subtitle')}
        />
        <div className="mt-space-md overflow-hidden rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={overview}>
            {(data) => <ControlsTable overview={data} />}
          </SectionBody>
        </div>
      </section>

      {/* Activity feed from the immutable audit chain. */}
      <section>
        <SectionHeader
          title={t('commandCenter.activity.heading')}
          subtitle={t('commandCenter.activity.subtitle')}
        />
        <div className="mt-space-md overflow-hidden rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={events}>
            {(data) => <ActivityTable events={data.events} />}
          </SectionBody>
        </div>
      </section>

      {/* Bypass detection: aggregates + open incidents (read-only here). */}
      <section>
        <SectionHeader
          title={t('commandCenter.bypass.heading')}
          subtitle={t('commandCenter.bypass.subtitle')}
        />
        <SectionBody query={bypassStats}>
          {(data) => <BypassStatsKpis stats={data} />}
        </SectionBody>
        <div className="mt-space-md overflow-hidden rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={incidents}>
            {(data) => <IncidentsTable incidents={data.incidents} />}
          </SectionBody>
        </div>
      </section>
    </div>
  );
}

/**
 * One honest state machine for every section (plan F4 per-screen DoD):
 * loading line, verbatim section error, the brief §3.2 "not connected"
 * chip for transport failures (the shared banner sits above), and the
 * real content once the contract answers.
 */
function SectionBody<T>({
  query,
  children,
}: {
  query: UseQueryResult<T>;
  children: (data: T) => ReactNode;
}) {
  const { t } = useTranslation();
  if (query.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-outline">
        {t('commandCenter.states.loading')}
      </p>
    );
  }
  if (query.error !== null && query.error !== undefined) {
    if (isBackendDown(query.error)) return <NotConnected />;
    const message =
      query.error instanceof Error ? query.error.message : String(query.error);
    return (
      <p role="alert" className="font-body-sm text-body-sm text-error">
        {t('commandCenter.states.sectionError', { message })}
      </p>
    );
  }
  if (query.data === undefined) return null;
  return <>{children(query.data)}</>;
}

/** Health strip chips: status, database, auth, node, algorithms, formats. */
function HealthStrip({ health }: { health: Health }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap items-center gap-space-md">
      <Chip className="gap-1.5">
        <StatusDot state={health.status === 'ok' ? 'ok' : 'error'} />
        {t('commandCenter.health.status', { status: health.status })}
      </Chip>
      <Chip className="gap-1.5">
        <StatusDot state={health.database === 'ok' ? 'ok' : 'error'} />
        {t('commandCenter.health.database', { state: health.database })}
      </Chip>
      <Chip>
        {health.auth === 'open'
          ? t('commandCenter.health.authOpen')
          : t('commandCenter.health.auth', { mode: health.auth })}
      </Chip>
      {health.node !== undefined ? (
        <Chip>{t('commandCenter.health.node', { name: health.node })}</Chip>
      ) : null}
      <Chip>
        {t('commandCenter.health.algorithms', { count: health.algorithms.length })}
      </Chip>
      <Chip>{t('commandCenter.health.formats', { count: health.formats.length })}</Chip>
    </div>
  );
}

/** The posture KPI quad (plan §4 line 105), every value server-owned. */
function PostureKpis({ overview }: { overview: Overview }) {
  const { t } = useTranslation();
  const { posture, licenses, vault } = overview;
  const passed = posture.controls.filter((control) => control.passed).length;
  const rotation = vault.rotation;
  return (
    <div className="mt-space-md grid grid-cols-1 gap-space-lg sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('commandCenter.kpis.postureScore')}
        value={posture.score}
        accent="primary"
        footer={t('commandCenter.kpis.postureScoreFooter', {
          passed,
          total: posture.controls.length,
        })}
      />
      <KpiCard
        label={t('commandCenter.kpis.violations')}
        value={posture.violations}
        accent={posture.violations > 0 ? 'error' : 'primary-container'}
      />
      <KpiCard
        label={t('commandCenter.kpis.activeLicenses')}
        value={licenses.active ?? null}
        accent="tertiary"
        footer={
          licenses.active !== undefined &&
          licenses.total !== undefined &&
          licenses.expiring_soon !== undefined
            ? t('commandCenter.kpis.activeLicensesFooter', {
                active: licenses.active,
                total: licenses.total,
                expiring: licenses.expiring_soon,
              })
            : undefined
        }
      />
      <KpiCard
        label={t('commandCenter.kpis.vaultSecrets')}
        value={vault.total}
        accent="tertiary"
        footer={
          rotation.compliance_pct !== undefined && rotation.due !== undefined
            ? t('commandCenter.kpis.vaultSecretsFooter', {
                pct: rotation.compliance_pct,
                due: rotation.due,
              })
            : undefined
        }
      />
    </div>
  );
}

/** Per-control evidence table (PASS/FAIL dot + label + server evidence). */
function ControlsTable({ overview }: { overview: Overview }) {
  const { t } = useTranslation();
  const columns: DataTableColumn<OverviewPostureControlsItem>[] = [
    {
      key: 'label',
      header: t('commandCenter.controls.label'),
      render: (row) => <span className="font-body-md text-body-md">{row.label}</span>,
    },
    {
      key: 'state',
      header: t('commandCenter.controls.state'),
      render: (row) => (
        <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider">
          <StatusDot state={row.passed ? 'ok' : 'error'} />
          <span className={row.passed ? 'text-tertiary' : 'text-error'}>
            {row.passed
              ? t('commandCenter.controls.passed')
              : t('commandCenter.controls.failed')}
          </span>
        </span>
      ),
    },
    {
      key: 'evidence',
      header: t('commandCenter.controls.evidence'),
      render: (row) => <Value value={row.evidence} />,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={overview.posture.controls}
      rowKey={(row) => row.id}
      caption={t('commandCenter.controls.caption')}
      emptyMessage={t('commandCenter.controls.empty')}
    />
  );
}

/** Activity feed table: time, source chip, action, subject, actor. */
function ActivityTable({ events }: { events: UnifiedEvent[] }) {
  const { t } = useTranslation();
  const columns: DataTableColumn<UnifiedEvent>[] = [
    {
      key: 'time',
      header: t('commandCenter.activity.time'),
      render: (row) => <Value value={formatTime(row.created_at)} />,
    },
    {
      key: 'source',
      header: t('commandCenter.activity.source'),
      render: (row) => <Chip>{row.source}</Chip>,
    },
    {
      key: 'action',
      header: t('commandCenter.activity.action'),
      render: (row) => <span className="font-code-sm text-code-sm">{row.action}</span>,
    },
    {
      key: 'subject',
      header: t('commandCenter.activity.subject'),
      render: (row) => <Value value={row.subject} />,
    },
    {
      key: 'actor',
      header: t('commandCenter.activity.actor'),
      render: (row) => <Value value={row.actor} />,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={events}
      rowKey={(row) => `${row.source}:${row.seq}`}
      caption={t('commandCenter.activity.caption')}
      emptyMessage={t('commandCenter.activity.empty')}
    />
  );
}

/** Bypass KPI trio + last ingest/scan stamps (null = honest "never"). */
function BypassStatsKpis({ stats }: { stats: BypassStats }) {
  const { t } = useTranslation();
  const closed = stats.incidents.closed ?? 0;
  const total = stats.incidents.total ?? 0;
  return (
    <div className="mt-space-md flex flex-col gap-space-md">
      <div className="grid grid-cols-1 gap-space-lg sm:grid-cols-3">
        <KpiCard
          label={t('commandCenter.bypass.signalsKpi')}
          value={stats.signals.observed ?? null}
          accent="primary"
        />
        <KpiCard
          label={t('commandCenter.bypass.incidentsKpi')}
          value={stats.incidents.open ?? null}
          accent={(stats.incidents.open ?? 0) > 0 ? 'error' : 'primary-container'}
          footer={t('commandCenter.bypass.incidentsFooter', { closed, total })}
        />
        <KpiCard
          label={t('commandCenter.bypass.rotationsKpi')}
          value={stats.rotations_forced}
          accent="primary-container"
        />
      </div>
      <p className="font-code-sm text-code-sm text-outline">
        {t('commandCenter.bypass.lastIngest', {
          time: formatTime(stats.last_ingest_at) ?? t('commandCenter.bypass.never'),
        })}
        {' · '}
        {t('commandCenter.bypass.lastScan', {
          time: formatTime(stats.last_scan_at) ?? t('commandCenter.bypass.never'),
        })}
      </p>
    </div>
  );
}

/** Open incidents table: ref, user, target, protocol, status, observed. */
function IncidentsTable({ incidents }: { incidents: BypassIncident[] }) {
  const { t } = useTranslation();
  const columns: DataTableColumn<BypassIncident>[] = [
    {
      key: 'ref',
      header: t('commandCenter.bypass.incidentsTable.ref'),
      render: (row) => (
        <span className="font-code-sm text-code-sm">{row.incident_ref}</span>
      ),
    },
    {
      key: 'user',
      header: t('commandCenter.bypass.incidentsTable.user'),
      render: (row) => <Value value={row.user} />,
    },
    {
      key: 'target',
      header: t('commandCenter.bypass.incidentsTable.target'),
      render: (row) => <Value value={row.target} />,
    },
    {
      key: 'protocol',
      header: t('commandCenter.bypass.incidentsTable.protocol'),
      render: (row) => <Value value={row.protocol} />,
    },
    {
      key: 'status',
      header: t('commandCenter.bypass.incidentsTable.status'),
      render: (row) => (
        <Chip tone={row.status === 'open' ? 'info' : 'inactive'}>{row.status}</Chip>
      ),
    },
    {
      key: 'observed',
      header: t('commandCenter.bypass.incidentsTable.observed'),
      render: (row) => <Value value={formatTime(row.observed_at)} />,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={incidents}
      rowKey={(row) => row.incident_ref}
      caption={t('commandCenter.bypass.incidentsTable.caption')}
      emptyMessage={t('commandCenter.bypass.incidentsTable.empty')}
    />
  );
}
