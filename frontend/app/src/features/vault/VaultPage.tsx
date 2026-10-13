import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import {
  Button,
  Chip,
  DataTable,
  KpiCard,
  Modal,
  NotConnected,
  SectionHeader,
  StatusDot,
  Value,
} from '../../components';
import type { DataTableColumn, DotState } from '../../components';
import type {
  SecretReveal,
  VaultEvent,
  VaultItem,
  VaultItemDetail,
  VaultItemStatus,
  VaultStats,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import {
  useRevealSecret,
  useVaultAction,
  useVaultEvents,
  useVaultItemDetail,
  useVaultItems,
  useVaultStats,
  type VaultActionKind,
} from './queries';

/**
 * The F4 Credential Vault (plan §4 line 106): inventory, checkout, reveal,
 * rotate and version history - live data only, honest loading / error /
 * empty / not-connected / backend-down states (F4 per-screen DoD).
 * Design-system components and generated query hooks only; every action
 * carries the signed-in principal as the contract's `X-Actor` header so the
 * server-side audit trail names a human.
 */
export function VaultPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const stats = useVaultStats();
  const items = useVaultItems();
  const events = useVaultEvents();
  const action = useVaultAction();
  const reveal = useRevealSecret();

  const [revealItem, setRevealItem] = useState<VaultItem | null>(null);
  const [historyItem, setHistoryItem] = useState<VaultItem | null>(null);

  const backendDownError = [stats.error, items.error, events.error].find(
    (error) => error !== null && error !== undefined && isBackendDown(error),
  );

  /** Who acts: the real session principal (open mode reports `open`). */
  const actor = whoami?.principal ?? 'console';

  function runAction(kind: VaultActionKind, item: VaultItem) {
    action.mutate({ kind, itemId: item.id, actor });
  }

  function closeReveal(open: boolean) {
    if (!open) {
      reveal.reset(); // never keep plaintext around after the modal closes
      setRevealItem(null);
    }
  }

  return (
    <div className="flex w-full flex-col gap-space-xl pt-space-xl">
      <section className="flex flex-col gap-space-sm">
        <Chip>{t('vault.kicker')}</Chip>
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          {t('vault.title')}
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          {t('vault.subtitle')}
        </p>
      </section>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {/* Vault posture KPIs: server-computed aggregate, absent = em-dash. */}
      <section>
        <SectionHeader title={t('vault.kpis.heading')} />
        <SectionBody query={stats}>{(data) => <VaultStatsKpis stats={data} />}</SectionBody>
      </section>

      {/* Inventory with the per-row lifecycle actions. */}
      <section>
        <SectionHeader
          title={t('vault.inventory.heading')}
          subtitle={t('vault.inventory.subtitle')}
        />
        {/* Mutation feedback: the server's own message, verbatim. */}
        {action.isSuccess ? (
          <p role="status" className="mt-space-md font-body-sm text-body-sm text-tertiary">
            {t('vault.states.actionDone', { message: action.data.message })}
          </p>
        ) : null}
        {action.isError ? (
          <p role="alert" className="mt-space-md font-body-sm text-body-sm text-error">
            {t('vault.states.actionFailed', {
              message: isBackendDown(action.error)
                ? t('errors.backendDown')
                : action.error.message,
            })}
          </p>
        ) : null}
        <div className="mt-space-md overflow-x-auto rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={items}>
            {(data) => (
              <InventoryTable
                items={data.items}
                busy={action.isPending}
                onCheckout={(item) => runAction('checkout', item)}
                onRevoke={(item) => runAction('revoke', item)}
                onRotate={(item) => runAction('rotate', item)}
                onReveal={(item) => setRevealItem(item)}
                onHistory={(item) => setHistoryItem(item)}
              />
            )}
          </SectionBody>
        </div>
      </section>

      {/* Vault audit feed: onboarding, checkouts, revocations, rotations. */}
      <section>
        <SectionHeader
          title={t('vault.events.heading')}
          subtitle={t('vault.events.subtitle')}
        />
        <div className="mt-space-md overflow-hidden rounded-xl bg-surface-container-lowest shadow-sm">
          <SectionBody query={events}>
            {(data) => <EventsTable events={data.events} />}
          </SectionBody>
        </div>
      </section>

      {/* Reveal modal: plaintext shown once, cleared on close (never cached). */}
      <Modal
        open={revealItem !== null}
        onOpenChange={closeReveal}
        title={t('vault.reveal.title')}
        closeLabel={t('common.close')}
        footer={
          <>
            {revealItem !== null && reveal.data === undefined ? (
              <Button
                icon="visibility"
                onClick={() => reveal.mutate(revealItem.id)}
                disabled={reveal.isPending}
              >
                {t('vault.reveal.confirm')}
              </Button>
            ) : null}
            <Button variant="secondary" onClick={() => closeReveal(false)}>
              {t('vault.reveal.hide')}
            </Button>
          </>
        }
      >
        <RevealBody item={revealItem} reveal={reveal} />
      </Modal>

      {/* History modal: this credential's audit trail (version history). */}
      <Modal
        open={historyItem !== null}
        onOpenChange={(open) => {
          if (!open) setHistoryItem(null);
        }}
        title={t('vault.history.title', { name: historyItem?.name ?? '' })}
        closeLabel={t('common.close')}
      >
        <HistoryBody item={historyItem} />
      </Modal>
    </div>
  );
}

/**
 * One honest state machine for every section (F4 per-screen DoD): loading
 * line, verbatim section error, the brief §3.2 "not connected" chip for
 * transport failures (the shared banner sits above), and the real content
 * once the contract answers.
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
      <p className="p-space-md font-body-sm text-body-sm text-outline">
        {t('vault.states.loading')}
      </p>
    );
  }
  if (query.error !== null && query.error !== undefined) {
    if (isBackendDown(query.error)) return <NotConnected />;
    const message =
      query.error instanceof Error ? query.error.message : String(query.error);
    return (
      <p role="alert" className="p-space-md font-body-sm text-body-sm text-error">
        {t('vault.states.sectionError', { message })}
      </p>
    );
  }
  if (query.data === undefined) return null;
  return <>{children(query.data)}</>;
}

/** Posture KPI quad: total, rotation compliance, checked out, failures. */
function VaultStatsKpis({ stats }: { stats: VaultStats }) {
  const { t } = useTranslation();
  return (
    <div className="mt-space-md grid grid-cols-1 gap-space-lg sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('vault.kpis.total')}
        value={stats.total}
        accent="primary"
        footer={t('vault.kpis.totalFooter', { versions: stats.secrets.versions })}
      />
      <KpiCard
        label={t('vault.kpis.compliance')}
        value={
          stats.rotation.compliance_pct !== undefined
            ? `${stats.rotation.compliance_pct}%`
            : null
        }
        accent="tertiary"
        footer={t('vault.kpis.complianceFooter', {
          due: stats.rotation.due ?? 0,
          onDemand: stats.rotation.on_demand ?? 0,
        })}
      />
      <KpiCard
        label={t('vault.kpis.checkedOut')}
        value={stats.checked_out}
        accent={stats.checked_out > 0 ? 'primary-container' : 'primary'}
        footer={t('vault.kpis.checkedOutFooter', {
          checkouts: stats.events_today.checkouts ?? 0,
          rotations: stats.events_today.rotations ?? 0,
        })}
      />
      <KpiCard
        label={t('vault.kpis.failures')}
        value={stats.attention.failed ?? null}
        accent={(stats.attention.failed ?? 0) > 0 ? 'error' : 'primary-container'}
        footer={t('vault.kpis.failuresFooter', { failed: stats.attention.failed ?? 0 })}
      />
    </div>
  );
}

/** Server status -> the as-built dot state (text label always renders too). */
const STATUS_DOT: Record<VaultItemStatus, DotState> = {
  available: 'ok',
  rotation_due: 'live',
  rotating: 'live',
  checked_out: 'muted',
  failed: 'error',
};

/** Inventory table: credential, type, target, principal, SLA and actions. */
function InventoryTable({
  items,
  busy,
  onCheckout,
  onRevoke,
  onRotate,
  onReveal,
  onHistory,
}: {
  items: VaultItem[];
  busy: boolean;
  onCheckout: (item: VaultItem) => void;
  onRevoke: (item: VaultItem) => void;
  onRotate: (item: VaultItem) => void;
  onReveal: (item: VaultItem) => void;
  onHistory: (item: VaultItem) => void;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<VaultItem>[] = [
    {
      key: 'credential',
      header: t('vault.inventory.credential'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-body-md text-body-md text-on-surface">{row.name}</span>
          <Value value={row.description} />
        </div>
      ),
    },
    {
      key: 'type',
      header: t('vault.inventory.type'),
      render: (row) => <Chip>{row.secret_type}</Chip>,
    },
    {
      key: 'target',
      header: t('vault.inventory.target'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm">{row.target}</span>
          <Value value={row.target_detail} />
        </div>
      ),
    },
    {
      key: 'principal',
      header: t('vault.inventory.principal'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm">{row.principal}</span>
          {row.access_tier !== undefined ? (
            <span className="font-body-sm text-body-sm text-outline">
              {t('vault.inventory.tier', { tier: row.access_tier })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'sla',
      header: t('vault.inventory.rotation'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="font-body-sm text-body-sm">{row.rotation_interval_label}</span>
          {row.status === 'failed' ? (
            <span className="font-body-sm text-body-sm text-error">
              {t('vault.inventory.statusLabels.failed')}
            </span>
          ) : row.status === 'rotating' ? (
            <span className="font-body-sm text-body-sm text-on-surface-variant">
              {t('vault.inventory.statusLabels.rotating')}
            </span>
          ) : row.rotation_hours_remaining !== null &&
            row.rotation_hours_remaining !== undefined ? (
            <span className="font-body-sm text-body-sm text-outline">
              {t('vault.inventory.rotationDueIn', { hours: row.rotation_hours_remaining })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'status',
      header: t('vault.inventory.status'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="inline-flex items-center gap-1.5 font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
            <StatusDot state={STATUS_DOT[row.status]} />
            {t(`vault.inventory.statusLabels.${row.status}`)}
          </span>
          {row.status === 'checked_out' && row.checked_out_by ? (
            <span className="font-body-sm text-body-sm text-outline">
              {t('vault.inventory.checkedOutBy', { who: row.checked_out_by })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('vault.inventory.actions'),
      render: (row) => (
        <div className="flex flex-wrap items-center gap-space-xs">
          {row.status === 'checked_out' ? (
            <Button
              icon="lock_open"
              ariaLabel={t('vault.inventory.actionsUi.named', {
                action: t('vault.inventory.actionsUi.revoke'),
                name: row.name,
              })}
              disabled={busy}
              onClick={() => onRevoke(row)}
            >
              {t('vault.inventory.actionsUi.revoke')}
            </Button>
          ) : row.status === 'rotating' ? (
            <Button disabled ariaLabel={t('vault.inventory.actionsUi.locked')}>
              {t('vault.inventory.actionsUi.locked')}
            </Button>
          ) : (
            <>
              <Button
                icon="key"
                ariaLabel={t('vault.inventory.actionsUi.named', {
                  action: t('vault.inventory.actionsUi.checkout'),
                  name: row.name,
                })}
                disabled={busy}
                onClick={() => onCheckout(row)}
              >
                {t('vault.inventory.actionsUi.checkout')}
              </Button>
              <Button
                icon="autorenew"
                ariaLabel={t('vault.inventory.actionsUi.named', {
                  action:
                    row.status === 'failed'
                      ? t('vault.inventory.actionsUi.retry')
                      : t('vault.inventory.actionsUi.rotate'),
                  name: row.name,
                })}
                disabled={busy}
                onClick={() => onRotate(row)}
              >
                {row.status === 'failed'
                  ? t('vault.inventory.actionsUi.retry')
                  : t('vault.inventory.actionsUi.rotate')}
              </Button>
            </>
          )}
          <Button
            variant="secondary"
            icon="visibility"
            ariaLabel={t('vault.inventory.actionsUi.named', {
              action: t('vault.inventory.actionsUi.reveal'),
              name: row.name,
            })}
            onClick={() => onReveal(row)}
          >
            {t('vault.inventory.actionsUi.reveal')}
          </Button>
          <Button
            variant="secondary"
            icon="history"
            ariaLabel={t('vault.inventory.actionsUi.named', {
              action: t('vault.inventory.actionsUi.history'),
              name: row.name,
            })}
            onClick={() => onHistory(row)}
          >
            {t('vault.inventory.actionsUi.history')}
          </Button>
        </div>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(row) => String(row.id)}
      caption={t('vault.inventory.caption')}
      emptyMessage={t('vault.inventory.empty')}
    />
  );
}

/** Audit feed table: time, action, credential, actor and secret version. */
function EventsTable({ events }: { events: VaultEvent[] }) {
  const { t } = useTranslation();
  const columns: DataTableColumn<VaultEvent>[] = [
    {
      key: 'time',
      header: t('vault.events.time'),
      render: (row) => <Value value={formatTime(row.created_at)} />,
    },
    {
      key: 'action',
      header: t('vault.events.action'),
      render: (row) => <Chip>{row.action}</Chip>,
    },
    {
      key: 'credential',
      header: t('vault.events.credential'),
      render: (row) => <span className="font-body-sm text-body-sm">{row.item_name}</span>,
    },
    {
      key: 'actor',
      header: t('vault.events.actor'),
      render: (row) => <Value value={row.actor} />,
    },
    {
      key: 'version',
      header: t('vault.events.version'),
      render: (row) => {
        const version = row.detail?.secret_version;
        return typeof version === 'number' ? (
          <span className="font-code-sm text-code-sm">v{version}</span>
        ) : (
          <Value value={null} />
        );
      },
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={events}
      rowKey={(row) => String(row.id)}
      caption={t('vault.events.caption')}
      emptyMessage={t('vault.events.empty')}
    />
  );
}

/** Reveal modal body: prompt, honest pending/error, then the plaintext once. */
function RevealBody({
  item,
  reveal,
}: {
  item: VaultItem | null;
  reveal: ReturnType<typeof useRevealSecret>;
}) {
  const { t } = useTranslation();
  if (item === null) return null;
  if (reveal.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-outline">{t('vault.states.loading')}</p>
    );
  }
  if (reveal.isError) {
    const message = isBackendDown(reveal.error)
      ? t('errors.backendDown')
      : reveal.error.message;
    return (
      <p role="alert" className="font-body-sm text-body-sm text-error">
        {t('vault.states.actionFailed', { message })}
      </p>
    );
  }
  if (reveal.data === undefined) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('vault.reveal.prompt', { name: item.name })}
      </p>
    );
  }
  return <RevealResult reveal={reveal.data} />;
}

/** The revealed value with its honest entropy label and provenance. */
function RevealResult({ reveal }: { reveal: SecretReveal }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-space-md">
      <p
        className="rounded-lg bg-surface-container-high p-space-md font-code-md text-code-md break-all select-all"
        data-testid="revealed-secret"
      >
        {reveal.secret}
      </p>
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('vault.reveal.entropy', { bits: reveal.entropy_bits })}
      </p>
      <p className="font-code-sm text-code-sm text-outline">
        {t('vault.reveal.version', {
          version: reveal.version,
          alg: reveal.alg,
          source: reveal.source,
        })}
      </p>
      <p className="font-code-sm text-code-sm text-outline">
        {t('vault.reveal.storedAt', {
          time: formatTime(reveal.rotated_at) ?? '—',
        })}
      </p>
    </div>
  );
}

/** History modal body: the credential's own events (version history). */
function HistoryBody({ item }: { item: VaultItem | null }) {
  const { t } = useTranslation();
  const detail = useVaultItemDetail(item?.id ?? null);
  if (item === null) return null;
  if (detail.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-outline">{t('vault.states.loading')}</p>
    );
  }
  if (detail.error !== null && detail.error !== undefined) {
    const message = isBackendDown(detail.error)
      ? t('errors.backendDown')
      : detail.error.message;
    return (
      <p role="alert" className="font-body-sm text-body-sm text-error">
        {t('vault.states.sectionError', { message })}
      </p>
    );
  }
  const events = (detail.data?.item.events ?? []) as VaultEvent[];
  return <HistoryEvents events={events} name={item.name} detail={detail.data} />;
}

/** The version-history table inside the history modal. */
function HistoryEvents({
  events,
  name,
  detail,
}: {
  events: VaultEvent[];
  name: string;
  detail: VaultItemDetail | undefined;
}) {
  const { t } = useTranslation();
  const columns: DataTableColumn<VaultEvent>[] = [
    {
      key: 'time',
      header: t('vault.events.time'),
      render: (row) => <Value value={formatTime(row.created_at)} />,
    },
    {
      key: 'action',
      header: t('vault.events.action'),
      render: (row) => (
        <div className="flex flex-col gap-1">
          <Chip>{row.action}</Chip>
          {typeof row.detail?.reason === 'string' ? (
            <span className="font-code-sm text-code-sm text-outline">
              {row.detail.reason}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'actor',
      header: t('vault.events.actor'),
      render: (row) => <Value value={row.actor} />,
    },
    {
      key: 'version',
      header: t('vault.events.version'),
      render: (row) => {
        const version = row.detail?.secret_version;
        return typeof version === 'number' ? (
          <span className="font-code-sm text-code-sm">
            {t('vault.history.version', { version })}
          </span>
        ) : (
          <Value value={null} />
        );
      },
    },
  ];
  return (
    <div className="flex flex-col gap-space-md">
      {detail?.item.secret_version !== null && detail?.item.secret_version !== undefined ? (
        <p className="font-code-sm text-code-sm text-outline">
          {t('vault.history.version', { version: detail.item.secret_version })}
        </p>
      ) : null}
      <DataTable
        columns={columns}
        rows={events}
        rowKey={(row) => String(row.id)}
        caption={t('vault.history.caption', { name })}
        emptyMessage={t('vault.history.empty')}
      />
    </div>
  );
}
