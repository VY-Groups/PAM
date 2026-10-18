import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { Button, Chip, DataTable, KpiCard, SectionHeader } from '../../components';
import type {
  ClusterBackup,
  ClusterNode,
  ClusterReplicasNodes,
} from '../../api/generated/models';
import { postApiV1ClusterFailover } from '../../api/generated';
import { expectOk, isBackendDown } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import { FeedbackLine } from './SettingsGroupActions';
import { settingsAgo } from './ago';
import { useClusterBackups, useClusterOverview } from './queries';

interface NodeRow {
  id: number;
  name: string;
  site: string;
  role: string;
  health: string;
}

/** One replica row: what THIS node pulled from one peer, never merged. */
interface ReplicaRow {
  peer: string;
  held: ClusterReplicasNodes[string];
}

/**
 * HA / DC / DR Cluster posture (screen 11, ADR-0015). The read surface is
 * the legacy `platform_settings_center` page's own - summary line, role
 * badge, four posture tiles, registered-node table, replica posture and
 * the backup ledger - all from `GET /api/v1/cluster` +
 * `GET /api/v1/cluster/backups` over the verbatim rig shape the topology
 * network view already renders.
 *
 * 11.5 (the flip): this section carries the standing gate's whole 6a
 * contract - the same `data-role` hooks and honest-state regexes the
 * legacy page was held to, no `id=` anywhere - so the gate reads THIS
 * page now. The failover control is real: `window.confirm` with the
 * legacy's verbatim questions, then `POST /api/v1/cluster/failover` with
 * the legacy's reason (`platform settings ui`), and an honest feedback
 * line either way. Register / probe / sync / New Backup stay strangled:
 * they are not in the gate contract and join a later slice.
 *
 * A pristine node reports `peers`/`backups` as absent rather than
 * zero-filled (the ADR-0015 honest-state rule), so every counter is read
 * through optional chaining and shown as an honest 0 or em-dash - never
 * as an invented peer count. Before the overview settles the tiles show
 * the em-dash, not a zero that would claim "no peers".
 */
export function ClusterPostureSection() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const overview = useClusterOverview();
  const backups = useClusterBackups();
  const [feedback, setFeedback] = useState<{ tone: 'error' | 'ok'; text: string } | null>(
    null,
  );

  // The sibling actions' honest error arm (SettingsGroupActions): a dead
  // backend says so, anything else shows the server's own refusal.
  const failoverErrorText = (error: unknown): string => {
    if (isBackendDown(error)) return t('settings.forms.actions.unreachable');
    if (error instanceof Error) return error.message;
    return t('settings.forms.actions.unreachable');
  };

  const failover = useMutation({
    mutationFn: async (action: 'promote' | 'demote') =>
      expectOk(await postApiV1ClusterFailover({ action, reason: 'platform settings ui' }))
        .data,
    onSuccess: (body) => {
      setFeedback({
        tone: 'ok',
        text: t('settings.cluster.failoverDone', {
          from: body.from,
          node: body.node,
          to: body.to,
        }),
      });
      // The legacy handler reloads health + cluster: the overview (role
      // badge, label, summary) and the ledger re-read together here.
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsCluster });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsClusterBackups });
    },
    onError: (error) => setFeedback({ tone: 'error', text: failoverErrorText(error) }),
  });

  if (overview.isError) {
    return (
      <section
        className="flex flex-col gap-space-md"
        data-role="cluster-section"
        data-testid="settings-cluster"
      >
        <SectionHeader
          subtitle={t('settings.cluster.subtitle')}
          title={t('settings.cluster.title')}
        />
        <p
          role="alert"
          className="font-body-sm text-body-sm text-error"
          data-testid="settings-cluster-error"
        >
          {t('settings.cluster.unreachable')}
        </p>
      </section>
    );
  }

  const cluster = overview.data;
  const nodes: ClusterNode[] = cluster?.nodes ?? [];
  const peers = cluster?.peers?.total ?? 0;
  const self = cluster?.self;
  // Replication/backups counters are optional in the contract and absent
  // on a pristine node - read honestly as 0, never invented (ADR-0015).
  const byHealth = cluster?.peers?.by_health ?? {};
  const totals = cluster?.replication?.totals ?? {};
  const healthy = byHealth.healthy ?? 0;
  const audit = totals.audit ?? 0;
  const vault = totals.vault ?? 0;
  const sessions = totals.sessions ?? 0;
  const backupCount = cluster?.backups?.total ?? 0;

  const nodeRows: NodeRow[] = nodes.map((node) => ({
    id: node.id,
    name: node.name,
    role: node.role,
    site: node.site,
    health: node.health,
  }));

  const replicaRows: ReplicaRow[] = Object.entries(cluster?.replication?.nodes ?? {}).map(
    ([peer, held]) => ({ held, peer }),
  );

  const backupRows = backups.data?.backups ?? [];

  // Legacy `renderCluster` wiring: active flips to Demote, anything else
  // to Promote; before the read settles the label is the honest em-dash.
  const role = self?.role;
  const action: 'promote' | 'demote' = role === 'active' ? 'demote' : 'promote';
  const failoverLabel = role
    ? t(action === 'demote' ? 'settings.cluster.demote' : 'settings.cluster.promote')
    : '\u2014';
  const requestFailover = () => {
    const question =
      action === 'demote'
        ? t('settings.cluster.confirmDemote')
        : t('settings.cluster.confirmPromote');
    if (!window.confirm(question)) return;
    setFeedback(null);
    failover.mutate(action);
  };

  return (
    <section
      className="flex flex-col gap-space-md"
      data-role="cluster-section"
      data-testid="settings-cluster"
    >
      <SectionHeader
        subtitle={t('settings.cluster.subtitle')}
        title={t('settings.cluster.title')}
      />

      <p
        className="font-code-sm text-code-sm text-on-surface-variant"
        data-role="cluster-summary"
        data-testid="settings-cluster-summary"
      >
        {self
          ? t('settings.cluster.summary', {
              audit,
              backups: backupCount,
              healthy,
              name: self.name,
              peerWord: `${peers} ${t(
                peers === 1
                  ? 'settings.cluster.summarySingular'
                  : 'settings.cluster.summaryPlural',
              )}`,
              role: self.role,
              sessions,
              site: self.site,
              vault,
            })
          : ''}
      </p>

      {/* role badge + the real failover control (the gate's 6a reads both) */}
      <div className="flex flex-wrap items-center gap-space-sm">
        <Chip dataRole="cluster-role">{role ?? '\u2014'}</Chip>
        <Button
          disabled={!role || failover.isPending}
          icon="swap_horiz"
          onClick={requestFailover}
          type="button"
        >
          <span data-role="cluster-failover-label">{failoverLabel}</span>
        </Button>
      </div>
      <FeedbackLine feedback={feedback} />

      {/* four posture tiles, all numbers from the aggregate */}
      <div className="grid grid-cols-2 gap-space-sm lg:grid-cols-4">
        <KpiCard
          footer={
            cluster
              ? t('settings.cluster.tileSelfSub', {
                  auth: self?.auth ?? '\u2014',
                  role: role ?? '\u2014',
                })
              : null
          }
          label={t('settings.cluster.tileSelf')}
          value={
            cluster && self
              ? `${self.name}${self.site ? ' \u00b7 ' + self.site : ''}`
              : null
          }
          valueDataRole="cluster-tile-self"
        />
        <KpiCard
          footer={
            cluster
              ? t('settings.cluster.tilePeersSub', {
                  degraded: byHealth.degraded ?? 0,
                  healthy,
                  unknown: byHealth.unknown ?? 0,
                  unreachable: byHealth.unreachable ?? 0,
                })
              : null
          }
          label={t('settings.cluster.tilePeers')}
          value={cluster ? String(peers) : null}
          valueDataRole="cluster-tile-peers"
        />
        <KpiCard
          footer={
            cluster
              ? t('settings.cluster.tileReplicationSub', {
                  sessions,
                  vault,
                })
              : null
          }
          label={t('settings.cluster.tileReplication')}
          value={cluster ? String(audit) : null}
          valueDataRole="cluster-tile-replication"
        />
        <KpiCard
          footer={
            cluster
              ? t('settings.cluster.tileBackupsSub', {
                  verified: cluster.backups?.verified ?? 0,
                })
              : null
          }
          label={t('settings.cluster.tileBackups')}
          value={cluster ? String(backupCount) : null}
          valueDataRole="cluster-tile-backups"
        />
      </div>

      <DataTable
        bodyDataRole="cluster-rows"
        caption={t('settings.cluster.nodesCaption')}
        columns={[
          {
            key: 'name',
            header: t('settings.cluster.columns.name'),
            render: (row: NodeRow) => row.name,
          },
          {
            key: 'site',
            header: t('settings.cluster.columns.site'),
            render: (row: NodeRow) => row.site,
          },
          {
            key: 'role',
            header: t('settings.cluster.columns.role'),
            render: (row: NodeRow) => row.role,
          },
          {
            key: 'health',
            header: t('settings.cluster.columns.health'),
            render: (row: NodeRow) => row.health,
          },
        ]}
        emptyMessage={t('settings.cluster.nodesEmpty')}
        rows={nodeRows}
        rowKey={(row) => String(row.id)}
      />

      {/* replica posture: what THIS node pulled, verbatim legacy cells */}
      <h3 className="font-headline-sm text-headline-sm text-on-surface">
        {t('settings.cluster.replicaTitle')}
      </h3>
      <DataTable
        bodyDataRole="cluster-replica-rows"
        caption={t('settings.cluster.replicaCaption')}
        columns={[
          {
            key: 'peer',
            header: t('settings.cluster.columns.peer'),
            render: (row: ReplicaRow) => (
              <span className="font-code-sm text-code-sm font-medium">{row.peer}</span>
            ),
          },
          {
            key: 'audit',
            header: t('settings.cluster.columns.audit'),
            render: (row: ReplicaRow) => {
              const heldAudit = row.held.audit ?? {};
              const unverified = heldAudit.unverified ?? 0;
              return (
                <span
                  className={`font-code-sm text-code-sm ${
                    unverified ? 'text-error font-medium' : 'text-on-surface-variant'
                  }`}
                >
                  {unverified
                    ? t('settings.cluster.replicaAuditUnverified', {
                        records: heldAudit.records ?? 0,
                        unverified,
                        verified: heldAudit.verified ?? 0,
                      })
                    : t('settings.cluster.replicaAudit', {
                        records: heldAudit.records ?? 0,
                        verified: heldAudit.verified ?? 0,
                      })}
                </span>
              );
            },
          },
          {
            key: 'vault',
            header: t('settings.cluster.columns.vault'),
            render: (row: ReplicaRow) =>
              t('settings.cluster.replicaVault', {
                decryptable: row.held.vault?.decryptable_here ?? 0,
                secrets: row.held.vault?.secrets ?? 0,
              }),
          },
          {
            key: 'sessions',
            header: t('settings.cluster.columns.sessions'),
            render: (row: ReplicaRow) => String(row.held.sessions ?? 0),
          },
          {
            key: 'synced',
            header: t('settings.cluster.columns.synced'),
            render: (row: ReplicaRow) => settingsAgo(row.held.last_synced_at, t),
          },
        ]}
        emptyMessage={t('settings.cluster.replicasEmpty')}
        rows={replicaRows}
        rowKey={(row) => row.peer}
      />

      <h3 className="font-headline-sm text-headline-sm text-on-surface">
        {t('settings.cluster.backupsTitle')}
      </h3>
      <DataTable
        bodyDataRole="cluster-backup-rows"
        caption={t('settings.cluster.backupsCaption')}
        columns={[
          {
            key: 'path',
            header: t('settings.cluster.columns.backup'),
            render: (row: ClusterBackup) => row.path,
          },
          {
            key: 'size',
            header: t('settings.cluster.columns.size'),
            render: (row: ClusterBackup) =>
              t('settings.cluster.sizeBytes', { bytes: row.size_bytes }),
          },
          {
            key: 'seq',
            header: t('settings.cluster.columns.auditSeq'),
            render: (row: ClusterBackup) => String(row.audit_seq),
          },
          {
            key: 'verified',
            header: t('settings.cluster.columns.verified'),
            render: (row: ClusterBackup) =>
              t(
                row.verified
                  ? 'settings.cluster.verifiedYes'
                  : 'settings.cluster.verifiedNo',
              ),
          },
        ]}
        emptyMessage={t('settings.cluster.backupsEmpty')}
        rows={backupRows}
        rowKey={(row) => String(row.id)}
      />
    </section>
  );
}
