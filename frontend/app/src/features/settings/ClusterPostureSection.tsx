import { useTranslation } from 'react-i18next';

import { DataTable, SectionHeader } from '../../components';
import type { ClusterBackup, ClusterNode } from '../../api/generated/models';
import { useClusterBackups, useClusterOverview } from './queries';

interface NodeRow {
  id: number;
  name: string;
  site: string;
  role: string;
  health: string;
}

/**
 * HA / DC / DR Cluster posture (screen 11, ADR-0015). A read-only view
 * of `GET /api/v1/cluster` plus the `GET /api/v1/cluster/backups`
 * ledger: the summary line, the registered-node table and the backup
 * table, all from the same verbatim rig shape the topology network view
 * already renders.
 *
 * A pristine node reports `peers`/`backups` as absent rather than
 * zero-filled (the ADR-0015 honest-state rule), so every counter is read
 * through optional chaining and shown as an honest 0 or em-dash - never
 * as an invented peer count. The interactive cluster actions (register,
 * failover, sync) join in 11.4; this slice only reads.
 */
export function ClusterPostureSection() {
  const { t } = useTranslation();
  const overview = useClusterOverview();
  const backups = useClusterBackups();

  if (overview.isError) {
    return (
      <section className="flex flex-col gap-space-md" data-testid="settings-cluster">
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

  const backupRows = backups.data?.backups ?? [];

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-cluster">
      <SectionHeader
        subtitle={t('settings.cluster.subtitle')}
        title={t('settings.cluster.title')}
      />

      <p
        className="font-body-sm text-body-sm text-on-surface-variant"
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

      <DataTable
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

      <h3 className="font-headline-sm text-headline-sm text-on-surface">
        {t('settings.cluster.backupsTitle')}
      </h3>
      <DataTable
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
