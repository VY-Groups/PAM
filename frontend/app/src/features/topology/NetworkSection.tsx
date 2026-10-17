import { useTranslation } from 'react-i18next';

import { Chip, NotConnected, SectionHeader, StatusDot, Value } from '../../components';
import type { DotState } from '../../components';
import { useClusterOverview, useHealth, useTopologyIntegrations } from './queries';

/** Dot state from a measured health string - never optimistic. */
function dotFor(health: string): DotState {
  if (health === 'ok' || health === 'healthy') return 'ok';
  if (health === 'unknown') return 'muted';
  return 'error';
}

/**
 * View 4 - Network (ADR-0013): the only LIVE view. Every figure comes
 * from the running node's own answers - `GET /health`,
 * `GET /api/v1/cluster`, `GET /api/v1/integrations/status` - through
 * the generated client. Loading and transport failure render honestly;
 * nothing here is drawn from memory.
 */
export function NetworkSection() {
  const { t } = useTranslation();
  return (
    <section aria-label={t('topology.network.title')} className="space-y-space-md">
      <SectionHeader
        title={t('topology.network.title')}
        subtitle={t('topology.network.subtitle')}
      />
      <SelfCard />
      <ClusterCard />
      <IntegrationsCard />
    </section>
  );
}

function SelfCard() {
  const { t } = useTranslation();
  const health = useHealth();
  if (health.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('topology.network.loading')}
      </p>
    );
  }
  if (health.isError || !health.data) {
    return (
      <div className="flex items-center gap-space-sm">
        <NotConnected label={t('topology.network.notConnected')} />
        <code className="font-code-sm text-code-sm text-error">
          {health.error?.message}
        </code>
      </div>
    );
  }
  const node = health.data;
  return (
    <div className="rounded-lg border border-outline-variant/30 p-space-md">
      <h3 className="font-title-md text-title-md text-on-surface">
        {t('topology.network.selfTitle')}
      </h3>
      <div className="mt-space-sm flex flex-wrap items-center gap-space-sm font-body-sm text-body-sm text-on-surface">
        <StatusDot state={dotFor(node.status)} />
        <code className="font-code-sm text-code-sm">{node.node}</code>
        <span className="text-on-surface-variant">
          {node.site} · {node.role} · {node.auth}
        </span>
        <Chip>
          {t('topology.network.status')} {node.status}
        </Chip>
        <Chip tone="inactive">
          {t('topology.network.database')} {node.database}
        </Chip>
        <Chip tone="inactive">
          {t('topology.network.keyMaterial')}{' '}
          {node.ed25519_key ? t('topology.network.present') : t('topology.network.absent')}
        </Chip>
      </div>
      <div className="mt-space-sm flex flex-wrap items-center gap-space-xs">
        {node.algorithms.map((algorithm) => (
          <code
            key={algorithm}
            className="rounded bg-surface-container px-space-xs font-code-sm text-code-sm text-on-surface-variant"
          >
            {algorithm}
          </code>
        ))}
        {node.formats.map((format) => (
          <code
            key={format}
            className="rounded bg-surface-container px-space-xs font-code-sm text-code-sm text-on-surface-variant"
          >
            {format}
          </code>
        ))}
        <span className="font-code-sm text-code-sm text-outline">
          {t('topology.network.privateKey')} <Value value={node.private_key} />
        </span>
      </div>
    </div>
  );
}

function ClusterCard() {
  const { t } = useTranslation();
  const cluster = useClusterOverview();
  if (cluster.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('topology.network.loading')}
      </p>
    );
  }
  if (cluster.isError || !cluster.data) {
    return (
      <div className="flex items-center gap-space-sm">
        <NotConnected label={t('topology.network.notConnected')} />
        <code className="font-code-sm text-code-sm text-error">
          {cluster.error?.message}
        </code>
      </div>
    );
  }
  const overview = cluster.data;
  const byHealth = overview.peers.by_health ?? {};
  const peers = [
    ['healthy', byHealth.healthy ?? 0],
    ['degraded', byHealth.degraded ?? 0],
    ['unknown', byHealth.unknown ?? 0],
    ['unreachable', byHealth.unreachable ?? 0],
  ] as const;
  return (
    <div className="rounded-lg border border-outline-variant/30 p-space-md">
      <h3 className="font-title-md text-title-md text-on-surface">
        {t('topology.network.clusterTitle')}
      </h3>
      <div className="mt-space-sm flex flex-wrap items-center gap-space-sm">
        {peers.map(([label, count]) => (
          <Chip
            key={label}
            tone={
              count > 0 && label !== 'healthy' && label !== 'unknown' ? 'info' : 'inactive'
            }
          >
            {t(`topology.network.peers.${label}`)} {count}
          </Chip>
        ))}
      </div>
      <ul className="mt-space-sm space-y-space-xs">
        {overview.nodes.map((node) => (
          <li key={node.id} className="flex flex-wrap items-baseline gap-space-sm">
            <StatusDot state={dotFor(node.health)} />
            <code className="font-code-sm text-code-sm text-on-surface">{node.name}</code>
            <span className="font-body-sm text-body-sm text-on-surface-variant">
              {node.site} · {node.role} · {node.health}
            </span>
            <span className="font-body-sm text-body-sm text-error">
              <Value value={node.last_error} />
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {t('topology.network.lastProbe')} <Value value={node.last_probe_at} />
            </span>
          </li>
        ))}
      </ul>
      <div className="mt-space-sm flex flex-wrap items-center gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
        <span>
          {t('topology.network.replication')} · {t('topology.network.audit')}{' '}
          <Value value={overview.replication.totals.audit} /> ·{' '}
          {t('topology.network.sessions')}{' '}
          <Value value={overview.replication.totals.sessions} /> ·{' '}
          {t('topology.network.vault')} <Value value={overview.replication.totals.vault} />
        </span>
        <span>
          {t('topology.network.backups')} <Value value={overview.backups.total} /> (
          {t('topology.network.verified')} <Value value={overview.backups.verified} />)
        </span>
      </div>
    </div>
  );
}

function IntegrationsCard() {
  const { t } = useTranslation();
  const integrations = useTopologyIntegrations();
  if (integrations.isPending) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('topology.network.loading')}
      </p>
    );
  }
  if (integrations.isError || !integrations.data) {
    return (
      <div className="flex items-center gap-space-sm">
        <NotConnected label={t('topology.network.notConnected')} />
        <code className="font-code-sm text-code-sm text-error">
          {integrations.error?.message}
        </code>
      </div>
    );
  }
  const state = integrations.data;
  const groups = [
    { name: 'ITSM', configured: state.itsm.configured, detail: state.itsm.detail },
    { name: 'LDAP', configured: state.ldap.configured, detail: state.ldap.detail },
    { name: 'MFA', configured: state.mfa.configured, detail: state.mfa.gate },
    { name: 'SIEM', configured: state.siem.configured, detail: state.siem.detail },
  ];
  return (
    <div className="rounded-lg border border-outline-variant/30 p-space-md">
      <h3 className="font-title-md text-title-md text-on-surface">
        {t('topology.network.integrationsTitle')}
      </h3>
      <ul className="mt-space-sm space-y-space-xs">
        {groups.map((group) => (
          <li key={group.name} className="flex flex-wrap items-baseline gap-space-sm">
            <code className="font-code-sm text-code-sm font-semibold text-on-surface">
              {group.name}
            </code>
            <Chip tone={group.configured ? 'info' : 'inactive'}>
              {group.configured
                ? t('topology.network.configured')
                : t('topology.network.notConfigured')}
            </Chip>
            <span className="font-body-sm text-body-sm text-on-surface-variant">
              <Value value={group.detail} />
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
