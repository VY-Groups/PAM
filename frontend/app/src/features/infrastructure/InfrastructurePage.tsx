import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import { Chip, KpiCard, SectionHeader } from '../../components';
import { formatRelative } from '../../lib/format';
import { AssetsSection } from './AssetsSection';
import { ConnectorsSection } from './ConnectorsSection';
import { ScansSection } from './ScansSection';
import { SectionBody } from './SectionBody';
import { useCloudStats, useDiscoveryEvents, useDiscoveryStats } from './queries';

/**
 * Target Infrastructure (F4 screen 7, plan §4 line 109: "Scans, assets,
 * cloud connectors") - the React successor of
 * `target_infrastructure_connectors/code.html`.
 *
 * Parity: the real scan trigger + scan history, the target inventory
 * with PAM-status/type chips and search (server-side contract
 * parameters), per-target Ignore/Restore/adopt actions, the privileged
 * accounts list, the cloud connector fleet with probe/discover/remove
 * and add, and the discovery event tape. Every number and message
 * renders from the API; absent data is the honest em-dash or an honest
 * empty line. The legacy screen's "Connector Mesh Health" and the
 * Inventory/RBAC connector tabs are not here: the plan scope names
 * scans/assets/cloud connectors, and the gateway mesh has its own
 * contract surface for a later screen.
 */
export function InfrastructurePage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const actor = whoami?.principal ?? 'console';

  const stats = useDiscoveryStats();
  const cloudStats = useCloudStats();
  const events = useDiscoveryEvents();

  const backendDownError = [stats, cloudStats, events].find(
    (q) => q.error !== null && q.error !== undefined && isBackendDown(q.error),
  )?.error;

  // A non-transport stats failure must surface its message verbatim,
  // not just the honest em-dash KPIs (per-screen DoD 2).
  const statsError = [stats, cloudStats]
    .map((q) => q.error)
    .find((e) => e !== null && e !== undefined && !isBackendDown(e));

  const s = stats.data;
  const c = cloudStats.data;
  const byPam = s?.by_pam_status ?? {};

  /* -------------------------------------------------------------- kpis */
  const kpis = (
    <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('infrastructure.kpis.assets')}
        value={s?.total ?? null}
        footer={
          s
            ? t('infrastructure.kpis.assetsFooter', {
                managed: byPam.managed ?? 0,
                ignored: byPam.ignored ?? 0,
                unmanaged: byPam.unmanaged ?? 0,
              })
            : t('infrastructure.kpis.assetsFooterNone')
        }
        accent="primary"
      />
      <KpiCard
        label={t('infrastructure.kpis.accounts')}
        value={s?.accounts_total ?? null}
        footer={t('infrastructure.kpis.accountsFooter')}
        accent="tertiary"
      />
      <KpiCard
        label={t('infrastructure.kpis.scans')}
        value={s?.scans.total ?? null}
        footer={
          s?.scans.last
            ? t('infrastructure.kpis.scansFooter', {
                scope: s.scans.last.scope,
                status: s.scans.last.status,
              })
            : t('infrastructure.kpis.scansFooterNone')
        }
        accent="primary-container"
      />
      <KpiCard
        label={t('infrastructure.kpis.connectors')}
        value={c?.connectors ?? null}
        footer={
          c
            ? t('infrastructure.kpis.connectorsFooter', {
                connected: c.by_status.connected ?? 0,
                error: c.by_status.error ?? 0,
                configured: c.by_status.configured ?? 0,
                unprobed: c.by_status['not connected'] ?? 0,
              })
            : t('infrastructure.kpis.connectorsFooterNone')
        }
        accent={c && (c.by_status.error ?? 0) > 0 ? 'error' : 'primary'}
      />
    </div>
  );

  /* ------------------------------------------------------------- render */
  return (
    <div className="flex flex-col gap-space-lg">
      <div className="flex flex-col gap-space-md">
        <div className="flex flex-wrap items-center gap-space-sm">
          <Chip>{t('infrastructure.kicker')}</Chip>
          <span className="font-code-sm text-code-sm text-on-surface-variant">
            {t('infrastructure.line')}{' '}
            <span className="font-semibold text-on-surface">
              {s
                ? t('infrastructure.lineValue', {
                    total: s.total,
                    types: Object.keys(s.by_type).length,
                    accounts: s.accounts_total,
                  })
                : '—'}
            </span>
          </span>
        </div>
        <div className="flex max-w-3xl flex-col gap-space-xs">
          <h1 className="font-headline-xl text-headline-xl font-bold text-on-surface">
            {t('infrastructure.title')}
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {t('infrastructure.subtitle')}
          </p>
        </div>
      </div>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {statsError ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {t('infrastructure.states.sectionError', {
            message: statsError instanceof Error ? statsError.message : String(statsError),
          })}
        </p>
      ) : null}

      {kpis}

      <ScansSection />
      <AssetsSection />
      <ConnectorsSection actor={actor} />

      {/* Discovery event stream (the legacy screen's live tape). */}
      <div className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('infrastructure.events.title')}
          subtitle={t('infrastructure.events.subtitle')}
          actions={
            events.data
              ? t('infrastructure.events.count', {
                  shown: events.data.events.length,
                  total: events.data.total,
                })
              : undefined
          }
        />
        <SectionBody query={events}>
          {(data) =>
            data.events.length === 0 ? (
              <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
                {t('infrastructure.events.empty')}
              </p>
            ) : (
              <div className="flex flex-col gap-space-sm">
                {data.events.map((e) => (
                  <div
                    key={e.seq}
                    className="flex flex-col gap-space-xs rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm"
                  >
                    <div className="flex flex-wrap items-center gap-space-sm">
                      <span className="font-code-sm text-code-sm text-outline">
                        #{e.seq}
                      </span>
                      <Chip tone="info">{e.source}</Chip>
                      <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                        {e.action}
                      </span>
                      <span className="font-body-sm text-body-sm text-on-surface-variant">
                        {e.subject}
                      </span>
                      <span className="ml-auto font-body-sm text-body-sm text-outline">
                        {e.actor} · {formatRelative(e.created_at) ?? '—'}
                      </span>
                      <span
                        className="font-code-sm text-code-sm text-outline"
                        title={e.event_hash}
                      >
                        {e.event_hash.slice(0, 12)}…
                      </span>
                    </div>
                    {e.detail && typeof e.detail === 'object' ? (
                      <span className="font-code-sm text-code-sm text-outline">
                        {Object.entries(e.detail)
                          .slice(0, 2)
                          .map(
                            ([k, v]) =>
                              `${k}=${(typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)).slice(0, 40)}`,
                          )
                          .join('  ')}
                      </span>
                    ) : null}
                  </div>
                ))}
              </div>
            )
          }
        </SectionBody>
      </div>
    </div>
  );
}
