import { useTranslation } from 'react-i18next';

import { Chip, DataTable, SectionHeader } from '../../components';
import type { LicenseEvent, LicenseRecord, Meta } from '../../api/generated/models';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import { SectionBody } from './SectionBody';
import { useLicenseDetail } from './queries';

/**
 * Feature-local narrow views of the contract's free-form members. The
 * spec types `quotas`/`usage`/`usage_limits` as open maps (the server
 * owns the field set), so the screen documents the exact shapes the
 * live rig answers (Temp/opencode/cap10 captures) and degrades honestly
 * when a field is absent - never a fabricated number.
 */
export interface QuotaUsage {
  consumed: number;
  headroom: number;
  quota: number;
  utilization: number;
  over_quota: boolean;
}

export interface QuotaPool {
  id: string;
  name: string;
  regions: string[];
  enforcement: string;
  quota_nodes: number;
}

export interface UsagePool extends QuotaPool {
  consumed: number;
  headroom: number;
  utilization: number;
  over_quota: boolean;
}

export interface LicenseQuotas {
  nodes?: number;
  concurrent_sessions?: number;
  bastion_tunnels?: number;
  max_lease_hours?: number;
  worm_retention_days?: number;
  pools?: QuotaPool[];
}

export interface LicenseUsage {
  nodes?: QuotaUsage;
  concurrent_sessions?: QuotaUsage;
  bastion_tunnels?: QuotaUsage;
  pools?: UsagePool[];
}

/** A module catalog row as the record carries it (name/detail/status). */
export interface LicenseModule {
  id: string;
  name?: string;
  detail?: string;
  description?: string;
  status?: string;
  entitled?: boolean | string;
  [key: string]: unknown;
}

/** Read the free-form members through the narrow views (defensive casts). */
function readQuotas(license: LicenseRecord): LicenseQuotas {
  return (license.quotas ?? {}) as LicenseQuotas;
}
function readUsage(license: LicenseRecord): LicenseUsage {
  return (license.usage ?? {}) as LicenseUsage;
}
function readModules(license: LicenseRecord): LicenseModule[] {
  return (license.modules ?? []) as LicenseModule[];
}
function readUsageLimits(license: LicenseRecord): Record<string, unknown> {
  return (license.usage_limits ?? {}) as Record<string, unknown>;
}

/**
 * One utilization meter (the legacy "Node Quota Breakdown" rows): the
 * real consumed/quota numbers, a bar scaled to the server's own
 * `utilization` (0..1), and the `over_quota` flag read verbatim - an
 * over-quota row reads error, never clamped to a pretty 100%.
 */
function UsageMeter({
  label,
  usage,
  unitKey,
}: {
  label: string;
  usage: QuotaUsage | undefined;
  unitKey: string;
}) {
  const { t } = useTranslation();
  if (!usage) {
    return (
      <div className="flex flex-col gap-1">
        <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
          {label}
        </span>
        <span className="font-body-sm text-body-sm text-outline">
          {t('licensing.detail.noTelemetry')}
        </span>
      </div>
    );
  }
  const pct = Math.round(usage.utilization * 100);
  return (
    <div className="flex flex-col gap-1" data-testid={`lic-meter-${label}`}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
          {label}
        </span>
        <span className="font-code-sm text-code-sm font-semibold text-on-surface">
          {usage.consumed}/{usage.quota}
          {t(unitKey)} {usage.over_quota ? '⚠' : ''}
        </span>
      </div>
      <div
        role="meter"
        aria-valuenow={usage.consumed}
        aria-valuemin={0}
        aria-valuemax={usage.quota}
        aria-label={`${label} ${usage.consumed}/${usage.quota}`}
        className="h-2 w-full overflow-hidden rounded-full bg-surface-container-high"
      >
        <div
          className={`h-full rounded-full ${usage.over_quota ? 'bg-error' : 'bg-primary'}`}
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      <span className="font-body-sm text-body-sm text-outline">
        {t('licensing.detail.meterLine', {
          pct,
          headroom: usage.headroom,
        })}
      </span>
    </div>
  );
}

/** The activity timeline: the server's own event rows, verbatim. */
function ActivityTimeline({ events }: { events: LicenseEvent[] }) {
  const { t } = useTranslation();
  if (events.length === 0) {
    return (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('licensing.detail.noEvents')}
      </p>
    );
  }
  return (
    <ol className="flex flex-col gap-2">
      {events.map((event) => (
        <li key={event.id} className="flex flex-col gap-0.5">
          <div className="flex flex-wrap items-baseline gap-2">
            <Chip tone={event.action === 'revoked' ? 'inactive' : 'info'}>
              {event.action}
            </Chip>
            <span className="font-code-sm text-code-sm text-outline">
              {event.created_at}
            </span>
          </div>
          {event.detail ? (
            <span className="font-code-sm text-code-sm text-on-surface-variant">
              {JSON.stringify(event.detail)}
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

/**
 * The license inspector (F4 screen 10): the legacy sections "Active
 * Feature Entitlements & Subsystems", "Node Quota Breakdown by
 * Environment & Connector Mesh", "License Payload Signature" and
 * "Recent License Activity", all fed by the contract's own record -
 * identity and status, the 8-module entitlement grid with the server's
 * entitled/not-entitled status per module, the quota meters and the
 * pool-by-environment table (enforcement level included), the payload
 * signature block (algorithm / wire format / fingerprint) and the event
 * timeline. Lifecycle actions (revoke/restore, signed file, offline
 * validate) live on the page and operate on the selected key.
 */
export function LicenseDetailSection({
  licenseKey,
  meta,
  onRevoke,
  onRestore,
  onShowFile,
  onValidate,
  onStatus,
}: {
  licenseKey: string | null;
  meta: Meta | undefined;
  onRevoke: (license: LicenseRecord) => void;
  onRestore: (license: LicenseRecord) => void;
  onShowFile: (license: LicenseRecord) => void;
  onValidate: (license: LicenseRecord) => void;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: revoke/restore are administrator-class - the auditor who picked the
  // key still gets the signed file, but the lifecycle writes show the reason.
  const canRevoke = canOperate(ACTION_OPS.licenseRevoke, whoami);
  const canRestore = canOperate(ACTION_OPS.licenseRestore, whoami);
  const detail = useLicenseDetail(licenseKey);

  if (licenseKey === null) {
    return (
      <div className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('licensing.detail.title')}
          subtitle={t('licensing.detail.subtitle')}
        />
        <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
          {t('licensing.detail.noSelection')}
        </p>
      </div>
    );
  }

  const poolColumns = [
    {
      key: 'pool',
      header: t('licensing.detail.colPool'),
      render: (row: UsagePool) => (
        <div className="font-code-sm text-code-sm">
          <span className="font-semibold text-on-surface">{row.name}</span>
          <div className="text-outline">{row.id}</div>
        </div>
      ),
    },
    {
      key: 'regions',
      header: t('licensing.detail.colRegions'),
      render: (row: UsagePool) => (
        <span className="font-body-sm text-body-sm text-on-surface-variant">
          {row.regions.join(', ')}
        </span>
      ),
    },
    {
      key: 'enforcement',
      header: t('licensing.detail.colEnforcement'),
      render: (row: UsagePool) => <Chip tone="info">{row.enforcement}</Chip>,
    },
    {
      key: 'quota',
      header: t('licensing.detail.colQuota'),
      render: (row: UsagePool) => (
        <span className="font-code-sm text-code-sm">
          {row.consumed}/{row.quota_nodes}
        </span>
      ),
    },
    {
      key: 'meter',
      header: t('licensing.detail.colUtilization'),
      render: (row: UsagePool) => (
        <div className="flex min-w-36 flex-col gap-1">
          <div className="h-2 w-full overflow-hidden rounded-full bg-surface-container-high">
            <div
              className={`h-full rounded-full ${row.over_quota ? 'bg-error' : 'bg-primary'}`}
              style={{ width: `${Math.min(100, Math.round(row.utilization * 100))}%` }}
            />
          </div>
          <span className="font-code-sm text-code-sm text-outline">
            {Math.round(row.utilization * 100)}% · {row.headroom}
          </span>
        </div>
      ),
    },
    {
      key: 'state',
      header: t('licensing.detail.colState'),
      render: (row: UsagePool) => (
        <Chip tone={row.over_quota ? 'inactive' : 'info'}>
          {row.over_quota
            ? t('licensing.detail.overQuota')
            : t('licensing.detail.withinQuota')}
        </Chip>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-space-md" data-testid="licensing-detail">
      <SectionHeader
        title={t('licensing.detail.title')}
        subtitle={t('licensing.detail.subtitle')}
      />
      <SectionBody query={detail}>
        {(data) => {
          const license = data.license;
          const quotas = readQuotas(license);
          const usage = readUsage(license);
          const modules = readModules(license);
          const limits = readUsageLimits(license);
          const events = license.events ?? [];
          const quotaFields = [
            {
              key: 'nodes',
              label: t('licensing.detail.nodes'),
              unitKey: 'licensing.detail.unitNodes',
            },
            {
              key: 'concurrent_sessions',
              label: t('licensing.detail.sessions'),
              unitKey: 'licensing.detail.unitSessions',
            },
            {
              key: 'bastion_tunnels',
              label: t('licensing.detail.tunnels'),
              unitKey: 'licensing.detail.unitTunnels',
            },
          ] as const;
          return (
            <div className="flex flex-col gap-space-lg">
              {/* Identity */}
              <div className="grid gap-space-md rounded-lg border border-outline-variant/30 p-space-md md:grid-cols-3">
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.licenseId')}
                  </span>
                  <span className="font-code-sm text-code-sm font-semibold text-on-surface">
                    {license.license_id ?? '—'}
                  </span>
                  <span className="font-code-sm text-code-sm text-outline">
                    {license.license_key}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.issuedTo')}
                  </span>
                  <span className="font-body-sm text-body-sm text-on-surface">
                    {license.issued_to ?? '—'}
                  </span>
                  <span className="font-body-sm text-body-sm text-outline">
                    {license.classification ?? license.subject_entity ?? '—'}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.tierPlan')}
                  </span>
                  <span className="font-body-sm text-body-sm text-on-surface">
                    {license.tier ?? '—'}
                    {license.plan ? ` · ${license.plan}` : ''}
                  </span>
                  <span className="font-body-sm text-body-sm text-outline">
                    {license.license_type} · {license.issuer ?? '—'}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.status')}
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip
                      tone={
                        license.effective_status === 'revoked' ||
                        license.effective_status === 'expired'
                          ? 'inactive'
                          : 'info'
                      }
                    >
                      {license.effective_status}
                    </Chip>
                    <span className="font-body-sm text-body-sm text-outline">
                      {t('licensing.detail.rawStatus', { status: license.status })}
                    </span>
                  </div>
                  {license.revoked_reason ? (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {license.revoked_reason}
                    </span>
                  ) : null}
                </div>
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.validity')}
                  </span>
                  <span className="font-body-sm text-body-sm text-on-surface">
                    {t('licensing.detail.issuedOn', { date: license.issued_date ?? '—' })}
                  </span>
                  <span className="font-body-sm text-body-sm text-outline">
                    {license.expires_on
                      ? t('licensing.detail.expiresOn', {
                          date: license.expires_on,
                          days: license.days_until_expiry ?? 0,
                        })
                      : t('licensing.detail.noExpiry')}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.detail.usageReported')}
                  </span>
                  <span className="font-body-sm text-body-sm text-on-surface">
                    {license.last_reported_at ?? t('licensing.detail.neverReported')}
                  </span>
                </div>
              </div>

              {/* Entitlements */}
              <section aria-label={t('licensing.detail.entitlements')}>
                <h3 className="font-title-md text-title-md text-on-surface">
                  {t('licensing.detail.entitlements')}
                </h3>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('licensing.detail.entitlementsHint', {
                    entitled: modules.filter(
                      (module) => module.entitled === true || module.status === 'entitled',
                    ).length,
                    total: meta?.modules.length ?? modules.length,
                  })}
                </p>
                <div className="mt-2 grid gap-space-sm sm:grid-cols-2">
                  {modules.map((module) => {
                    const entitled =
                      module.entitled === true || module.status === 'entitled';
                    return (
                      <div
                        key={module.id}
                        className="flex items-start justify-between gap-2 rounded border border-outline-variant/30 p-space-sm"
                      >
                        <div className="flex flex-col">
                          <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                            {module.name ?? module.id}
                          </span>
                          <span className="font-body-sm text-body-sm text-outline">
                            {module.detail ?? module.description ?? ''}
                          </span>
                        </div>
                        <Chip tone={entitled ? 'info' : 'inactive'}>
                          {entitled
                            ? t('licensing.detail.entitled')
                            : t('licensing.detail.notEntitled')}
                        </Chip>
                      </div>
                    );
                  })}
                  {modules.length === 0 ? (
                    <p className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('licensing.detail.noModules')}
                    </p>
                  ) : null}
                </div>
              </section>

              {/* Quota breakdown */}
              <section aria-label={t('licensing.detail.quotas')}>
                <h3 className="font-title-md text-title-md text-on-surface">
                  {t('licensing.detail.quotas')}
                </h3>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('licensing.detail.quotasHint')}
                </p>
                <div className="mt-2 grid gap-space-md sm:grid-cols-3">
                  {quotaFields.map((field) => (
                    <UsageMeter
                      key={field.key}
                      label={field.label}
                      unitKey={field.unitKey}
                      usage={usage[field.key]}
                    />
                  ))}
                </div>
                <div className="mt-2 grid gap-space-sm sm:grid-cols-3">
                  {quotas.max_lease_hours !== undefined ? (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('licensing.detail.maxLease', { hours: quotas.max_lease_hours })}
                    </span>
                  ) : null}
                  {quotas.worm_retention_days !== undefined ? (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('licensing.detail.wormRetention', {
                        days: quotas.worm_retention_days,
                      })}
                    </span>
                  ) : null}
                  {Object.entries(limits).map(([limitKey, limitValue]) => (
                    <span
                      key={limitKey}
                      className="font-body-sm text-body-sm text-on-surface-variant"
                    >
                      {limitKey}: {String(limitValue)}
                    </span>
                  ))}
                </div>
                {usage.pools && usage.pools.length > 0 ? (
                  <div className="mt-3 overflow-x-auto rounded-lg border border-outline-variant/30">
                    <DataTable
                      columns={poolColumns}
                      rows={usage.pools}
                      rowKey={(row) => row.id}
                      caption={t('licensing.detail.poolsCaption')}
                    />
                  </div>
                ) : (
                  <p className="mt-3 font-body-sm text-body-sm text-on-surface-variant">
                    {t('licensing.detail.noPools')}
                  </p>
                )}
              </section>

              {/* Payload signature */}
              <section
                aria-label={t('licensing.detail.signature')}
                className="rounded-lg border border-outline-variant/30 p-space-md"
              >
                <h3 className="font-title-md text-title-md text-on-surface">
                  {t('licensing.detail.signature')}
                </h3>
                <dl className="mt-2 grid gap-space-sm sm:grid-cols-2">
                  <div className="flex flex-col">
                    <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                      {t('licensing.detail.algorithm')}
                    </dt>
                    <dd className="font-code-sm text-code-sm text-on-surface">
                      {license.algorithm ?? '—'}
                    </dd>
                  </div>
                  <div className="flex flex-col">
                    <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                      {t('licensing.detail.format')}
                    </dt>
                    <dd className="font-code-sm text-code-sm text-on-surface">
                      {license.signature_format ?? '—'}
                    </dd>
                  </div>
                  <div className="flex flex-col sm:col-span-2">
                    <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                      {t('licensing.detail.fingerprint')}
                    </dt>
                    <dd className="break-all font-code-sm text-code-sm text-on-surface">
                      {license.fingerprint ?? '—'}
                    </dd>
                  </div>
                </dl>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => onShowFile(license)}
                    className="rounded border border-outline-variant/60 px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider text-on-surface hover:bg-surface-container-high"
                  >
                    {t('licensing.detail.showFile')}
                  </button>
                  <button
                    type="button"
                    onClick={() => onValidate(license)}
                    className="rounded border border-outline-variant/60 px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider text-on-surface hover:bg-surface-container-high"
                  >
                    {t('licensing.detail.validateOffline')}
                  </button>
                  {license.status === 'active' ? (
                    <button
                      type="button"
                      disabled={!canRevoke}
                      title={canRevoke ? undefined : t('roleReasons.administrator')}
                      onClick={() => {
                        onStatus(null);
                        onRevoke(license);
                      }}
                      className="rounded border border-error/60 px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider text-error hover:bg-error/10 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {t('licensing.detail.revoke')}
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={!canRestore}
                      title={canRestore ? undefined : t('roleReasons.administrator')}
                      onClick={() => {
                        onStatus(null);
                        onRestore(license);
                      }}
                      className="rounded border border-outline-variant/60 px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider text-on-surface hover:bg-surface-container-high disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {t('licensing.detail.restore')}
                    </button>
                  )}
                </div>
              </section>

              {/* Recent activity */}
              <section aria-label={t('licensing.detail.activity')}>
                <h3 className="font-title-md text-title-md text-on-surface">
                  {t('licensing.detail.activity')}
                </h3>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('licensing.detail.activityHint')}
                </p>
                <div className="mt-2">
                  <ActivityTimeline events={events} />
                </div>
              </section>
            </div>
          );
        }}
      </SectionBody>
    </div>
  );
}
