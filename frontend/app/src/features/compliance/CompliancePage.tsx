import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { Button, Chip, KpiCard, SectionHeader } from '../../components';
import type { EventFeedSource } from '../../api/generated/models';
import { EventFeedSource as SOURCES } from '../../api/generated/models';
import { formatRelative, formatTime } from '../../lib/format';
import { buildAuditCsv, parseNdjson } from './csv';
import { SectionBody } from './SectionBody';
import {
  useAuditEvents,
  useAuditStats,
  useExportLedger,
  useIntegrationsStatus,
  useVerifyChain,
} from './queries';

/** The trail's filter chips: `all` first, then the contract's enum order. */
const TRAIL_SOURCES: readonly EventFeedSource[] = [
  'all',
  ...Object.values(SOURCES).filter((s): s is EventFeedSource => s !== 'all'),
];

/**
 * Compliance & SOC2 (F4 screen 6, plan §4 line 111: "Ledger digest,
 * verify walk, export, source chips") - the React successor of
 * `compliance_soc_2_audit_center/code.html`.
 *
 * Parity: the honest digest card (chain head + window, correctly
 * labelled a hash chain - not a Merkle tree, which the legacy screen
 * also corrected at runtime), the on-demand verify walk with the
 * server's verdict verbatim, the connector chips (SIEM push state from
 * `GET /integrations/status`), the source-filtered unified trail and
 * the full-ledger CSV export. Every number renders from the API; absent
 * data is the honest em-dash. The legacy design's fabricated controls
 * matrix / TSC radar / probe values do not exist here at all - only the
 * five contract-backed reads this screen owns.
 */
export function CompliancePage() {
  const { t } = useTranslation();

  const stats = useAuditStats();
  const [source, setSource] = useState<EventFeedSource>('all');
  const events = useAuditEvents(source);
  const integrations = useIntegrationsStatus();
  const verify = useVerifyChain();
  const exportLedger = useExportLedger();

  const [status, setStatus] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const backendDownError = [stats, events, integrations].find(
    (q) => q.error !== null && q.error !== undefined && isBackendDown(q.error),
  )?.error;

  const s = stats.data;
  const bySource = s?.by_source ?? {};
  const sourceKeys = Object.keys(bySource);
  const sourcesReporting = sourceKeys.filter((k) => (bySource[k] ?? 0) > 0).length;
  const headShort = s?.head_hash ? `${s.head_hash.slice(0, 12)}…` : null;

  /* ------------------------------------------------------------ export */
  const onExport = () => {
    setExportError(null);
    exportLedger.mutate(undefined, {
      onSuccess: (text) => {
        try {
          const records = parseNdjson(text);
          const blob = new Blob([buildAuditCsv(records)], { type: 'text/csv' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `audit-events-${new Date().toISOString().slice(0, 10)}.csv`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          setStatus(t('compliance.toast.exported', { count: records.length }));
        } catch {
          // A malformed NDJSON line never silently becomes an empty file.
          setStatus(null);
          setExportError(t('compliance.toast.exportMalformed'));
        }
      },
      onError: (err) => {
        setStatus(null);
        setExportError(err instanceof Error ? err.message : String(err));
      },
    });
  };

  /* --------------------------------------------------------- connectors */
  const siem = integrations.data?.siem;
  const siemPush = siem?.last_push;

  /* -------------------------------------------------------------- kpis */
  const kpis = (
    <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('compliance.kpis.records')}
        value={s?.total ?? null}
        footer={
          s && s.oldest_at && s.newest_at
            ? t('compliance.kpis.recordsFooter', {
                oldest: formatTime(s.oldest_at) ?? '—',
                newest: formatTime(s.newest_at) ?? '—',
              })
            : t('compliance.kpis.recordsFooterNone')
        }
        accent="primary"
      />
      <KpiCard
        label={t('compliance.kpis.depth')}
        value={s?.last_seq ?? null}
        footer={
          headShort
            ? t('compliance.kpis.depthFooter', { hash: headShort })
            : t('compliance.kpis.depthFooterNone')
        }
        accent="tertiary"
      />
      <KpiCard
        label={t('compliance.kpis.sources')}
        value={s ? sourcesReporting : null}
        footer={s ? t('compliance.kpis.sourcesFooter', { total: sourceKeys.length }) : '—'}
        accent="primary-container"
      />
      <KpiCard
        label={t('compliance.kpis.triggers')}
        value={
          s
            ? s.trigger_protection
              ? t('compliance.kpis.triggersInstalled')
              : t('compliance.kpis.triggersMissing')
            : null
        }
        footer={t('compliance.kpis.triggersFooter')}
        accent={s?.trigger_protection ? 'tertiary' : 'error'}
      />
    </div>
  );

  /* ----------------------------------------------------- verify panel */
  let verifyPanel;
  if (verify.isPending) {
    verifyPanel = (
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {t('compliance.verify.running')}
      </p>
    );
  } else if (verify.error !== null && verify.error !== undefined) {
    verifyPanel = (
      <p role="alert" className="font-body-sm text-body-sm text-error">
        {t('compliance.verify.failed', {
          message:
            verify.error instanceof Error ? verify.error.message : String(verify.error),
        })}
      </p>
    );
  } else if (verify.data) {
    verifyPanel = verify.data.intact ? (
      <p
        role="status"
        className="font-code-sm text-code-sm text-tertiary"
        data-testid="verify-result"
      >
        {t('compliance.verify.ok', {
          checked: verify.data.checked,
          total: verify.data.total,
          hash: `${verify.data.head_hash.slice(0, 12)}…`,
        })}
      </p>
    ) : (
      <p
        role="alert"
        className="font-code-sm text-code-sm text-error"
        data-testid="verify-result"
      >
        {t('compliance.verify.broken', {
          brokenAt: verify.data.broken_at ?? '—',
          reason: verify.data.reason ?? '—',
        })}
      </p>
    );
  } else {
    verifyPanel = (
      <p className="font-body-sm text-body-sm text-outline">
        {t('compliance.verify.idle')}
      </p>
    );
  }

  /* ------------------------------------------------------------- render */
  return (
    <div className="flex flex-col gap-space-lg">
      <div className="flex flex-col gap-space-md">
        <div className="flex flex-wrap items-center gap-space-sm">
          <Chip>{t('compliance.kicker')}</Chip>
          <span className="font-code-sm text-code-sm text-on-surface-variant">
            {t('compliance.chainLine')}{' '}
            <span className="font-semibold text-on-surface">
              {s
                ? t('compliance.chainLineValue', {
                    seq: s.last_seq,
                    hash: headShort ?? '—',
                  })
                : '—'}
            </span>
          </span>
        </div>
        <div className="flex flex-col gap-space-md xl:flex-row xl:items-start xl:justify-between">
          <div className="flex max-w-3xl flex-col gap-space-xs">
            <h1 className="font-headline-xl text-headline-xl font-bold text-on-surface">
              {t('compliance.title')}
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant">
              {t('compliance.subtitle')}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-space-sm">
            <Button
              type="button"
              icon="download"
              onClick={onExport}
              disabled={exportLedger.isPending}
            >
              {exportLedger.isPending
                ? t('compliance.actions.exporting')
                : t('compliance.actions.export')}
            </Button>
          </div>
        </div>
        <p
          role="status"
          aria-live="polite"
          className="min-h-5 font-code-sm text-code-sm text-tertiary"
        >
          {status ?? ''}
        </p>
        <p
          role="alert"
          className={`min-h-5 font-code-sm text-code-sm text-error${exportError ? '' : ' hidden'}`}
        >
          {exportError ?? ''}
        </p>
      </div>

      <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />

      {kpis}

      <div className="grid grid-cols-1 items-start gap-space-lg lg:grid-cols-12">
        {/* Left: hash-chain digest + verify walk */}
        <div className="flex flex-col gap-space-md lg:col-span-7">
          <SectionHeader
            title={t('compliance.digest.title')}
            subtitle={t('compliance.digest.subtitle')}
            actions={
              <Button
                type="button"
                variant="secondary"
                icon="verified"
                onClick={() => verify.mutate(undefined)}
                disabled={verify.isPending}
              >
                {verify.isPending
                  ? t('compliance.actions.verifying')
                  : t('compliance.actions.verify')}
              </Button>
            }
          />
          <div className="flex flex-col gap-space-md rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
            <SectionBody query={stats}>
              {(digest) => (
                <>
                  <div className="flex flex-col gap-space-xs">
                    <span className="font-label-md text-label-md text-on-surface-variant">
                      {t('compliance.digest.chainHead')}
                    </span>
                    <span className="font-code-sm text-code-sm break-all text-on-surface">
                      {digest.head_hash || '—'}
                    </span>
                  </div>
                  <div className="mt-space-sm flex flex-wrap items-center gap-space-sm">
                    <Chip tone="info">
                      {t('compliance.digest.seq', { seq: digest.last_seq })}
                    </Chip>
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {digest.oldest_at && digest.newest_at
                        ? t('compliance.digest.window', {
                            oldest: formatTime(digest.oldest_at) ?? '—',
                            newest: formatTime(digest.newest_at) ?? '—',
                          })
                        : t('compliance.digest.windowNone')}
                    </span>
                  </div>
                  <div
                    className="mt-space-md flex flex-wrap items-center gap-space-sm border-t border-outline-variant/20 pt-space-md"
                    role="group"
                    aria-label={t('compliance.digest.sourcesLabel')}
                  >
                    {Object.entries(digest.by_source).map(([name, count]) => (
                      <Chip key={name} tone={count > 0 ? 'info' : 'inactive'}>
                        {`${name} ${count}`}
                      </Chip>
                    ))}
                  </div>
                </>
              )}
            </SectionBody>
            <div className="mt-space-md border-t border-outline-variant/30 pt-space-md">
              {verifyPanel}
            </div>
          </div>
        </div>

        {/* Right: connector chips (the contract's compliance chips) */}
        <div className="flex flex-col gap-space-md lg:col-span-5">
          <SectionHeader
            title={t('compliance.connectors.title')}
            subtitle={t('compliance.connectors.subtitle')}
          />
          <SectionBody query={integrations}>
            {(data) => (
              <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
                {[
                  {
                    key: 'mfa',
                    chip: data.mfa.configured
                      ? t('compliance.connectors.configured')
                      : t('compliance.connectors.notConfigured'),
                    detail: data.mfa.configured
                      ? t('compliance.connectors.mfaEnrolled', {
                          who: data.mfa.enrolled_for || '—',
                        })
                      : data.mfa.gate,
                  },
                  {
                    key: 'itsm',
                    chip: data.itsm.configured
                      ? t('compliance.connectors.configured')
                      : t('compliance.connectors.notConnected'),
                    detail: data.itsm.configured ? data.itsm.base_url : data.itsm.detail,
                  },
                  {
                    key: 'siem',
                    chip: data.siem.state,
                    detail: data.siem.detail ?? '',
                  },
                  {
                    key: 'ldap',
                    chip: data.ldap.configured
                      ? t('compliance.connectors.configured')
                      : t('compliance.connectors.notConnected'),
                    detail: data.ldap.configured ? data.ldap.server : data.ldap.detail,
                  },
                ].map((row) => (
                  <div
                    key={row.key}
                    className="flex items-start justify-between gap-space-sm border-b border-outline-variant/20 pb-space-sm last:border-b-0 last:pb-0"
                  >
                    <span className="font-label-badge text-label-badge uppercase tracking-wider text-on-surface">
                      {row.key}
                    </span>
                    <div className="flex flex-col items-end gap-1 text-right">
                      <Chip
                        tone={
                          row.chip === 'not connected' ||
                          row.chip === 'not configured' ||
                          row.chip === 'error'
                            ? 'inactive'
                            : 'info'
                        }
                      >
                        {row.chip}
                      </Chip>
                      <span className="font-code-sm text-code-sm text-on-surface-variant">
                        {row.detail}
                      </span>
                      {row.key === 'siem' && siemPush ? (
                        <span className="font-code-sm text-code-sm text-outline">
                          {siemPush.last_push_status === 'never'
                            ? t('compliance.connectors.pushNever')
                            : t('compliance.connectors.pushLine', {
                                status: siemPush.last_push_status,
                                at: formatTime(siemPush.last_push_at) ?? '—',
                                ok: siemPush.batches_ok,
                                failed: siemPush.batches_failed,
                                records: siemPush.records_pushed,
                              })}
                        </span>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </SectionBody>
        </div>
      </div>

      {/* Unified trail with source chips */}
      <div className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('compliance.trail.title')}
          subtitle={t('compliance.trail.subtitle')}
          actions={
            events.data
              ? t('compliance.trail.count', {
                  shown: events.data.events.length,
                  total: events.data.total,
                })
              : undefined
          }
        />
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('compliance.trail.filterLabel')}
        >
          {TRAIL_SOURCES.map((s2) => (
            <button
              key={s2}
              type="button"
              aria-pressed={source === s2}
              onClick={() => setSource(s2)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                source === s2
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {s2 === 'all' ? t('compliance.trail.filterAll') : s2}
            </button>
          ))}
        </div>
        <SectionBody query={events}>
          {(data) =>
            data.events.length === 0 ? (
              <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
                {t('compliance.trail.empty')}
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
