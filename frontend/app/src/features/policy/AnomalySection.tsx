import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader, Value } from '../../components';
import type { AnomalyIncident, BehaviorBaseline } from '../../api/generated/models';
import { formatRelative } from '../../lib/format';
import { SectionBody } from './SectionBody';
import { useRiskAnomalies, useRiskBaselines, useTrainBaselines } from './queries';

/**
 * Section 11 UEBA layer (plan §4 line 110 "anomalies"): trained
 * baselines, per-reason deviation chips and the incident chain, fed by
 * `GET /api/v1/risk/baselines` and `/risk/anomalies`. Training posts on
 * click only; the status line shows the server's own message verbatim
 * ("Trained N baseline(s) from real history") - nothing is
 * client-estimated, and an empty store says so honestly.
 */

const BAND_CLASS: Record<string, string> = {
  low: 'bg-surface-container text-tertiary',
  medium: 'bg-surface-container-high text-primary',
  high: 'bg-error-container text-on-error-container',
  critical: 'bg-error text-on-error',
};

function bandChip(band: string): string {
  return `shrink-0 px-1.5 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
    BAND_CLASS[band] ?? 'bg-error text-on-error'
  }`;
}

/** One trained baseline row - every field is a real server column. */
function BaselineRow({ row }: { row: BehaviorBaseline }) {
  const { t } = useTranslation();
  const hours = (row.hours ?? []).join(',');
  const priv = row.privilege_verbs ?? [];
  return (
    <div className="border-b border-outline-variant/20 py-1.5 last:border-0">
      <div className="flex items-center justify-between gap-space-sm">
        <span className="truncate font-code-sm text-code-sm font-semibold text-on-surface">
          {row.subject}
        </span>
        <span className="shrink-0 font-code-sm text-code-sm text-outline">
          {t('policy.anomalies.baselineMeta', {
            samples: row.samples,
            perDay: row.sessions_per_day,
          })}
        </span>
      </div>
      <div className="pt-0.5 font-code-sm text-code-sm text-on-surface-variant">
        {t('policy.anomalies.baselineDetail', {
          hours: hours === '' ? '—' : hours,
          devices: (row.devices ?? []).length,
          ips: (row.source_ips ?? []).length,
          targets: (row.targets ?? []).length,
          verbs: (row.command_verbs ?? []).length,
          trained: formatRelative(row.updated_at) ?? '—',
        })}
        {priv.length > 0 ? ` · ${t('policy.anomalies.priv')}${priv.join(',')}` : ''}
      </div>
    </div>
  );
}

/** One anomaly incident - band, parties, deviations, action chain. */
function AnomalyRow({ inc }: { inc: AnomalyIncident }) {
  const { t } = useTranslation();
  const acts = inc.actions ?? {};
  const notes = acts.notes ?? [];
  return (
    <div className="border-b border-outline-variant/20 py-1.5 last:border-0">
      <div className="flex items-center justify-between gap-space-sm">
        <div className="flex min-w-0 items-center gap-2">
          <span className={bandChip(inc.band)}>{inc.band}</span>
          <span className="truncate font-code-sm text-code-sm text-on-surface">
            {inc.subject} → <Value value={inc.target ?? null} />
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-space-sm font-code-sm text-code-sm text-on-surface-variant">
          <span className="font-semibold text-on-surface">{inc.score}</span>
          <span className="text-outline">{formatRelative(inc.created_at) ?? '—'}</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-1 pt-1">
        {(inc.reasons ?? []).map((reason) => (
          <span
            key={reason}
            className="rounded bg-error-container px-1.5 py-0.5 font-code-sm text-code-sm text-on-error-container"
          >
            {t('policy.anomalies.reasonChip', { reason })}
          </span>
        ))}
      </div>
      <div className="pt-1 font-code-sm text-code-sm text-on-surface-variant">
        {acts.blocked
          ? t('policy.anomalies.chainBlocked')
          : t('policy.anomalies.chainNotBlocked')}{' '}
        {t('policy.anomalies.chainCounts', {
          ended: (acts.sessions_ended ?? []).length,
          rotations: (acts.rotations ?? []).length,
        })}
        {notes.length > 0 ? (
          <span className="text-error"> · {notes.join('; ')}</span>
        ) : null}{' '}
        · {inc.incident_ref}
      </div>
    </div>
  );
}

export function AnomalySection({ actor }: { actor: string }) {
  const { t } = useTranslation();
  const baselines = useRiskBaselines();
  const anomalies = useRiskAnomalies();
  const train = useTrainBaselines();
  const [status, setStatus] = useState<string | null>(null);

  const onTrain = () => {
    setStatus(t('policy.anomalies.training'));
    train.mutate(
      { actor },
      {
        onSuccess: (data) =>
          setStatus(data.message || t('policy.anomalies.trainedN', { n: data.trained })),
        onError: (err) => setStatus(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  return (
    <section
      className="mt-space-xl flex flex-col gap-space-lg border-t border-outline-variant/30 pt-space-lg"
      data-role="anomaly-panel"
    >
      <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-space-lg">
        <div className="flex max-w-3xl flex-col gap-space-xs">
          <div className="flex flex-wrap items-center gap-space-sm">
            <Chip>{t('policy.anomalies.kicker')}</Chip>
            <span className="font-code-sm text-code-sm text-outline">
              {t('policy.anomalies.baselinesLine')}{' '}
              <span className="font-semibold text-on-surface">
                <Value value={baselines.data?.baselines.length ?? null} />
              </span>
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {t('policy.anomalies.incidentsLine')}{' '}
              <span className="font-semibold text-on-surface">
                <Value value={anomalies.data?.anomalies.length ?? null} />
              </span>
            </span>
          </div>
          <h3 className="font-headline-lg text-headline-lg text-on-surface">
            {t('policy.anomalies.title')}
          </h3>
          <p className="font-body-sm text-body-sm leading-relaxed text-on-surface-variant">
            {t('policy.anomalies.subtitle')}
          </p>
        </div>
        <div className="flex shrink-0 flex-col gap-space-xs">
          <Button type="button" onClick={onTrain} disabled={train.isPending}>
            {t('policy.anomalies.train')}
          </Button>
          <span role="status" className="text-right font-code-sm text-code-sm text-outline">
            {status ?? t('policy.anomalies.trainHint')}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-space-md lg:grid-cols-2">
        <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
          <SectionHeader
            title={t('policy.anomalies.baselinesTitle')}
            subtitle={t('policy.anomalies.baselinesHint')}
          />
          <SectionBody query={baselines}>
            {(data) =>
              data.baselines.length === 0 ? (
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('policy.anomalies.baselinesEmpty')}
                </p>
              ) : (
                <div>
                  {data.baselines.map((row) => (
                    <BaselineRow key={row.id} row={row} />
                  ))}
                </div>
              )
            }
          </SectionBody>
        </div>
        <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
          <SectionHeader
            title={t('policy.anomalies.anomaliesTitle')}
            subtitle={t('policy.anomalies.anomaliesHint')}
          />
          <SectionBody query={anomalies}>
            {(data) =>
              data.anomalies.length === 0 ? (
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('policy.anomalies.anomaliesEmpty')}
                </p>
              ) : (
                <div>
                  {data.anomalies.map((inc) => (
                    <AnomalyRow key={inc.incident_ref} inc={inc} />
                  ))}
                </div>
              )
            }
          </SectionBody>
        </div>
      </div>
    </section>
  );
}
