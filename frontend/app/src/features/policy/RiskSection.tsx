import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Chip, KpiCard, SectionHeader, Value } from '../../components';
import type { RiskEvaluation } from '../../api/generated/models';
import { formatRelative } from '../../lib/format';
import { SectionBody } from './SectionBody';
import { useRiskEvaluations, useRiskStats, useScoreRequest } from './queries';
import { scoreSchema, type ScoreForm, type ScoreValues } from './schemas';

/**
 * Section 7 risk engine + its score tool (plan §4 line 110 "risk"). The
 * eight component caps and the band legend are architecture spec
 * constants rendered as static legend text (the legacy screen says so
 * too) - every *runtime* number (totals, scores, points, details,
 * decisions) comes from `/api/v1/risk/*`. Scoring posts on click only
 * (ADR-0006 for the form, contract limits mirrored exactly).
 */

const BAND_CLASS: Record<string, string> = {
  low: 'bg-surface-container text-tertiary',
  medium: 'bg-surface-container-high text-primary',
  high: 'bg-error-container text-on-error-container',
  critical: 'bg-error text-on-error',
};

function bandChip(band: string): string {
  return `shrink-0 px-1.5 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
    BAND_CLASS[band] ?? 'bg-surface-container text-on-surface-variant'
  }`;
}

/** The eight scorer rows: static label + spec cap, live points/detail. */
function useComponentRows() {
  const { t } = useTranslation();
  return [
    {
      key: 'user',
      label: t('policy.risk.components.user'),
      cap: t('policy.risk.caps.user'),
    },
    {
      key: 'device',
      label: t('policy.risk.components.device'),
      cap: t('policy.risk.caps.device'),
    },
    {
      key: 'asset',
      label: t('policy.risk.components.asset'),
      cap: t('policy.risk.caps.asset'),
    },
    {
      key: 'time',
      label: t('policy.risk.components.time'),
      cap: t('policy.risk.caps.time'),
    },
    {
      key: 'location',
      label: t('policy.risk.components.location'),
      cap: t('policy.risk.caps.location'),
    },
    {
      key: 'behavior',
      label: t('policy.risk.components.behavior'),
      cap: t('policy.risk.caps.behavior'),
    },
    {
      key: 'ticket',
      label: t('policy.risk.components.ticket'),
      cap: t('policy.risk.caps.ticket'),
    },
    {
      key: 'command',
      label: t('policy.risk.components.command'),
      cap: t('policy.risk.caps.command'),
    },
  ];
}

export function RiskSection({ actor }: { actor: string }) {
  const { t } = useTranslation();
  const stats = useRiskStats();
  const recent = useRiskEvaluations();
  const score = useScoreRequest();

  const form = useForm<ScoreForm, unknown, ScoreValues>({
    resolver: zodResolver(scoreSchema),
    defaultValues: {
      subject: '',
      target: '',
      device: '',
      source_ip: '',
      ticket: '',
      command: '',
    },
  });
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = form;

  const onSubmit = handleSubmit((values) => {
    score.mutate({
      actor,
      payload: {
        subject: values.subject,
        ...(values.target === '' ? {} : { target: values.target }),
        ...(values.device === '' ? {} : { device: values.device }),
        ...(values.source_ip === '' ? {} : { source_ip: values.source_ip }),
        ...(values.ticket === '' ? {} : { ticket: values.ticket }),
        ...(values.command === '' ? {} : { command: values.command }),
      },
    });
  });

  const s = stats.data;
  const evaluated = score.data?.evaluation ?? null;
  const componentRows = useComponentRows();
  const pointsOf = (key: string): number | null =>
    evaluated?.components.find((c) => c.component === key)?.points ?? null;
  const detailOf = (key: string): string | null =>
    evaluated?.components.find((c) => c.component === key)?.detail ?? null;

  const field =
    'w-full rounded bg-surface-container-low px-3 py-1.5 font-code-sm text-code-sm text-on-surface focus:outline-none';

  return (
    <section className="mt-space-xl flex flex-col gap-space-lg">
      <div className="flex flex-col xl:flex-row xl:items-start justify-between gap-space-lg">
        <div className="flex max-w-3xl flex-col gap-space-xs">
          <div className="flex flex-wrap items-center gap-space-sm">
            <Chip>{t('policy.risk.kicker')}</Chip>
            <span className="font-code-sm text-code-sm text-outline">
              {t('policy.risk.recordedLine')}{' '}
              <span className="font-semibold text-on-surface">
                <Value value={s?.total ?? null} />
              </span>
            </span>
          </div>
          <h2 className="font-headline-lg text-headline-lg text-on-surface">
            {t('policy.risk.title')}
          </h2>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {t('policy.risk.subtitle')}
          </p>
        </div>
        <div className="grid w-full shrink-0 grid-cols-2 gap-space-md lg:grid-cols-4 xl:max-w-3xl">
          <KpiCard
            label={t('policy.risk.kpis.evaluations')}
            value={s?.total ?? null}
            footer={
              <>
                {t('policy.risk.kpis.evaluationsSuffix')} ·{' '}
                {t('policy.risk.kpis.lastAt', {
                  rel: formatRelative(s?.last_evaluated_at ?? null) ?? '—',
                })}
              </>
            }
            accent="primary"
          />
          <KpiCard
            label={t('policy.risk.kpis.avgScore')}
            value={s && s.avg_score !== null ? `${s.avg_score} / 100` : '— / 100'}
            footer={t('policy.risk.kpis.avgSuffix')}
            accent="tertiary"
          />
          <KpiCard
            label={t('policy.risk.kpis.refused')}
            value={s?.refused ?? null}
            footer={t('policy.risk.kpis.refusedSuffix')}
            accent="error"
          />
          <KpiCard
            label={t('policy.risk.kpis.spread')}
            value={
              s
                ? t('policy.risk.kpis.spreadValue', {
                    critical: s.by_band.critical,
                    high: s.by_band.high,
                  })
                : t('policy.risk.kpis.spreadNone')
            }
            footer={t('policy.risk.kpis.spreadSuffix')}
            accent="primary-container"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-space-lg xl:grid-cols-3 items-start">
        {/* Score one access request (POST on click only) */}
        <div className="flex flex-col gap-space-md rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
          <SectionHeader
            title={t('policy.risk.scoreTitle')}
            subtitle={t('policy.risk.scoreAdvises')}
          />
          <form className="flex flex-col gap-space-sm" onSubmit={onSubmit} noValidate>
            <label className="font-code-sm text-code-sm text-outline uppercase">
              {t('policy.risk.fields.subject')}
              <input
                className={field}
                maxLength={160}
                placeholder={t('policy.risk.placeholders.subject')}
                {...register('subject')}
              />
            </label>
            <div className="grid grid-cols-1 gap-space-sm sm:grid-cols-2">
              <label className="font-code-sm text-code-sm text-outline uppercase">
                {t('policy.risk.fields.target')}
                <input
                  className={field}
                  maxLength={255}
                  placeholder={t('policy.risk.placeholders.target')}
                  {...register('target')}
                />
              </label>
              <label className="font-code-sm text-code-sm text-outline uppercase">
                {t('policy.risk.fields.device')}
                <input
                  className={field}
                  maxLength={128}
                  placeholder={t('policy.risk.placeholders.device')}
                  {...register('device')}
                />
              </label>
              <label className="font-code-sm text-code-sm text-outline uppercase">
                {t('policy.risk.fields.sourceIp')}
                <input
                  className={field}
                  maxLength={64}
                  placeholder={t('policy.risk.placeholders.sourceIp')}
                  {...register('source_ip')}
                />
              </label>
              <label className="font-code-sm text-code-sm text-outline uppercase">
                {t('policy.risk.fields.ticket')}
                <input
                  className={field}
                  maxLength={64}
                  placeholder={t('policy.risk.placeholders.ticket')}
                  {...register('ticket')}
                />
              </label>
            </div>
            <label className="font-code-sm text-code-sm text-outline uppercase">
              {t('policy.risk.fields.command')}
              <textarea
                className={field}
                rows={2}
                maxLength={1000}
                placeholder={t('policy.risk.placeholders.command')}
                {...register('command')}
              />
            </label>
            <Button type="submit" disabled={score.isPending}>
              {t('policy.risk.score')}
            </Button>
            {errors.subject !== undefined ? (
              <span role="alert" className="font-body-sm text-body-sm text-error">
                {t('policy.risk.invalid')}
              </span>
            ) : null}
            {score.error instanceof Error ? (
              <p role="alert" className="font-body-sm text-body-sm text-error">
                {score.error.message}
              </p>
            ) : null}
          </form>
          {/* Evaluation result */}
          <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-low p-space-md">
            <div className="flex items-center justify-between">
              <span className="font-label-badge text-label-badge uppercase text-outline">
                {t('policy.risk.result.title')}
              </span>
              <span
                className={
                  evaluated
                    ? bandChip(evaluated.band)
                    : 'rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm font-semibold text-on-surface-variant'
                }
              >
                {evaluated ? evaluated.band : '—'}
              </span>
            </div>
            <div className="flex items-baseline gap-space-xs">
              <span className="font-headline-xl text-headline-xl font-bold text-on-surface">
                {evaluated ? `${evaluated.score} / 100` : '— / 100'}
              </span>
              <span className="font-code-sm text-code-sm text-outline">
                {t('policy.risk.result.score')}
              </span>
            </div>
            <div className="flex flex-wrap gap-x-space-md font-code-sm text-code-sm text-on-surface-variant">
              <span>
                {t('policy.risk.result.decision')}:{' '}
                <span className="font-semibold text-on-surface">
                  {evaluated ? evaluated.decision : '—'}
                </span>
              </span>
              <span>
                {t('policy.risk.result.outcome')}:{' '}
                <span className="font-semibold text-on-surface">
                  {evaluated ? `${evaluated.result} · ${evaluated.context}` : '—'}
                </span>
              </span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {score.data?.message ??
                (evaluated
                  ? t('policy.risk.result.recorded')
                  : t('policy.risk.result.idle'))}
            </p>
          </div>
        </div>

        {/* Component breakdown + spec legend */}
        <div className="flex flex-col gap-space-md">
          <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
            <SectionHeader
              title={t('policy.risk.breakdownTitle')}
              subtitle={t('policy.risk.breakdownHint')}
            />
            <table className="w-full text-left">
              <thead>
                <tr className="font-label-badge text-label-badge uppercase text-outline">
                  <th className="pb-1">{t('policy.risk.table.component')}</th>
                  <th className="pb-1 text-right">{t('policy.risk.table.points')}</th>
                  <th className="pb-1">{t('policy.risk.table.input')}</th>
                </tr>
              </thead>
              <tbody className="font-code-sm text-code-sm">
                {componentRows.map((row) => (
                  <tr key={row.key} className="border-t border-outline-variant/20">
                    <td className="py-1.5 text-on-surface">
                      {row.label} <span className="text-outline">{row.cap}</span>
                    </td>
                    <td className="py-1.5 text-right font-semibold text-on-surface">
                      <Value value={pointsOf(row.key)} />
                    </td>
                    <td className="py-1.5 text-on-surface-variant">
                      <Value value={detailOf(row.key)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-col gap-1 rounded-xl bg-surface-container-high/40 p-space-md">
            <div className="flex items-center justify-between pb-1">
              <span className="font-label-badge text-label-badge uppercase text-outline">
                {t('policy.risk.legend.title')}
              </span>
              <span className="font-code-sm text-code-sm text-outline">
                {t('policy.risk.legend.hint')}
              </span>
            </div>
            {(['low', 'medium', 'high', 'critical'] as const).map((band) => (
              <div
                key={band}
                className="flex items-center justify-between font-code-sm text-code-sm"
              >
                <span className={bandChip(band)}>
                  {t(`policy.risk.legend.${band}` as const)}
                </span>
                <span className="text-on-surface-variant">
                  {t(`policy.risk.legend.${band}Effect` as const)}
                </span>
              </div>
            ))}
            <div className="mt-1 border-t border-outline-variant/30 pt-1 font-code-sm text-code-sm text-outline">
              {t('policy.risk.legend.caps')}
            </div>
          </div>
        </div>

        {/* Recent evaluations + enforcement note */}
        <div className="flex flex-col gap-space-md">
          <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
            <SectionHeader
              title={t('policy.risk.recentTitle')}
              subtitle={t('policy.risk.recentHint')}
            />
            <SectionBody query={recent}>
              {(data) =>
                data.evaluations.length === 0 ? (
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    {t('policy.risk.recentEmpty')}
                  </p>
                ) : (
                  <div>
                    {data.evaluations.map((ev: RiskEvaluation) => (
                      <div
                        key={ev.id}
                        className="flex items-center justify-between gap-space-sm border-b border-outline-variant/20 py-1.5 last:border-0"
                      >
                        <div className="flex min-w-0 items-center gap-2">
                          <span className={bandChip(ev.band)}>{ev.band}</span>
                          <span className="truncate font-code-sm text-code-sm text-on-surface">
                            {ev.subject}
                          </span>
                          <span className="shrink-0 font-code-sm text-code-sm text-outline">
                            {ev.context}
                          </span>
                        </div>
                        <div className="flex shrink-0 items-center gap-space-sm font-code-sm text-code-sm text-on-surface-variant">
                          <span className="font-semibold text-on-surface">{ev.score}</span>
                          <span>{ev.decision}</span>
                          <span
                            className={
                              ev.result === 'refused' ? 'text-error' : 'text-tertiary'
                            }
                          >
                            {ev.result}
                          </span>
                          <span className="text-outline">
                            {formatRelative(ev.created_at) ?? '—'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )
              }
            </SectionBody>
          </div>
          <div className="flex gap-space-sm rounded-xl bg-surface-container-high/40 p-space-md">
            <span className="material-symbols-outlined shrink-0 text-[20px] text-primary">
              policy
            </span>
            <div className="flex flex-col gap-1">
              <span className="font-headline-sm text-headline-sm font-semibold leading-tight text-on-surface">
                {t('policy.risk.enforcementTitle')}
              </span>
              <p className="font-body-sm text-body-sm leading-relaxed text-on-surface-variant">
                {t('policy.risk.enforcementBody')}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
