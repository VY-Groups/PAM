import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import { Button, Chip, KpiCard, Tabs, Value } from '../../components';
import type { TabItem } from '../../components';
import type {
  CommandApproval,
  CommandDecision,
  CommandIncident,
  CommandRule,
} from '../../api/generated/models';
import { formatRelative } from '../../lib/format';
import { AnomalySection } from './AnomalySection';
import { RiskSection } from './RiskSection';
import { RuleDialog } from './RuleDialog';
import { SectionBody } from './SectionBody';
import {
  useCloseIncident,
  useDeleteRule,
  useDryRun,
  usePolicyApprovals,
  usePolicyIncidents,
  usePolicyRules,
  usePolicyStats,
  useResolveApproval,
} from './queries';
import { dryRunSchema, type DryRunForm, type DryRunValues } from './schemas';

/**
 * Policy & Zero Trust (F4 screen 5, plan §4 line 110: "Command rules,
 * risk, anomalies, incidents") - the React successor of
 * `policy_zero_trust_rules_engine/code.html`.
 *
 * Parity: header actions (dry-run, JSON export, create rule), the KPI
 * quad, the three-tab catalog (rules / approvals / incidents) with the
 * filter + evaluation-order lines, the right rail (real dry-run simulator
 * against `POST /command-control/evaluate`, live posture, incident
 * trail jump), then section 7 (eight-component risk scorer) and section
 * 11 (UEBA baselines / anomalies) below. Every number renders from the
 * API; absent data is the honest em-dash. The legacy design's fabricated
 * OPA/Rego/latency/cluster values do not exist here at all.
 *
 * The tab bar remounts via `tabSeed` when the incident-trail teaser
 * jumps tabs (the design-system Tabs is uncontrolled by design - ADR-0003
 * arrow-key navigation stays intact).
 */
export function PolicyPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const actor = whoami?.principal ?? 'console';

  const stats = usePolicyStats();
  const rules = usePolicyRules();
  const approvals = usePolicyApprovals();
  const incidents = usePolicyIncidents();

  const [status, setStatus] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<CommandRule | null>(null);
  const [tabSeed, setTabSeed] = useState(0);
  const [tabDefault, setTabDefault] = useState('rules');

  const deleteRule = useDeleteRule();
  const resolve = useResolveApproval();
  const closeIncident = useCloseIncident();
  const dryRun = useDryRun();

  const backendDownError = [stats, rules, approvals, incidents].find(
    (q) => q.error !== null && q.error !== undefined && isBackendDown(q.error),
  )?.error;

  /* ------------------------------------------------- dry-run simulator */
  const dryForm = useForm<DryRunForm, unknown, DryRunValues>({
    resolver: zodResolver(dryRunSchema),
    defaultValues: { command: '', target: '' },
  });
  const [dryResult, setDryResult] = useState<{
    result: CommandDecision;
    command: string;
    target: string;
  } | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const onDrySubmit = dryForm.handleSubmit((values) => {
    setSimError(null);
    if (stats.error !== null && stats.error !== undefined) {
      setSimError(t('policy.simulator.notConnected'));
      return;
    }
    dryRun.mutate(
      { command: values.command, target: values.target },
      {
        onSuccess: (data) =>
          setDryResult({
            result: data.result,
            command: values.command,
            target: values.target,
          }),
        onError: (err) =>
          setSimError(
            t('policy.simulator.evaluateFailed', {
              message: err instanceof Error ? err.message : String(err),
            }),
          ),
      },
    );
  });

  /* --------------------------------------------------------- export */
  const exportPolicy = () => {
    const items = rules.data?.items ?? [];
    const body = JSON.stringify(
      { engine_hash: stats.data?.engine_hash ?? null, rules: items },
      null,
      2,
    );
    const blob = new Blob([body], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vy-pam-command-policy.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus(t('policy.toast.exported', { count: items.length }));
  };

  /* ------------------------------------------------------------ lists */
  const onDelete = (rule: CommandRule) => {
    deleteRule.mutate(
      { ruleId: rule.id },
      {
        onSuccess: () => setStatus(t('policy.toast.ruleDeleted', { id: rule.id })),
        onError: (err) => setStatus(err instanceof Error ? err.message : String(err)),
      },
    );
  };
  const onResolve = (item: CommandApproval, decision: 'approve' | 'deny') => {
    resolve.mutate(
      { sessionId: item.session.id, seq: item.event.seq, decision, actor },
      {
        onSuccess: () =>
          setStatus(
            decision === 'approve' ? t('policy.toast.approved') : t('policy.toast.denied'),
          ),
        onError: (err) => setStatus(err instanceof Error ? err.message : String(err)),
      },
    );
  };
  const onCloseIncident = (incident: CommandIncident) => {
    closeIncident.mutate(
      { incidentId: incident.id, actor },
      {
        onSuccess: (data) => setStatus(data.message ?? null),
        onError: (err) => setStatus(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  const s = stats.data;

  /* ---------------------------------------------------------- KPI quad */
  const kpis = (
    <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('policy.kpis.activePolicies')}
        value={s?.rules_total ?? null}
        footer={
          s
            ? t('policy.kpis.policiesFooter', {
                enabled: s.rules_enabled,
                total: s.rules_total,
              })
            : t('policy.kpis.policiesFooterNone')
        }
        accent="primary"
      />
      <KpiCard
        label={t('policy.kpis.blocksToday')}
        value={s?.intercepts_today ?? null}
        footer={t('policy.kpis.blocksFooter')}
        accent="error"
      />
      <KpiCard
        label={t('policy.kpis.approvals')}
        value={s?.approvals.approved ?? null}
        footer={
          s
            ? t('policy.kpis.approvalsFooter', { pending: s.approvals.pending })
            : t('policy.kpis.approvalsFooterNone')
        }
        accent="tertiary"
      />
      <KpiCard
        label={t('policy.kpis.engineHash')}
        value={s?.engine_hash ?? null}
        footer={
          <>
            <span>
              {s && s.last_sync
                ? t('policy.kpis.syncLine', {
                    rel: formatRelative(s.last_sync) ?? '—',
                    by: s.last_sync_by || '—',
                  })
                : t('policy.kpis.syncLineNone')}
            </span>
            <span className="text-outline">
              {s
                ? t('policy.kpis.byAction', {
                    block: s.by_action.block,
                    approval: s.by_action.approval,
                    allow: s.by_action.allow,
                  })
                : t('policy.kpis.byActionNone')}
            </span>
          </>
        }
        accent="primary-container"
      />
    </div>
  );

  /* ------------------------------------------------------------ tabs */
  const jumpTo = (value: string) => {
    setTabDefault(value);
    setTabSeed((n) => n + 1);
  };

  const rulesFilter = (
    <div className="flex flex-wrap items-center justify-between gap-space-sm rounded-lg bg-surface-container-low px-space-sm py-1.5">
      <div className="flex items-center gap-space-xs">
        <span className="font-code-sm text-code-sm text-on-surface-variant">
          {s
            ? t('policy.filter.rulesCount', {
                shown: rules.data?.items.length ?? 0,
                total: s.rules_total,
              })
            : t('policy.filter.rulesCountNone')}
        </span>
        <span className="font-code-sm text-code-sm text-outline">
          {t('policy.filter.matchNote')}
        </span>
      </div>
      <span className="font-code-sm text-code-sm text-outline">
        {t('policy.filter.order')}
      </span>
    </div>
  );

  const ruleCards = (data: { items: CommandRule[] }) =>
    data.items.length === 0 ? (
      <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
        {t('policy.states.rulesEmpty')}
      </p>
    ) : (
      <div className="grid grid-cols-1 gap-space-md 2xl:grid-cols-2">
        {data.items.map((rule) => (
          <RuleCard
            key={rule.id}
            rule={rule}
            pending={deleteRule.isPending}
            onEdit={() => {
              setEditingRule(rule);
              setDialogOpen(true);
            }}
            onDelete={() => onDelete(rule)}
          />
        ))}
      </div>
    );

  const tabs: TabItem[] = [
    {
      value: 'rules',
      label: t('policy.tabs.rulesWithCount', { count: s?.rules_total ?? '—' }),
      content: (
        <div className="flex flex-col gap-space-sm pt-space-sm">
          {rulesFilter}
          <SectionBody query={rules}>{ruleCards}</SectionBody>
        </div>
      ),
    },
    {
      value: 'approvals',
      label: t('policy.tabs.approvalsWithCount', {
        count: s?.approvals.pending ?? '—',
      }),
      content: (
        <div className="flex flex-col gap-space-sm pt-space-sm">
          <div className="flex flex-wrap items-center justify-between gap-space-sm rounded-lg bg-surface-container-low px-space-sm py-1.5">
            <span className="font-code-sm text-code-sm text-on-surface-variant">
              {approvals.data
                ? approvals.data.items.length === 1
                  ? t('policy.filter.approvalsCountOne', {
                      n: approvals.data.items.length,
                    })
                  : t('policy.filter.approvalsCountMany', {
                      n: approvals.data.items.length,
                    })
                : t('policy.filter.approvalsCountNone')}
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {t('policy.filter.resolveNote')}
            </span>
          </div>
          <SectionBody query={approvals}>
            {(data) =>
              data.items.length === 0 ? (
                <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
                  {t('policy.states.approvalsEmpty')}
                </p>
              ) : (
                <div className="flex flex-col gap-space-md">
                  {data.items.map((item) => (
                    <ApprovalCard
                      key={item.event.seq}
                      item={item}
                      pending={resolve.isPending}
                      onApprove={() => onResolve(item, 'approve')}
                      onDeny={() => onResolve(item, 'deny')}
                    />
                  ))}
                </div>
              )
            }
          </SectionBody>
        </div>
      ),
    },
    {
      value: 'incidents',
      label: t('policy.tabs.incidentsWithCount', { count: s?.incidents.open ?? '—' }),
      content: (
        <div className="flex flex-col gap-space-sm pt-space-sm">
          <div className="flex flex-wrap items-center justify-between gap-space-sm rounded-lg bg-surface-container-low px-space-sm py-1.5">
            <span className="font-code-sm text-code-sm text-on-surface-variant">
              {incidents.data
                ? t('policy.filter.incidentsCount', {
                    n: incidents.data.total,
                  })
                : t('policy.filter.incidentsCountNone')}
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {t('policy.filter.evidenceNote')}
            </span>
          </div>
          <SectionBody query={incidents}>
            {(data) =>
              data.items.length === 0 ? (
                <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
                  {t('policy.states.incidentsEmpty')}
                </p>
              ) : (
                <div className="flex flex-col gap-space-md">
                  {data.items.map((incident) => (
                    <IncidentCard
                      key={incident.id}
                      incident={incident}
                      pending={closeIncident.isPending}
                      onClose={() => onCloseIncident(incident)}
                    />
                  ))}
                </div>
              )
            }
          </SectionBody>
        </div>
      ),
    },
  ];

  /* ------------------------------------------------------- page render */
  return (
    <div className="flex flex-col gap-space-lg">
      <div className="flex flex-col gap-space-md">
        <div className="flex flex-wrap items-center gap-space-sm">
          <Chip>{t('policy.kicker')}</Chip>
          <span className="font-code-sm text-code-sm text-on-surface-variant">
            {t('policy.policyLine')}{' '}
            <span className="font-semibold text-on-surface">
              {s
                ? t('policy.policyLineValue', {
                    rules: s.rules_total,
                    hash: s.engine_hash,
                  })
                : '—'}
            </span>
          </span>
        </div>
        <div className="flex flex-col gap-space-md xl:flex-row xl:items-start xl:justify-between">
          <div className="flex max-w-3xl flex-col gap-space-xs">
            <h1 className="font-headline-xl text-headline-xl font-bold text-on-surface">
              {t('policy.title')}
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant">
              {t('policy.subtitle')}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-space-sm">
            <Button
              type="button"
              variant="secondary"
              icon="play_arrow"
              onClick={() => void onDrySubmit()}
            >
              {t('policy.actions.dryRun')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              icon="download"
              onClick={exportPolicy}
            >
              {t('policy.actions.export')}
            </Button>
            <Button
              type="button"
              icon="add"
              onClick={() => {
                setEditingRule(null);
                setDialogOpen(true);
              }}
            >
              {t('policy.actions.create')}
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
      </div>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {kpis}

      <div className="grid grid-cols-1 items-start gap-space-lg lg:grid-cols-12">
        {/* Left: policy catalog */}
        <div className="flex flex-col gap-space-md lg:col-span-8">
          <Tabs
            key={tabSeed}
            defaultValue={tabDefault}
            tabs={tabs}
            label={t('policy.tabs.label')}
          />
        </div>

        {/* Right: simulator + posture + incident trail */}
        <div className="flex flex-col gap-space-md lg:col-span-4 lg:sticky lg:top-space-md">
          {/* Live Rule Simulator */}
          <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
            <div className="flex items-center justify-between gap-2">
              <span className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                {t('policy.simulator.title')}
              </span>
              <span className="rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm text-primary">
                {s ? t('policy.simulator.engine', { hash: s.engine_hash }) : '—'}
              </span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('policy.simulator.hint')}
            </p>
            <form
              id="policy-dryrun-form"
              className="flex flex-col gap-space-sm"
              onSubmit={(e) => {
                e.preventDefault();
                void onDrySubmit();
              }}
              noValidate
            >
              <label className="font-code-sm text-code-sm text-outline uppercase">
                {t('policy.simulator.target')}
                <input
                  className="w-full rounded bg-surface-container-low px-3 py-1.5 font-code-sm text-code-sm text-on-surface focus:outline-none"
                  maxLength={255}
                  placeholder={t('policy.simulator.targetPh')}
                  {...dryForm.register('target')}
                />
              </label>
              <div className="flex items-center justify-between">
                <label className="font-code-sm text-code-sm text-outline uppercase">
                  {t('policy.simulator.payload')}
                </label>
                <span className="font-code-sm text-code-sm text-outline">
                  {t('policy.simulator.dryRunNote')}
                </span>
              </div>
              <textarea
                className="w-full rounded bg-surface-container-low px-3 py-1.5 font-code-sm text-code-sm text-on-surface focus:outline-none"
                rows={2}
                aria-label={t('policy.simulator.payload')}
                placeholder={t('policy.simulator.payloadPh')}
                {...dryForm.register('command')}
              />
              <Button type="submit" disabled={dryRun.isPending}>
                {t('policy.simulator.run')}
              </Button>
              {dryForm.formState.errors.command !== undefined ? (
                <span role="alert" className="font-body-sm text-body-sm text-error">
                  {t('policy.simulator.invalid')}
                </span>
              ) : null}
              {simError !== null ? (
                <p role="alert" className="font-body-sm text-body-sm text-error">
                  {simError}
                </p>
              ) : null}
            </form>
            <DryRunOutput result={dryResult} />
          </div>

          {/* Realtime Engine Posture */}
          <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-label-badge text-label-badge font-semibold uppercase text-outline">
                {t('policy.posture.title')}
              </span>
              <span className="font-code-sm text-code-sm font-bold text-tertiary">
                {s ? `${s.rules_enabled} / ${s.rules_total}` : '— / —'}
              </span>
            </div>
            <div className="flex gap-1" aria-hidden="true">
              {Array.from({ length: 12 }, (_, i) => {
                const lit =
                  s && s.rules_total > 0
                    ? i < Math.round((12 * s.rules_enabled) / s.rules_total)
                    : false;
                return (
                  <span
                    key={i}
                    className={`h-3 w-2 rounded-sm ${lit ? 'bg-primary' : 'bg-surface-container'}`}
                  />
                );
              })}
            </div>
            <div className="flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant">
              <span>{t('policy.posture.commands')}</span>
              <span className="font-semibold text-on-surface">
                <Value value={s?.commands_recorded ?? null} />
              </span>
            </div>
            <div className="flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant">
              <span>{t('policy.posture.orderLabel')}</span>
              <span className="font-semibold text-tertiary">
                {t('policy.posture.orderValue')}
              </span>
            </div>
          </div>

          {/* Audit drawer teaser */}
          <div className="flex items-center justify-between gap-space-sm rounded-xl bg-surface-container-high/40 p-space-md">
            <div className="flex min-w-0 flex-col">
              <span className="font-headline-sm text-headline-sm font-semibold leading-tight text-on-surface">
                {t('policy.teaser.title')}
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant">
                {s
                  ? t('policy.teaser.meta', {
                      incidents:
                        s.incidents.total === 1
                          ? t('policy.teaser.incidentOne', { n: s.incidents.total })
                          : t('policy.teaser.incidentsMany', { n: s.incidents.total }),
                      commands: s.commands_recorded,
                    })
                  : t('policy.teaser.metaNone')}
              </span>
            </div>
            <Button
              type="button"
              variant="secondary"
              icon="arrow_forward"
              ariaLabel={t('policy.teaser.jump')}
              onClick={() => jumpTo('incidents')}
            />
          </div>
        </div>
      </div>

      <RiskSection actor={actor} />
      <AnomalySection actor={actor} />

      <RuleDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        rule={editingRule}
        actor={actor}
        onStatus={(message) => {
          setStatus(message);
        }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ cards */

/** Decision metadata for the simulator output box. */
const DEC_META: Record<
  CommandDecision['decision'],
  { i18nKey: 'block' | 'approval' | 'allow'; text: string }
> = {
  block: { i18nKey: 'block', text: 'text-error' },
  approval: { i18nKey: 'approval', text: 'text-primary' },
  allow: { i18nKey: 'allow', text: 'text-tertiary' },
};

function DryRunOutput({
  result,
}: {
  result: { result: CommandDecision; command: string; target: string } | null;
}) {
  const { t } = useTranslation();
  if (result === null) {
    return (
      <div className="flex flex-col gap-1 rounded-xl bg-surface-container/60 p-space-md">
        <div className="flex items-center justify-between gap-space-sm">
          <span className="flex items-center gap-1 font-label-badge font-bold uppercase text-outline">
            <span className="material-symbols-outlined text-[16px]" aria-hidden="true">
              help
            </span>
            {t('policy.simulator.idle')}
          </span>
          <span className="font-code-sm font-semibold text-outline">
            {t('policy.simulator.idleRule')}
          </span>
        </div>
        <p className="mt-1 font-body-sm text-body-sm text-on-surface-variant">
          {t('policy.simulator.idleBody')}
        </p>
      </div>
    );
  }
  const { result: decision, command, target } = result;
  const meta = DEC_META[decision.decision];
  const rule = decision.rule;
  return (
    <div className="flex flex-col gap-1 rounded-xl bg-surface-container/60 p-space-md">
      <div className="flex items-center justify-between gap-space-sm">
        <span
          className={`flex items-center gap-1 font-label-badge font-bold uppercase ${meta.text}`}
        >
          <span className="material-symbols-outlined text-[16px]" aria-hidden="true">
            help
          </span>
          {t(`policy.decision.${meta.i18nKey}` as const)}
          {decision.terminate ? t('policy.decision.terminate') : ''}
        </span>
        <span className={`font-code-sm font-semibold ${meta.text}`}>
          {rule
            ? t('policy.simulator.ruleLine', { id: rule.id, pattern: rule.pattern })
            : t('policy.simulator.defaultLine')}
        </span>
      </div>
      <p className="font-body-sm text-body-sm text-on-surface">
        {rule ? (
          <>
            <strong>{rule.name}</strong> - {rule.action}{' '}
            {rule.target_pattern
              ? t('policy.simulator.inScope', { glob: rule.target_pattern })
              : t('policy.simulator.anyTarget')}
          </>
        ) : (
          t('policy.simulator.defaultBody')
        )}
      </p>
      <dl className="mt-1 flex flex-col gap-1 border-t border-outline-variant/40 pt-2 font-code-sm text-code-sm text-on-surface-variant">
        <div className="flex justify-between gap-space-sm">
          <dt>{t('policy.simulator.rowCommand')}</dt>
          <dd className="truncate text-on-surface">{command}</dd>
        </div>
        <div className="flex justify-between gap-space-sm">
          <dt>{t('policy.simulator.rowTarget')}</dt>
          <dd className="text-on-surface">{target === '' ? '(any)' : target}</dd>
        </div>
        <div className="flex justify-between gap-space-sm">
          <dt>{t('policy.simulator.rowDecision')}</dt>
          <dd className="text-on-surface">
            {decision.default
              ? t('policy.simulator.decisionDefault', { decision: decision.decision })
              : decision.decision}
          </dd>
        </div>
        <div className="flex justify-between gap-space-sm">
          <dt>{t('policy.simulator.rowEscalation')}</dt>
          <dd className={decision.terminate ? 'text-error' : 'text-on-surface'}>
            {decision.terminate
              ? t('policy.simulator.escalates')
              : t('policy.simulator.noEscalation')}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function RuleCard({
  rule,
  pending,
  onEdit,
  onDelete,
}: {
  rule: CommandRule;
  pending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const effectKey = (
    rule.action === 'block' ? 'block' : rule.action === 'approval' ? 'approval' : 'allow'
  ) as 'block' | 'approval' | 'allow';
  const stripe =
    rule.action === 'block'
      ? 'bg-error'
      : rule.action === 'approval'
        ? 'bg-primary'
        : 'bg-tertiary';
  return (
    <div className="relative flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg pl-space-lg shadow-sm">
      <span
        className={`absolute bottom-0 left-0 top-0 w-1.5 rounded-l-xl ${stripe}`}
        aria-hidden="true"
      />
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-surface-container px-2 py-0.5 font-label-badge text-label-badge font-bold uppercase text-primary">
          {t('policy.rules.idChip', { id: rule.id })}
        </span>
        <code className="rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm text-on-surface">
          {rule.pattern}
        </code>
        <span
          className={`font-label-badge text-label-badge font-bold ${
            rule.enabled ? 'text-tertiary' : 'text-outline'
          }`}
        >
          {rule.enabled ? t('policy.rules.enforced') : t('policy.rules.disabled')}
        </span>
      </div>
      <h2 className="font-headline-sm text-headline-sm font-semibold leading-tight text-on-surface">
        {rule.name}
      </h2>
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded px-2 py-0.5 font-code-sm text-code-sm font-semibold ${
            rule.action === 'block'
              ? 'bg-error-container text-on-error-container'
              : rule.action === 'approval'
                ? 'bg-surface-container-high text-primary'
                : 'bg-surface-container text-tertiary'
          }`}
        >
          {t('policy.rules.matchChip', {
            action: rule.action.toUpperCase(),
            matches: rule.match_count,
          })}
        </span>
        <div className="flex flex-col gap-0.5 font-code-sm text-code-sm text-on-surface-variant">
          <span>
            {rule.target_pattern
              ? t('policy.rules.targetScope', { glob: rule.target_pattern })
              : t('policy.rules.anyTarget')}
          </span>
          {rule.terminate_on_match ? (
            <span className="text-error">{t('policy.rules.terminates')}</span>
          ) : null}
        </div>
      </div>
      <div className="flex items-center gap-2 rounded-lg bg-surface-container-low px-space-sm py-1.5">
        <span
          className={`material-symbols-outlined text-[18px] ${
            rule.action === 'block'
              ? 'text-error'
              : rule.action === 'approval'
                ? 'text-primary'
                : 'text-tertiary'
          }`}
          aria-hidden="true"
        >
          {rule.action === 'block'
            ? 'block'
            : rule.action === 'approval'
              ? 'schedule'
              : 'check_circle'}
        </span>
        <div className="flex min-w-0 flex-col">
          <span className="font-label-badge text-label-badge uppercase text-outline">
            {t('policy.rules.effectTitle')}
          </span>
          <span className="font-body-sm text-body-sm text-on-surface">
            {t(`policy.effects.${effectKey}` as const)}
          </span>
        </div>
      </div>
      <div className="flex items-center justify-between">
        <span className="font-code-sm text-code-sm font-semibold uppercase text-outline">
          {t('policy.rules.matchTitle')}
        </span>
        <span className="font-code-sm text-code-sm text-outline">
          {t('policy.rules.matchHint')}
        </span>
      </div>
      <div className="overflow-x-auto rounded border border-outline-variant/40 bg-surface-container-lowest p-space-sm shadow-inner">
        <code
          className={`font-code-sm font-medium ${
            rule.action === 'block'
              ? 'text-error'
              : rule.action === 'approval'
                ? 'text-primary'
                : 'text-tertiary'
          }`}
        >
          {rule.pattern}
        </code>
      </div>
      <div className="font-code-sm text-code-sm text-on-surface-variant">
        {t('policy.rules.updatedBy', {
          rel: formatRelative(rule.updated_at) ?? '—',
          by: rule.updated_by || '—',
        })}
        {rule.description ? ` · ${rule.description}` : ''}
      </div>
      <div className="flex gap-space-sm">
        <Button type="button" variant="secondary" icon="edit" onClick={onEdit}>
          {t('policy.rules.edit')}
        </Button>
        <Button
          type="button"
          variant="destructive"
          icon="delete"
          onClick={onDelete}
          disabled={pending}
        >
          {t('policy.rules.delete')}
        </Button>
      </div>
    </div>
  );
}

function ApprovalCard({
  item,
  pending,
  onApprove,
  onDeny,
}: {
  item: CommandApproval;
  pending: boolean;
  onApprove: () => void;
  onDeny: () => void;
}) {
  const { t } = useTranslation();
  const { event, session } = item;
  return (
    <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-surface-container px-2 py-0.5 font-label-badge text-label-badge font-bold uppercase text-primary">
          {t('policy.approvals.seqChip', { seq: event.seq })}
        </span>
        <code className="rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm text-on-surface">
          {session.session_ref}
        </code>
        <code className="rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm text-on-surface">
          {session.target}
        </code>
      </div>
      <h2 className="font-headline-sm text-headline-sm font-semibold leading-tight text-on-surface">
        {event.content}
      </h2>
      <span className="self-start rounded bg-error-container px-2 py-0.5 font-label-badge text-label-badge font-bold uppercase text-on-error-container">
        {t('policy.approvals.heldChip')}
      </span>
      <div className="font-code-sm text-code-sm text-on-surface-variant">
        {t('policy.approvals.heldMeta', {
          rel: formatRelative(event.created_at) ?? '—',
          actor: event.actor,
        })}{' '}
        · {session.protocol} · {t('policy.approvals.heldState')}
      </div>
      <div className="flex gap-space-sm">
        <Button type="button" icon="check" onClick={onApprove} disabled={pending}>
          {t('policy.approvals.approve')}
        </Button>
        <Button
          type="button"
          variant="destructive"
          icon="close"
          onClick={onDeny}
          disabled={pending}
        >
          {t('policy.approvals.deny')}
        </Button>
      </div>
    </div>
  );
}

function IncidentCard({
  incident,
  pending,
  onClose,
}: {
  incident: CommandIncident;
  pending: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const closed = incident.status === 'closed';
  return (
    <div className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-lg shadow-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`rounded px-2 py-0.5 font-label-badge text-label-badge font-bold uppercase ${
            closed
              ? 'bg-surface-container text-outline'
              : 'bg-error-container text-on-error-container'
          }`}
        >
          {incident.incident_ref}
        </span>
        <code className="rounded bg-surface-container px-2 py-0.5 font-code-sm text-code-sm text-on-surface">
          {incident.rule_pattern}
        </code>
        <span
          className={`font-label-badge text-label-badge font-bold uppercase ${
            closed ? 'text-outline' : 'text-error'
          }`}
        >
          {closed ? t('policy.incidents.closed') : t('policy.incidents.open')}
        </span>
      </div>
      <h2 className="font-headline-sm text-headline-sm font-semibold leading-tight text-on-surface">
        {incident.command}
      </h2>
      <span
        className={`self-start rounded px-2 py-0.5 font-label-badge text-label-badge font-bold uppercase ${
          closed
            ? 'bg-surface-container text-tertiary'
            : 'bg-error-container text-on-error-container'
        }`}
      >
        {closed ? t('policy.incidents.reviewedChip') : t('policy.incidents.escalatedChip')}
      </span>
      <div className="rounded-lg bg-surface-container-low px-space-sm py-1.5 font-code-sm text-code-sm">
        <div className="flex items-center gap-2">
          <span
            className="material-symbols-outlined text-[16px] text-primary"
            aria-hidden="true"
          >
            records
          </span>
          <span className="font-label-badge text-label-badge uppercase text-outline">
            {t('policy.incidents.evidenceTitle')}
          </span>
        </div>
        <div className="text-on-surface">
          {t('policy.incidents.evidenceSession', {
            session: incident.session_id,
            seq: incident.event_seq,
          })}
        </div>
        <div className="text-on-surface-variant">
          <Value value={incident.target} />
        </div>
      </div>
      <div className="flex flex-col gap-1 rounded-lg bg-surface-container-low px-space-sm py-1.5 font-code-sm text-code-sm">
        <span className="font-label-badge font-semibold uppercase text-outline">
          {t('policy.incidents.ruleSnapshot')}
        </span>
        <div className="flex items-center gap-2">
          <span
            className="material-symbols-outlined text-[16px] text-error"
            aria-hidden="true"
          >
            gavel
          </span>
          <span className="text-on-surface">{incident.rule_name}</span>
        </div>
      </div>
      <div className="font-code-sm text-code-sm text-on-surface-variant">
        {t('policy.incidents.raisedMeta', {
          rel: formatRelative(incident.created_at) ?? '—',
          actor: incident.actor,
        })}
        {closed
          ? ` · ${t('policy.incidents.closedMeta', {
              rel: formatRelative(incident.closed_at) ?? '—',
              by: incident.closed_by || '—',
            })}${incident.close_note ? ` · ${incident.close_note}` : ''}`
          : ''}
      </div>
      {closed ? (
        <span className="font-label-badge text-label-badge uppercase text-tertiary">
          {t('policy.incidents.reviewed')}
        </span>
      ) : (
        <Button
          type="button"
          variant="destructive"
          icon="lock"
          onClick={onClose}
          disabled={pending}
        >
          {t('policy.incidents.close')}
        </Button>
      )}
    </div>
  );
}
