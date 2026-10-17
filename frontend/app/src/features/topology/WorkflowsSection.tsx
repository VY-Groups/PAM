import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { WORKFLOWS } from './workflows';

/**
 * View 5 - Application workflows (ADR-0013): five real lifecycles
 * drawn from contract operations, each step carrying its proof - the
 * verbatim capture fixture or the test/gate name that drives it. The
 * generated-contract test validates every operation and every evidence
 * reference, so a diagram step cannot describe something the product
 * does not implement or prove.
 */
export function WorkflowsSection() {
  const { t } = useTranslation();
  return (
    <section aria-label={t('topology.workflows.title')} className="space-y-space-lg">
      <SectionHeader
        title={t('topology.workflows.title')}
        subtitle={t('topology.workflows.subtitle')}
      />
      {WORKFLOWS.map((workflow) => (
        <div
          key={workflow.id}
          className="rounded-lg border border-outline-variant/30 p-space-md"
        >
          <h3 className="font-title-md text-title-md text-on-surface">
            {t(workflow.titleKey)}
          </h3>
          <p className="mt-space-xs font-body-sm text-body-sm text-on-surface-variant">
            {t(workflow.subtitleKey)}
          </p>
          <ol className="mt-space-sm">
            {workflow.steps.map((step, index) => (
              <li key={`${workflow.id}-${index}`} className="py-space-xs">
                <div className="flex flex-wrap items-baseline gap-space-sm">
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary-container font-code-sm text-code-sm text-on-primary-container">
                    {index + 1}
                  </span>
                  <code className="font-code-sm text-code-sm font-semibold text-on-surface">
                    {step.operation}
                  </code>
                </div>
                <p className="mt-space-xs pl-space-lg font-body-md text-body-md text-on-surface">
                  {t(step.labelKey)}
                </p>
                {step.noteKey && (
                  <p className="pl-space-lg font-body-sm text-body-sm text-on-surface-variant">
                    {t(step.noteKey)}
                  </p>
                )}
                <p className="pl-space-lg font-code-sm text-code-sm text-outline">
                  {t('topology.workflows.evidence')}:{' '}
                  <code className="text-on-surface-variant">{step.evidence.file}</code>
                  <code className="text-on-surface-variant">
                    {' '}
                    :: {step.evidence.contains}
                  </code>
                </p>
                {index < workflow.steps.length - 1 && (
                  <div aria-hidden="true" className="pl-space-sm text-outline">
                    ↓
                  </div>
                )}
              </li>
            ))}
          </ol>
        </div>
      ))}
    </section>
  );
}
