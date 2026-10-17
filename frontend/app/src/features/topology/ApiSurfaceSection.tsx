import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader } from '../../components';
import {
  API_METHOD_COUNTS,
  API_OPERATION_COUNT,
  API_PATH_COUNT,
  API_TAGS,
} from './topology.generated';

/**
 * View 3 - API (ADR-0013): the contract itself, extracted from
 * `apis/openapi.yaml` - the same file the typed client is generated
 * from (ADR-0004), so this surface and the app's calls cannot drift
 * apart without CI failing. Summaries are the contract's own text,
 * rendered verbatim.
 */
export function ApiSurfaceSection() {
  const { t } = useTranslation();
  return (
    <section aria-label={t('topology.api.title')} className="space-y-space-md">
      <SectionHeader
        title={t('topology.api.title')}
        subtitle={t('topology.api.subtitle')}
      />
      <div className="flex flex-wrap items-center gap-space-sm">
        <Chip>
          {API_PATH_COUNT} {t('topology.api.pathsCount')}
        </Chip>
        <Chip>
          {API_OPERATION_COUNT} {t('topology.api.opsCount')}
        </Chip>
        <Chip tone="inactive">
          {API_TAGS.length} {t('topology.api.tagsCount')}
        </Chip>
        {Object.entries(API_METHOD_COUNTS).map(([method, count]) => (
          <Chip key={method} tone="inactive">
            {method} {count}
          </Chip>
        ))}
      </div>
      <div className="space-y-space-sm">
        {API_TAGS.map((tag, index) => (
          <details
            key={tag.name}
            open={index === 0}
            className="rounded-lg border border-outline-variant/30 p-space-md"
          >
            <summary className="cursor-pointer font-title-md text-title-md text-on-surface">
              {tag.name}
              <span className="ml-space-sm font-code-sm text-code-sm text-outline">
                {tag.operations.length}
              </span>
            </summary>
            <ul className="mt-space-sm space-y-space-xs">
              {tag.operations.map((op) => (
                <li
                  key={`${op.method} ${op.path}`}
                  className="flex flex-wrap items-baseline gap-space-sm"
                >
                  <code className="w-16 shrink-0 font-code-sm text-code-sm font-semibold text-primary">
                    {op.method}
                  </code>
                  <code className="font-code-sm text-code-sm text-on-surface">
                    {op.path}
                  </code>
                  {op.summary && (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {op.summary}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </section>
  );
}
