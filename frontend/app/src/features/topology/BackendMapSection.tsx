import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import { BACKEND_PACKAGES } from './topology.generated';

/**
 * View 2 - Backend (ADR-0013): the python packages that serve the API,
 * their file trees and the import edges between their own modules.
 * Extracted strictly (tests/conftest excluded; an edge is drawn only
 * when its target file really exists in the tree), so the map is the
 * code's own dependency picture, not a remembered architecture slide.
 */
export function BackendMapSection() {
  const { t } = useTranslation();
  return (
    <section aria-label={t('topology.backend.title')} className="space-y-space-lg">
      {BACKEND_PACKAGES.map((pkg) => {
        const totalLines = pkg.files.reduce((sum, f) => sum + f.lines, 0);
        const edges = pkg.files.reduce((sum, f) => sum + f.imports.length, 0);
        return (
          <div
            key={pkg.name}
            className="rounded-lg border border-outline-variant/30 p-space-md"
          >
            <SectionHeader
              title={pkg.name}
              subtitle={`${pkg.root} · ${pkg.files.length} ${t('topology.backend.filesCount')} · ${totalLines} ${t('topology.backend.linesLabel')} · ${edges} ${t('topology.backend.edgesLabel')}`}
            />
            <ul className="mt-space-sm space-y-space-xs">
              {pkg.files.map((file) => (
                <li key={file.path} className="flex flex-wrap items-baseline gap-space-sm">
                  <code className="font-code-sm text-code-sm text-on-surface">
                    {file.path}
                  </code>
                  <span className="font-code-sm text-code-sm text-outline">
                    {file.lines}
                  </span>
                  {file.imports.length > 0 ? (
                    <span className="flex flex-wrap gap-space-xs">
                      {file.imports.map((target) => (
                        <code
                          key={target}
                          className="rounded bg-surface-container px-space-xs font-code-sm text-code-sm text-on-surface-variant"
                        >
                          <span aria-hidden="true">→ </span>
                          {target.split('/').pop()}
                        </code>
                      ))}
                    </span>
                  ) : (
                    <span className="font-body-sm text-body-sm text-outline">
                      {t('topology.backend.noImports')}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </section>
  );
}
