import type { ReactNode } from 'react';

import '../../i18n';

/**
 * ADR-0010: i18next is initialised once with `en.json` (English first).
 * The provider exists so the tree has a single obvious wiring point -
 * `hi.json` later is a translations-only change, no code edits.
 */
export function I18nProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
