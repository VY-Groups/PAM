import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

/**
 * Real client-side 404 (ADR-0005: unknown routes render a page, never the
 * bundle). i18n strings, no fabricated suggestions.
 */
export function NotFound() {
  const { t } = useTranslation();
  return (
    <section className="max-w-xl mx-auto mt-space-xl flex flex-col gap-space-md">
      <h1 className="font-headline-lg text-headline-lg text-on-surface">
        {t('errors.notFoundTitle')}
      </h1>
      <p className="font-body-md text-body-md text-on-surface-variant">
        {t('errors.notFoundBody')}
      </p>
      <Link
        to="/"
        className="self-start px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-md text-label-md shadow-sm"
      >
        {t('errors.goHome')}
      </Link>
    </section>
  );
}
