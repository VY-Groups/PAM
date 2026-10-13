import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

/**
 * The top-bar Break-Glass shortcut (plan §3 layout, as-built classes from
 * the legacy header): red uppercase button straight into the route.
 */
export function BreakGlassButton() {
  const { t } = useTranslation();
  return (
    <Link
      to="/break-glass"
      className="flex items-center gap-1.5 px-space-md py-1.5 rounded-lg bg-error text-on-error hover:bg-error/90 font-label-md text-label-md transition-colors shadow-sm font-semibold tracking-wide uppercase"
    >
      <span className="material-symbols-outlined text-[16px]" aria-hidden="true">
        warning
      </span>
      <span>{t('shell.breakGlassButton')}</span>
    </Link>
  );
}
