import { useTranslation } from 'react-i18next';
import { Link, NavLink } from 'react-router';

import mark from '../../assets/vy-pam-mark.svg';
import { NAV_ITEMS } from './nav';

const linkBase =
  'flex items-center gap-space-sm px-space-md py-space-sm rounded-lg transition-colors ';
const linkActive = 'bg-primary-container text-on-primary-container font-semibold shadow-sm';
const linkInactive =
  'text-on-surface-variant hover:bg-surface-container hover:text-on-surface transition-colors font-body-md text-body-md';

/**
 * Sidebar (as-built markup from the legacy screens, plan §3 layout):
 * fixed w-64 rail, brand header, "Privileged Controls" section, one nav
 * link per ADR-0005 route. Active state matches the legacy
 * `bg-primary-container` pill; NavLink sets `aria-current="page"`.
 */
export function Sidebar() {
  const { t } = useTranslation();
  return (
    <aside className="fixed left-0 top-0 h-full w-64 bg-surface-container-lowest border-r border-outline-variant/30 z-50 flex flex-col justify-between shadow-[0_1px_8px_rgba(0,0,0,0.03)]">
      <div className="flex flex-col">
        <div className="h-16 px-space-lg flex items-center justify-between border-b border-outline-variant/20">
          <Link to="/" className="flex items-center gap-space-sm">
            <img alt="VY-PAM logo" className="h-8 w-8 shrink-0" src={mark} />
            <span className="flex flex-col">
              <span className="font-headline-sm text-headline-sm text-on-surface tracking-tight leading-none">
                VY-<span className="text-primary">PAM</span>
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant font-normal tracking-wide">
                {t('app.kicker')}
              </span>
            </span>
          </Link>
          <span
            className="material-symbols-outlined text-outline text-[18px]"
            aria-hidden="true"
          >
            verified_user
          </span>
        </div>
        <div className="px-space-md py-space-sm">
          <div className="px-space-sm py-space-xs mb-space-xs font-code-sm text-code-sm text-outline uppercase tracking-wider font-semibold">
            {t('app.sectionLabel')}
          </div>
          <nav aria-label={t('nav.ariaLabel')} className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `${linkBase}${isActive ? linkActive : linkInactive}`
                }
              >
                <span
                  className={`material-symbols-outlined text-[20px]${item.danger ? ' text-error' : ''}`}
                  aria-hidden="true"
                >
                  {item.icon}
                </span>
                <span>{t(item.labelKey)}</span>
              </NavLink>
            ))}
          </nav>
        </div>
      </div>
    </aside>
  );
}
