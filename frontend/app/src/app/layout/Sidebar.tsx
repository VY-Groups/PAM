import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, NavLink, useNavigate } from 'react-router';

import mark from '../../assets/vy-pam-mark.svg';
import { Button, NotConnected, StatusDot, Value } from '../../components';
import { useSetupState } from '../../features/setup/queries';
import { useClusterOverview } from '../../features/topology/queries';
import { useAuth } from '../providers/useAuth';
import { visibleByRole } from '../guards/RoleGate';
import { NAV_GROUPS, NAV_ITEMS } from './nav';

const linkBase =
  'flex items-center gap-space-sm px-space-md py-space-sm rounded-lg transition-colors ';
const linkActive = 'bg-primary-container text-on-primary-container font-semibold shadow-sm';
const linkInactive =
  'text-on-surface-variant hover:bg-surface-container hover:text-on-surface transition-colors font-body-md text-body-md';

/**
 * Sidebar (ADR-0020 Decision 1): three regions. Header = the as-built
 * brand block plus a client-side nav filter (the contract has no
 * /search endpoint, so it filters sidebar links only). Body = one nav
 * landmark wrapping the six Decision-3 groups. Footer = the real cluster
 * context (GET /api/v1/cluster self) and the whoami identity chip +
 * sign-out moved verbatim out of the TopBar. Collapses to a drawer below
 * lg (AppShell owns the toggle).
 */
export function Sidebar({ open, onNavigate }: { open: boolean; onNavigate: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { whoami, logout } = useAuth();
  const cluster = useClusterOverview();
  // ADR-0018 batch 11.11: the instance brands the shell (company name /
  // logo) and an unconfigured instance shows the first-run setup link -
  // both views of the same public setup state.
  const setup = useSetupState();
  const [filter, setFilter] = useState('');

  const needle = filter.trim().toLowerCase();
  const visiblePaths = useMemo(
    () =>
      new Set(
        NAV_ITEMS.filter((item) => t(item.labelKey).toLowerCase().includes(needle)).map(
          (item) => item.path,
        ),
      ),
    [needle, t],
  );

  const onSignOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <aside
      id="app-sidebar"
      className={`fixed left-0 top-0 h-full w-64 bg-surface-container-lowest border-r border-outline-variant/30 z-50 flex-col justify-between shadow-[0_1px_8px_rgba(0,0,0,0.03)] ${
        open ? 'flex' : 'hidden'
      } lg:flex`}
    >
      <div className="flex-1 min-h-0 flex flex-col">
        <div className="h-16 px-space-lg flex items-center justify-between border-b border-outline-variant/20">
          <Link to="/" className="flex items-center gap-space-sm">
            <img
              alt={
                setup.data?.company_name ? `${setup.data.company_name} logo` : 'VY-PAM logo'
              }
              className="h-8 w-8 shrink-0 object-contain"
              src={
                setup.data?.logo_data_uri !== '' && setup.data?.logo_data_uri !== undefined
                  ? setup.data.logo_data_uri
                  : mark
              }
            />
            <span className="flex flex-col">
              <span className="font-headline-sm text-headline-sm text-on-surface tracking-tight leading-none">
                {setup.data?.company_name ? (
                  setup.data.company_name
                ) : (
                  <>
                    VY-<span className="text-primary">PAM</span>
                  </>
                )}
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
        {setup.data !== undefined && !setup.data.configured ? (
          <NavLink
            to="/setup"
            onClick={onNavigate}
            className="flex items-center gap-space-sm px-space-md py-space-sm bg-primary-container text-on-primary-container font-label-md text-label-md font-semibold border-b border-outline-variant/20"
          >
            <span className="material-symbols-outlined text-[20px]" aria-hidden="true">
              rocket_launch
            </span>
            <span>{t('shell.setupOpen')}</span>
          </NavLink>
        ) : null}
        <div className="px-space-md py-space-sm border-b border-outline-variant/20">
          <label htmlFor="nav-filter" className="sr-only">
            {t('shell.filterLabel')}
          </label>
          <input
            id="nav-filter"
            type="search"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder={t('shell.filterPlaceholder')}
            className="w-full px-space-sm py-1 rounded bg-surface-container text-on-surface font-body-sm text-body-sm border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container"
          />
        </div>
        <nav
          aria-label={t('nav.ariaLabel')}
          className="px-space-md py-space-sm flex flex-col gap-space-md flex-1 min-h-0 overflow-y-auto"
        >
          {NAV_GROUPS.map((group) => {
            const items = NAV_ITEMS.filter(
              (item) =>
                group.paths.includes(item.path) &&
                visiblePaths.has(item.path) &&
                visibleByRole(item.path, whoami),
            );
            if (items.length === 0) return null;
            return (
              <div key={group.labelKey}>
                <div className="px-space-sm py-space-xs mb-space-xs font-code-sm text-code-sm text-outline uppercase tracking-wider font-semibold">
                  {t(group.labelKey)}
                </div>
                <div className="flex flex-col gap-1">
                  {items.map((item) => (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        `${linkBase}${isActive ? linkActive : linkInactive}`
                      }
                    >
                      <span
                        className={`material-symbols-outlined text-[20px]${
                          item.danger ? ' text-error' : ''
                        }`}
                        aria-hidden="true"
                      >
                        {item.icon}
                      </span>
                      <span>{t(item.labelKey)}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
          {visiblePaths.size === 0 ? (
            <p className="px-space-sm font-body-sm text-body-sm text-on-surface-variant">
              {t('shell.filterEmpty')}
            </p>
          ) : null}
        </nav>
      </div>
      <div className="px-space-md py-space-sm border-t border-outline-variant/20 flex flex-col gap-space-sm">
        <div className="flex items-center gap-space-sm font-code-sm text-code-sm text-on-surface">
          <span className="text-outline uppercase tracking-wider">
            {t('shell.clusterContext')}
          </span>
          {cluster.data ? (
            // One text node on purpose: a combined line never collides with
            // exact-match queries for the bare node name elsewhere.
            <span>{`${cluster.data.self.name} · ${cluster.data.self.role} · ${cluster.data.self.site}`}</span>
          ) : cluster.isError ? (
            <NotConnected />
          ) : (
            <Value />
          )}
        </div>
        {whoami ? (
          <div className="flex items-center gap-space-sm px-space-sm py-1 rounded bg-surface-container border border-outline-variant/30 font-code-sm text-code-sm text-on-surface">
            <StatusDot state="ok" />
            <span>{whoami.principal}</span>
            <span className="text-outline">|</span>
            <span className="text-outline font-semibold">
              {t('shell.roleBadge', { role: whoami.role })}
            </span>
            {(() => {
              // ADR-0021 step 7: the ABAC binding scope, straight from whoami -
              // empty scope means the role governs everywhere, so no chip.
              const scope = whoami.scope;
              const targets = Array.isArray(scope?.targets) ? scope.targets.length : 0;
              const items = Array.isArray(scope?.vault_items)
                ? scope.vault_items.length
                : 0;
              if (targets > 0 && items > 0)
                return (
                  <span className="text-outline">
                    {t('shell.scopeBoth', { targets, items })}
                  </span>
                );
              if (targets > 0)
                return (
                  <span className="text-outline">
                    {t('shell.scope', { count: targets })}
                  </span>
                );
              if (items > 0)
                return (
                  <span className="text-outline">
                    {t('shell.scopeItems', { count: items })}
                  </span>
                );
              return null;
            })()}
          </div>
        ) : null}
        <Button
          variant="secondary"
          icon="logout"
          className="w-full justify-center"
          onClick={() => void onSignOut()}
        >
          {t('shell.signOut')}
        </Button>
      </div>
    </aside>
  );
}
