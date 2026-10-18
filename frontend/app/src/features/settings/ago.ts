/**
 * The legacy page's `ago()` (code.html:1029-1040) as a shared helper:
 * relative time for the group meta lines and the changelog rows, with the
 * RBAC screen's i18n keys (screen 11, ADR-0015 - the settings forms carry
 * the same relative times the legacy `renderGroup` writes into
 * `data-group-meta`, e.g. `saved 3 days ago by demo-seed`).
 */
import type { TFunction } from 'i18next';

export function settingsAgo(iso: string | null | undefined, t: TFunction): string {
  if (!iso) return t('settings.never');
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return iso;
  const seconds = Math.max(0, (Date.now() - then.getTime()) / 1000);
  if (seconds < 60) return t('settings.rbac.agoJustNow');
  if (seconds < 3600)
    return t('settings.rbac.agoMinutes', { count: Math.floor(seconds / 60) });
  if (seconds < 86400)
    return t('settings.rbac.agoHours', { count: Math.floor(seconds / 3600) });
  const days = Math.floor(seconds / 86400);
  return days === 1
    ? t('settings.rbac.agoYesterday')
    : t('settings.rbac.agoDays', { count: days });
}
