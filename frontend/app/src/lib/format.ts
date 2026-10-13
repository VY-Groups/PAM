/**
 * Shared formatting helpers (plan section 3 `lib/format, dates`).
 *
 * ISO strings from the API render as the operator's local time; an absent
 * or unparseable timestamp renders null, which the design-system `Value`
 * turns into the honest em-dash (never a fabricated clock). Feature
 * modules import from `lib/` - a feature never imports another feature
 * (plan layer rules), so the Command Center copy moved here.
 */

/** ISO timestamp -> compact local time; empty/unparseable values -> null. */
export function formatTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return null; // unparseable = no data
  return parsed.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
