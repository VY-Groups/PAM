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

/**
 * Seconds -> compact duration (`2h 05m`, `5m 12s`, `18s`); absent or
 * non-finite values -> null (the honest em-dash via `Value`). The session
 * list and detail chips report the server-computed duration verbatim.
 */
export function formatDuration(seconds: number | null | undefined): string | null {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) {
    return null;
  }
  const total = Math.max(0, Math.floor(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}

/**
 * Relative age in the legacy console's wording ("just now", "5m ago",
 * "3h ago", "2d ago") for "updated / trained / held ... ago" captions;
 * absent or unparseable timestamps -> null (the honest em-dash, never a
 * guessed clock). `nowMs` is injectable so tests stay deterministic.
 */
export function formatRelative(
  iso: string | null | undefined,
  nowMs: number = Date.now(),
): string | null {
  if (!iso) return null;
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return null;
  const mins = Math.max(0, Math.round((nowMs - then) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}
