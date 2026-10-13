import type { ReactNode } from 'react';

/**
 * Honest-state primitives (plan F2 "honest-state patterns", brief §3.2).
 * No sample numbers ever render: an absent value is an em-dash.
 */

export interface ValueProps {
  /** Real API value. null / undefined / '' render the em-dash. */
  value?: string | number | null;
  children?: ReactNode;
}

/** Renders `value`, or the honest em-dash when there is no data (brief §3.2). */
export function Value({ value, children }: ValueProps) {
  const empty = value === null || value === undefined || value === '';
  if (empty) return <span aria-label="no data">—</span>;
  return <span>{children ?? String(value)}</span>;
}

export interface NotConnectedProps {
  /** Chip label from brief §3.2 ("not connected" / "NOT CONNECTED"). */
  label?: string;
  className?: string;
}

/** The brief §3.2 "not connected" chip: muted dot + label (as-built pattern). */
export function NotConnected({
  label = 'not connected',
  className = '',
}: NotConnectedProps) {
  return (
    <span
      className={`inline-flex items-center gap-1 font-label-badge text-label-badge text-outline font-semibold ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-outline" aria-hidden="true" />
      {label}
    </span>
  );
}
