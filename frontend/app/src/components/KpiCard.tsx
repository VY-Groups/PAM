import type { ReactNode } from 'react';

import { Value } from './HonestStates';

export type KpiAccent = 'primary' | 'primary-container' | 'tertiary' | 'error';

export interface KpiCardProps {
  label: string;
  /** Real API value; null/undefined renders the honest em-dash (brief §3.2). */
  value?: string | number | null;
  /** Footer row (body-sm), e.g. a delta or a timestamp. */
  footer?: ReactNode;
  /** 4px accent bar color (brief §2: bg-primary(-container) as-built). */
  accent?: KpiAccent;
  className?: string;
}

const accentClasses: Record<KpiAccent, string> = {
  primary: 'bg-primary',
  'primary-container': 'bg-primary-container',
  tertiary: 'bg-tertiary',
  error: 'bg-error',
};

/**
 * KPI card (brief §2, as-built command-center markup):
 * rounded-xl surface card, 4px accent bar, font-label-md label,
 * font-headline-xl value, body-sm footer.
 */
export function KpiCard({
  label,
  value,
  footer,
  accent = 'primary',
  className = '',
}: KpiCardProps) {
  return (
    <div
      className={`relative overflow-hidden rounded-xl bg-surface-container-lowest p-space-lg shadow-sm hover:shadow-md transition-all flex flex-col justify-between ${className}`}
    >
      <div
        className={`absolute top-0 left-0 right-0 h-1 ${accentClasses[accent]}`}
        aria-hidden="true"
      />
      <div className="flex items-start justify-between">
        <span className="font-label-md text-label-md text-on-surface-variant font-medium">
          {label}
        </span>
      </div>
      <div className="my-space-md flex items-baseline gap-space-sm">
        <span className="font-headline-xl text-headline-xl text-on-surface">
          <Value value={value} />
        </span>
      </div>
      {footer ? (
        <div className="font-body-sm text-body-sm text-on-surface-variant">{footer}</div>
      ) : null}
    </div>
  );
}
