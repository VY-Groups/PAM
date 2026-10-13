import type { ReactNode } from 'react';

export interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  /** Right-aligned action cluster (brief §2). */
  actions?: ReactNode;
  className?: string;
}

/** Section header (brief §2): headline-lg + body-md subtitle + action cluster. */
export function SectionHeader({
  title,
  subtitle,
  actions,
  className = '',
}: SectionHeaderProps) {
  return (
    <div className={`flex items-start justify-between gap-space-lg ${className}`}>
      <div className="flex flex-col gap-space-xs">
        <h2 className="font-headline-lg text-headline-lg text-on-surface">{title}</h2>
        {subtitle ? (
          <p className="font-body-md text-body-md text-on-surface-variant">{subtitle}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-space-sm">{actions}</div> : null}
    </div>
  );
}
