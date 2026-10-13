export type ChipTone = 'info' | 'inactive';

export interface ChipProps {
  children: React.ReactNode;
  /** info = bg-surface-container text-primary; inactive = text-outline (brief §2). */
  tone?: ChipTone;
  className?: string;
}

const toneClasses: Record<ChipTone, string> = {
  info: 'bg-surface-container text-primary',
  inactive: 'text-outline',
};

/** Chip / badge: rounded, font-label-badge, uppercase, tracking-wider (brief §2). */
export function Chip({ children, tone = 'info', className = '' }: ChipProps) {
  return (
    <span
      className={`inline-flex items-center rounded font-label-badge text-label-badge uppercase tracking-wider px-1.5 py-0.5 ${toneClasses[tone]} ${className}`}
    >
      {children}
    </span>
  );
}
