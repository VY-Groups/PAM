export type DotState = 'live' | 'ok' | 'error' | 'muted';

export interface StatusDotProps {
  /**
   * live = bg-primary + animate-pulse, ok = bg-tertiary (flat),
   * error = bg-error, muted = bg-outline (as-built patterns, brief §2).
   */
  state?: DotState;
  className?: string;
}

const stateClasses: Record<DotState, string> = {
  live: 'bg-primary animate-pulse',
  ok: 'bg-tertiary',
  error: 'bg-error',
  muted: 'bg-outline',
};

/**
 * Status dot (brief §2). Always paired with a text label (brief §5) -
 * decorative, therefore hidden from assistive tech.
 */
export function StatusDot({ state = 'ok', className = '' }: StatusDotProps) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block w-1.5 h-1.5 rounded-full ${stateClasses[state]} ${className}`}
    />
  );
}
