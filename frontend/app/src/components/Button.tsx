import type { ButtonHTMLAttributes, ReactNode } from 'react';

export type ButtonVariant = 'primary' | 'secondary' | 'destructive';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children?: ReactNode;
  /** Material Symbols glyph name rendered as the leading icon (ADR-0007). */
  icon?: string;
  variant?: ButtonVariant;
  /**
   * Icon-only buttons MUST carry an accessible name (brief §5) - required
   * by test contract when `children` is omitted.
   */
  ariaLabel?: string;
}

const base =
  'flex items-center gap-1.5 px-space-md py-2 rounded-lg font-label-md text-label-md transition-all shadow-sm ' +
  'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary-container ' +
  'disabled:opacity-50 disabled:cursor-not-allowed';

const variants: Record<ButtonVariant, string> = {
  // as-built command-center buttons (brief §2)
  primary: 'bg-surface-container hover:bg-surface-container-high text-on-surface',
  secondary: 'bg-surface-container-lowest hover:bg-surface-container text-on-surface',
  destructive: 'bg-error hover:bg-error/90 text-on-error font-semibold tracking-wide',
};

/** Buttons (brief §2): rounded-lg, font-label-md, leading icon, honest disabled state. */
export function Button({
  children,
  icon,
  variant = 'primary',
  ariaLabel,
  className = '',
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      aria-label={ariaLabel}
      className={`${base} ${variants[variant]} ${className}`}
      {...rest}
    >
      {icon ? (
        <span className="material-symbols-outlined text-[18px]" aria-hidden="true">
          {icon}
        </span>
      ) : null}
      {children}
    </button>
  );
}
