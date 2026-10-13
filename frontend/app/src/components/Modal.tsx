import * as Dialog from '@radix-ui/react-dialog';
import type { ReactNode } from 'react';

export interface ModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  /** Footer action cluster (e.g. confirm/cancel buttons). */
  footer?: ReactNode;
  closeLabel?: string;
}

/**
 * Modal (brief §2): centered card rounded-xl bg-surface-container-lowest,
 * dark scrim, close ×. Radix Dialog primitive per ADR-0003 (focus trap,
 * Esc, aria wiring for free); title is required for the accessible name.
 */
export function Modal({
  open,
  onOpenChange,
  title,
  children,
  footer,
  closeLabel = 'Close dialog',
}: ModalProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-50" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl bg-surface-container-lowest p-space-xl shadow-lg focus:outline-none">
          <div className="flex items-start justify-between gap-space-md">
            <Dialog.Title className="font-headline-lg text-headline-lg text-on-surface">
              {title}
            </Dialog.Title>
            <Dialog.Close
              aria-label={closeLabel}
              className="rounded-lg p-space-xs text-on-surface-variant hover:bg-surface-container focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary-container"
            >
              <span className="material-symbols-outlined text-[20px]" aria-hidden="true">
                close
              </span>
            </Dialog.Close>
          </div>
          <div className="mt-space-md font-body-md text-body-md text-on-surface">
            {children}
          </div>
          {footer ? (
            <div className="mt-space-xl flex justify-end gap-space-sm">{footer}</div>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
