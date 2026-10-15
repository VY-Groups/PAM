import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useVendorItsm, useVendorTicket } from './queries';
import { ticketSchema, type TicketValues } from './schemas';

/**
 * "Verify ITSM ticket" dialog (F4 screen 8, chain step 3). The ticket
 * goes to the contract's REAL section-20 upstream check - unconfigured
 * ITSM is a server 409 and a refused connection is reported honestly,
 * never simulated. The dialog shows the integrations status hint above
 * the field so the operator sees the configured state before trying
 * (legacy parity), but the hint never guesses the outcome.
 */
export function TicketDialog({
  open,
  onOpenChange,
  onStatus,
  vendorId,
  actor,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
  vendorId: number;
  actor: string;
}) {
  const { t } = useTranslation();
  const vendorTicket = useVendorTicket();
  const integrations = useVendorItsm();

  const form = useForm<TicketValues, unknown, TicketValues>({
    resolver: zodResolver(ticketSchema),
    defaultValues: { ticket: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ ticket: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) vendorTicket.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    vendorTicket.error instanceof Error ? vendorTicket.error.message : null;
  const itsm = integrations.data?.itsm;
  const unconfigured = itsm !== undefined && !itsm.configured;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    vendorTicket.mutate(
      { actor, vendorId, ticket: values.ticket },
      {
        onSuccess: (data) => {
          onStatus(data.message);
          reset();
          onOpenChange(false);
        },
      },
    );
  });

  const field =
    'w-full rounded bg-surface-container-low p-2 font-body-sm text-body-sm text-on-surface focus:outline-none';

  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={t('vendor.dialogs.ticketTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-ticket-form" disabled={vendorTicket.isPending}>
            {vendorTicket.isPending
              ? t('vendor.dialogs.checking')
              : t('vendor.dialogs.ticketSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-ticket-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        {unconfigured ? (
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {t('vendor.dialogs.itsmHint', { detail: itsm.detail ?? '' })}
          </p>
        ) : null}
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.ticket')}
          <input
            className={field}
            maxLength={64}
            placeholder="INC-23891"
            {...register('ticket')}
          />
        </label>
        {errors.ticket !== undefined ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t('vendor.dialogs.invalid')}
          </span>
        ) : null}
        {mutationError !== null ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {mutationError}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}
