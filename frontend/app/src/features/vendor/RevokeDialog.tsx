import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useVendorRevoke } from './queries';
import { reasonSchema, type ReasonForm, type ReasonValues } from './schemas';

/**
 * "Revoke vendor" dialog (F4 screen 8): POST /vendors/{id}/revoke.
 * The response names every active grant the server closed - when the
 * list is not empty the ids append to the status line, so nothing the
 * server did stays invisible. Reason is optional per contract.
 */
export function RevokeDialog({
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
  const vendorRevoke = useVendorRevoke();

  const form = useForm<ReasonForm, unknown, ReasonValues>({
    resolver: zodResolver(reasonSchema),
    defaultValues: { reason: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ reason: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) vendorRevoke.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    vendorRevoke.error instanceof Error ? vendorRevoke.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    vendorRevoke.mutate(
      { actor, vendorId, reason: values.reason },
      {
        onSuccess: (data) => {
          onStatus(
            data.grants_ended.length > 0
              ? `${data.message} · ${t('vendor.dialogs.grantsEnded', {
                  ids: data.grants_ended.join(', '),
                })}`
              : data.message,
          );
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
      title={t('vendor.dialogs.revokeTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-revoke-form" disabled={vendorRevoke.isPending}>
            {vendorRevoke.isPending
              ? t('vendor.dialogs.revoking')
              : t('vendor.dialogs.revokeSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-revoke-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.reason')}
          <input className={field} maxLength={255} {...register('reason')} />
        </label>
        {errors.reason !== undefined ? (
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
