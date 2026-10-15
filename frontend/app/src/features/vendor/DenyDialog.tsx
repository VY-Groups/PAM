import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useVendorDeny } from './queries';
import { reasonSchema, type ReasonForm, type ReasonValues } from './schemas';

/**
 * "Deny vendor" dialog (F4 screen 8): POST /vendors/{id}/deny with the
 * optional contract reason (<= 255). The server's message and the
 * resulting denied status render from its own response.
 */
export function DenyDialog({
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
  const vendorDeny = useVendorDeny();

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
    if (!nextOpen) vendorDeny.reset();
    onOpenChange(nextOpen);
  };

  const mutationError = vendorDeny.error instanceof Error ? vendorDeny.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    vendorDeny.mutate(
      { actor, vendorId, reason: values.reason },
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
      title={t('vendor.dialogs.denyTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-deny-form" disabled={vendorDeny.isPending}>
            {vendorDeny.isPending
              ? t('vendor.dialogs.denying')
              : t('vendor.dialogs.denySubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-deny-form"
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
