import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useVendorNda } from './queries';
import { ndaSchema, type NdaForm, type NdaValues } from './schemas';

/**
 * "Record NDA / agreement" dialog (F4 screen 8, chain step 2). The
 * reference is optional in the contract; the write records the
 * acceptance and the server's own message renders verbatim.
 */
export function NdaDialog({
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
  const vendorNda = useVendorNda();

  const form = useForm<NdaForm, unknown, NdaValues>({
    resolver: zodResolver(ndaSchema),
    defaultValues: { ref: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ ref: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) vendorNda.reset();
    onOpenChange(nextOpen);
  };

  const mutationError = vendorNda.error instanceof Error ? vendorNda.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    vendorNda.mutate(
      { actor, vendorId, ref: values.ref },
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
      title={t('vendor.dialogs.ndaTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-nda-form" disabled={vendorNda.isPending}>
            {vendorNda.isPending
              ? t('vendor.dialogs.recordingNda')
              : t('vendor.dialogs.ndaSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-nda-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.ref')}
          <input
            className={field}
            maxLength={64}
            placeholder="NDA-2026-0042"
            {...register('ref')}
          />
        </label>
        {errors.ref !== undefined ? (
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
