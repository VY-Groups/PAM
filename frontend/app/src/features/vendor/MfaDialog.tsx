import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useVendorMfa } from './queries';
import { mfaSchema, type MfaValues } from './schemas';

/**
 * "Verify vendor MFA" dialog (F4 screen 8, chain step 1). The code goes
 * to the contract's REAL RFC-6238 verification - a wrong or expired
 * code comes back 401 and its message renders verbatim; the client
 * pattern (6-8 digits) is UX only.
 */
export function MfaDialog({
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
  const vendorMfa = useVendorMfa();

  const form = useForm<MfaValues, unknown, MfaValues>({
    resolver: zodResolver(mfaSchema),
    defaultValues: { code: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ code: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) vendorMfa.reset();
    onOpenChange(nextOpen);
  };

  const mutationError = vendorMfa.error instanceof Error ? vendorMfa.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    vendorMfa.mutate(
      { actor, vendorId, code: values.code },
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
      title={t('vendor.dialogs.mfaTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-mfa-form" disabled={vendorMfa.isPending}>
            {vendorMfa.isPending
              ? t('vendor.dialogs.verifying')
              : t('vendor.dialogs.mfaSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-mfa-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.code')}
          <input
            className={field}
            maxLength={8}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            {...register('code')}
          />
        </label>
        {errors.code !== undefined ? (
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
