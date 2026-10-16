import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import type { LicenseRecord } from '../../api/generated/models';
import { useRevokeLicense } from './queries';
import { revokeSchema, type RevokeForm } from './schemas';

/**
 * Revoke dialog (F4 screen 10): revocation is terminal (the contract's
 * own lifecycle - a revoked license can only be restored through the
 * explicit restore action), so the destructive confirm always asks for
 * the recorded reason. The reason is optional in the contract and stays
 * optional here (never tighter); the server answers its mutation
 * message verbatim, and the activity timeline picks up the `revoked`
 * event through the shared key-root invalidation.
 */
export function RevokeDialog({
  open,
  onOpenChange,
  onStatus,
  license,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
  license: LicenseRecord | null;
}) {
  const { t } = useTranslation();
  const revokeLicense = useRevokeLicense();

  const form = useForm<RevokeForm, unknown, RevokeForm>({
    resolver: zodResolver(revokeSchema),
    defaultValues: { reason: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use revoke form).
  useEffect(() => {
    if (!open) return;
    reset({ reason: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) revokeLicense.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    revokeLicense.error instanceof Error ? revokeLicense.error.message : null;

  const onSubmit = handleSubmit((values) => {
    if (license === null) return;
    onStatus(null);
    revokeLicense.mutate(
      { licenseKey: license.license_key, reason: values.reason },
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
      title={t('licensing.dialogs.revokeTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('licensing.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="licensing-revoke-form"
            variant="destructive"
            disabled={revokeLicense.isPending}
          >
            {revokeLicense.isPending
              ? t('licensing.dialogs.revoking')
              : t('licensing.dialogs.revokeSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="licensing-revoke-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('licensing.dialogs.revokeConfirm', {
            license: license?.license_id ?? license?.license_key ?? '—',
          })}
        </p>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('licensing.dialogs.revokeReasonLabel')}
          <textarea
            className={field}
            rows={3}
            maxLength={500}
            placeholder={t('licensing.dialogs.revokeReasonPlaceholder')}
            {...register('reason')}
          />
        </label>
        <p className="font-code-sm text-code-sm text-outline">
          {t('licensing.dialogs.revokeNote')}
        </p>
        {errors.reason !== undefined ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t(errors.reason.message ?? 'licensing.dialogs.invalid')}
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
