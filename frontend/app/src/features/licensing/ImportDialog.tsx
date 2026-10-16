import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import type { LicenseEnvelope } from '../../api/generated/models';
import { useImportLicense } from './queries';
import { importSchema, type ImportForm } from './schemas';

/**
 * "Offline Air-Gap Ingestion" dialog (F4 screen 10, the legacy section
 * of the same name). The operator pastes the signed license file the
 * vendor delivered out-of-band; the client checks only that the paste
 * parses as JSON carrying the envelope's two required members -
 * signature verification, duplicate detection and every other refusal
 * are the SERVER's judgement, rendered verbatim (the captured duplicate
 * import answers 409 with its own reason).
 */
export function ImportDialog({
  open,
  onOpenChange,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const importLicense = useImportLicense();

  const form = useForm<ImportForm, unknown, ImportForm>({
    resolver: zodResolver(importSchema),
    defaultValues: { envelope: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use paste form).
  useEffect(() => {
    if (!open) return;
    reset({ envelope: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) importLicense.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    importLicense.error instanceof Error ? importLicense.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    const envelope = JSON.parse(values.envelope) as LicenseEnvelope;
    importLicense.mutate(envelope, {
      onSuccess: (data) => {
        onStatus(data.message);
        reset();
        onOpenChange(false);
      },
    });
  });

  const field =
    'w-full rounded bg-surface-container-low p-2 font-code-sm text-code-sm text-on-surface focus:outline-none';

  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={t('licensing.dialogs.importTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('licensing.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="licensing-import-form"
            disabled={importLicense.isPending}
          >
            {importLicense.isPending
              ? t('licensing.dialogs.importing')
              : t('licensing.dialogs.importSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="licensing-import-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('licensing.dialogs.importLabel')}
          <textarea
            className={field}
            rows={8}
            placeholder={t('licensing.dialogs.importPlaceholder')}
            {...register('envelope')}
          />
        </label>
        <p className="font-code-sm text-code-sm text-outline">
          {t('licensing.dialogs.importNote')}
        </p>
        {errors.envelope !== undefined ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t(errors.envelope.message ?? 'licensing.dialogs.invalid')}
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
