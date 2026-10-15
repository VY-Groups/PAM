import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useFileBreakGlass } from './queries';
import {
  breakGlassProtocols,
  breakGlassSeverities,
  fileSchema,
  type FileForm,
  type FileValues,
} from './schemas';

/**
 * "File emergency request" dialog (F4 screen 9; ADR-0006: RHF + Zod,
 * client UX only - the contract 400 stays authoritative). Mirrors
 * `BreakGlassCreateRequest`: target and reason required with the
 * server's own limits, severity defaults to sev1 and the protocol to
 * ssh, and the legacy console's EMERGENCY-AUTHORIZE typing guard stays
 * (client-only, never posted). The server answers the request row plus
 * its filing message, rendered verbatim.
 */
export function FileDialog({
  open,
  onOpenChange,
  onStatus,
  actor,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
  actor: string;
}) {
  const { t } = useTranslation();
  const fileBreakGlass = useFileBreakGlass();

  const form = useForm<FileForm, unknown, FileValues>({
    resolver: zodResolver(fileSchema),
    defaultValues: {
      target: '',
      severity: 'sev1',
      protocol: 'ssh',
      reason: '',
      confirm: '',
    },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use filing form).
  useEffect(() => {
    if (!open) return;
    reset({
      target: '',
      severity: 'sev1',
      protocol: 'ssh',
      reason: '',
      confirm: '',
    });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) fileBreakGlass.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    fileBreakGlass.error instanceof Error ? fileBreakGlass.error.message : null;
  const hasErrors =
    errors.target !== undefined ||
    errors.severity !== undefined ||
    errors.protocol !== undefined ||
    errors.reason !== undefined ||
    errors.confirm !== undefined;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    fileBreakGlass.mutate(
      {
        actor,
        payload: {
          target: values.target,
          reason: values.reason,
          severity: values.severity,
          protocol: values.protocol,
        },
      },
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
      title={t('breakGlass.dialogs.fileTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('breakGlass.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="break-glass-file-form"
            disabled={fileBreakGlass.isPending}
          >
            {fileBreakGlass.isPending
              ? t('breakGlass.dialogs.filing')
              : t('breakGlass.dialogs.fileSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="break-glass-file-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <p className="font-code-sm text-code-sm text-outline">
          {t('breakGlass.dialogs.fileHint')}
        </p>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('breakGlass.dialogs.target')}
          <input
            className={field}
            maxLength={255}
            placeholder="db-01.corp:5432"
            {...register('target')}
          />
        </label>
        <div className="flex gap-space-sm">
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('breakGlass.dialogs.severity')}
            <select className={field} {...register('severity')}>
              {breakGlassSeverities.map((severity) => (
                <option key={severity} value={severity}>
                  {t(`breakGlass.dialogs.${severity}`)}
                </option>
              ))}
            </select>
          </label>
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('breakGlass.dialogs.protocol')}
            <select className={field} {...register('protocol')}>
              {breakGlassProtocols.map((protocol) => (
                <option key={protocol} value={protocol}>
                  {protocol}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('breakGlass.dialogs.reason')}
          <textarea
            className={field}
            rows={4}
            maxLength={1000}
            placeholder={t('breakGlass.dialogs.reasonPlaceholder')}
            {...register('reason')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('breakGlass.dialogs.confirmLabel')}
          <input
            className={field}
            placeholder="EMERGENCY-AUTHORIZE"
            {...register('confirm')}
          />
        </label>
        {hasErrors ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t('breakGlass.dialogs.invalid')}
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
