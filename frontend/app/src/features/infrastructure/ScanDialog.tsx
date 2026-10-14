import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useRunScan } from './queries';
import { scanSchema, type ScanForm, type ScanValues } from './schemas';

/**
 * "Run Discovery Scan" dialog (F4 screen 7; ADR-0006: RHF + Zod, client
 * validation is UX only - the contract 400 stays authoritative). The
 * scan is a REAL synchronous TCP-connect probe of the operator's scope,
 * so the contract demands an explicit one - there is no default scope
 * and this dialog cannot invent one. Empty ports keep the parameter
 * absent, letting the server use its management-plane default set.
 */
export function ScanDialog({
  open,
  onOpenChange,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const runScan = useRunScan();

  const form = useForm<ScanForm, unknown, ScanValues>({
    resolver: zodResolver(scanSchema),
    defaultValues: { scope: '', portsText: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use probe form).
  useEffect(() => {
    if (!open) return;
    reset({ scope: '', portsText: '' });
  }, [open, reset]);

  const mutationError = runScan.error instanceof Error ? runScan.error.message : null;
  const hasErrors = errors.scope !== undefined || errors.portsText !== undefined;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    // `portsText` transforms to `number[] | undefined`; absent keeps the
    // contract's default port set instead of posting a fabricated one.
    runScan.mutate(
      values.portsText === undefined
        ? { scope: values.scope }
        : { scope: values.scope, ports: values.portsText },
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
      onOpenChange={onOpenChange}
      title={t('infrastructure.dialogs.scanTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('infrastructure.dialogs.cancel')}
          </Button>
          <Button type="submit" form="infra-scan-form" disabled={runScan.isPending}>
            {runScan.isPending
              ? t('infrastructure.dialogs.scanning')
              : t('infrastructure.dialogs.scanSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="infra-scan-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.scope')}
          <input
            className={field}
            maxLength={64}
            placeholder="10.99.8.0/24"
            {...register('scope')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.ports')}
          <input
            className={field}
            maxLength={64}
            placeholder={t('infrastructure.dialogs.portsHint')}
            {...register('portsText')}
          />
        </label>
        {hasErrors ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t('infrastructure.dialogs.invalid')}
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
