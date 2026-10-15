import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../../api/http';
import { Button, Modal } from '../../components';
import { useVendorAccessRequest, useVendorItems } from './queries';
import { requestSchema, type RequestForm, type RequestValues } from './schemas';

/**
 * The reason the server attached to a refusal. The captured 403 carries
 * it under `details.vendor` (e.g. "account is revoked"); a top-level
 * `details.reason` is honoured too, so neither shape hides the truth.
 */
function refusalDetail(details: unknown): string | null {
  if (typeof details !== 'object' || details === null) return null;
  const record = details as Record<string, unknown>;
  if (typeof record.reason === 'string') return record.reason;
  const vendor = record.vendor;
  if (typeof vendor === 'object' && vendor !== null) {
    const reason = (vendor as Record<string, unknown>).reason;
    if (typeof reason === 'string') return reason;
  }
  return null;
}

/**
 * "Vendor requests access" dialog (F4 screen 8): POST
 * /vendors/{id}/requests - a REAL scoped JIT request against a picked
 * vault item. The server owns the governance answer (approved account,
 * target inside the allow list, current time inside the window, the
 * risk band) - on a refusal the contract's 403 renders verbatim AND
 * the server's own reason line (the captured arm carries
 * `details.vendor.reason`, "account is revoked"), so the cause stays
 * visible instead of hiding behind the generic message.
 */
export function RequestDialog({
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
  const accessRequest = useVendorAccessRequest();
  const items = useVendorItems();

  const form = useForm<RequestForm, unknown, RequestValues>({
    resolver: zodResolver(requestSchema),
    defaultValues: { itemId: '', reason: '', minutesText: '', ticket: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ itemId: '', reason: '', minutesText: '', ticket: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) accessRequest.reset();
    onOpenChange(nextOpen);
  };

  const error = accessRequest.error;
  const mutationError = error instanceof Error ? error.message : null;
  const refusalReason = error instanceof ApiError ? refusalDetail(error.details) : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    accessRequest.mutate(
      {
        actor,
        vendorId,
        payload: {
          item_id: values.itemId,
          reason: values.reason,
          minutes: values.minutesText,
          ticket: values.ticket,
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
      title={t('vendor.dialogs.requestTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="vendor-request-form"
            disabled={accessRequest.isPending}
          >
            {accessRequest.isPending
              ? t('vendor.dialogs.filing')
              : t('vendor.dialogs.requestSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-request-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.item')}
          <select className={field} {...register('itemId')}>
            <option value="">{t('vendor.dialogs.itemPick')}</option>
            {(items.data?.items ?? []).map((item) => (
              <option key={item.id} value={item.id}>
                {`${item.name} · ${item.target}`}
              </option>
            ))}
          </select>
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.requestReason')}
          <input
            className={field}
            maxLength={255}
            placeholder="change window on the reporting replica"
            {...register('reason')}
          />
        </label>
        <div className="flex gap-space-sm">
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('vendor.dialogs.minutes')}
            <input
              className={field}
              maxLength={4}
              inputMode="numeric"
              placeholder="15"
              {...register('minutesText')}
            />
          </label>
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('vendor.dialogs.requestTicket')}
            <input className={field} maxLength={64} {...register('ticket')} />
          </label>
        </div>
        {errors.itemId !== undefined ||
        errors.reason !== undefined ||
        errors.minutesText !== undefined ||
        errors.ticket !== undefined ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t('vendor.dialogs.invalid')}
          </span>
        ) : null}
        {mutationError !== null ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {refusalReason !== null ? `${mutationError} — ${refusalReason}` : mutationError}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}
