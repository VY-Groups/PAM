import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useOpenBreakGlass } from './queries';
import { releaseSchema, type ReleaseValues } from './schemas';

/**
 * "Open emergency - MFA release" dialog (F4 screen 9, section 20). It
 * exists ONLY while `integrations/status` reports a factor enrolled -
 * the legacy console's gate - and posts the 6-digit TOTP code for
 * server-side verification; a rejected code keeps the dialog open with
 * the server's own 401 reason, never simulated. With no factor
 * enrolled the screen opens directly with no code at all (the honest
 * `not configured` path).
 */
export function ReleaseDialog({
  open,
  onOpenChange,
  onStatus,
  requestId,
  actor,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
  requestId: number | null;
  actor: string;
}) {
  const { t } = useTranslation();
  const openBreakGlass = useOpenBreakGlass();

  const form = useForm<{ mfaCode: string }, unknown, ReleaseValues>({
    resolver: zodResolver(releaseSchema),
    defaultValues: { mfaCode: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use release form).
  useEffect(() => {
    if (!open) return;
    reset({ mfaCode: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) openBreakGlass.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    openBreakGlass.error instanceof Error ? openBreakGlass.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    openBreakGlass.mutate(
      { actor, requestId: requestId as number, mfaCode: values.mfaCode },
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
    'w-full rounded bg-surface-container-low p-2 font-body-sm text-body-sm tracking-[0.4em] text-on-surface focus:outline-none';

  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={t('breakGlass.dialogs.releaseTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('breakGlass.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="break-glass-release-form"
            variant="destructive"
            disabled={openBreakGlass.isPending}
          >
            {openBreakGlass.isPending
              ? t('breakGlass.dialogs.releasing')
              : t('breakGlass.dialogs.releaseSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="break-glass-release-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('breakGlass.dialogs.codeLabel')}
          <input
            className={field}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            {...register('mfaCode')}
          />
        </label>
        <p className="font-code-sm text-code-sm text-outline">
          {t('breakGlass.dialogs.releaseNote')}
        </p>
        {errors.mfaCode !== undefined ? (
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
