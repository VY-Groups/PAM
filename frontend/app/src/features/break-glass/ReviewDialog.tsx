import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useCloseBreakGlass } from './queries';
import { reviewSchema, type ReviewValues } from './schemas';

/**
 * "Close emergency - post-incident review" dialog (F4 screen 9, section
 * 17 final step). The review note is REQUIRED by the contract (an
 * emergency that is not reviewed is not closed) and at most 1000
 * chars; the server answers the closed request plus its rotation
 * outcome, rendered verbatim.
 */
export function ReviewDialog({
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
  const closeBreakGlass = useCloseBreakGlass();

  const form = useForm<{ review: string }, unknown, ReviewValues>({
    resolver: zodResolver(reviewSchema),
    defaultValues: { review: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use review form).
  useEffect(() => {
    if (!open) return;
    reset({ review: '' });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) closeBreakGlass.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    closeBreakGlass.error instanceof Error ? closeBreakGlass.error.message : null;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    closeBreakGlass.mutate(
      { actor, requestId: requestId as number, review: values.review },
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
      title={t('breakGlass.dialogs.reviewTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('breakGlass.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="break-glass-review-form"
            disabled={closeBreakGlass.isPending}
          >
            {closeBreakGlass.isPending
              ? t('breakGlass.dialogs.reviewing')
              : t('breakGlass.dialogs.reviewSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="break-glass-review-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('breakGlass.dialogs.reviewLabel')}
          <textarea
            className={field}
            rows={4}
            maxLength={1000}
            placeholder={t('breakGlass.dialogs.reviewPlaceholder')}
            {...register('review')}
          />
        </label>
        <p className="font-code-sm text-code-sm text-outline">
          {t('breakGlass.dialogs.reviewNote')}
        </p>
        {errors.review !== undefined ? (
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
