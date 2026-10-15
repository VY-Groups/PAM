import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useInviteVendor } from './queries';
import { inviteSchema, type InviteForm, type InviteValues } from './schemas';
import type { VendorSeed } from './SeedCard';

/**
 * "Invite vendor" dialog (F4 screen 8; ADR-0006: RHF + Zod, client UX
 * only - the contract 400 stays authoritative). Mirrors
 * `VendorInviteRequest`: name/contact, the allowed/denied target lists
 * one per line, the HH:MM window only as a pair, recording on by
 * default. The server answers with the account row plus the one-time
 * TOTP seed - handed straight to the page's seed card, never stored.
 */
export function InviteDialog({
  open,
  onOpenChange,
  onStatus,
  onSeed,
  actor,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
  onSeed: (seed: VendorSeed | null) => void;
  actor: string;
}) {
  const { t } = useTranslation();
  const inviteVendor = useInviteVendor();

  const form = useForm<InviteForm, unknown, InviteValues>({
    resolver: zodResolver(inviteSchema),
    defaultValues: {
      name: '',
      contact: '',
      allowedText: '',
      deniedText: '',
      windowStart: '',
      windowEnd: '',
      recording: true,
    },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use invite form).
  useEffect(() => {
    if (!open) return;
    reset({
      name: '',
      contact: '',
      allowedText: '',
      deniedText: '',
      windowStart: '',
      windowEnd: '',
      recording: true,
    });
  }, [open, reset]);

  /** Clear a stale refusal when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) inviteVendor.reset();
    onOpenChange(nextOpen);
  };

  const mutationError =
    inviteVendor.error instanceof Error ? inviteVendor.error.message : null;
  const hasErrors =
    errors.name !== undefined ||
    errors.contact !== undefined ||
    errors.allowedText !== undefined ||
    errors.deniedText !== undefined ||
    errors.windowStart !== undefined ||
    errors.windowEnd !== undefined ||
    errors.recording !== undefined;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    inviteVendor.mutate(
      {
        actor,
        payload: {
          name: values.name,
          contact: values.contact,
          allowed_targets: values.allowed_targets,
          denied_targets: values.denied_targets,
          window_start: values.window_start,
          window_end: values.window_end,
          recording: values.recording,
        },
      },
      {
        onSuccess: (data) => {
          onStatus(data.message);
          onSeed({ name: data.vendor.name, mfa: data.mfa });
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
      title={t('vendor.dialogs.inviteTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => close(false)}>
            {t('vendor.dialogs.cancel')}
          </Button>
          <Button type="submit" form="vendor-invite-form" disabled={inviteVendor.isPending}>
            {inviteVendor.isPending
              ? t('vendor.dialogs.inviting')
              : t('vendor.dialogs.inviteSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="vendor-invite-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.name')}
          <input
            className={field}
            maxLength={128}
            placeholder="acme-consultant.example"
            {...register('name')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.contact')}
          <input
            className={field}
            maxLength={160}
            placeholder="ops@acme.example"
            {...register('contact')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.allowed')}
          <textarea
            className={field}
            rows={3}
            placeholder={'10.66.66.0/24\ndb-alpha.internal'}
            {...register('allowedText')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('vendor.dialogs.denied')}
          <textarea className={field} rows={2} {...register('deniedText')} />
        </label>
        <div className="flex gap-space-sm">
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('vendor.dialogs.windowStart')}
            <input className={field} type="time" {...register('windowStart')} />
          </label>
          <label className="flex-1 font-code-sm text-code-sm text-outline uppercase">
            {t('vendor.dialogs.windowEnd')}
            <input className={field} type="time" {...register('windowEnd')} />
          </label>
        </div>
        <label className="flex items-center gap-space-sm font-body-sm text-body-sm text-on-surface-variant">
          <input type="checkbox" {...register('recording')} />
          {t('vendor.dialogs.recording')}
        </label>
        {hasErrors ? (
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
