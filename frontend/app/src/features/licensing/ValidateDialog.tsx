import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Chip, Modal } from '../../components';
import type { ValidationResult } from '../../api/generated/models';
import { useValidateLicense } from './queries';
import { validateSchema, type ValidateForm } from './schemas';

/**
 * Offline-parity validation dialog (F4 screen 10): the operator pastes
 * a license file (envelope JSON) or the compact JWT token straight from
 * the `text/plain` file answer, and the SERVER returns its verdict -
 * signature validity, registration match, revocation and expiry state -
 * without touching the registry. The dialog renders the verdict
 * structurally (every flag the contract answers), so "valid" and
 * "signature invalid" are the server's words, never the client's
 * opinion.
 */
export function ValidateDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation();
  const validateLicense = useValidateLicense();
  const [verdict, setVerdict] = useState<ValidationResult | null>(null);

  const form = useForm<ValidateForm, unknown, ValidateForm>({
    resolver: zodResolver(validateSchema),
    defaultValues: { payload: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  // Refill blank every time the dialog opens (single-use paste form).
  // The verdict and the mutation state clear in `close` below - no
  // setState or mutation.reset in an effect (both would loop: the
  // mutation object's identity changes every render).
  useEffect(() => {
    if (!open) return;
    reset({ payload: '' });
  }, [open, reset]);

  /** Clear a stale verdict when the dialog closes; next open is fresh. */
  const close = (nextOpen: boolean) => {
    if (!nextOpen) {
      validateLicense.reset();
      setVerdict(null);
    }
    onOpenChange(nextOpen);
  };

  const mutationError =
    validateLicense.error instanceof Error ? validateLicense.error.message : null;

  const onSubmit = handleSubmit((values) => {
    const raw = values.payload;
    // A compact JWT goes as the string arm; parsed JSON as the envelope.
    const body = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw)
      ? raw
      : (JSON.parse(raw) as Record<string, unknown>);
    setVerdict(null);
    validateLicense.mutate(body, { onSuccess: (data) => setVerdict(data) });
  });

  const field =
    'w-full rounded bg-surface-container-low p-2 font-code-sm text-code-sm text-on-surface focus:outline-none';

  return (
    <Modal
      open={open}
      onOpenChange={close}
      title={t('licensing.dialogs.validateTitle')}
      closeLabel={t('common.close')}
      footer={
        <Button type="button" variant="secondary" onClick={() => close(false)}>
          {t('licensing.dialogs.close')}
        </Button>
      }
    >
      <form
        id="licensing-validate-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('licensing.dialogs.validateLabel')}
          <textarea
            className={field}
            rows={6}
            placeholder={t('licensing.dialogs.validatePlaceholder')}
            {...register('payload')}
          />
        </label>
        <Button
          type="submit"
          form="licensing-validate-form"
          variant="secondary"
          disabled={validateLicense.isPending}
        >
          {validateLicense.isPending
            ? t('licensing.dialogs.validating')
            : t('licensing.dialogs.validateSubmit')}
        </Button>
        {errors.payload !== undefined ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t(errors.payload.message ?? 'licensing.dialogs.invalid')}
          </span>
        ) : null}
        {mutationError !== null ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {mutationError}
          </p>
        ) : null}
      </form>
      {verdict !== null ? (
        <div
          className="mt-3 flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 p-space-sm"
          data-testid="validate-verdict"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone={verdict.valid ? 'info' : 'inactive'}>
              {verdict.valid
                ? t('licensing.dialogs.verdictValid')
                : t('licensing.dialogs.verdictInvalid')}
            </Chip>
            <span className="font-code-sm text-code-sm text-outline">
              {verdict.status} · {verdict.reason ?? t('licensing.dialogs.noReason')}
            </span>
          </div>
          <dl className="grid gap-1 font-code-sm text-code-sm sm:grid-cols-2">
            <div>
              <dt className="text-outline">{t('licensing.dialogs.signatureValid')}</dt>
              <dd>{String(verdict.signature_valid)}</dd>
            </div>
            <div>
              <dt className="text-outline">{t('licensing.dialogs.registered')}</dt>
              <dd>{String(verdict.registered)}</dd>
            </div>
            <div>
              <dt className="text-outline">{t('licensing.dialogs.revoked')}</dt>
              <dd>
                {String(verdict.revoked ?? false)}
                {verdict.revoked_reason ? ` · ${verdict.revoked_reason}` : ''}
              </dd>
            </div>
            <div>
              <dt className="text-outline">{t('licensing.dialogs.expired')}</dt>
              <dd>{String(verdict.expired ?? false)}</dd>
            </div>
            <div>
              <dt className="text-outline">{t('licensing.dialogs.matchesRecord')}</dt>
              <dd>{String(verdict.matches_registered_record ?? '—')}</dd>
            </div>
            <div>
              <dt className="text-outline">{t('licensing.dialogs.fingerprint')}</dt>
              <dd className="break-all">{verdict.fingerprint ?? '—'}</dd>
            </div>
          </dl>
          {Array.isArray(verdict.license?.entitled_modules) &&
          verdict.license.entitled_modules.length > 0 ? (
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('licensing.dialogs.entitledCount', {
                count: verdict.license.entitled_modules.length,
                total: Number(verdict.license.module_catalog_size ?? 0),
              })}
            </p>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}
