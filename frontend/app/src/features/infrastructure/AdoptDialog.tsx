import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useAdoptAsset } from './queries';
import { adoptSchema, accessTiers, type AdoptForm, type AdoptValues } from './schemas';

/**
 * "Onboard to Vault Now" dialog (F4 screen 7; ADR-0006) - adopts ONE
 * discovered target into the vault via `POST
 * /api/v1/discovery/assets/{id}/onboard`. The server refuses an
 * already-managed target ("already onboarded"); that 409 surfaces
 * verbatim, the 400 stays authoritative, and the response's own
 * message reports the metadata-only credential it created.
 */
export function AdoptDialog({
  open,
  onOpenChange,
  target,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  target: { id: number; address: string } | null;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const adopt = useAdoptAsset();

  const form = useForm<AdoptForm, unknown, AdoptValues>({
    resolver: zodResolver(adoptSchema),
    defaultValues: {
      principal: '',
      access_tier: 'Tier-2',
      auth_method: 'Password',
      rotationText: '',
    },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({
      principal: '',
      access_tier: 'Tier-2',
      auth_method: 'Password',
      rotationText: '',
    });
  }, [open, reset]);

  const mutationError = adopt.error instanceof Error ? adopt.error.message : null;
  const hasErrors =
    errors.principal !== undefined ||
    errors.access_tier !== undefined ||
    errors.rotationText !== undefined;

  const onSubmit = handleSubmit((values) => {
    if (target === null) return;
    onStatus(null);
    adopt.mutate(
      {
        assetId: target.id,
        payload: {
          principal: values.principal,
          access_tier: values.access_tier,
          ...(values.auth_method !== '' ? { auth_method: values.auth_method } : {}),
          ...(values.rotationText !== undefined
            ? { rotation_interval_hours: values.rotationText }
            : {}),
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
      onOpenChange={onOpenChange}
      title={
        target
          ? t('infrastructure.dialogs.adoptTitle', { address: target.address })
          : t('infrastructure.dialogs.adoptTitleFallback')
      }
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('infrastructure.dialogs.cancel')}
          </Button>
          <Button type="submit" form="infra-adopt-form" disabled={adopt.isPending}>
            {adopt.isPending
              ? t('infrastructure.dialogs.adopting')
              : t('infrastructure.dialogs.adoptSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="infra-adopt-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.principal')}
          <input className={field} maxLength={128} {...register('principal')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.tier')}
          <select className={field} {...register('access_tier')}>
            {accessTiers.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.authMethod')}
          <input className={field} maxLength={32} {...register('auth_method')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.rotation')}
          <input
            className={field}
            maxLength={5}
            placeholder={t('infrastructure.dialogs.rotationHint')}
            {...register('rotationText')}
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
