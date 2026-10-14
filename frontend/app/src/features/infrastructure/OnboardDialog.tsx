import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useOnboardAsset } from './queries';
import {
  onboardSchema,
  assetTypes,
  accessTiers,
  type OnboardForm,
  type OnboardValues,
} from './schemas';

/**
 * "Onboard Target Host" dialog (F4 screen 7; ADR-0006). `POST
 * /api/v1/discovery/assets` registers and classifies a target and
 * ingests its first privileged account into the vault in one call -
 * the response's own `message` and vault credential report what really
 * happened, and the 400 stays authoritative for a CIDR address or an
 * out-of-range rotation.
 */
export function OnboardDialog({
  open,
  onOpenChange,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const onboard = useOnboardAsset();

  const form = useForm<OnboardForm, unknown, OnboardValues>({
    resolver: zodResolver(onboardSchema),
    defaultValues: {
      address: '',
      hostname: '',
      asset_type: 'unknown',
      notes: '',
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
      address: '',
      hostname: '',
      asset_type: 'unknown',
      notes: '',
      principal: '',
      access_tier: 'Tier-2',
      auth_method: 'Password',
      rotationText: '',
    });
  }, [open, reset]);

  const mutationError = onboard.error instanceof Error ? onboard.error.message : null;
  const hasErrors =
    errors.address !== undefined ||
    errors.principal !== undefined ||
    errors.asset_type !== undefined ||
    errors.access_tier !== undefined ||
    errors.rotationText !== undefined;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    onboard.mutate(
      {
        address: values.address,
        principal: values.principal,
        asset_type: values.asset_type,
        access_tier: values.access_tier,
        ...(values.hostname !== '' ? { hostname: values.hostname } : {}),
        ...(values.notes !== '' ? { notes: values.notes } : {}),
        ...(values.auth_method !== '' ? { auth_method: values.auth_method } : {}),
        ...(values.rotationText !== undefined
          ? { rotation_interval_hours: values.rotationText }
          : {}),
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
      title={t('infrastructure.dialogs.onboardTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('infrastructure.dialogs.cancel')}
          </Button>
          <Button type="submit" form="infra-onboard-form" disabled={onboard.isPending}>
            {onboard.isPending
              ? t('infrastructure.dialogs.onboarding')
              : t('infrastructure.dialogs.onboardSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="infra-onboard-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.address')}
          <input
            className={field}
            maxLength={64}
            placeholder="10.99.8.23"
            {...register('address')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.hostname')}
          <input className={field} maxLength={255} {...register('hostname')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.type')}
          <select className={field} {...register('asset_type')}>
            {assetTypes.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
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
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.notes')}
          <input className={field} maxLength={255} {...register('notes')} />
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
