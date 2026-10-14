import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import { useCreateConnector } from './queries';
import {
  connectorSchema,
  connectorProviders,
  type ConnectorForm,
  type ConnectorValues,
} from './schemas';

/**
 * "Add Cloud Connector" dialog (F4 screen 7; ADR-0006) - `POST
 * /api/v1/cloud/connectors` with the signed-in principal in the
 * contract's `X-Actor` header. The contract's endpoint rule ("https;
 * http only on loopback") is mirrored as a UX guard; the 400 stays
 * authoritative. The response's own message reports the registered
 * status (`configured` until a credential is attached server-side).
 */
export function ConnectorDialog({
  open,
  onOpenChange,
  actor,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  actor: string;
  onStatus: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const createConnector = useCreateConnector();

  const form = useForm<ConnectorForm, unknown, ConnectorValues>({
    resolver: zodResolver(connectorSchema),
    defaultValues: { name: '', provider: 'aws', account_ref: '', endpoint: '' },
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = form;

  useEffect(() => {
    if (!open) return;
    reset({ name: '', provider: 'aws', account_ref: '', endpoint: '' });
  }, [open, reset]);

  const mutationError =
    createConnector.error instanceof Error ? createConnector.error.message : null;
  const hasErrors =
    errors.name !== undefined ||
    errors.provider !== undefined ||
    errors.endpoint !== undefined;

  const onSubmit = handleSubmit((values) => {
    onStatus(null);
    createConnector.mutate(
      {
        actor,
        payload: {
          name: values.name,
          provider: values.provider,
          ...(values.account_ref !== '' ? { account_ref: values.account_ref } : {}),
          ...(values.endpoint !== '' ? { endpoint: values.endpoint } : {}),
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
      title={t('infrastructure.dialogs.connectorTitle')}
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('infrastructure.dialogs.cancel')}
          </Button>
          <Button
            type="submit"
            form="infra-connector-form"
            disabled={createConnector.isPending}
          >
            {createConnector.isPending
              ? t('infrastructure.dialogs.registering')
              : t('infrastructure.dialogs.connectorSubmit')}
          </Button>
        </>
      }
    >
      <form
        id="infra-connector-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.name')}
          <input className={field} maxLength={64} {...register('name')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.provider')}
          <select className={field} {...register('provider')}>
            {connectorProviders.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.accountRef')}
          <input className={field} maxLength={128} {...register('account_ref')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('infrastructure.dialogs.endpoint')}
          <input
            className={field}
            maxLength={255}
            placeholder="https://api.example.com"
            {...register('endpoint')}
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
