import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import type { CommandRule } from '../../api/generated/models';
import { useCreateRule, useUpdateRule } from './queries';
import { ruleSchema, type RuleForm, type RuleValues } from './schemas';

/**
 * Create / Edit Policy Rule dialog (plan §4 line 110; ADR-0006: RHF +
 * Zod, client validation is UX only - the contract 400 stays
 * authoritative). The legacy modal sent every field on both create and
 * update; so does this one. `terminate_on_match` is only offerable when
 * the action is `block` - the same rule the contract enforces
 * ("Refused unless action is block"), mirrored in the UX so the dialog
 * cannot propose a payload the server will reject.
 */
export function RuleDialog({
  open,
  onOpenChange,
  rule,
  actor,
  onStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule: CommandRule | null;
  actor: string;
  onStatus: (message: string) => void;
}) {
  const { t } = useTranslation();
  const createRule = useCreateRule();
  const updateRule = useUpdateRule();

  const form = useForm<RuleForm, unknown, RuleValues>({
    resolver: zodResolver(ruleSchema),
    defaultValues: {
      name: '',
      pattern: '',
      action: 'allow',
      target_pattern: '',
      description: '',
      terminate_on_match: false,
      enabled: true,
    },
  });
  const {
    register,
    handleSubmit,
    reset,
    control,
    formState: { errors },
  } = form;
  // useWatch (not watch): subscription-based, memoizable by React Compiler.
  const action = useWatch({ control, name: 'action' });
  const terminate = useWatch({ control, name: 'terminate_on_match' });

  // Refill whenever the dialog opens: blank for create, the real rule for edit.
  useEffect(() => {
    if (!open) return;
    reset(
      rule === null
        ? {
            name: '',
            pattern: '',
            action: 'allow',
            target_pattern: '',
            description: '',
            terminate_on_match: false,
            enabled: true,
          }
        : {
            name: rule.name,
            pattern: rule.pattern,
            action: rule.action,
            target_pattern: rule.target_pattern,
            description: rule.description,
            terminate_on_match: rule.terminate_on_match,
            enabled: rule.enabled,
          },
    );
  }, [open, rule, reset]);

  const pending = createRule.isPending || updateRule.isPending;
  const mutationError =
    createRule.error instanceof Error
      ? createRule.error.message
      : updateRule.error instanceof Error
        ? updateRule.error.message
        : null;
  const hasErrors =
    errors.name !== undefined ||
    errors.pattern !== undefined ||
    errors.action !== undefined ||
    errors.target_pattern !== undefined ||
    errors.description !== undefined;

  const onSubmit = handleSubmit((values) => {
    const payload = {
      name: values.name,
      pattern: values.pattern,
      action: values.action,
      target_pattern: values.target_pattern,
      description: values.description,
      // Never propose an escalation the contract would refuse.
      terminate_on_match: values.action === 'block' && values.terminate_on_match,
      enabled: values.enabled,
    };
    if (rule === null) {
      createRule.mutate(
        { actor, payload },
        {
          onSuccess: (data) => {
            onStatus(t('policy.toast.ruleCreated', { id: data.rule.id }));
            reset();
            onOpenChange(false);
          },
        },
      );
    } else {
      updateRule.mutate(
        { actor, ruleId: rule.id, payload },
        {
          onSuccess: () => {
            onStatus(t('policy.toast.ruleUpdated', { id: rule.id }));
            onOpenChange(false);
          },
        },
      );
    }
  });

  const field =
    'w-full rounded bg-surface-container-low p-2 font-body-sm text-body-sm text-on-surface focus:outline-none';

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={
        rule === null ? t('policy.dialogs.createTitle') : t('policy.dialogs.editTitle')
      }
      closeLabel={t('common.close')}
      footer={
        <>
          <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
            {t('policy.dialogs.cancel')}
          </Button>
          <Button type="submit" form="policy-rule-form" disabled={pending}>
            {rule === null ? t('policy.dialogs.create') : t('policy.dialogs.save')}
          </Button>
        </>
      }
    >
      <form
        id="policy-rule-form"
        className="flex flex-col gap-space-sm"
        onSubmit={onSubmit}
        noValidate
      >
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('policy.dialogs.name')}
          <input className={field} maxLength={120} {...register('name')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('policy.dialogs.pattern')}
          <input className={field} maxLength={160} {...register('pattern')} />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('policy.dialogs.action')}
          <select className={field} {...register('action')}>
            <option value="allow">allow</option>
            <option value="approval">approval</option>
            <option value="block">block</option>
          </select>
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('policy.dialogs.target')}
          <input
            className={field}
            maxLength={120}
            placeholder="prod-*"
            {...register('target_pattern')}
          />
        </label>
        <label className="font-code-sm text-code-sm text-outline uppercase">
          {t('policy.dialogs.description')}
          <input className={field} maxLength={255} {...register('description')} />
        </label>
        <div className="flex items-center gap-space-md font-body-sm text-body-sm text-on-surface">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              disabled={action !== 'block'}
              checked={action === 'block' && terminate}
              onChange={(e) =>
                form.setValue('terminate_on_match', e.target.checked, {
                  shouldValidate: true,
                })
              }
            />
            {t('policy.dialogs.terminate')}
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" {...register('enabled')} />
            {t('policy.dialogs.enabled')}
          </label>
        </div>
        {hasErrors ? (
          <span role="alert" className="font-body-sm text-body-sm text-error">
            {t('policy.dialogs.invalid')}
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
