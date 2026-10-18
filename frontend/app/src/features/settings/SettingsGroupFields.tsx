/**
 * One schema group's controls (screen 11, ADR-0015 11.3) - a verbatim
 * translation of the legacy page's `renderGroup`/`controlHtml`
 * (code.html:1096-1190): one control per schema field inside a
 * `data-settings-group="<group>"` grid, labels from the i18n catalogue
 * (the legacy `pretty()+WORDS` output, keyed per group/field), the
 * meta line in `data-group-meta="<group>"` with the legacy
 * `saved <ago> by <who>` / `built-in defaults (not saved yet)` words,
 * and `loading...` only while the read is actually in flight - never
 * after settle (ADR-0015 cross-cutting honesty rule).
 */
import { useTranslation } from 'react-i18next';

import { settingsAgo } from './ago';
import { useSettingsForm } from './settingsFormContext';
import { controlKind, fieldError, formatFieldError } from './settingsSchema';
import type { FieldSpec } from './settingsSchema';

const INPUT_CLASS =
  'px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm ' +
  'border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

/** The `data-group-meta` span: stored-or-defaults, honestly. */
export function GroupMeta({ group }: { group: string }) {
  const { t } = useTranslation();
  const { rows, loading, loadFailed } = useSettingsForm();
  const row = rows?.[group];

  let text: string;
  if (loading) text = t('settings.forms.loading');
  else if (loadFailed) text = '\u2014';
  else if (row?.stored)
    text = t('settings.forms.metaSaved', {
      ago: settingsAgo(row.updated_at, t),
      by: row.updated_by ?? '',
    });
  else text = t('settings.forms.metaDefault');

  return (
    <span
      className="font-code-sm text-code-sm text-on-surface-variant"
      data-group-meta={group}
    >
      {text}
    </span>
  );
}

/** The group's controls grid - empty while the schema is not there. */
export function SettingsGroupFields({ group }: { group: string }) {
  const fields = useSettingsForm().schema?.[group];
  if (!fields) return null;
  return (
    <div
      className="grid grid-cols-1 md:grid-cols-2 gap-space-sm"
      data-settings-group={group}
    >
      {Object.entries(fields).map(([field, spec]) => (
        <SettingsField key={field} field={field} group={group} spec={spec} />
      ))}
    </div>
  );
}

function SettingsField({
  field,
  group,
  spec,
}: {
  field: string;
  group: string;
  spec: FieldSpec;
}) {
  const { t } = useTranslation();
  const { form, rows, schema } = useSettingsForm();
  const name = `${group}.${field}`;
  const label = t(`settings.forms.fieldLabels.${group}.${field}`);
  const kind = controlKind(spec);
  const messageKey = fieldError(form.formState.errors, group, field);

  const error =
    messageKey && schema ? (
      <p className="font-body-sm text-body-sm text-error" role="alert">
        {formatFieldError(schema, group, field, messageKey, t)}
      </p>
    ) : null;

  if (kind === 'checkbox') {
    // `name` is a dynamic dotted path: RHF's Path maps this index-signature
    // form to the GROUP record for typing, so the runtime value is narrowed
    // here instead (the dot-path lookup itself is exact).
    const watched = form.watch(name);
    const checked = typeof watched === 'boolean' ? watched : false;
    return (
      <div className="flex flex-col gap-1.5 p-space-sm rounded-lg bg-surface-container-low">
        <label className="flex items-center gap-2 cursor-pointer font-label-md text-label-md text-on-surface">
          {/* The explicit space keeps the accessible name reading
              "Enabled OFF" instead of "EnabledOFF". */}
          {label} <input type="checkbox" {...form.register(name)} />
          <span
            className="font-code-sm text-code-sm text-on-surface-variant"
            data-state={`${group}.${field}`}
          >
            {t(checked ? 'settings.forms.on' : 'settings.forms.off')}
          </span>
        </label>
        {error}
      </div>
    );
  }

  const header = (
    <span className="font-label-md text-label-md text-on-surface">
      {label}
      {spec.readonly ? (
        <span className="ml-1 font-code-sm text-code-sm text-outline">
          ({t('settings.forms.readOnlyBadge')})
        </span>
      ) : null}
    </span>
  );

  let control;
  if (kind === 'readonly-text') {
    // The served value, disabled - read-only state (MFA factor, the SCIM
    // sha256) is server truth the form never edits or submits.
    const value = rows?.[group]?.values?.[field];
    control = (
      <input
        className={`${INPUT_CLASS} bg-surface-container cursor-not-allowed`}
        disabled
        readOnly
        type="text"
        value={value === undefined || value === null ? '' : String(value)}
      />
    );
  } else if (kind === 'password') {
    const placeholder = rows?.[group]?.values?.[field]
      ? t('settings.forms.secretStored')
      : t('settings.forms.secretNotSet');
    control = (
      <input
        autoComplete="new-password"
        className={INPUT_CLASS}
        placeholder={placeholder}
        type="password"
        {...form.register(name)}
      />
    );
  } else if (kind === 'select') {
    control = (
      <select className={INPUT_CLASS} {...form.register(name)}>
        {(spec.choices ?? []).map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
      </select>
    );
  } else if (kind === 'number') {
    control = (
      <input
        className={INPUT_CLASS}
        max={spec.max}
        min={spec.min}
        type="number"
        {...form.register(name, { valueAsNumber: true })}
      />
    );
  } else {
    control = (
      <input
        className={INPUT_CLASS}
        type={kind === 'url' ? 'url' : 'text'}
        {...form.register(name)}
      />
    );
  }

  return (
    <label className="flex flex-col gap-1.5 p-space-sm rounded-lg bg-surface-container-low">
      {header}
      {control}
      {error}
    </label>
  );
}

/**
 * The `Stored Configuration` divider block the legacy page drops inside
 * a section card (code.html:235-241, 303-311, 488-494): label + meta +
 * the group's grid. The sso/hsm forms live in their posture sections,
 * zsp/worm use it as their section body.
 */
export function StoredConfigurationBlock({ group }: { group: string }) {
  const { t } = useTranslation();
  return (
    <div className="mt-space-md pt-space-md border-t border-surface-container flex flex-col gap-space-sm">
      <span className="font-label-md text-label-md text-on-surface-variant">
        {t('settings.forms.storedConfiguration')}
      </span>
      <GroupMeta group={group} />
      <SettingsGroupFields group={group} />
    </div>
  );
}
