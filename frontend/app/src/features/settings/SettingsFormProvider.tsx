/**
 * The 15-group settings form host (screen 11, ADR-0015 11.3).
 *
 * ONE react-hook-form instance holds the whole `settings[group].values`
 * tree: the legacy page is a single page with a single page-level Save
 * button and a global dirty counter (`markDirtyUi` -> `Save Changes (N)`),
 * so a single form with per-group dirty tracking is the faithful shape -
 * `dirtyFields` gives exactly the legacy `dirty[group]` map, and the save
 * loop walks the groups in the legacy page's document order.
 *
 * The Zod resolver is derived at runtime from the served schema
 * (`buildSettingsZod`); each rule mirrors the server's own
 * `_validate_setting`, so a save that would be refused is refused before
 * the round-trip with the server's own wording, and a save that passes
 * still trusts the server (a 400 is rendered verbatim, never swallowed).
 *
 * Save semantics are the legacy page's (`collect`/`save`, code.html
 * 1806-1889): every dirty group PUTs its full field set (read-only
 * fields never sent, secrets only when typed), the first refusal stops
 * the loop and prints the server's banner copy; on success the form
 * resets from the server-returned values, the settings root is
 * invalidated (the legacy `loadAll`) and the success toast + banner
 * appear. Export JSON is the legacy header download, byte-for-byte the
 * same payload shape.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

import { zodResolver } from '@hookform/resolvers/zod';
import { useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { ApiError, isBackendDown } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import { usePutSettingsGroup, useSettingsGroups } from './queries';
import { SettingsFormContext } from './settingsFormContext';
import type {
  SettingsBanner,
  SettingsFormContextValue,
  SettingsGroupRow,
  SettingsToast,
} from './settingsFormContext';
import {
  buildDefaultValues,
  buildGroupPayload,
  buildSettingsZod,
  firstFieldError,
  formatFieldError,
  isGroupDirty,
  SETTINGS_GROUP_ORDER,
} from './settingsSchema';
import type {
  SettingsGroupName,
  SettingsSchemaMap,
  SettingsValues,
} from './settingsSchema';

export function SettingsFormProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const groupsQuery = useSettingsGroups();
  const putGroup = usePutSettingsGroup();

  const data = groupsQuery.data ?? null;

  const schema: SettingsSchemaMap | null = useMemo(() => {
    if (!data) return null;
    // The generated response types are loose maps; the CAPTURE is the
    // shape (15 groups x typed field specs). Asserted once, here.
    return data.schema as unknown as SettingsSchemaMap;
  }, [data]);

  const rows = useMemo<Record<string, SettingsGroupRow> | null>(() => {
    if (!data) return null;
    const out: Record<string, SettingsGroupRow> = {};
    for (const [group, groupRow] of Object.entries(data.settings)) {
      out[group] = {
        stored: groupRow.stored,
        updated_at: groupRow.updated_at,
        updated_by: groupRow.updated_by,
        values: groupRow.values as Record<string, unknown>,
      };
    }
    return out;
  }, [data]);

  const resolver = useMemo(
    () => (schema ? zodResolver(buildSettingsZod(schema)) : undefined),
    [schema],
  );

  const form = useForm<SettingsValues>({
    defaultValues: {},
    resolver,
  });

  // The schema+values arrive async; adopt them into the form the way the
  // legacy page's loadAll re-fills every control. `keepDirtyValues` keeps
  // an operator's in-flight edits when a background refresh lands.
  useEffect(() => {
    if (!data || !schema) return;
    form.reset(buildDefaultValues(schema, data.settings as unknown as SettingsValues), {
      keepDirtyValues: true,
    });
  }, [data, schema, form]);

  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<SettingsBanner | null>(null);
  const [toast, setToast] = useState<SettingsToast | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (toastTimer.current) clearTimeout(toastTimer.current);
    },
    [],
  );
  const showToast = useCallback((next: SettingsToast) => {
    setToast(next);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 4000);
  }, []);

  // Reading `dirtyFields` during render SUBSCRIBES the provider to the
  // dirty map (RHF notifies it on every edit). No useMemo on it, though:
  // RHF mutates the map in place, so its identity never changes and a
  // memo would freeze the count. The 15-group filter per render is
  // trivial.
  const { dirtyFields } = form.formState;
  const dirtyCount = schema
    ? SETTINGS_GROUP_ORDER.filter((group) => isGroupDirty(dirtyFields, group)).length
    : 0;

  const saveErrorMessage = useCallback(
    (error: unknown): string => {
      if (isBackendDown(error)) return t('settings.forms.unreachableSave');
      if (error instanceof ApiError) {
        const details = error.body?.details as
          { fields?: string[]; field?: string } | undefined;
        const bad = (details?.fields ?? []).join(', ') || details?.field || '';
        // Legacy banner: server `error` verbatim (the 401 line included),
        // its own fallback only when the server sent none.
        const base =
          error.body?.error ??
          t(
            error.status === 401
              ? 'settings.forms.tokenFallback'
              : 'settings.forms.rejectedFallback',
          );
        return bad ? `${base} - ${bad}` : base;
      }
      return t('settings.forms.unreachableSave');
    },
    [t],
  );

  const runSave = useCallback(async () => {
    if (!schema) return;
    setSaving(true);
    const current = form.getValues();
    const merged: SettingsValues = { ...current };
    const changed: Array<{ group: string; field: string }> = [];
    try {
      for (const group of SETTINGS_GROUP_ORDER) {
        if (!isGroupDirty(form.formState.dirtyFields, group)) continue;
        const body = buildGroupPayload(schema, group, current[group] ?? {});
        const result = await putGroup.mutateAsync({
          group: group as SettingsGroupName,
          body,
        });
        for (const field of result.changed_fields ?? []) changed.push({ group, field });
        merged[group] = {
          ...(merged[group] ?? {}),
          ...(result.values as Record<string, unknown>),
        };
      }
      form.reset(merged);
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoot });
      setBanner({ tone: 'ok', text: t('settings.forms.storedOk') });
      showToast({
        title: t('settings.forms.storedToast'),
        desc: changed.length
          ? t('settings.forms.storedToastFields', {
              fields: changed
                .map((entry) =>
                  t(`settings.forms.fieldLabels.${entry.group}.${entry.field}`),
                )
                .join(', '),
            })
          : t('settings.forms.storedToastNoChanges'),
      });
    } catch (error) {
      setBanner({ tone: 'error', text: saveErrorMessage(error) });
    } finally {
      setSaving(false);
    }
  }, [schema, form, putGroup, queryClient, showToast, t, saveErrorMessage]);

  const showFirstFieldError = useCallback(
    (errors: Record<string, unknown>) => {
      if (!schema) return;
      const first = firstFieldError(errors, schema);
      if (!first) return;
      setBanner({
        tone: 'error',
        text: formatFieldError(schema, first.group, first.field, first.messageKey, t),
      });
    },
    [schema, t],
  );

  const save = useCallback(() => {
    // Legacy `save` checks dirt first: nothing dirty is an honest info
    // banner, not a request.
    if (dirtyCount === 0) {
      setBanner({ tone: 'info', text: t('settings.forms.nothingToSave') });
      return;
    }
    // `handleSubmit` is composed at EVENT time on purpose: RHF's submit
    // machinery reads its internal refs, never during render
    // (react-hooks/refs). The invalid arm takes the error tree RHF
    // hands the callback - never re-read state that may lag a render.
    void form.handleSubmit(
      () => runSave(),
      (errors) => showFirstFieldError(errors as unknown as Record<string, unknown>),
    )();
  }, [dirtyCount, form, runSave, showFirstFieldError, t]);

  const exportJson = useCallback(() => {
    if (!data) {
      setBanner({ tone: 'info', text: t('settings.forms.exportNotLoaded') });
      return;
    }
    // Legacy exportSettings (code.html:1891-1908): the settings half of
    // the response under `exported_at`, downloaded as
    // platform_settings.json; the object URL is revoked a second later.
    const payload = JSON.stringify(
      { exported_at: new Date().toISOString(), settings: data.settings },
      null,
      2,
    );
    const blob = new Blob([payload], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'platform_settings.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }, [data, t]);

  const value: SettingsFormContextValue = {
    schema,
    rows,
    loading: groupsQuery.isLoading,
    loadFailed: groupsQuery.isError,
    form,
    dirtyCount,
    saving,
    banner,
    toast,
    save,
    exportJson,
  };

  return (
    <SettingsFormContext.Provider value={value}>{children}</SettingsFormContext.Provider>
  );
}
