/**
 * The context contract shared by the 15-group settings form host and its
 * consumers (screen 11, ADR-0015 11.3). It lives in its own module so
 * the provider file exports components only (react-refresh rule) and the
 * field/section components can import `useSettingsForm` without pulling
 * the provider implementation.
 */
import { createContext, useContext } from 'react';
import type { UseFormReturn } from 'react-hook-form';

import type { SettingsSchemaMap, SettingsValues } from './settingsSchema';

/** The page-level banner (legacy `#banner`): info/error/ok copy strip. */
export interface SettingsBanner {
  tone: 'error' | 'info' | 'ok';
  text: string;
}

/** The auto-hiding toast (legacy `#toast-notification`): title + line. */
export interface SettingsToast {
  title: string;
  desc: string;
}

/** The per-group facts `data-group-meta` renders: stored-or-defaults. */
export interface SettingsGroupRow {
  stored: boolean;
  updated_at: string | null;
  updated_by: string | null;
  values: Record<string, unknown>;
}

export interface SettingsFormContextValue {
  /** The served render schema (null until it loads, null after a failure). */
  schema: SettingsSchemaMap | null;
  /** The served group rows (meta + the values the read-only controls show). */
  rows: Record<string, SettingsGroupRow> | null;
  loading: boolean;
  loadFailed: boolean;
  form: UseFormReturn<SettingsValues>;
  /** How many of the 15 groups currently hold edits (legacy dirty count). */
  dirtyCount: number;
  saving: boolean;
  banner: SettingsBanner | null;
  toast: SettingsToast | null;
  save: () => void;
  exportJson: () => void;
}

export const SettingsFormContext = createContext<SettingsFormContextValue | null>(null);

export function useSettingsForm(): SettingsFormContextValue {
  const value = useContext(SettingsFormContext);
  if (!value) throw new Error('useSettingsForm must be used inside <SettingsFormProvider>');
  return value;
}
