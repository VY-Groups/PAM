/**
 * Schema-derived Zod rules + payload building for the 15 settings group
 * forms (screen 11, ADR-0015 11.3).
 *
 * Every rule mirrors the server's own `_validate_setting`
 * (`backend/phase2_license_server/service.py:1265-1348`) one-for-one:
 * type, int min/max, enum choices, max_length (checked on the TRIMMED
 * value, like the server strips first), `allow_empty` (required when it
 * is absent), the https/loopback rule for URLs and the DNS-style slug
 * pattern. Each rule's message is the i18n KEY of the captured server
 * string (see the 400 fixtures) - the page translates it with the same
 * `group.field` name the server prints, exactly like the licensing
 * dialogs (`t(errors.envelope.message)`). The client pre-empts the
 * round-trip; the server stays the authority.
 *
 * The control mapping is the legacy page's `controlHtml`
 * (`platform_settings_center/code.html:1096-1146`) translated 1:1:
 * one control per schema field, which is what the standing gate's
 * per-group `input,select` counts tally.
 */

import type { TFunction } from 'i18next';
import { z } from 'zod';

/** The field descriptors `GET /api/v1/settings` carries, as captured. */
export interface FieldSpec {
  type: 'str' | 'int' | 'bool' | 'enum' | 'url' | 'slug' | 'secret';
  default: unknown;
  choices?: string[];
  min?: number;
  max?: number;
  max_length?: number;
  allow_empty?: boolean;
  allow_http?: boolean;
  readonly?: boolean;
  help?: string;
}

export type SettingsSchemaMap = Record<string, Record<string, FieldSpec>>;

/** `settings[group].values` as the API serves them. */
export type SettingsValues = Record<string, Record<string, unknown>>;

/**
 * The 15 groups in the LEGACY PAGE's document order (code.html: sso/hsm
 * sit in their posture sections, zsp/worm follow, the four connectors
 * inside integrations, auth..scim in the identity section, gateway
 * last). The save loop walks this order so multi-group failures surface
 * deterministically; tests pin it as the render order too.
 */
export const SETTINGS_GROUP_ORDER = [
  'sso',
  'hsm',
  'zsp',
  'worm',
  'mfa',
  'itsm',
  'siem',
  'ldap',
  'auth',
  'webauthn',
  'smtp',
  'sms',
  'radius',
  'scim',
  'gateway',
] as const;

export type SettingsGroupName = (typeof SETTINGS_GROUP_ORDER)[number];

/** Which control `controlHtml` would emit for this spec. */
export type ControlKind =
  'readonly-text' | 'password' | 'checkbox' | 'select' | 'number' | 'url' | 'text';

export function controlKind(spec: FieldSpec): ControlKind {
  if (spec.readonly) return 'readonly-text'; // legacy checks readonly FIRST
  switch (spec.type) {
    case 'secret':
      return 'password';
    case 'bool':
      return 'checkbox';
    case 'enum':
      return 'select';
    case 'int':
      return 'number';
    case 'url':
      return 'url';
    default:
      return 'text';
  }
}

/** Server's `_BUCKET_RE` (service.py:939), verbatim (the dash stays last,
 * unescaped, so eslint's useless-escape rule holds; same semantics). */
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

/**
 * Hosts the server accepts over plain http even without `allow_http`
 * (service.py:1324) - loopback test IdPs and local stubs.
 */
function isLoopbackHost(value: string): boolean {
  const afterScheme = value.includes('://') ? value.slice(value.indexOf('://') + 3) : '';
  const host = afterScheme.split('/', 1)[0].split(':', 1)[0];
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

/** i18n keys of the mirrored server rules (`settings.forms.validation.*`). */
export const RULE_KEY = {
  bool: 'settings.forms.validation.bool',
  integer: 'settings.forms.validation.integer',
  min: 'settings.forms.validation.min',
  max: 'settings.forms.validation.max',
  maxLength: 'settings.forms.validation.maxLength',
  enum: 'settings.forms.validation.enum',
  required: 'settings.forms.validation.required',
  urlHttps: 'settings.forms.validation.urlHttps',
  urlHttp: 'settings.forms.validation.urlHttp',
  slug: 'settings.forms.validation.slug',
} as const;

/** One field's Zod rule, mirroring `_validate_setting`. */
function fieldZod(spec: FieldSpec): z.ZodTypeAny {
  switch (spec.type) {
    case 'bool':
      return z.boolean(RULE_KEY.bool);
    case 'int': {
      let node = z.number(RULE_KEY.integer);
      if (spec.min !== undefined) node = node.min(spec.min, RULE_KEY.min);
      if (spec.max !== undefined) node = node.max(spec.max, RULE_KEY.max);
      return node;
    }
    case 'enum': {
      const choices = spec.choices ?? [];
      if (choices.length === 0) return z.string();
      return z.enum(choices as [string, ...string[]], RULE_KEY.enum);
    }
    case 'secret':
      return z.string().max(spec.max_length ?? 4096, RULE_KEY.maxLength);
    case 'url':
      return z.string().superRefine((value, ctx) => {
        const trimmed = value.trim();
        if (!trimmed) {
          if (!spec.allow_empty)
            ctx.addIssue({ code: 'custom', message: RULE_KEY.required });
          return;
        }
        const httpOk = spec.allow_http === true || isLoopbackHost(trimmed);
        const ok = httpOk
          ? trimmed.startsWith('https://') || trimmed.startsWith('http://')
          : trimmed.startsWith('https://');
        if (!ok) {
          ctx.addIssue({
            code: 'custom',
            message: httpOk ? RULE_KEY.urlHttp : RULE_KEY.urlHttps,
          });
        }
      });
    case 'slug':
      return z.string().superRefine((value, ctx) => {
        const trimmed = value.trim();
        if (!trimmed) {
          if (!spec.allow_empty)
            ctx.addIssue({ code: 'custom', message: RULE_KEY.required });
          return;
        }
        if (!BUCKET_RE.test(trimmed))
          ctx.addIssue({ code: 'custom', message: RULE_KEY.slug });
      });
    default: {
      const max = spec.max_length ?? 255;
      return z.string().superRefine((value, ctx) => {
        const trimmed = value.trim();
        if (!trimmed) {
          if (!spec.allow_empty)
            ctx.addIssue({ code: 'custom', message: RULE_KEY.required });
          return;
        }
        if (trimmed.length > max)
          ctx.addIssue({ code: 'custom', message: RULE_KEY.maxLength });
      });
    }
  }
}

/**
 * The whole settings object as one Zod schema - `zod derived from the
 * API schema` (ADR-0015 11.3 row). The Output/Input pair is asserted to
 * the captured values shape so the resolver types the form without an
 * `any` (the shape itself IS the capture's structure).
 */
export function buildSettingsZod(
  schema: SettingsSchemaMap,
): z.ZodType<SettingsValues, SettingsValues> {
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const [group, fields] of Object.entries(schema)) {
    const groupShape: Record<string, z.ZodTypeAny> = {};
    for (const [name, spec] of Object.entries(fields)) groupShape[name] = fieldZod(spec);
    shape[group] = z.object(groupShape);
  }
  return z.object(shape) as unknown as z.ZodType<SettingsValues, SettingsValues>;
}

/**
 * Translate one failing field's rule key with the params the server's
 * own message interpolates (qualified field name, range, choices). Used
 * by the field's inline error AND the save banner's first-error line.
 */
export function formatFieldError(
  schema: SettingsSchemaMap,
  group: string,
  field: string,
  messageKey: string,
  t: TFunction,
): string {
  const spec = schema[group]?.[field];
  const params: Record<string, string | number> = { field: `${group}.${field}` };
  if (spec) {
    if (messageKey === RULE_KEY.min) params.min = spec.min ?? '';
    if (messageKey === RULE_KEY.max) params.max = spec.max ?? '';
    if (messageKey === RULE_KEY.maxLength) params.max = spec.max_length ?? 255;
    if (messageKey === RULE_KEY.enum) params.choices = (spec.choices ?? []).join(', ');
  }
  return t(messageKey, params);
}

interface ErrorLeaf {
  message?: unknown;
}

/** One field's rule key from the RHF error tree (null when it passes). */
export function fieldError(errors: unknown, group: string, field: string): string | null {
  const tree = errors as Record<string, unknown> | undefined;
  const groupError = tree?.[group];
  if (!groupError || typeof groupError !== 'object') return null;
  const leaf = (groupError as Record<string, unknown>)[field];
  if (leaf && typeof leaf === 'object' && typeof (leaf as ErrorLeaf).message === 'string') {
    return (leaf as ErrorLeaf).message as string;
  }
  return null;
}

/**
 * First failing field of the RHF error tree (group -> field -> leaf),
 * skipping anything that is not a schema-known field (formState
 * bookkeeping keys). Returns the rule KEY; the caller formats it with
 * `formatFieldError`.
 */
export function firstFieldError(
  errors: Record<string, unknown>,
  schema: SettingsSchemaMap,
): { group: string; field: string; messageKey: string } | null {
  for (const [group, groupError] of Object.entries(errors)) {
    const fields = schema[group];
    if (!fields || !groupError || typeof groupError !== 'object') continue;
    for (const [field, fieldError] of Object.entries(
      groupError as Record<string, unknown>,
    )) {
      if (!(field in fields)) continue;
      const leaf = fieldError as ErrorLeaf | null;
      if (leaf && typeof leaf === 'object' && typeof leaf.message === 'string') {
        return { group, field, messageKey: leaf.message };
      }
    }
  }
  return null;
}

/**
 * The PUT payload for one group - the legacy page's `collect()`
 * (code.html:1806-1836) translated: read-only fields are NEVER sent
 * (the server rejects them with its own 400), booleans go as booleans,
 * ints as whole numbers, everything else trimmed strings, and a secret
 * is included only when the operator actually typed one (empty means
 * "leave it alone", so a settings PUT cannot clear a stored secret by
 * accident - the legacy page's rule, proven against the rig).
 */
export function buildGroupPayload(
  schema: SettingsSchemaMap,
  group: string,
  values: Record<string, unknown>,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  const fields = schema[group] ?? {};
  for (const [name, spec] of Object.entries(fields)) {
    if (spec.readonly) continue;
    const value = values[name];
    if (spec.type === 'bool') {
      payload[name] = value === true;
      continue;
    }
    if (spec.type === 'int') {
      const number = typeof value === 'number' ? value : Number(value);
      if (Number.isNaN(number)) continue; // zod already blocked the save
      payload[name] = number;
      continue;
    }
    const text = String(value ?? '').trim();
    if (spec.type === 'secret') {
      if (text) payload[name] = text;
      continue;
    }
    payload[name] = text;
  }
  return payload;
}

/**
 * RHF `defaultValues` from the captured values: secrets always start
 * EMPTY (the API only ever answers `<set>` / `` for them - material
 * never reaches the form), every other field takes the served value.
 */
export function buildDefaultValues(
  schema: SettingsSchemaMap,
  settings: SettingsValues,
): SettingsValues {
  const defaults: SettingsValues = {};
  for (const [group, fields] of Object.entries(schema)) {
    const served = (settings[group]?.values ?? {}) as Record<string, unknown>;
    const row: Record<string, unknown> = {};
    for (const [name, spec] of Object.entries(fields)) {
      row[name] = spec.type === 'secret' ? '' : (served[name] ?? spec.default);
    }
    defaults[group] = row;
  }
  return defaults;
}

/** True when the RHF `dirtyFields` map marks any field of this group. */
export function isGroupDirty(dirtyFields: Record<string, unknown>, group: string): boolean {
  const groupDirty = dirtyFields[group];
  return (
    groupDirty !== undefined &&
    typeof groupDirty === 'object' &&
    groupDirty !== null &&
    Object.keys(groupDirty).length > 0
  );
}
