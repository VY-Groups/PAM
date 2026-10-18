import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  SETTINGS_PUT_NOOP_RESPONSE,
  SETTINGS_PUT_REJECTED_RESPONSE,
  SETTINGS_PUT_UNAUTHORIZED_RESPONSE,
  SETTINGS_RESPONSE,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';
import { buildDefaultValues, buildSettingsZod } from './settingsSchema';
import type { SettingsSchemaMap, SettingsValues } from './settingsSchema';

/**
 * The 15 schema-driven group forms (screen 11, ADR-0015 11.3).
 *
 * The field-count block is the STANDING GATE's own parity contract: the
 * exact per-group `input,select` tallies the gate holds the legacy page
 * to (shots_tool/__verify_agent.mjs sections 7 and 8a), asserted here on
 * the React page so the 11.5 flip re-points at the same numbers. The
 * save arms are the rig's verbatim PUT captures: the full-field-set
 * payload (read-only fields excluded, secrets only when typed), the
 * strict-validation 400 that prints the server's own line and stops the
 * loop, the no-token 401, the no-op re-submit and the honest
 * unreachable banner.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/** The gate's exact counts (lines 604-606 and 624). */
const GATE_FIELD_COUNTS: Record<string, number> = {
  auth: 16,
  gateway: 12,
  radius: 5,
  scim: 2,
  smtp: 7,
  sms: 5,
  webauthn: 3,
};

/** All 15 groups of the capture, in the legacy page's document order. */
const ALL_GROUPS = [
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
];

function controlsIn(group: string): number {
  return document.querySelectorAll(
    `[data-settings-group="${group}"] input, [data-settings-group="${group}"] select`,
  ).length;
}

function groupBox(group: string): HTMLElement {
  const box = document.querySelector(`[data-settings-group="${group}"]`);
  expect(box, `expected the ${group} group box`).toBeTruthy();
  return box as HTMLElement;
}

function metaText(group: string): string {
  return document.querySelector(`[data-group-meta="${group}"]`)?.textContent?.trim() ?? '';
}

function putCalls(fetchMock: ReturnType<typeof stubFetch>) {
  return fetchMock.mock.calls.filter(
    ([, init]) => (init as RequestInit | undefined)?.method === 'PUT',
  );
}

function findPut(fetchMock: ReturnType<typeof stubFetch>, group: string) {
  const call = putCalls(fetchMock).find(([url]) =>
    String(url).endsWith(`/settings/${group}`),
  );
  expect(call, `expected a PUT /api/v1/settings/${group}`).toBeTruthy();
  return {
    url: String(call?.[0]),
    body: JSON.parse(String((call?.[1] as RequestInit | undefined)?.body)),
  };
}

async function renderSettled(element = <SettingsPage />) {
  const fetchMock = stubFetch(settingsRoutes());
  const rendered = renderWithProviders(element);
  await waitFor(() => expect(controlsIn('auth')).toBe(16));
  return { fetchMock, ...rendered };
}

describe('settings group forms (screen 11, ADR-0015) - 11.3', () => {
  it('renders every schema group with the gate-exact control counts', async () => {
    await renderSettled();

    for (const [group, count] of Object.entries(GATE_FIELD_COUNTS)) {
      expect(controlsIn(group), `${group} control count`).toBe(count);
    }
    for (const group of ALL_GROUPS) {
      expect(
        document.querySelector(`[data-settings-group="${group}"]`),
        `${group} box present`,
      ).toBeTruthy();
    }
  });

  it('the meta lines read stored-or-defaults (gate 8a meta check)', async () => {
    await renderSettled();

    await waitFor(() => expect(metaText('auth')).toContain('by demo-seed'));
    expect(metaText('auth')).toMatch(/^saved .+ by demo-seed$/);
    expect(metaText('auth')).not.toBe('loading...');
    // The gate's own gateway check (line 626): meta real data, never the
    // loading word after settle.
    expect(metaText('gateway')).toMatch(/^saved .+ by gate$/);
    expect(metaText('gateway')).not.toBe('loading...');
    expect(metaText('sso')).toBe('built-in defaults (not saved yet)');
  });

  it('controls start from the served values; secrets stay empty with their placeholder', async () => {
    await renderSettled();

    const lockout = screen.getByLabelText('Lockout Minutes') as HTMLInputElement;
    expect(lockout.type).toBe('number');
    expect(lockout.value).toBe('15');
    expect(lockout.min).toBe('1');
    expect(lockout.max).toBe('1440');

    // The legacy ON/OFF state words (controlHtml line 1126).
    expect(document.querySelector('[data-state="auth.mfa_required"]')?.textContent).toBe(
      'OFF',
    );

    // Read-only state renders the stored value, disabled, and is never
    // editable (SCIM's token sha256 - the gate counts it as a control).
    const sha = screen.getByLabelText(/^Token Sha256/) as HTMLInputElement;
    expect(sha.disabled).toBe(true);
    expect(sha.readOnly).toBe(true);
    expect(sha.value).toBe('');

    // Secrets render empty with the honest placeholder (capture serves
    // `` = unset).
    const password = within(groupBox('smtp')).getByPlaceholderText(
      'not set',
    ) as HTMLInputElement;
    expect(password.type).toBe('password');
    expect(password.value).toBe('');
  });

  it('the served values parse clean through the mirrored rules (pristine resolver)', () => {
    const schema = SETTINGS_RESPONSE.body.schema as unknown as SettingsSchemaMap;
    const defaults = buildDefaultValues(
      schema,
      SETTINGS_RESPONSE.body.settings as unknown as SettingsValues,
    );
    // A pristine rig MUST parse: the resolver may only refuse what the
    // server itself refuses.
    expect(() => buildSettingsZod(schema).parse(defaults)).not.toThrow();
  });

  it('a dirty group saves its full field set and reports the stored fields', async () => {
    const { fetchMock } = await renderSettled();

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), { target: { value: '16' } });
    const save = await screen.findByRole('button', { name: 'Save Changes (1)' });
    fireEvent.click(save);

    await screen.findByText('Settings stored - config audit changelog updated.');
    const toast = await screen.findByTestId('settings-toast');
    expect(toast).toHaveTextContent('Settings Stored Successfully');
    expect(toast).toHaveTextContent('Lockout Minutes updated.');

    // The legacy `collect()` payload: EVERY auth field, ints as numbers,
    // bools as booleans, strings trimmed - not just the edited key.
    expect(findPut(fetchMock, 'auth').body).toEqual({
      breached_password_extra: '',
      emergency_window_minutes: 15,
      lockout_minutes: 16,
      lockout_threshold: 5,
      max_sessions_per_user: 5,
      mfa_required: false,
      password_min_length: 14,
      progressive_delay: true,
      rate_limit_per_account: 15,
      rate_limit_per_ip: 30,
      remember_device_days: 30,
      require_device_posture: false,
      session_absolute_hours: 12,
      session_idle_minutes: 30,
      spray_threshold: 10,
      stepup_ttl_minutes: 5,
    });

    // The dirty count clears once the save loop lands (legacy
    // markDirtyUi after load-after-save).
    await screen.findByRole('button', { name: 'Save Changes' });
  });

  it('read-only fields are never sent and secrets ride only when typed', async () => {
    const { fetchMock } = await renderSettled();

    // scim: `enabled` is the only editable field - the read-only sha256
    // must NOT reach the wire (the server refuses it with its own 400).
    fireEvent.click(within(groupBox('scim')).getByRole('checkbox'));
    // smtp: type the secret; the other smtp fields stay pristine.
    fireEvent.change(within(groupBox('smtp')).getByPlaceholderText('not set'), {
      target: { value: 'hunter2' },
    });

    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (2)' }));
    await waitFor(() => expect(putCalls(fetchMock)).toHaveLength(2));

    expect(findPut(fetchMock, 'scim').body).toEqual({ enabled: true });
    const smtpPut = findPut(fetchMock, 'smtp');
    expect(smtpPut.body.password).toBe('hunter2');
    // smtp's other fields are still sent (full field set), untrimmed-edit
    // free - the pristine values with the typed secret.
    expect(smtpPut.body).toMatchObject({
      enabled: false,
      host: '',
      port: 587,
      use_tls: true,
      username: '',
    });
  });

  it('an out-of-range edit is refused client-side with the server wording and sends nothing', async () => {
    const { fetchMock } = await renderSettled();

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), {
      target: { value: '9999' },
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (1)' }));

    // The server's own captured 400 line, translated with the same
    // qualified field name the server prints.
    const banner = await screen.findByTestId('settings-banner');
    expect(banner).toHaveTextContent("'auth.lockout_minutes' must be <= 1440");
    // The field shows it inline, too.
    expect(
      await within(groupBox('auth')).findByText("'auth.lockout_minutes' must be <= 1440"),
    ).toBeTruthy();

    expect(putCalls(fetchMock)).toHaveLength(0);
  });

  it("the server's strict 400 prints its own line and stops the save loop", async () => {
    const fetchMock = stubFetch(
      settingsRoutes({ putGroup: SETTINGS_PUT_REJECTED_RESPONSE }),
    );
    renderWithProviders(<SettingsPage />);
    await waitFor(() => expect(controlsIn('auth')).toBe(16));

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), { target: { value: '16' } });
    fireEvent.click(
      within(groupBox('gateway')).getByRole('checkbox', { name: /^Enabled/ }),
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (2)' }));

    // Verbatim server `error` + its `details.field`, legacy banner glue.
    const banner = await screen.findByTestId('settings-banner');
    expect(banner).toHaveTextContent(
      "'auth.lockout_minutes' must be <= 1440 - auth.lockout_minutes",
    );

    // The loop stopped at the first refusal: auth PUT out, gateway never.
    await waitFor(() => expect(putCalls(fetchMock)).toHaveLength(1));
    expect(String(putCalls(fetchMock)[0][0])).toContain('/settings/auth');
    expect(
      putCalls(fetchMock).some(([url]) => String(url).endsWith('/settings/gateway')),
    ).toBe(false);
  });

  it('a no-token write renders the 401 line verbatim', async () => {
    stubFetch(settingsRoutes({ putGroup: SETTINGS_PUT_UNAUTHORIZED_RESPONSE }));
    renderWithProviders(<SettingsPage />);
    await waitFor(() => expect(controlsIn('auth')).toBe(16));

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), { target: { value: '16' } });
    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (1)' }));

    const banner = await screen.findByTestId('settings-banner');
    expect(banner).toHaveTextContent(
      'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
    );
  });

  it('a no-op re-submit lands the "no value changes" toast', async () => {
    stubFetch(settingsRoutes({ putGroup: SETTINGS_PUT_NOOP_RESPONSE }));
    renderWithProviders(<SettingsPage />);
    await waitFor(() => expect(controlsIn('auth')).toBe(16));

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), { target: { value: '16' } });
    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (1)' }));

    const toast = await screen.findByTestId('settings-toast');
    expect(toast).toHaveTextContent('Settings Stored Successfully');
    expect(toast).toHaveTextContent('No value changes were detected.');
  });

  it('a dead backend mid-save renders the honest NOT-saved banner', async () => {
    const routes = [
      {
        match: (url: string) => /\/api\/v1\/settings\/auth(\?|$)/.test(url),
        respond: () => Promise.reject(new TypeError('Failed to fetch')),
      },
      ...settingsRoutes(),
    ];
    stubFetch(routes);
    renderWithProviders(<SettingsPage />);
    await waitFor(() => expect(controlsIn('auth')).toBe(16));

    fireEvent.change(screen.getByLabelText('Lockout Minutes'), { target: { value: '16' } });
    fireEvent.click(await screen.findByRole('button', { name: 'Save Changes (1)' }));

    const banner = await screen.findByTestId('settings-banner');
    expect(banner).toHaveTextContent(
      'Could not reach the license server - the changes were NOT saved.',
    );
  });

  it('an unreachable settings read shows the honest load alert and no forms', async () => {
    stubFetch([]);
    renderWithProviders(<SettingsPage />);

    const alert = await screen.findByTestId('settings-load-error');
    expect(alert).toHaveTextContent('Settings unavailable (license server not reachable)');
    expect(document.querySelectorAll('[data-settings-group]')).toHaveLength(0);
  });

  it('saving with nothing dirty is the honest info banner, not a request', async () => {
    const { fetchMock } = await renderSettled();

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

    const banner = await screen.findByTestId('settings-banner');
    expect(banner).toHaveTextContent('Nothing to save - no settings have been changed.');
    expect(putCalls(fetchMock)).toHaveLength(0);
  });

  it('the whole page passes axe once the forms have settled', async () => {
    const { container } = await renderSettled();
    await expectNoAxeViolations(container);
  });
});
