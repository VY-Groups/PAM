import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  SCIM_ROTATE_UNAUTHORIZED_RESPONSE,
  SETTINGS_RESPONSE,
  SMTP_TEST_UNAUTHORIZED_RESPONSE,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * The two 11.3 actions the legacy page never wired (screen 11,
 * ADR-0015: both endpoints exist server-side, no legacy button calls
 * them) plus the Export JSON header download.
 *
 * Every answer below is a verbatim rig capture: the SMTP test's honest
 * 503 refusal naming what to set (the pristine rig refuses, and that
 * refusal IS the rendered feedback), the 401 no-token lines, and the
 * one-time SCIM token whose fixture is the documented stand-in for the
 * rig-generated secret (house rule: it never enters the repo).
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

async function renderSettled(overrides?: Parameters<typeof settingsRoutes>[0]) {
  stubFetch(settingsRoutes(overrides));
  const rendered = renderWithProviders(<SettingsPage />);
  await waitFor(() =>
    expect(
      document.querySelectorAll(
        '[data-settings-group="smtp"] input, [data-settings-group="smtp"] select',
      ).length,
    ).toBe(7),
  );
  return rendered;
}

function postCalls(fetchMock: ReturnType<typeof stubFetch>, stem: string) {
  return fetchMock.mock.calls.filter(
    ([url, init]) =>
      (init as RequestInit | undefined)?.method === 'POST' && String(url).includes(stem),
  );
}

describe('settings 11.3 actions (screen 11, ADR-0015)', () => {
  it('the SMTP test renders the server 503 refusal verbatim (pristine rig)', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    await waitFor(() =>
      expect(
        document.querySelectorAll(
          '[data-settings-group="smtp"] input, [data-settings-group="smtp"] select',
        ).length,
      ).toBe(7),
    );

    // The recipient input lives in the card's footer (outside the
    // settings-group grid), so query it page-wide.
    fireEvent.change(screen.getByLabelText('Test recipient'), {
      target: { value: 'ops@example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send Test Email' }));

    // The server's refusal IS the feedback - it names exactly what to
    // set first (verbatim capture, fixture line for line).
    const refusal = await screen.findByText(/SMTP is not configured/);
    expect(refusal).toHaveTextContent(
      'SMTP is not configured - set host, port and from_address in the `smtp` settings group and enable it first',
    );

    const call = postCalls(fetchMock, '/settings/smtp/test')[0];
    expect(call, 'expected the smtp test POST').toBeTruthy();
    expect(JSON.parse(String((call?.[1] as RequestInit | undefined)?.body))).toEqual({
      to: 'ops@example.com',
    });
  });

  it('a no-token SMTP test renders the 401 line verbatim', async () => {
    await renderSettled({ smtpTest: SMTP_TEST_UNAUTHORIZED_RESPONSE });

    fireEvent.click(screen.getByRole('button', { name: 'Send Test Email' }));

    const refusal = await screen.findByRole('alert');
    expect(refusal).toHaveTextContent(
      'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
    );
  });

  it('the SCIM rotate asks first, then shows the minted token exactly once', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    await waitFor(() =>
      expect(document.querySelector('[data-settings-group="scim"]')).toBeTruthy(),
    );

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    fireEvent.click(screen.getByRole('button', { name: 'Rotate SCIM Token' }));

    expect(confirmSpy).toHaveBeenCalledWith(
      'Rotate the SCIM bearer token? The current token stops working immediately and the identity provider must be reconfigured with the new one.',
    );

    const box = await screen.findByTestId('settings-scim-token-once');
    // The fixture token is the documented stand-in for the rig-generated
    // secret; the point it pins is that the RESPONSE token renders.
    expect(box).toHaveTextContent('vypam-scim1.<redacted-shown-once>');
    expect(box).toHaveTextContent(
      'Shown once - configure it on the identity provider now.',
    );

    expect(postCalls(fetchMock, '/settings/scim/rotate')).toHaveLength(1);
  });

  it('declining the rotate confirmation sends nothing', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);
    await waitFor(() =>
      expect(document.querySelector('[data-settings-group="scim"]')).toBeTruthy(),
    );

    vi.spyOn(window, 'confirm').mockReturnValue(false);
    fireEvent.click(screen.getByRole('button', { name: 'Rotate SCIM Token' }));

    expect(postCalls(fetchMock, '/settings/scim/rotate')).toHaveLength(0);
    expect(screen.queryByTestId('settings-scim-token-once')).toBeNull();
  });

  it('a no-token rotate renders the 401 line and no token box', async () => {
    await renderSettled({ scimRotate: SCIM_ROTATE_UNAUTHORIZED_RESPONSE });
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    fireEvent.click(screen.getByRole('button', { name: 'Rotate SCIM Token' }));

    const refusal = await screen.findByRole('alert');
    expect(refusal).toHaveTextContent(
      'Admin token required (Authorization: Bearer <token> or X-Admin-Token)',
    );
    expect(screen.queryByTestId('settings-scim-token-once')).toBeNull();
  });

  it('Export JSON downloads the served settings (legacy payload shape)', async () => {
    const { container } = await renderSettled();

    const created: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      created.push(blob);
      return 'blob:export-mock';
    });
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: createObjectURL,
    });
    Object.defineProperty(URL, 'revokeObjectURL', {
      configurable: true,
      value: revokeObjectURL,
    });
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    try {
      // Fake timers BEFORE the click: the legacy-parity revoke is a
      // 1s setTimeout scheduled by the export handler itself.
      vi.useFakeTimers();
      fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));

      // Legacy exportSettings (code.html:1891-1908) - the anchor click,
      // the platform_settings.json filename, the settings half of the
      // response under `exported_at`.
      expect(clickSpy).toHaveBeenCalledTimes(1);
      const anchor = clickSpy.mock.instances[0] as HTMLAnchorElement;
      expect(anchor.download).toBe('platform_settings.json');
      expect(created).toHaveLength(1);

      const payload = JSON.parse(await created[0].text()) as {
        exported_at: string;
        settings: unknown;
      };
      expect(payload.settings).toEqual(SETTINGS_RESPONSE.body.settings);
      expect(Number.isNaN(Date.parse(payload.exported_at))).toBe(false);

      // The object URL is revoked a second later, legacy-parity.
      vi.advanceTimersByTime(1000);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:export-mock');
    } finally {
      vi.useRealTimers();
      clickSpy.mockRestore();
      const url = URL as unknown as Record<string, unknown>;
      delete url.createObjectURL;
      delete url.revokeObjectURL;
    }

    await expectNoAxeViolations(container);
  });
});
