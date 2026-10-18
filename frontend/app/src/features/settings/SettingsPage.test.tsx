import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  HSM_STATUS_SEALED_RESPONSE,
  hsmStatusRoute,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { SettingsPage } from './SettingsPage';

/**
 * Platform Settings (screen 11, ADR-0015) - the 11.1 read-only posture
 * shell. Every string asserted below is a VERBATIM carry-over from the
 * legacy `platform_settings_center` page, which is the parity contract:
 * the same regexes the standing gate holds the legacy page to are
 * re-pointed here at flip time (11.5), so 11.1 locks the copy now.
 *
 * Nothing is invented: the fixtures are the live rig's own answers
 * (settingsFixtures.ts), and the honest "—"/unreachable arms are proven
 * for each section rather than assumed. The route is still `pending` on
 * purpose, so these render the page directly through the provider stack
 * - they never claim the route is served.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('Platform Settings (screen 11, ADR-0015) - 11.1 posture shell', () => {
  it('renders the page header from i18n, never a raw key', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    expect(
      await screen.findByRole('heading', { name: 'Platform Settings' }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('settings-page')).toBeInTheDocument();
  });

  it('SSO section: the "no idp configured" chip and the honest no-IdP line', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    const sso = await screen.findByTestId('settings-sso');
    // The captured rig has no IdP slot configured: the chips read the
    // "off" arms and the live line says why, verbatim.
    await waitFor(() => expect(sso.textContent).toContain('enforce sso: off'));
    expect(sso.textContent).toContain('mfa at login: optional');
    expect(sso.textContent).toContain('no idp configured');
    expect(screen.getByTestId('settings-sso-line').textContent).toBe(
      'no IdP configured \u2014 set a slot provider to enable SAML/OIDC logins',
    );
  });

  it('HSM section: advisory file custody line and the unsealed chip', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    await waitFor(() =>
      expect(screen.getByTestId('settings-hsm-line').textContent).toBe(
        'no provider configured \u2014 advisory file custody',
      ),
    );
    const hsm = screen.getByTestId('settings-hsm');
    expect(hsm.textContent).toContain('unsealed');
    expect(hsm.textContent).toContain('mode: advisory');
    expect(hsm.textContent).toContain('key in use: file');
  });

  it('HSM section: a sealed vault says sealed verbatim, never dressed up', async () => {
    stubFetch([
      ...settingsRoutes().filter((r) => !r.match('/hsm/status')),
      hsmStatusRoute(HSM_STATUS_SEALED_RESPONSE),
    ]);
    renderWithProviders(<SettingsPage />);

    await waitFor(() =>
      expect(screen.getByTestId('settings-hsm-line').textContent).toBe(
        'no provider configured \u2014 advisory file custody',
      ),
    );
    // Even sealed with no provider, the custody line is the honest
    // "no provider" arm; the chip carries the sealed state.
    expect(screen.getByTestId('settings-hsm').textContent).toContain('sealed');
  });

  it('Integrations section: all four connectors read "not configured"', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    const box = await screen.findByTestId('settings-integrations');
    await waitFor(() => expect(box.textContent).toContain('MFA'));
    for (const name of ['MFA', 'ITSM', 'SIEM', 'LDAP']) {
      expect(box.textContent).toContain(`${name}: not configured`);
    }
  });

  it('Cluster section: the summary is the gate parity regex over real data', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    const summary = await screen.findByTestId('settings-cluster-summary');
    // Verbatim from the standing gate (shots_tool/__verify_agent.mjs):
    await waitFor(() =>
      expect(summary.textContent).toMatch(
        /^\S+ \((dc|dr)\) \u2022 (active|passive) \u2022 \d+ peers? \u2022 \d+ healthy \u2022 audit \d+ \u2022 vault \d+ \u2022 sessions \d+ \u2022 backups \d+$/,
      ),
    );
  });

  it('Cluster section: the empty backup ledger renders an honest empty row', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    const cluster = await screen.findByTestId('settings-cluster');
    await waitFor(() => expect(cluster.textContent).toContain('Backup ledger'));
    expect(cluster.textContent).toContain('No backups yet');
  });

  it('a dead backend renders the honest unreachable arms, not zeros', async () => {
    // No routes at all: every read is refused, so each section must say
    // so - a zeroed posture would read as "SSO off, unsealed, no peers",
    // which is a different and false claim.
    stubFetch([]);
    renderWithProviders(<SettingsPage />);

    expect(
      await screen.findByText('SSO status unavailable (license server not reachable)'),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('HSM status unavailable (license server not reachable)'),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('Cluster state unavailable (license server not reachable).'),
    ).toBeInTheDocument();
  });

  it('has no axe violations (live data)', async () => {
    stubFetch(settingsRoutes());
    const { container } = renderWithProviders(<SettingsPage />);
    await screen.findByTestId('settings-cluster-summary');
    await expectNoAxeViolations(container);
  });

  it('has no axe violations (backend down)', async () => {
    stubFetch([]);
    const { container } = renderWithProviders(<SettingsPage />);
    await screen.findByText('SSO status unavailable (license server not reachable)');
    await expectNoAxeViolations(container);
  });
});
