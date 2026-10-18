import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  WHOAMI_OPEN_BODY,
  stubFetch,
  topologyRoutes,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * System & Workflow Maps (ADR-0013, /topology): every extracted figure
 * is asserted against the real sources (the generated module is
 * cross-checked in topology.generated.test.ts), and the live network
 * view is asserted against the verbatim rig captures in
 * topologyFixtures.ts - name, algorithms, private key path, the honest
 * "unknown" health, the four not-configured integrations and their
 * verbatim gate texts. The backend-down test proves each of the three
 * live cards fails independently and honestly. No raw i18n key may
 * ever render in any view.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

const TABS = ['Frontend', 'Backend', 'API', 'Network', 'Application'] as const;

/** Waits out the shell's session check before activating a tab
 * (Radix tab triggers activate on mousedown). */
async function openTab(name: string) {
  const trigger = await screen.findByRole('tab', { name });
  fireEvent.mouseDown(trigger);
  fireEvent.click(trigger);
}

describe('TopologyPage (F4-native, ADR-0013)', () => {
  it('renders all five views with the extracted frontend map by default', async () => {
    stubFetch(topologyRoutes());
    const { container } = renderApp('/topology');

    expect(
      await screen.findByRole('heading', { name: 'System & Workflow Maps' }),
    ).toBeDefined();
    for (const tab of TABS) {
      expect(screen.getByRole('tab', { name: tab })).toBeDefined();
    }

    // Sidebar + route row both carry the translated nav label (i18n).
    expect(screen.getAllByText('System Maps').length).toBeGreaterThanOrEqual(2);

    // The licensing row shows its extracted client endpoints (layer 1
    // output pinned here): import is really part of that feature.
    expect(screen.getByText('POST /api/v1/licenses/import')).toBeDefined();

    // 11.5 flip closed the last pending route: no F4-pending chip and no
    // "open the legacy screen" link remains on the map - every sidebar
    // item is route-wired now (ADR-0015's completed strangler).
    expect(screen.queryByText('F4 pending')).toBeNull();
    expect(screen.queryByRole('link', { name: 'open the legacy screen' })).toBeNull();

    await expectNoAxeViolations(container);
  });

  it('shows the backend packages with real files and import edges', async () => {
    stubFetch(topologyRoutes());
    renderApp('/topology');
    await openTab('Backend');

    expect(screen.getByText(/pam_master · \d+ files/)).toBeDefined();
    expect(screen.getByText(/phase2_license_server · \d+ files/)).toBeDefined();
    expect(screen.getByText(/ipam_licensing · \d+ files/)).toBeDefined();
    // Real modules of both python trees, with at least one drawn edge
    // (the "→ target.py" import chips).
    expect(screen.getAllByText('routes.py').length).toBeGreaterThanOrEqual(2);
    expect(
      screen.getAllByText(
        (_, el) => el?.tagName === 'CODE' && (el.textContent ?? '').startsWith('→ '),
      ).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('shows the contract surface with its real counts and tag groups', async () => {
    stubFetch(topologyRoutes());
    renderApp('/topology');
    await openTab('API');

    expect(screen.getByText(/^209 paths$/)).toBeDefined();
    expect(screen.getByText(/^250 operations$/)).toBeDefined();
    expect(screen.getByText(/^24 tags$/)).toBeDefined();
    expect(screen.getByText(/^POST 120$/)).toBeDefined();
    // Tag groups carry the contract's own operations and summaries.
    expect(screen.getByText('identity')).toBeDefined();
    expect(screen.getAllByText('/api/v1/licenses').length).toBeGreaterThanOrEqual(1);
  });

  it('renders the live network posture from the verbatim rig captures', async () => {
    stubFetch(topologyRoutes());
    const { container } = renderApp('/topology');
    await openTab('Network');

    // The node appears twice: the /health self card and the cluster's
    // own registered-node row (honest "unknown" until a probe answers).
    // waitFor: both queries must have landed, not just the first poll.
    await waitFor(() => expect(screen.getAllByText('pam-node-1').length).toBe(2));
    expect(screen.getByText('RSA-PSS-SHA256')).toBeDefined();
    expect(screen.getByText('/data/vypam-keys/private.pem')).toBeDefined();
    expect(screen.getByText('dc · active · unknown')).toBeDefined();
    expect(screen.getByText(/^replicated records/)).toBeDefined();

    // All four integrations unconfigured in the capture, with the MFA
    // gate text verbatim.
    expect(screen.getAllByText('not configured').length).toBe(4);
    expect(screen.getByText('not configured - the mfa band stays advisory')).toBeDefined();

    await expectNoAxeViolations(container);
  });

  it('renders the honest not-connected state when the node cannot be reached', async () => {
    // whoami stays healthy (the shell must not log the user out); the
    // three live topology endpoints fail at the transport layer, which
    // is never retried (ADR-0004).
    const down = () => ({
      match: (url: string) =>
        /\/(health|api\/v1\/cluster|api\/v1\/integrations\/status)(\?|$)/.test(url),
      respond: () => Promise.reject(new TypeError('Failed to fetch')),
    });
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), down()]);
    renderApp('/topology');
    await openTab('Network');

    // Each card fails independently: self, cluster, integrations.
    await waitFor(() => expect(screen.getAllByText('not connected').length).toBe(3));
  });

  it('shows all five workflows with contract operations and their proof', async () => {
    stubFetch(topologyRoutes());
    renderApp('/topology');
    await openTab('Application');

    for (const title of [
      'License lifecycle',
      'Emergency break-glass',
      'Auth & RBAC',
      'Vendor onboarding',
      'JIT access',
    ]) {
      expect(screen.getByText(title)).toBeDefined();
    }
    // The import step appears twice: the success and the 409 refusal.
    expect(screen.getAllByText('POST /api/v1/licenses/import').length).toBe(2);
    // Proof references: fixture files and the gate's RBAC flow.
    expect(
      screen.getAllByText('frontend/app/src/test/licensingFixtures.ts').length,
    ).toBeGreaterThanOrEqual(5);
    expect(screen.getAllByText('shots_tool/__verify_agent.mjs').length).toBe(3);
    expect(screen.getByText(/LIC_LIST_RESPONSE/)).toBeDefined();
  });

  it('never renders a raw i18n key in any view', async () => {
    stubFetch(topologyRoutes());
    renderApp('/topology');
    for (const tab of TABS) {
      await openTab(tab);
      expect(document.body.textContent).not.toContain('topology.');
    }
    expect(document.body.textContent).not.toContain('nav.topology');
  });
});
