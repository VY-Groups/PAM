import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  ROLE_BINDING_CREATE_RESPONSE,
  ROLE_BINDING_CREATE_SSO_RESPONSE,
  ROLE_BINDINGS_RESPONSE,
  ROLES_RESPONSE,
  roleBindingsRoute,
  rolesRoute,
  settingsRoutes,
  stubFetch,
} from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { RbacSection } from './RbacSection';
import { SettingsPage } from './SettingsPage';

/**
 * RBAC / ABAC (screen 11, ADR-0015, 11.2) - every assertion below is a
 * parity requirement lifted from the standing gate's 6b block
 * (shots_tool/__verify_agent.mjs lines 391-432 + the kind-select check
 * at 477-478), asserted here against the React section exactly as the
 * gate holds the legacy page. The gate re-points at these hooks in the
 * 11.5 flip; 11.2 locks the contract now.
 *
 * Fixtures are verbatim rig captures (settingsFixtures.ts): five seeded
 * roles from the open rig, three demo bindings, and the write cycle -
 * grant 201 (local principal WITH the one-time token, sso principal
 * WITHOUT one) and revoke 200 - captured from the token rig with the
 * probes deleted again (Temp/opencode/rbac_capture_112.json).
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/** The exact summary regex the gate holds the legacy page to (line 418). */
const GATE_SUMMARY_RE = /^\d+ roles · \d+ active bindings? \(\d+ local · \d+ directory\)$/;

function findPost(fetchMock: ReturnType<typeof stubFetch>) {
  const call = fetchMock.mock.calls.find(
    ([, init]) => (init as RequestInit | undefined)?.method === 'POST',
  );
  expect(call, 'expected a POST /role-bindings call').toBeTruthy();
  return {
    url: String(call?.[0]),
    body: JSON.parse(String((call?.[1] as RequestInit | undefined)?.body)),
  };
}

describe('RBAC / ABAC section (screen 11, ADR-0015) - 11.2', () => {
  it('the summary is the gate parity regex over the real registry', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    const summary = await screen.findByTestId('settings-rbac-summary');
    // Verbatim from the standing gate (line 418): five roles, three
    // local bindings, zero directory - exactly what the rig answered.
    await waitFor(() =>
      expect(summary.textContent).toBe(
        '5 roles · 3 active bindings (3 local · 0 directory)',
      ),
    );
    expect(summary.textContent).toMatch(GATE_SUMMARY_RE);
  });

  it('the tiles read the seeded five and the binding count (gate tile checks)', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    // The gate reads textContent of the value span itself (lines
    // 420/422), so the test does exactly that - the value lives in a
    // nested span, which text-matching with a selector would miss.
    await waitFor(() =>
      expect(document.querySelector('[data-role="rbac-tile-roles"]')?.textContent).toBe(
        '5',
      ),
    );
    await waitFor(() =>
      expect(document.querySelector('[data-role="rbac-tile-bindings"]')?.textContent).toBe(
        '3',
      ),
    );
  });

  it('the role directory renders exactly the five seeded roles (gate roleRows)', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    // Gate line 424: five <tr> under the role tbody hook.
    await waitFor(() =>
      expect(document.querySelectorAll('[data-role="rbac-role-rows"] tr').length).toBe(5),
    );
    // The computed operation counts, verbatim from the rig: the page
    // reads what the server seeded, it never hardcodes the numbers.
    for (const operations of ['144', '13', '34', '31', '48']) {
      expect(document.querySelector('[data-role="rbac-role-rows"]')?.textContent).toContain(
        operations,
      );
    }
  });

  it('the binding table renders the demo rows with honest scope and last-use', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    // Gate line 426: binding rows render (rows or honest empty state).
    await waitFor(() =>
      expect(document.querySelectorAll('[data-role="rbac-binding-rows"] tr').length).toBe(
        3,
      ),
    );
    const tbody = document.querySelector('[data-role="rbac-binding-rows"]');
    // Empty scope renders the legacy "unscoped" wording, null last-use
    // renders "never", and only the public token prefix is shown - the
    // secret never leaves the server.
    expect(tbody?.textContent).toContain('unscoped (role governs everywhere)');
    expect(tbody?.textContent).toContain('never');
    expect(tbody?.textContent).toContain('vypam-rbac1.1.');
    expect(tbody?.textContent).toContain('Revoke');
  });

  it('the kind select offers the four API kinds - sso and user included (gate line 477)', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    const kindSelect = (await screen.findByTestId(
      'settings-rbac-input-kind',
    )) as HTMLSelectElement;
    // Gate line 477-478: values must include 'sso' and 'user'.
    expect(Array.from(kindSelect.options).map((option) => option.value)).toEqual([
      'local',
      'ldap',
      'sso',
      'user',
    ]);
    // Labels verbatim from the legacy page's option text.
    expect(
      within(kindSelect).getByRole('option', { name: 'sso (SSO subject)' }),
    ).toBeTruthy();
    expect(
      within(kindSelect).getByRole('option', { name: 'user (local console user)' }),
    ).toBeTruthy();
  });

  it('the one-time token box starts hidden and the section carries no id= (gate lines 428-431)', async () => {
    stubFetch(settingsRoutes());
    const { container } = renderWithProviders(<RbacSection />);

    // Gate line 428: the box exists AND starts with class 'hidden'.
    const box = await screen.findByTestId('settings-rbac-token-once');
    expect(box.className).toContain('hidden');
    expect(box.textContent).not.toContain('vypam-rbac1');

    // Gate line 430: no id= anywhere in the section (the legacy page's
    // one id="rbac-token-value" is banned by the React DoD).
    const section = screen.getByTestId('settings-rbac');
    expect(section.querySelectorAll('[id]').length).toBe(0);
    expect(container.querySelectorAll('[id]').length).toBe(0);
  });

  it('the RBAC section sits below the HA/DC/DR section (gate belowCluster, line 417)', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<SettingsPage />);

    const cluster = await screen.findByTestId('settings-cluster');
    const rbac = await screen.findByTestId('settings-rbac');
    // Same expression the gate evaluates (DOCUMENT_POSITION_FOLLOWING = 4).
    expect(cluster.compareDocumentPosition(rbac) & 4).toBeGreaterThan(0);
  });

  it('granting a local principal posts the verbatim payload and shows the token once', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    fireEvent.change(await screen.findByPlaceholderText('svc-nightly'), {
      target: { value: 'svc-nightly' },
    });
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'auditor' } });
    fireEvent.change(screen.getByPlaceholderText('web-*, bastion-1'), {
      target: { value: 'web-*, bastion-1' },
    });
    fireEvent.change(screen.getByPlaceholderText('3, 7'), {
      target: { value: '3, 7' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Grant Role' }));

    // The legacy payload shape, field for field: comma lists trimmed,
    // vault items parsed to ints, scope omitted when both lists are empty.
    await waitFor(() => {
      const post = findPost(fetchMock);
      expect(post.url).toContain('/api/v1/role-bindings');
      expect(post.body).toEqual({
        principal: 'svc-nightly',
        role: 'auditor',
        kind: 'local',
        scope: { targets: ['web-*', 'bastion-1'], vault_items: [3, 7] },
      });
    });

    // The captured 201 carries a token: the box un-hides and shows it
    // verbatim (the fixture's synthetic stand-in for the redacted rig
    // secret), and the feedback line is the legacy toast copy.
    const box = screen.getByTestId('settings-rbac-token-once');
    await waitFor(() => expect(box.className).not.toContain('hidden'));
    expect(box.textContent).toContain('vypam-rbac1.16.<redacted-shown-once>');
    expect(
      await screen.findByText(
        'capture-112-probe is now operator - the token is shown once above.',
      ),
    ).toBeInTheDocument();

    // The form clears and the lists re-read (create invalidates both).
    expect((screen.getByPlaceholderText('svc-nightly') as HTMLInputElement).value).toBe('');
    const getRoleBindings = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes('/api/v1/role-bindings'),
    );
    expect(getRoleBindings.length).toBeGreaterThan(1);
  });

  it('granting an sso principal answers 201 without a token - the box stays hidden', async () => {
    stubFetch([
      ...settingsRoutes().filter((route) => !route.match('/api/v1/role-bindings')),
      roleBindingsRoute(ROLE_BINDINGS_RESPONSE, ROLE_BINDING_CREATE_SSO_RESPONSE),
    ]);
    renderWithProviders(<RbacSection />);

    fireEvent.change(await screen.findByPlaceholderText('svc-nightly'), {
      target: { value: 'alice@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Kind'), { target: { value: 'sso' } });
    fireEvent.click(screen.getByRole('button', { name: 'Grant Role' }));

    // Legacy toast arm for directory identities, verbatim.
    expect(
      await screen.findByText(
        'capture-112-sso-probe is now auditor (directory identity - a login ticket will carry it).',
      ),
    ).toBeInTheDocument();
    // The token box never un-hides: an SSO subject's bearer is minted
    // by the IdP login, not by the grant.
    expect(screen.getByTestId('settings-rbac-token-once').className).toContain('hidden');
  });

  it('an empty principal is refused verbatim without a POST', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Grant Role' }));

    expect(
      await screen.findByText(
        'A principal (name, or the directory username for kind ldap) is required.',
      ),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(
        ([, init]) => (init as RequestInit | undefined)?.method === 'POST',
      ),
    ).toHaveLength(0);
  });

  it('revoking asks for confirmation, then DELETEs and reports the legacy line', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    const row = (await screen.findByText('demo-operator')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

    // Legacy confirm text, verbatim (interpolated with the principal).
    expect(confirmSpy).toHaveBeenCalledWith(
      'Revoke the role binding for "demo-operator"? Its token stops working immediately; the row stays as audit evidence.',
    );
    // The DELETE is dispatched by the mutation, so the call lands
    // asynchronously - wait for it rather than racing the click.
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([url, init]) =>
            String(url).includes('/api/v1/role-bindings/2') &&
            (init as RequestInit | undefined)?.method === 'DELETE',
        ),
      ).toBe(true),
    );
    // Legacy toast copy, verbatim.
    expect(
      await screen.findByText('demo-operator no longer holds operator.'),
    ).toBeInTheDocument();
  });

  it('a declined confirmation sends nothing', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    const fetchMock = stubFetch(settingsRoutes());
    renderWithProviders(<RbacSection />);

    const row = (await screen.findByText('demo-operator')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));

    expect(
      fetchMock.mock.calls.filter(
        ([, init]) => (init as RequestInit | undefined)?.method === 'DELETE',
      ),
    ).toHaveLength(0);
  });

  it('an empty binding table renders the honest empty row (gate "rows or empty state")', async () => {
    stubFetch([
      ...settingsRoutes().filter((route) => !route.match('/api/v1/role-bindings')),
      roleBindingsRoute({ status: 200, body: { bindings: [] } }),
    ]);
    renderWithProviders(<RbacSection />);

    // Verbatim legacy empty-row copy; the summary counts honestly too.
    // Both queries settle on different ticks, so wait for the summary.
    expect(
      await screen.findByText(
        'No role bindings yet - the admin token (and open/dev mode) remain the only access.',
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId('settings-rbac-summary').textContent).toBe(
        '5 roles · 0 active bindings (0 local · 0 directory)',
      ),
    );
    expect(screen.getByTestId('settings-rbac-summary').textContent).toMatch(
      GATE_SUMMARY_RE,
    );
  });

  it('a 401 on the role read says the admin token is required - not "unreachable"', async () => {
    stubFetch([
      ...settingsRoutes().filter((route) => !route.match('/api/v1/roles')),
      rolesRoute({ status: 401, body: { error: 'Admin token required' } }),
    ]);
    renderWithProviders(<RbacSection />);

    // Non-transport failures retry twice (QueryProvider), hence the timeout.
    expect(
      await screen.findByText(
        'Admin token required to read roles and bindings - set it with the Token button.',
        {},
        { timeout: 10_000 },
      ),
    ).toBeInTheDocument();
  });

  it('a dead backend says so verbatim - never a zero-registry summary', async () => {
    stubFetch([]);
    renderWithProviders(<RbacSection />);

    expect(
      await screen.findByText('RBAC state unavailable (license server not reachable).'),
    ).toBeInTheDocument();
  });

  it('has no axe violations (live data)', async () => {
    stubFetch(settingsRoutes());
    const { container } = renderWithProviders(<RbacSection />);
    await waitFor(() =>
      expect(document.querySelector('[data-role="rbac-tile-roles"]')?.textContent).toBe(
        '5',
      ),
    );
    await expectNoAxeViolations(container);
  });

  it('has no axe violations (backend down)', async () => {
    stubFetch([]);
    const { container } = renderWithProviders(<RbacSection />);
    await screen.findByText('RBAC state unavailable (license server not reachable).');
    await expectNoAxeViolations(container);
  });

  it('the fixture roles match the verbatim rig capture the summary is built from', () => {
    // A guard on the fixtures themselves: if someone hand-edits the
    // counts, the parity tests above would still pass against the edit.
    // This one pins them to the capture (ROLES_RESPONSE is the rig's
    // own body): five roles, operations summing to the seeded policy.
    expect(ROLES_RESPONSE.status).toBe(200);
    expect(ROLES_RESPONSE.body.roles).toHaveLength(5);
    expect(ROLES_RESPONSE.body.roles.map((role) => role.operations)).toEqual([
      144, 13, 34, 31, 48,
    ]);
    expect(ROLE_BINDINGS_RESPONSE.body.bindings).toHaveLength(3);
    expect(ROLE_BINDING_CREATE_RESPONSE.status).toBe(201);
    expect(ROLE_BINDING_CREATE_RESPONSE.body.token).toContain('vypam-rbac1.16.');
  });
});
