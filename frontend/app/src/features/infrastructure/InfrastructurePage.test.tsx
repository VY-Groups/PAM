import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  ASSETS_EMPTY_RESPONSE,
  ASSETS_WITH_UNMANAGED_RESPONSE,
  CONNECTORS_EMPTY_RESPONSE,
  INFRA_FACTS,
  WHOAMI_OPEN_BODY,
  adoptAssetRoute,
  connectorsListRoute,
  discoveredAssetsRoute,
  discoveryStatsRoute,
  healthRoute,
  infrastructureRoutes,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Target Infrastructure (F4 screen 7): every assertion runs against the
 * verbatim rig captures in infrastructureFixtures.ts - no invented
 * values. The tests prove the digest KPI quad over the real discovery +
 * cloud aggregates, the real scan trigger (contract body, no X-Actor)
 * and the captured scan history, the target inventory with contract
 * filter parameters (pam_status / type / q) driving real refetches, the
 * Ignore/Restore/adopt writes (no X-Actor, server messages verbatim),
 * the privileged-accounts panel, the connector fleet with its captured
 * probe history, Probe/Discover/Remove/Add (X-Actor on every one, the
 * 409 credential refusal verbatim, a real DELETE), the discovery event
 * tape, and the honest section-error / empty / not-connected states.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** The recorded write call for `suffix` with the given HTTP method. */
function callWrite(fetchMock: ReturnType<typeof vi.fn>, suffix: string, method: string) {
  return fetchMock.mock.calls.find(
    ([input, init]) =>
      String(input).endsWith(suffix) &&
      ((init as RequestInit | undefined)?.method ?? 'GET') === method,
  );
}

/** Assert a cloud write carried the signed-in principal as `X-Actor`. */
function expectWrite(
  fetchMock: ReturnType<typeof vi.fn>,
  suffix: string,
  method: string,
  body?: unknown,
): void {
  const call = callWrite(fetchMock, suffix, method);
  expect(call).toBeDefined();
  const init = call?.[1] as RequestInit | undefined;
  expect(new Headers(init?.headers).get('X-Actor')).toBe('open');
  if (body !== undefined) {
    expect(JSON.parse(String(init?.body))).toEqual(body);
  }
}

/** Like `expectWrite` for the discovery writes, which carry no X-Actor. */
function expectAnonymousWrite(
  fetchMock: ReturnType<typeof vi.fn>,
  suffix: string,
  method: string,
  body?: unknown,
): void {
  const call = callWrite(fetchMock, suffix, method);
  expect(call).toBeDefined();
  const init = call?.[1] as RequestInit | undefined;
  expect(new Headers(init?.headers).get('X-Actor')).toBeNull();
  if (body !== undefined) {
    expect(JSON.parse(String(init?.body))).toEqual(body);
  }
}

/** Did any request carry this query-string fragment? */
function sawUrl(fetchMock: ReturnType<typeof vi.fn>, part: string): boolean {
  return fetchMock.mock.calls.some(([input]) => String(input).includes(part));
}

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/**
 * The asset card containing `address`. The address string can also
 * appear in the accounts panel and the event tape, so the first match
 * (the assets section renders first) is the row.
 */
async function assetRow(address: string): Promise<HTMLElement> {
  const els = await screen.findAllByText(address);
  return els[0].parentElement?.parentElement as HTMLElement;
}

describe('Target Infrastructure (F4 screen 7)', () => {
  it('renders the KPI quad from the real discovery and cloud aggregates', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');
    expect(
      await screen.findByRole('heading', { name: /Target Infrastructure & Discovery/ }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('3 targets · 15 types · 3 privileged accounts'),
    ).toBeInTheDocument();

    const assets = await kpiCard('DISCOVERED ASSETS');
    expect(within(assets).getByText('3')).toBeInTheDocument();
    expect(
      within(assets).getByText('2 managed · 1 ignored · 0 unmanaged'),
    ).toBeInTheDocument();

    const accounts = await kpiCard('PRIVILEGED ACCOUNTS');
    expect(within(accounts).getByText('3')).toBeInTheDocument();

    const scans = await kpiCard('SCANS RUN');
    expect(within(scans).getByText('1')).toBeInTheDocument();
    expect(within(scans).getByText('last 127.0.0.1 · completed')).toBeInTheDocument();

    const connectors = await kpiCard('CLOUD CONNECTORS');
    expect(within(connectors).getByText('1')).toBeInTheDocument();
    expect(
      within(connectors).getByText('0 connected · 1 error · 0 configured · 0 unprobed'),
    ).toBeInTheDocument();
  });

  it('scan history renders the real captured probe row', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 1 of 1 scans')).toBeInTheDocument();
    // The scope string also appears in the KPI footer and the event tape,
    // so assert it inside the scan row itself (chip parent = the row line).
    const methodChip = screen.getByText('tcp_probe');
    const scanLine = methodChip.parentElement as HTMLElement;
    expect(within(scanLine).getByText('127.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('tcp_probe')).toBeInTheDocument();
    expect(screen.getByText('completed')).toBeInTheDocument();
    expect(screen.getByText('22, 443')).toBeInTheDocument();
    expect(screen.getByText('1 probed · 0 open · 0 services')).toBeInTheDocument();
    expect(screen.getByText('triggered by open')).toBeInTheDocument();
  });

  it('the scan dialog validates the contract scope and posts the real probe request', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Run Discovery Scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Run Discovery Scan' });

    // Empty scope never reaches the network (ADR-0006: Zod is the gate).
    fireEvent.click(within(dialog).getByRole('button', { name: 'Run scan' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/discovery/scans', 'POST')).toBeUndefined();

    // Contract rule mirrored: a CIDR is a scope, the ports CSV must be ints.
    fireEvent.change(within(dialog).getByLabelText('Scope'), {
      target: { value: '10.99.8.0/24' },
    });
    fireEvent.change(within(dialog).getByLabelText('Ports (optional)'), {
      target: { value: 'abc' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Run scan' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText('Ports (optional)'), {
      target: { value: '22, 443' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Run scan' }));

    expect(await screen.findByText(INFRA_FACTS.scanMessage)).toBeInTheDocument();
    // Discovery writes carry no X-Actor (contract documents only rbac).
    expectAnonymousWrite(fetchMock, '/discovery/scans', 'POST', {
      scope: '10.99.8.0/24',
      ports: [22, 443],
    });
  });

  it('an empty ports field keeps the contract parameter absent', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Run Discovery Scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Run Discovery Scan' });
    fireEvent.change(within(dialog).getByLabelText('Scope'), {
      target: { value: 'scanme.test' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Run scan' }));

    expect(await screen.findByText(INFRA_FACTS.scanMessage)).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/discovery/scans', 'POST', {
      scope: 'scanme.test',
    });
  });

  it('the target list renders the real rows with status, risk and vault linkage', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 3 of 3 targets')).toBeInTheDocument();

    const gate = await assetRow('10.99.8.42');
    expect(within(gate).getByText('gate-8a.lab')).toBeInTheDocument();
    expect(within(gate).getByText('linux')).toBeInTheDocument();
    expect(within(gate).getByText('HIGH')).toBeInTheDocument();
    expect(within(gate).getByText('ignored')).toBeInTheDocument();
    expect(within(gate).getByText('manual/manual')).toBeInTheDocument();
    expect(within(gate).getByText('1 vault credential(s)')).toBeInTheDocument();
    expect(
      within(gate).getByText('SSH certificate JIT + 24h credential rotation'),
    ).toBeInTheDocument();
    expect(within(gate).getByRole('button', { name: 'Restore' })).toBeInTheDocument();

    const probeB = await assetRow('vypam-probe-b.test');
    expect(within(probeB).getByText('database')).toBeInTheDocument();
    expect(within(probeB).getByText('CRITICAL')).toBeInTheDocument();
    expect(within(probeB).getByText('managed')).toBeInTheDocument();
    expect(within(probeB).getByText('2 vault credential(s)')).toBeInTheDocument();

    // Managed rows offer Ignore, the ignored row Restore; nothing is
    // unmanaged in the real capture, so adopt stays absent.
    expect(screen.getAllByRole('button', { name: 'Ignore' })).toHaveLength(2);
    expect(screen.getAllByRole('button', { name: 'Restore' })).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Onboard to Vault Now' })).toBeNull();
  });

  it('the PAM-status and type chips drive the contract filter parameters', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');
    await screen.findByText('showing 3 of 3 targets');

    const pamGroup = screen.getByRole('group', { name: 'Filter targets by PAM status' });
    fireEvent.click(within(pamGroup).getByRole('button', { name: 'ignored' }));
    expect(await screen.findByText('showing 1 of 1 targets')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'pam_status=ignored')).toBe(true);
    expect(within(pamGroup).getByRole('button', { name: 'ignored' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );

    const typeGroup = screen.getByRole('group', { name: 'Filter targets by type' });
    fireEvent.click(within(pamGroup).getByRole('button', { name: 'all' }));
    await screen.findByText('showing 3 of 3 targets');
    fireEvent.click(within(typeGroup).getByRole('button', { name: 'database' }));
    expect(await screen.findByText('showing 1 of 1 targets')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'type=database')).toBe(true);
    expect(await assetRow('vypam-probe-b.test')).toBeInTheDocument();
  });

  it('the search box drives the contract q parameter', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');
    await screen.findByText('showing 3 of 3 targets');

    fireEvent.change(screen.getByLabelText('search address or hostname'), {
      target: { value: 'gate' },
    });
    expect(await screen.findByText('showing 1 of 1 targets')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'q=gate')).toBe(true);
  });

  it('Ignore patches the target with no X-Actor and reports the server message', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    const probeA = await assetRow('vypam-probe-a.test');
    fireEvent.click(within(probeA).getByRole('button', { name: 'Ignore' }));

    expect(await screen.findByText('Asset updated')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/discovery/assets/2', 'PATCH', {
      pam_status: 'ignored',
    });
  });

  it('Restore on the ignored gate asset posts managed', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    const gate = await assetRow('10.99.8.42');
    fireEvent.click(within(gate).getByRole('button', { name: 'Restore' }));

    expect(await screen.findByText('Asset updated')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/discovery/assets/1', 'PATCH', {
      pam_status: 'managed',
    });
  });

  it('an unmanaged row offers adopt, and adopt posts the contract body', async () => {
    const fetchMock = stubFetch([
      discoveredAssetsRoute(ASSETS_WITH_UNMANAGED_RESPONSE),
      adoptAssetRoute(INFRA_FACTS.gateAssetId + 2),
      ...infrastructureRoutes(),
    ]);
    renderApp('/infrastructure');

    const adopt = await screen.findByRole('button', { name: 'Onboard to Vault Now' });
    fireEvent.click(adopt);
    const dialog = await screen.findByRole('dialog', {
      name: 'Onboard to Vault: vypam-probe-b.test',
    });

    // A blank principal is refused client-side; nothing hits the network.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Adopt target' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();
    expect(callWrite(fetchMock, '/discovery/assets/3/onboard', 'POST')).toBeUndefined();

    fireEvent.change(within(dialog).getByLabelText('Privileged account'), {
      target: { value: 'vypam-probe-db' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Adopt target' }));

    expect(await screen.findByText('Target onboarded')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/discovery/assets/3/onboard', 'POST', {
      principal: 'vypam-probe-db',
      access_tier: 'Tier-2',
      auth_method: 'Password',
    });
  });

  it('the onboard dialog mirrors the no-CIDR rule and posts the contract body', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Onboard Target Host' }));
    const dialog = await screen.findByRole('dialog', { name: 'Onboard Target Host' });

    fireEvent.change(within(dialog).getByLabelText('Address'), {
      target: { value: '10.66.66.0/24' },
    });
    fireEvent.change(within(dialog).getByLabelText('Privileged account'), {
      target: { value: 'root' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Onboard' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText('Address'), {
      target: { value: '10.66.66.5' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Onboard' }));

    expect(await screen.findByText('Target onboarded')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/discovery/assets', 'POST', {
      address: '10.66.66.5',
      principal: 'root',
      asset_type: 'unknown',
      access_tier: 'Tier-2',
      auth_method: 'Password',
    });
  });

  it('the privileged accounts panel renders the ingested inventory', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 3 of 3 accounts')).toBeInTheDocument();
    expect(screen.getByText('root')).toBeInTheDocument();
    expect(screen.getByText('vypam-probe-admin')).toBeInTheDocument();
    expect(screen.getAllByText('10.99.8.42').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('builtin_admin')).toBeInTheDocument();
    expect(screen.getAllByText('other').length).toBeGreaterThanOrEqual(1);
  });

  it('the connector fleet renders the real probe history verbatim', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 1 of 1 connectors')).toBeInTheDocument();
    // Provider/status words also exist as filter chips, so scope to the card.
    const nameChip = screen.getByText(INFRA_FACTS.connectorName);
    const card = nameChip.parentElement?.parentElement as HTMLElement;
    expect(within(card).getByText('kubernetes')).toBeInTheDocument();
    expect(within(card).getByText('error')).toBeInTheDocument();
    expect(screen.getByText('account: vypam-probe-account-2')).toBeInTheDocument();
    expect(screen.getByText('endpoint: http://127.0.0.1:9/v1')).toBeInTheDocument();
    expect(screen.getByText(/^registered by open · /)).toBeInTheDocument();
    expect(
      screen.getByText(
        /last probe: connection failed: \[Errno 111\] Connection refused \(0 ms\)/,
      ),
    ).toBeInTheDocument();
  });

  it('the connector chips drive the contract filter parameters', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');
    await screen.findByText('showing 1 of 1 connectors');

    const providerGroup = screen.getByRole('group', {
      name: 'Filter connectors by provider',
    });
    fireEvent.click(within(providerGroup).getByRole('button', { name: 'aws' }));
    expect(
      await screen.findByText(
        'No cloud connectors registered - add one to probe it and import its inventory.',
      ),
    ).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'provider=aws')).toBe(true);

    // Reset the provider dimension, then the status chip drives status=.
    fireEvent.click(within(providerGroup).getByRole('button', { name: 'all providers' }));
    await screen.findByText('showing 1 of 1 connectors');
    const statusGroup = screen.getByRole('group', {
      name: 'Filter connectors by status',
    });
    fireEvent.click(within(statusGroup).getByRole('button', { name: 'error' }));
    expect(await screen.findByText('showing 1 of 1 connectors')).toBeInTheDocument();
    expect(sawUrl(fetchMock, 'status=error')).toBe(true);
  });

  it('Probe posts with X-Actor and renders the real failure verbatim', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Probe' }));
    expect(await screen.findByText(INFRA_FACTS.probeMessage)).toBeInTheDocument();
    expectWrite(fetchMock, '/cloud/connectors/1/test', 'POST');
  });

  it('Discover surfaces the server credential refusal verbatim', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Discover' }));
    const refusal = await screen.findByText('Cloud connector credential is not configured');
    expect(refusal).toHaveAttribute('role', 'alert');
    expectWrite(fetchMock, '/cloud/connectors/1/discover', 'POST');
  });

  it('Remove confirms first, then DELETEs with X-Actor', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    const confirm = await screen.findByRole('dialog', { name: 'Remove cloud connector' });
    expect(
      within(confirm).getByText(
        'Remove vypam-probe-conn? Its probe history and inventory records stay in the audit ledger.',
      ),
    ).toBeInTheDocument();

    // Cancel leaves the fleet untouched.
    fireEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog', { name: 'Remove cloud connector' })).toBeNull();
    expect(callWrite(fetchMock, '/cloud/connectors/1', 'DELETE')).toBeUndefined();

    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    const confirmAgain = await screen.findByRole('dialog', {
      name: 'Remove cloud connector',
    });
    fireEvent.click(within(confirmAgain).getByRole('button', { name: 'Remove' }));

    expect(
      await screen.findByText('Cloud connector vypam-probe-conn removed'),
    ).toBeInTheDocument();
    expectWrite(fetchMock, '/cloud/connectors/1', 'DELETE');
  });

  it('Add Cloud Connector validates the endpoint rule and posts with X-Actor', async () => {
    const fetchMock = stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    fireEvent.click(await screen.findByRole('button', { name: 'Add Cloud Connector' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add Cloud Connector' });

    fireEvent.click(within(dialog).getByRole('button', { name: 'Register' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText('Name'), {
      target: { value: 'vypam-test-conn' },
    });
    // The contract says https (http only on loopback) - mirrored in UX.
    fireEvent.change(within(dialog).getByLabelText('Endpoint (optional)'), {
      target: { value: 'http://evil.example.com' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Register' }));
    expect(
      await within(dialog).findByText(
        "Fix the highlighted fields - the form mirrors the contract's limits.",
      ),
    ).toBeInTheDocument();

    fireEvent.change(within(dialog).getByLabelText('Endpoint (optional)'), {
      target: { value: '' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Register' }));

    expect(
      await screen.findByText(
        'Cloud connector vypam-probe-conn registered (kubernetes, configured)',
      ),
    ).toBeInTheDocument();
    expectWrite(fetchMock, '/cloud/connectors', 'POST', {
      name: 'vypam-test-conn',
      provider: 'aws',
    });
  });

  it('the discovery event stream renders the real tape', async () => {
    stubFetch(infrastructureRoutes());
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 10 of 10 events')).toBeInTheDocument();
    const rows = await screen.findAllByText('asset_onboarded');
    const first = rows[0].parentElement?.parentElement as HTMLElement;
    expect(within(first).getByText('#80')).toBeInTheDocument();
    expect(within(first).getByText('discovery')).toBeInTheDocument();
    expect(within(first).getByText('vypam-probe-b.test')).toBeInTheDocument();
    expect(within(first).getByText(/^open · /)).toBeInTheDocument();
    expect(
      within(first).getByText((content) => content.includes('adopted=true')),
    ).toBeInTheDocument();
  });

  it('a stats error renders verbatim while the independent sections keep answering', async () => {
    stubFetch([
      discoveryStatsRoute({ status: 500, body: { error: 'digest exploded' } }),
      ...infrastructureRoutes(),
    ]);
    renderApp('/infrastructure');

    const alert = await screen.findByText(
      'Section unavailable: digest exploded',
      {},
      { timeout: 8000 },
    );
    expect(alert).toHaveAttribute('role', 'alert');

    // The stats-backed KPIs fall back to the honest em-dash...
    const assets = await kpiCard('DISCOVERED ASSETS');
    expect(within(assets).getByText('—')).toBeInTheDocument();
    // ...while the list sections keep answering from their own queries.
    expect(await screen.findByText('showing 3 of 3 targets')).toBeInTheDocument();
  });

  it('transport failure shows the shared banner and the not-connected chips', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/infrastructure');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect((await screen.findAllByText('not connected')).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Target Infrastructure & Discovery')).toBeInTheDocument();
  });

  it('the empty inventory and fleet keep their honest empty lines', async () => {
    stubFetch([
      discoveredAssetsRoute(ASSETS_EMPTY_RESPONSE),
      connectorsListRoute(CONNECTORS_EMPTY_RESPONSE),
      ...infrastructureRoutes(),
    ]);
    renderApp('/infrastructure');

    expect(await screen.findByText('showing 0 of 0 targets')).toBeInTheDocument();
    expect(
      await screen.findByText(
        'No targets match this filter - the discovery inventory is empty here.',
      ),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(
        'No cloud connectors registered - add one to probe it and import its inventory.',
      ),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(infrastructureRoutes());
    const { container } = renderApp('/infrastructure');
    await screen.findByText('showing 3 of 3 targets');
    await expectNoAxeViolations(container);
  });
});
