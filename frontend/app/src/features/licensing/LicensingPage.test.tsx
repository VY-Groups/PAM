import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  LIC_FILE_JWT_ACTIVE_TEXT,
  LIC_FILE_JSON_RESPONSE,
  LIC_IMPORT_DUP_REFUSAL,
  LIC_KEYS,
  licenseImportRoute,
  licensesListRoute,
  licenseRoutes,
  WHOAMI_OPEN_BODY,
  healthRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Enterprise Licensing (F4 screen 10): every assertion runs against the
 * verbatim rig captures in licensingFixtures.ts - no invented values.
 * The tests prove the KPI quad over the captured overview aggregates,
 * the contract catalog rail from /api/v1/meta, the registry with all
 * four server-side filters as REAL contract parameters (probed against
 * the live rig: status matches record OR effective status, tier/type
 * are equality, q is a case-insensitive substring over key/ID/issued-to/
 * tier and NOT classification), the selected license's parity block
 * (8/8 entitlements, quota meters, the four pool rows with their
 * enforcement levels, payload signature and activity), the restore and
 * revoke lifecycle with the server's own messages, the air-gap import
 * including the client's JSON guard and the captured duplicate-import
 * 409 refusal, the offline-parity verdict dispatched by payload key,
 * the signed-file viewer in both wire formats, plus the honest empty /
 * section-error / backend-down states and an axe pass.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/** Did any request carry this query-string fragment? */
function sawUrl(fetchMock: ReturnType<typeof vi.fn>, part: string): boolean {
  return fetchMock.mock.calls.some(([input]) => String(input).includes(part));
}

/** The LAST request to `suffix` with `method` (writes each assert their own). */
function callWrite(fetchMock: ReturnType<typeof vi.fn>, suffix: string, method: string) {
  return [...fetchMock.mock.calls]
    .reverse()
    .find(
      ([input, init]) =>
        String(input).endsWith(suffix) &&
        ((init as RequestInit | undefined)?.method ?? 'GET') === method,
    );
}

/** The registry row holding `id` (the identity cell renders first). */
async function rowFor(id: string): Promise<HTMLElement> {
  const el = await screen.findByText(id);
  return el.closest('tr') as HTMLElement;
}

/** Inspect the row addressing `id` and wait for the detail to settle. */
async function inspect(id: string): Promise<HTMLElement> {
  const row = await rowFor(id);
  fireEvent.click(within(row).getByRole('button', { name: 'Inspect' }));
  const detail = (await screen.findByTestId('licensing-detail')) as HTMLElement;
  // The detail query settles async (pending line -> content or error).
  await waitFor(() =>
    expect(within(detail).queryByText('Loading licenses…')).not.toBeInTheDocument(),
  );
  return detail;
}

describe('Enterprise Licensing (F4 screen 10)', () => {
  it('renders the header, the KPI quad from the captured overview, the tier chips, the catalog rail and the honest placeholder', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');

    expect(
      await screen.findByRole('heading', { name: 'Enterprise Licensing' }),
    ).toBeInTheDocument();

    // The KPI quad is the captured /api/v1/overview licenses block:
    // total 2, active 1, expiring_soon 0, revoked 1.
    const total = await kpiCard('Licenses');
    expect(within(total).getByText('2')).toBeInTheDocument();
    const active = await kpiCard('Active');
    expect(within(active).getByText('1')).toBeInTheDocument();
    const expiring = await kpiCard('Expiring soon');
    expect(within(expiring).getByText('0')).toBeInTheDocument();
    const revoked = await kpiCard('Revoked');
    expect(within(revoked).getByText('1')).toBeInTheDocument();

    // by_tier chips, verbatim from the capture.
    expect(await screen.findByText('Enterprise: 1')).toBeInTheDocument();
    expect(screen.getByText('PROFESSIONAL CLOUD: 1')).toBeInTheDocument();

    // The contract catalog rail from /api/v1/meta.
    expect(
      await screen.findByText(
        'ENTERPRISE ZSP ULTIMATE · PERPETUAL ON-PREM · PROFESSIONAL CLOUD · TRIAL EVALUATION',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('8 modules in the catalog')).toBeInTheDocument();

    // The air-gap ingestion process rail (the legacy section, live steps).
    expect(
      await screen.findByText(
        'Receive the signed license file from the vendor out-of-band.',
      ),
    ).toBeInTheDocument();

    // Registry from the contract: both captured rows, honest count.
    expect(await screen.findByText('LIC-5076-AEGIS-SEC-PROD')).toBeInTheDocument();
    expect(screen.getByText('LIC-9395-AEGIS-SEC-PROD')).toBeInTheDocument();
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();

    // No selection yet: the honest placeholder, not a fake default.
    expect(screen.getByText(/Select a license in the registry/)).toBeInTheDocument();
  });

  it('renders the registry from the contract with legacy columns and equal inspection affordance', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');

    for (const name of ['License', 'Issued to', 'Tier', 'Status', 'Expiry', 'Actions']) {
      expect(await screen.findByRole('columnheader', { name })).toBeInTheDocument();
    }

    // Both rows carry the server's own state: the live demo reads the
    // captured effective status 'valid', the scratch row reads 'revoked'
    // with its recorded reason.
    expect(await screen.findByText('valid')).toBeInTheDocument();
    expect(screen.getByText('capture run terminal state')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Inspect' })).toHaveLength(2);
  });

  it('sends the status chips to the contract (server-side, never a client re-filter)', async () => {
    const fetchMock = stubFetch(licenseRoutes());
    renderApp('/licensing');

    expect(await screen.findByText('LIC-5076-AEGIS-SEC-PROD')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'revoked' }));
    await waitFor(() => expect(sawUrl(fetchMock, 'status=revoked')).toBe(true));
    expect(await screen.findByText('1 shown of 1')).toBeInTheDocument();
    expect(screen.getByText('LIC-9395-AEGIS-SEC-PROD')).toBeInTheDocument();
    // A client re-filter of the stale page would still carry the demo row;
    // the server's filtered answer does not.
    expect(screen.queryByText('LIC-5076-AEGIS-SEC-PROD')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'all' }));
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();
    expect(screen.getByText('LIC-5076-AEGIS-SEC-PROD')).toBeInTheDocument();
  });

  it('drives the tier, type and free-text controls as real contract parameters', async () => {
    const fetchMock = stubFetch(licenseRoutes());
    renderApp('/licensing');
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();

    // Tier equality (the scratch row's captured tier).
    fireEvent.change(await screen.findByLabelText('Tier'), {
      target: { value: 'PROFESSIONAL CLOUD' },
    });
    await waitFor(() => expect(sawUrl(fetchMock, 'tier=PROFESSIONAL')).toBe(true));
    expect(await screen.findByText('1 shown of 1')).toBeInTheDocument();
    expect(screen.getByText('LIC-9395-AEGIS-SEC-PROD')).toBeInTheDocument();

    fireEvent.change(await screen.findByLabelText('Tier'), { target: { value: '' } });
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();

    // license_type equality.
    fireEvent.change(await screen.findByLabelText('Type'), {
      target: { value: 'subscription' },
    });
    await waitFor(() => expect(sawUrl(fetchMock, 'license_type=subscription')).toBe(true));
    expect(await screen.findByText('1 shown of 1')).toBeInTheDocument();

    fireEvent.change(await screen.findByLabelText('Type'), { target: { value: '' } });
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();

    // Free-text search over key / license ID / issued-to / tier.
    fireEvent.change(await screen.findByLabelText('Search'), {
      target: { value: '9395' },
    });
    await waitFor(() => expect(sawUrl(fetchMock, 'q=9395')).toBe(true));
    expect(await screen.findByText('1 shown of 1')).toBeInTheDocument();

    fireEvent.change(await screen.findByLabelText('Search'), {
      target: { value: '' },
    });
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();
  });

  it('renders the honest empty registry when the server answers zero rows (expired probe)', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');
    expect(await screen.findByText('2 shown of 2')).toBeInTheDocument();

    // The rig's own probe: no captured row carries expired in either
    // status field, so status=expired really answers an empty list.
    fireEvent.click(screen.getByRole('button', { name: 'expired' }));
    expect(
      await screen.findByText('No license matches these filters.'),
    ).toBeInTheDocument();
    expect(await screen.findByText('0 shown of 0')).toBeInTheDocument();
    expect(screen.queryByText('LIC-5076-AEGIS-SEC-PROD')).not.toBeInTheDocument();
  });

  it('inspects the active license: entitlements, quota meters, pool breakdown, signature and activity', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');

    const detail = await inspect('LIC-5076-AEGIS-SEC-PROD');

    // Identity: the captured record, status and validity verbatim.
    expect(
      within(detail).getByText('62070B33-4ACD-417B-A4FC-BE00A59498C7'),
    ).toBeInTheDocument();
    expect(within(detail).getByText('VY-PAM Demo Deployment')).toBeInTheDocument();
    expect(
      within(detail).getByText('Enterprise · Annual Subscription'),
    ).toBeInTheDocument();
    expect(within(detail).getByText('valid')).toBeInTheDocument();
    expect(within(detail).getByText('record status: active')).toBeInTheDocument();
    expect(within(detail).getByText('Perpetual - no expiry date')).toBeInTheDocument();
    expect(
      within(detail).getByText('Issued 2026-10-15T02:06:55.213620'),
    ).toBeInTheDocument();
    expect(within(detail).getByText('Never reported')).toBeInTheDocument();

    // Entitlements: the 8-module catalog, all entitled on this license.
    expect(
      within(detail).getByText('8 of 8 catalog modules entitled on this license.'),
    ).toBeInTheDocument();
    expect(
      within(detail).getByText('Zero-Standing Privilege Dynamic Leases'),
    ).toBeInTheDocument();
    expect(within(detail).getAllByText('Entitled')).toHaveLength(8);

    // Quota meters: the server's own numbers from the detail capture
    // (0/5000 nodes, 0/40 sessions, 0/1000 tunnels) with headroom lines
    // and the caps.
    expect(within(detail).getAllByRole('meter')).toHaveLength(3);
    expect(within(detail).getByRole('meter', { name: 'Nodes 0/5000' })).toBeInTheDocument();
    expect(within(detail).getByText('0/5000 nodes')).toBeInTheDocument();
    expect(within(detail).getByText('0% used · 5000 headroom')).toBeInTheDocument();
    expect(within(detail).getByText('Max lease: 4 h')).toBeInTheDocument();
    expect(within(detail).getByText('WORM retention: 2555 d')).toBeInTheDocument();
    expect(within(detail).getByText('max_users: 1000')).toBeInTheDocument();

    // The pool-by-environment table: four captured rows with their
    // enforcement levels and utilization.
    expect(within(detail).getByText('AWS Production')).toBeInTheDocument();
    expect(within(detail).getByText('soft-warning')).toBeInTheDocument();
    expect(within(detail).getByText('hard-block')).toBeInTheDocument();
    const poolTable = within(detail).getByText('AWS Production').closest('table');
    expect(within(poolTable as HTMLElement).getAllByRole('row')).toHaveLength(5);

    // Payload signature, verbatim.
    expect(within(detail).getByText('RSA-PSS-SHA256')).toBeInTheDocument();
    expect(
      within(detail).getByText(
        'sha256:900fa3099fe998ade41542eabc563bc15d3b8bc28e01b2e36af1db8cf68ed70a',
      ),
    ).toBeInTheDocument();

    // Recent activity: the captured imported event.
    const activity = within(detail).getByRole('region', {
      name: 'Recent License Activity',
    });
    expect(within(activity).getByText('imported')).toBeInTheDocument();

    // State-gated actions: a live license revokes (and can show its
    // file / validate offline); there is no restore affordance.
    expect(within(detail).getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
    expect(within(detail).getByRole('button', { name: 'Signed file' })).toBeInTheDocument();
    expect(
      within(detail).getByRole('button', { name: 'Validate offline' }),
    ).toBeInTheDocument();
    expect(
      within(detail).queryByRole('button', { name: 'Restore' }),
    ).not.toBeInTheDocument();
  });

  it('inspects the revoked license with its recorded reason and full lifecycle trail, then restores it', async () => {
    const fetchMock = stubFetch(licenseRoutes());
    renderApp('/licensing');

    const detail = await inspect('LIC-9395-AEGIS-SEC-PROD');

    // Status chip + the two captured revoke events carry the word
    // 'revoked' (three occurrences); the identity block also reads the
    // raw record status and the terminal reason verbatim.
    expect(within(detail).getByText('record status: revoked')).toBeInTheDocument();
    expect(within(detail).getAllByText('revoked')).toHaveLength(3);
    expect(within(detail).getByText('capture run terminal state')).toBeInTheDocument();
    expect(
      within(detail).getByText('PROFESSIONAL CLOUD · Capture-Run Annual'),
    ).toBeInTheDocument();
    expect(
      within(detail).getByText('6 of 8 catalog modules entitled on this license.'),
    ).toBeInTheDocument();

    // The captured trail: imported -> revoked -> restored -> revoked.
    const activity = within(detail).getByRole('region', {
      name: 'Recent License Activity',
    });
    expect(within(activity).getAllByRole('listitem')).toHaveLength(4);
    expect(within(activity).getAllByText('revoked')).toHaveLength(2);

    // A revoked license restores, never revokes again.
    expect(
      within(detail).queryByRole('button', { name: 'Revoke' }),
    ).not.toBeInTheDocument();
    fireEvent.click(within(detail).getByRole('button', { name: 'Restore' }));

    // The server's own answer, verbatim, on the page's status line.
    expect(await screen.findByText('License restored')).toBeInTheDocument();
    const call = callWrite(fetchMock, '/restore', 'POST');
    expect(call).toBeDefined();
    expect(String(call?.[0])).toContain(LIC_KEYS.revoked);
  });

  it('revoke posts the recorded reason and renders the server message', async () => {
    const fetchMock = stubFetch(licenseRoutes());
    renderApp('/licensing');

    const detail = await inspect('LIC-5076-AEGIS-SEC-PROD');
    fireEvent.click(within(detail).getByRole('button', { name: 'Revoke' }));

    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByRole('heading', { name: 'Revoke license' }),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(/terminal until an explicit restore/),
    ).toBeInTheDocument();

    fireEvent.change(
      within(dialog).getByLabelText('Reason (recorded on the license and in the ledger)'),
      { target: { value: 'contract test reason' } },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));

    expect(await screen.findByText('License revoked')).toBeInTheDocument();
    await waitFor(() => expect(sawUrl(fetchMock, '/revoke')).toBe(true));
    const call = callWrite(fetchMock, `/revoke`, 'POST');
    expect(call).toBeDefined();
    const init = call?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(init?.body))).toEqual({
      reason: 'contract test reason',
    });
  });

  it('import guards the paste client-side (no request) then posts the envelope and shows the server message', async () => {
    const fetchMock = stubFetch(licenseRoutes());
    renderApp('/licensing');

    const importButtons = await screen.findAllByRole('button', {
      name: 'Import license file',
    });
    fireEvent.click(importButtons[0]);
    const dialog = await screen.findByRole('dialog');
    const paste = within(dialog).getByLabelText('Signed license file (JSON)');

    // ADR-0006 client guard: unparseable paste never leaves the browser.
    fireEvent.change(paste, { target: { value: 'not json at all' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }));
    expect(
      await within(dialog).findByText('The paste is not valid JSON.'),
    ).toBeInTheDocument();
    expect(sawUrl(fetchMock, '/licenses/import')).toBe(false);

    // The real captured envelope imports (201) and the server's message
    // lands on the status line; the dialog closes.
    fireEvent.change(paste, {
      target: { value: JSON.stringify(LIC_FILE_JSON_RESPONSE.body) },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }));
    expect(await screen.findByText('License imported')).toBeInTheDocument();
    await waitFor(() => expect(sawUrl(fetchMock, '/licenses/import')).toBe(true));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('renders the captured duplicate-import refusal verbatim (409, dialog stays open)', async () => {
    stubFetch([licenseImportRoute(LIC_IMPORT_DUP_REFUSAL), ...licenseRoutes()]);
    renderApp('/licensing');

    const importButtons = await screen.findAllByRole('button', {
      name: 'Import license file',
    });
    fireEvent.click(importButtons[0]);
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Signed license file (JSON)'), {
      target: { value: JSON.stringify(LIC_FILE_JSON_RESPONSE.body) },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }));

    expect(
      await within(dialog).findByText(
        'License 31ED5F43-6D34-4553-88FA-1D0E6113C6DD is already installed',
      ),
    ).toBeInTheDocument();
    // The refusal is terminal for this submit: the dialog stays open and
    // no success message appears.
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByText('License imported')).not.toBeInTheDocument();
  });

  it('validates offline from the raw JWT and renders the captured verdict structurally', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');

    fireEvent.click(await screen.findByRole('button', { name: 'Validate offline' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('License file or compact JWT'), {
      target: { value: LIC_FILE_JWT_ACTIVE_TEXT },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Validate' }));

    // The demo license's own captured verdict, dispatched by the token's
    // payload key: valid, signature valid, registered, not revoked, not
    // expired, matches the registered record, 8/8 modules entitled.
    const verdict = await within(dialog).findByTestId('validate-verdict');
    expect(within(verdict).getByText('VALID')).toBeInTheDocument();
    expect(within(verdict).getByText('valid · no reason given')).toBeInTheDocument();
    const sigRow = within(verdict).getByText('Signature valid')
      .parentElement as HTMLElement;
    expect(within(sigRow).getByText('true')).toBeInTheDocument();
    const matchesRow = within(verdict).getByText('Matches registered record')
      .parentElement as HTMLElement;
    expect(within(matchesRow).getByText('true')).toBeInTheDocument();
    expect(
      within(verdict).getByText('8 of 8 catalog modules entitled'),
    ).toBeInTheDocument();
    expect(
      within(verdict).getByText(
        'sha256:900fa3099fe998ade41542eabc563bc15d3b8bc28e01b2e36af1db8cf68ed70a',
      ),
    ).toBeInTheDocument();
  });

  it('shows the signed file in both wire formats (JSON envelope, raw jwt text)', async () => {
    stubFetch(licenseRoutes());
    renderApp('/licensing');

    const detail = await inspect('LIC-5076-AEGIS-SEC-PROD');
    fireEvent.click(within(detail).getByRole('button', { name: 'Signed file' }));

    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByRole('heading', {
        name: 'Signed file - LIC-5076-AEGIS-SEC-PROD',
      }),
    ).toBeInTheDocument();
    // The json arm renders the captured envelope.
    expect(await within(dialog).findByText(/"license_data"/)).toBeInTheDocument();

    // The jwt arm renders the server's raw text/plain token verbatim.
    fireEvent.click(within(dialog).getByRole('button', { name: 'jwt' }));
    await waitFor(() =>
      expect(within(dialog).getByText(LIC_FILE_JWT_ACTIVE_TEXT)).toBeInTheDocument(),
    );
  });

  it('renders a section error verbatim without pretending the backend is down', async () => {
    stubFetch([
      licensesListRoute({ status: 500, body: { error: 'licensing registry exploded' } }),
      ...licenseRoutes(),
    ]);
    renderApp('/licensing');

    expect(
      await screen.findByText(
        'Licensing data unavailable: licensing registry exploded',
        {},
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Cannot reach the license server - live data is unavailable.'),
    ).not.toBeInTheDocument();
  });

  it('shows the honest not-connected state when the backend is down', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/licensing');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(licenseRoutes());
    const { container } = renderApp('/licensing');
    await screen.findAllByText('LIC-9395-AEGIS-SEC-PROD');
    await expectNoAxeViolations(container);
  });
});
