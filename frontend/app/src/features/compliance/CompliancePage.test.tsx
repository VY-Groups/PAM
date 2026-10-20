import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  AUDIT_VERIFY_BROKEN_RESPONSE,
  COMPLIANCE_FACTS,
  EVENTS_EMPTY_RESPONSE,
  WHOAMI_OPEN_BODY,
  auditExportRoute,
  auditStatsRoute,
  auditVerifyRoute,
  complianceEventsRoute,
  complianceRoutes,
  healthRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';
import { buildAuditCsv, parseNdjson } from './csv';

/**
 * Compliance & SOC2 (F4 screen 6): every assertion runs against the
 * verbatim rig captures in complianceFixtures.ts - no invented values.
 * The tests prove the digest KPI quad and the real chain head, the
 * on-demand verify walk (idle -> intact verdict / broken chain with the
 * server's own reason / failure verbatim), the measured connector chips,
 * the source-filtered unified trail with chain positions and hashes, the
 * full-ledger CSV export (record count, columns, blob), and the honest
 * section-error / not-connected / empty states.
 */

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/** The trail row containing `action` (span -> line -> row, as built). */
async function trailRow(action: string): Promise<HTMLElement> {
  const el = await screen.findByText(action);
  return el.parentElement?.parentElement as HTMLElement;
}

const HEAD12 = `${COMPLIANCE_FACTS.headHash.slice(0, 12)}…`;

describe('Compliance & SOC2 (F4 screen 6)', () => {
  it('renders the digest KPI quad from the real ledger stats', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');
    expect(
      await screen.findByRole('heading', {
        name: /Compliance & Continuous Audit Center/,
      }),
    ).toBeInTheDocument();

    const records = await kpiCard('LEDGER RECORDS');
    expect(within(records).getByText(String(COMPLIANCE_FACTS.total))).toBeInTheDocument();
    expect(within(records).getByText(/2026/)).toBeInTheDocument(); // window footer

    const depth = await kpiCard('CHAIN POSITION');
    expect(within(depth).getByText(String(COMPLIANCE_FACTS.lastSeq))).toBeInTheDocument();
    expect(within(depth).getByText(`head ${HEAD12}`)).toBeInTheDocument();

    const sources = await kpiCard('SOURCES REPORTING');
    expect(within(sources).getByText('12')).toBeInTheDocument(); // 12 of 21 carry records
    expect(
      within(sources).getByText('of 21 ledger sources carry records'),
    ).toBeInTheDocument();

    const triggers = await kpiCard('APPEND-ONLY TRIGGERS');
    expect(within(triggers).getByText('installed')).toBeInTheDocument();
    expect(
      within(triggers).getByText('append-only PostgreSQL enforcement'),
    ).toBeInTheDocument();
  });

  it('digest card shows the chain head, seq, window and per-source chips', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');

    expect(await screen.findByText(COMPLIANCE_FACTS.headHash)).toBeInTheDocument();
    expect(screen.getByText('seq 40')).toBeInTheDocument();
    expect(screen.getByText(/window:/)).toBeInTheDocument();

    // The 21-key by_source map, zero-filled: a reporting source and an
    // honest zero both render from the same capture.
    const group = screen.getByRole('group', { name: 'Ledger records by source' });
    expect(group.querySelectorAll('span')).toHaveLength(21);
    expect(within(group).getByText('gateway 11')).toBeInTheDocument();
    expect(within(group).getByText('sso 0')).toBeInTheDocument();

    expect(screen.getByText(/chain walk, not a Merkle proof/)).toBeInTheDocument();
  });

  it('verify walk stays honest until run, then reports the intact verdict', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');

    expect(await screen.findByText(/Not verified this session/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Verify hash chain' }));

    expect(await screen.findByTestId('verify-result')).toHaveTextContent(
      `Hash chain intact: ${COMPLIANCE_FACTS.verifyChecked}/${COMPLIANCE_FACTS.total} records verified, head ${HEAD12}`,
    );
  });

  it('broken chain renders the server reason as an alert', async () => {
    stubFetch([auditVerifyRoute(AUDIT_VERIFY_BROKEN_RESPONSE), ...complianceRoutes()]);
    renderApp('/compliance');
    await screen.findByText(COMPLIANCE_FACTS.headHash);

    fireEvent.click(screen.getByRole('button', { name: 'Verify hash chain' }));
    const verdict = await screen.findByText(
      'CHAIN BROKEN at seq 8: hash mismatch at seq 8',
    );
    expect(verdict).toHaveAttribute('role', 'alert');
  });

  it('verify failure surfaces the server message verbatim', async () => {
    stubFetch([
      auditVerifyRoute({ status: 500, body: { error: 'walk exploded' } }),
      ...complianceRoutes(),
    ]);
    renderApp('/compliance');
    await screen.findByText(COMPLIANCE_FACTS.headHash);

    fireEvent.click(screen.getByRole('button', { name: 'Verify hash chain' }));
    const failure = await screen.findByText('Verify failed - walk exploded');
    expect(failure).toHaveAttribute('role', 'alert');
  });

  it('connector chips report measured state, never placeholders', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');

    expect(
      await screen.findByText(
        'not connected - set siem.webhook_url, a signing secret and enabled=true',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText('not configured - the mfa band stays advisory'),
    ).toBeInTheDocument();
    expect(screen.getByText('not connected - set itsm.base_url')).toBeInTheDocument();
    expect(
      screen.getByText('not connected - set ldap.server and ldap.user_bind_template'),
    ).toBeInTheDocument();
    expect(screen.getByText('last push: never')).toBeInTheDocument();
    // siem chip = the contract's own state enum; itsm/ldap chips echo it.
    expect(screen.getAllByText('not connected')).toHaveLength(3);
  });

  it('trail renders newest first with chain position, source chip and hash', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');

    expect(await screen.findByText('showing 40 of 40 records')).toBeInTheDocument();
    const row = await trailRow('node-removed');
    expect(within(row).getByText('#40')).toBeInTheDocument();
    expect(within(row).getByText('cluster')).toBeInTheDocument();
    expect(within(row).getByText('gate-peer-6a')).toBeInTheDocument();
    expect(within(row).getByTitle(COMPLIANCE_FACTS.headHash)).toBeInTheDocument();
    expect(within(row).getByText(/^gate · /)).toBeInTheDocument();
    expect(
      within(row).getByText((content) => content.includes('role=passive')),
    ).toBeInTheDocument();
  });

  it('trail filter group carries the contract source enum', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');

    const group = await screen.findByRole('group', {
      name: 'Filter the trail by source',
    });
    // all + the eleven filterable sources from the contract enum.
    expect(within(group).getAllByRole('button')).toHaveLength(12);
  });

  it('source filter chips reload the trail from the server', async () => {
    stubFetch(complianceRoutes());
    renderApp('/compliance');
    await screen.findByText('showing 40 of 40 records');

    expect(screen.getByRole('button', { name: 'all' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    fireEvent.click(screen.getByRole('button', { name: 'vault' }));

    expect(await screen.findByText('showing 4 of 4 records')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'vault' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByRole('button', { name: 'all' })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
    expect(screen.getByText('rotated')).toBeInTheDocument();
    expect(screen.getAllByText('gate-8a.lab root')).toHaveLength(4);
  });

  it('trail keeps the honest empty state', async () => {
    stubFetch([
      complianceEventsRoute({ all: EVENTS_EMPTY_RESPONSE }),
      ...complianceRoutes(),
    ]);
    renderApp('/compliance');

    expect(await screen.findByText('showing 0 of 0 records')).toBeInTheDocument();
    expect(
      await screen.findByText('No entries yet - the selected audit trail is empty.'),
    ).toBeInTheDocument();
  });

  it('export downloads the whole ledger as CSV', async () => {
    stubFetch(complianceRoutes());
    const exportedBlobs: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      exportedBlobs.push(blob);
      return 'blob:vy-pam-audit';
    });
    const revokeObjectURL = vi.fn();
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = revokeObjectURL;

    try {
      renderApp('/compliance');
      await screen.findByText(COMPLIANCE_FACTS.headHash);

      fireEvent.click(screen.getByRole('button', { name: 'Download audit trail (CSV)' }));
      expect(
        await screen.findByText(`Exported ${COMPLIANCE_FACTS.exportLines} records as CSV`),
      ).toBeInTheDocument();

      expect(createObjectURL).toHaveBeenCalledTimes(1);
      expect(exportedBlobs).toHaveLength(1);
      const lines = (await exportedBlobs[0].text()).split('\n');
      expect(lines).toHaveLength(COMPLIANCE_FACTS.exportLines + 1);
      expect(lines[0]).toBe(
        'seq,created_at,source,action,actor,subject,detail,event_ref,prev_hash,event_hash',
      );
      expect(lines[1]).toContain('auth.emergency.seeded,system,emergency-admin');
      expect(lines[COMPLIANCE_FACTS.exportLines]).toContain(
        'node-removed,gate,gate-peer-6a',
      );
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:vy-pam-audit');
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
    }
  });

  it('export failure surfaces the server message verbatim', async () => {
    stubFetch([auditExportRoute('boom', 500), ...complianceRoutes()]);
    renderApp('/compliance');
    await screen.findByText(COMPLIANCE_FACTS.headHash);

    fireEvent.click(screen.getByRole('button', { name: 'Download audit trail (CSV)' }));
    const failure = await screen.findByText('Request failed (500)');
    expect(failure).toHaveAttribute('role', 'alert');
  });

  it('a section error renders verbatim while the rest stays honest', async () => {
    stubFetch([
      auditStatsRoute({ status: 500, body: { error: 'digest exploded' } }),
      ...complianceRoutes(),
    ]);
    renderApp('/compliance');

    const alert = await screen.findByText(
      'Section unavailable: digest exploded',
      {},
      { timeout: 8000 },
    );
    expect(alert).toHaveAttribute('role', 'alert');

    // The stats-backed KPIs fall back to the honest em-dash...
    const records = await kpiCard('LEDGER RECORDS');
    expect(within(records).getByText('—')).toBeInTheDocument();
    // ...while the independent sections keep answering.
    expect(await screen.findByText('showing 40 of 40 records')).toBeInTheDocument();
  });

  it('transport failure shows the shared banner and not-connected chips', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/compliance');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect((await screen.findAllByText('not connected')).length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText('Compliance & Continuous Audit Center')).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    stubFetch(complianceRoutes());
    const { container } = renderApp('/compliance');
    await screen.findByText(COMPLIANCE_FACTS.headHash);
    await expectNoAxeViolations(container);
  });
});

describe('ledger CSV helpers', () => {
  it('quotes fields containing commas and stringifies detail', () => {
    const csv = buildAuditCsv([
      {
        seq: 1,
        created_at: '2026-10-14T20:35:37.513000',
        source: 'vault',
        action: 'rotated',
        actor: 'gate',
        subject: 'gate-8a.lab root, db',
        detail: { note: 'a, b' },
        event_ref: 'vault:1',
        prev_hash: '0'.repeat(64),
        event_hash: 'f'.repeat(64),
      },
    ]);
    const [header, row] = csv.split('\n');
    expect(header).toBe(
      'seq,created_at,source,action,actor,subject,detail,event_ref,prev_hash,event_hash',
    );
    expect(row).toBe(
      '1,2026-10-14T20:35:37.513000,vault,rotated,gate,"gate-8a.lab root, db",' +
        '"{""note"":""a, b""}",vault:1,' +
        '0'.repeat(64) +
        ',' +
        'f'.repeat(64),
    );
  });

  it('parseNdjson reads one record per line and skips blank lines', () => {
    const records = parseNdjson(
      '{"seq":1,"source":"auth"}\n\n{"seq":2,"source":"vault"}\n',
    );
    expect(records).toHaveLength(2);
    expect(records[1].source).toBe('vault');
  });

  it('parseNdjson throws on a malformed line (never a silent empty export)', () => {
    expect(() => parseNdjson('{"seq":1}\nnot json\n')).toThrow();
  });
});
