import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import { clusterRoute, settingsRoutes, stubFetch } from '../../test/fetchMock';
import { renderWithProviders } from '../../test/renderApp';
import { TOPOLOGY_CLUSTER_RESPONSE } from '../../test/topologyFixtures';
import { ClusterPostureSection } from './ClusterPostureSection';
import { SettingsPage } from './SettingsPage';

/**
 * HA / DC / DR cluster posture (screen 11, ADR-0015, the 11.5 flip) -
 * every assertion is the standing gate's own 6a block
 * (shots_tool/__verify_agent.mjs lines 346-391) held against the React
 * section exactly as the gate holds the page now that `/app/settings`
 * serves THIS component: the `data-role` hooks, the honest-state regexes
 * (summary separator U+00B7, byte-checked at the flip - an earlier test
 * transcription had U+2022 and the catalogue drifted with it), at least
 * one row in all three tables (an honest empty-state row counts) and no
 * `id=` anywhere under the section.
 *
 * Plus the one write the contract names: the failover control, with the
 * legacy page's verbatim confirm question and request body.
 *
 * Fixtures: `TOPOLOGY_CLUSTER_RESPONSE` is the verbatim pristine-node
 * capture the route default already reuses (role active, site dc, zero
 * peers/backups/replicas). The failover ANSWER is the contract shape
 * (settingsFixtures.ts) - no rig capture exists because the standing
 * rigs are never failovered. The one non-empty replica literal below is
 * the `ClusterReplicasNodes` contract shape too: a pristine rig never
 * syncs (the gate's own peer flow registers a placeholder that cannot
 * serve), so no capture exists - the honest empty path is what the rigs
 * actually produce and is asserted verbatim.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

/** Verbatim from the gate (line 373) - the separator is U+00B7. */
const GATE_SUMMARY_RE =
  /^\S+ \((dc|dr)\) · (active|passive) · \d+ peers? · \d+ healthy · audit \d+ · vault \d+ · sessions \d+ · backups \d+$/;

/** Verbatim legacy confirm question (code.html `clusterFailover()`). */
const CONFIRM_DEMOTE =
  'Demote THIS node to passive? Every product write outside /api/v1/cluster/* (authentication excepted) will be refused with 409 until it is promoted.';
const CONFIRM_PROMOTE =
  'Promote THIS node to active? It will take over serving product writes.';

function findFailoverPost(fetchMock: ReturnType<typeof stubFetch>) {
  const call = fetchMock.mock.calls.find(
    ([, init]) => (init as RequestInit | undefined)?.method === 'POST',
  );
  expect(call, 'expected a POST /cluster/failover call').toBeTruthy();
  return {
    url: String(call?.[0]),
    body: JSON.parse(String((call?.[1] as RequestInit | undefined)?.body)),
  };
}

function text(selector: string): string {
  return (document.querySelector(selector)?.textContent ?? '').trim();
}

describe('Cluster posture section (screen 11, ADR-0015) - 11.5 flip', () => {
  it('carries the gate 6a read-surface: hooks, honest regexes, rows, no ids', async () => {
    stubFetch(settingsRoutes());
    const { container } = renderWithProviders(<SettingsPage />);

    const section = await screen.findByTestId('settings-cluster');
    expect(section.getAttribute('data-role')).toBe('cluster-section');

    await waitFor(() =>
      expect(text('[data-role="cluster-summary"]')).toMatch(GATE_SUMMARY_RE),
    );
    await waitFor(() =>
      expect(text('[data-role="cluster-role"]')).toMatch(/^(active|passive)$/),
    );
    await waitFor(() =>
      expect(text('[data-role="cluster-failover-label"]')).toMatch(/^(Promote|Demote)$/),
    );

    // Tile values, exactly the gate's arms (line 378-387): self is the
    // node name (any non-whitespace), the three counters are pure digits.
    const tileSelf = text('[data-role="cluster-tile-self"]');
    expect(/^\d+$/.test(tileSelf.split(' · ')[0] || '') || /\S/.test(tileSelf)).toBe(true);
    expect(text('[data-role="cluster-tile-peers"]')).toMatch(/^\d+$/);
    expect(text('[data-role="cluster-tile-replication"]')).toMatch(/^\d+$/);
    expect(text('[data-role="cluster-tile-backups"]')).toMatch(/^\d+$/);

    // All three tables keep at least one row - on the pristine capture
    // the replica and backup tables are honest empty-STATE rows.
    for (const role of ['cluster-rows', 'cluster-replica-rows', 'cluster-backup-rows']) {
      expect(
        document.querySelectorAll(`[data-role="${role}"] tr`).length,
      ).toBeGreaterThanOrEqual(1);
    }

    // The gate's noIds arm: nothing under the section may carry an id.
    expect(section.querySelectorAll('[id]').length).toBe(0);

    await expectNoAxeViolations(container);
  });

  it('failover: the Demote control really POSTs the flip (legacy verbatim)', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<ClusterPostureSection />);

    const button = await screen.findByRole('button', { name: /Demote/ });
    await waitFor(() => expect(text('[data-role="cluster-role"]')).toBe('active'));
    fireEvent.click(button);

    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledWith(CONFIRM_DEMOTE);
    await waitFor(() => {
      const post = findFailoverPost(fetchMock);
      expect(post.url).toContain('/api/v1/cluster/failover');
      expect(post.body).toEqual({ action: 'demote', reason: 'platform settings ui' });
    });

    // Honest receipt - the legacy toast's own composition.
    await screen.findByText('pam-node-1: active → passive - /health now reports passive.');
  });

  it('failover: cancelling the confirm sends nothing', async () => {
    const fetchMock = stubFetch(settingsRoutes());
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    renderWithProviders(<ClusterPostureSection />);

    fireEvent.click(await screen.findByRole('button', { name: /Demote/ }));

    expect(
      fetchMock.mock.calls.some(
        ([, init]) => (init as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(false);
    expect(screen.queryByText(/reports passive/)).toBeNull();
  });

  it('a passive node offers Promote with the legacy promote question', async () => {
    const fetchMock = stubFetch([
      clusterRoute({
        ...TOPOLOGY_CLUSTER_RESPONSE,
        self: { ...TOPOLOGY_CLUSTER_RESPONSE.self, role: 'passive' },
      }),
      ...settingsRoutes(),
    ]);
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<ClusterPostureSection />);

    const button = await screen.findByRole('button', { name: /Promote/ });
    await waitFor(() => expect(text('[data-role="cluster-role"]')).toBe('passive'));

    fireEvent.click(button);
    expect(confirm).toHaveBeenCalledWith(CONFIRM_PROMOTE);
    await waitFor(() => {
      expect(findFailoverPost(fetchMock).body).toEqual({
        action: 'promote',
        reason: 'platform settings ui',
      });
    });
  });

  it('replica posture: a pulled peer renders the verbatim legacy cells', async () => {
    // Contract shape per `ClusterReplicasNodes` (no capture exists - a
    // pristine rig never completes a sync; see the file header).
    stubFetch([
      clusterRoute({
        ...TOPOLOGY_CLUSTER_RESPONSE,
        replication: {
          nodes: {
            'gate-peer-6a': {
              audit: { records: 3, unverified: 0, verified: 3 },
              last_synced_at: null,
              sessions: 2,
              vault: { decryptable_here: 1, secrets: 1 },
            },
          },
          totals: { audit: 3, sessions: 2, vault: 1 },
        },
      }),
      ...settingsRoutes(),
    ]);
    renderWithProviders(<ClusterPostureSection />);

    // Wait for the DATA row - the loading/empty state is also one <tr>.
    await waitFor(() =>
      expect(
        document.querySelector('[data-role="cluster-replica-rows"]')?.textContent,
      ).toContain('gate-peer-6a'),
    );
    const body = document.querySelector(
      '[data-role="cluster-replica-rows"]',
    ) as HTMLElement;
    expect(body.querySelectorAll('tr').length).toBe(1);
    expect(body.textContent).toContain('3/3 verified');
    expect(body.textContent).toContain('1/1 openable here');
    // The replication tile counts the same held audit rows.
    await waitFor(() => expect(text('[data-role="cluster-tile-replication"]')).toBe('3'));
  });

  it('pristine node: the replica table keeps its honest empty row (gate >= 1)', async () => {
    stubFetch(settingsRoutes());
    renderWithProviders(<ClusterPostureSection />);

    // Settled = the overview answered (role badge knows active/passive);
    // only then does the empty row mean "no replicas", not "still loading".
    await waitFor(() =>
      expect(text('[data-role="cluster-failover-label"]')).toBe('Demote'),
    );
    const rows = document.querySelectorAll('[data-role="cluster-replica-rows"] tr');
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toBe(
      'No replicas pulled yet - run a sync against a registered peer.',
    );
  });

  it('the unverified arm of a replica row is flagged, not hidden', async () => {
    stubFetch([
      clusterRoute({
        ...TOPOLOGY_CLUSTER_RESPONSE,
        replication: {
          nodes: {
            'gate-peer-6a': {
              audit: { records: 5, unverified: 2, verified: 3 },
              last_synced_at: null,
              sessions: 0,
              vault: { decryptable_here: 0, secrets: 4 },
            },
          },
          totals: { audit: 5, sessions: 0, vault: 4 },
        },
      }),
      ...settingsRoutes(),
    ]);
    renderWithProviders(<ClusterPostureSection />);

    await waitFor(() =>
      expect(
        document.querySelector('[data-role="cluster-replica-rows"]')?.textContent,
      ).toContain('3/5 verified · 2 unverified'),
    );
    const body = document.querySelector(
      '[data-role="cluster-replica-rows"]',
    ) as HTMLElement;
    expect(body.querySelectorAll('tr').length).toBe(1);
    expect(body.textContent).toContain('gate-peer-6a');
    expect(body.textContent).toContain('0/4 openable here');
  });
});
