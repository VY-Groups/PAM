import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../../test/axe';
import {
  EVALUATE_BLOCK_RESPONSE,
  INCIDENTS_CLOSED_RESPONSE,
  RULE_DELETE_RESPONSE,
  RULE_UPDATE_RESPONSE,
  WHOAMI_OPEN_BODY,
  healthRoute,
  policyApprovalsRoute,
  policyEvaluateRoute,
  policyIncidentsRoute,
  policyRuleDetailRoute,
  policyRoutes,
  policyRulesRoute,
  riskAnomaliesRoute,
  riskBaselinesRoute,
  riskEvaluationsRoute,
  stubFetch,
  whoamiRoute,
} from '../../test/fetchMock';
import { renderApp } from '../../test/renderApp';

/**
 * Policy & Zero Trust (F4 screen 5): every assertion runs against the
 * verbatim rig captures in policyFixtures.ts - no invented values. The
 * tests prove the KPI quad and engine posture, the three-tab catalog
 * (rules / approvals / incidents) with its evaluation-order lines, the
 * contract writes (create / edit / delete rule, approve / deny a held
 * command, close an incident) with the X-Actor header, the real dry-run
 * simulator (default-allow and blocked-and-terminate branches plus the
 * zod guard), the section-7 risk scorer with its eight-component
 * breakdown, the section-11 UEBA baselines and the honest empty /
 * section-error / backend-down states.
 */

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/** Relative-age shapes the legacy console used (`formatRelative`). */
const REL = /^(just now|\d+[mhd] ago)$/;

/** The recorded write call for `suffix` with the given HTTP method. */
function callWrite(fetchMock: ReturnType<typeof vi.fn>, suffix: string, method: string) {
  return fetchMock.mock.calls.find(
    ([input, init]) =>
      String(input).endsWith(suffix) &&
      ((init as RequestInit | undefined)?.method ?? 'GET') === method,
  );
}

/**
 * Assert a write reached the contract: the signed-in principal as
 * `X-Actor`, and - when given - the exact JSON body the endpoint accepts.
 */
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

/** Like `expectWrite` for the writes that carry no `X-Actor` (dry-run, DELETE). */
function expectAnonymousWrite(
  fetchMock: ReturnType<typeof vi.fn>,
  suffix: string,
  method: string,
  body?: unknown,
): void {
  const call = callWrite(fetchMock, suffix, method);
  expect(call).toBeDefined();
  const init = call?.[1] as RequestInit | undefined;
  if (body !== undefined) {
    expect(JSON.parse(String(init?.body))).toEqual(body);
  }
}

/** Switch the design-system Tabs (Radix activates on pointer-down). */
async function selectTab(name: string) {
  fireEvent.mouseDown(await screen.findByRole('tab', { name }));
}

/** The KpiCard containing `label` (label -> row -> card, as built). */
async function kpiCard(label: string): Promise<HTMLElement> {
  const el = await screen.findByText(label);
  return el.parentElement?.parentElement as HTMLElement;
}

/* ---- empty-capture route helpers (honest zero rows, same list shapes) ---- */

function emptyRules() {
  return policyRulesRoute({
    status: 200,
    body: { items: [], limit: 200, offset: 0, total: 0 },
  });
}
function emptyApprovals() {
  return policyApprovalsRoute({
    status: 200,
    body: { items: [], limit: 20, offset: 0, total: 0 },
  });
}
function emptyIncidents() {
  return policyIncidentsRoute({
    status: 200,
    body: { items: [], limit: 200, offset: 0, total: 0 },
  });
}
function emptyEvaluations() {
  return riskEvaluationsRoute({
    status: 200,
    body: { evaluations: [], limit: 8, offset: 0, total: 0 },
  });
}
function emptyBaselines() {
  return riskBaselinesRoute({ status: 200, body: { baselines: [] } });
}
function emptyAnomalies() {
  return riskAnomaliesRoute({ status: 200, body: { anomalies: [], total: 0 } });
}

describe('Policy & Zero Trust (F4 screen 5)', () => {
  it('renders the legacy header, KPI quad, posture and policy line from live stats', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'Zero-Trust Access Policies & Rule Engine',
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Define deterministic granular session controls, command-level blacklists, multi-party quorum triggers, and context-aware JIT elevation constraints.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('POLICY ENGINE CORE')).toBeInTheDocument();
    expect(await screen.findByText('15 rules · e991b1bf8bf4')).toBeInTheDocument();

    expect(screen.getByRole('button', { name: 'Dry Run Simulation' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Export Policy (JSON)' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Create New Policy Rule' }),
    ).toBeInTheDocument();

    // KPI quad - real stats values with the legacy folded footers.
    const policies = await kpiCard('Active Policies');
    expect(within(policies).getByText('15')).toBeInTheDocument();
    expect(within(policies).getByText('15 of 15 rules enabled')).toBeInTheDocument();

    const blocks = await kpiCard('Command Blocks Today');
    expect(within(blocks).getByText('1')).toBeInTheDocument();
    expect(
      within(blocks).getByText('High-risk command attempts stopped'),
    ).toBeInTheDocument();

    const approvals = await kpiCard('Command Approvals');
    expect(within(approvals).getByText('1')).toBeInTheDocument();
    expect(
      within(approvals).getByText('Approved · 0 awaiting decision'),
    ).toBeInTheDocument();

    const hash = await kpiCard('Engine Hash & Sync');
    expect(within(hash).getByText('e991b1bf8bf4')).toBeInTheDocument();
    expect(
      within(hash).getByText('sha256(policy) • block 9 · approval 3 · allow 3'),
    ).toBeInTheDocument();
    expect(
      within(hash).getByText(/Updated (?:just now|\d+[mhd] ago) by admin/),
    ).toBeInTheDocument();

    // Right rail posture + audit teaser - all real counts.
    const posture = screen.getByText('Policy Rules Enabled').parentElement
      ?.parentElement as HTMLElement;
    expect(within(posture).getByText('15 / 15')).toBeInTheDocument();
    expect(within(posture).getByText('Commands recorded')).toBeInTheDocument();
    expect(within(posture).getByText('5')).toBeInTheDocument();
    expect(within(posture).getByText('Match order')).toBeInTheDocument();
    expect(within(posture).getByText('block → approval → allow')).toBeInTheDocument();

    expect(screen.getByText('Policy Incident Trail')).toBeInTheDocument();
    expect(
      screen.getByText('1 incident on record · 5 commands recorded'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Show incident trail' })).toBeInTheDocument();
  });

  it('rules tab: filter line, evaluation order, and the real rule cards', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    expect(
      await screen.findByRole('tab', { name: 'Policy Rules (15)' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Approvals (0)' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'SOC Incidents (0)' })).toBeInTheDocument();

    expect(await screen.findByText('15 of 15 rules')).toBeInTheDocument();
    expect(
      screen.getByText('match: case-insensitive substring · default allow'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('evaluation priority: block → approval → allow'),
    ).toBeInTheDocument();

    const card = (
      await screen.findByRole('heading', {
        name: 'Production database drop kills the session',
      })
    ).closest('div') as HTMLElement;
    expect(within(card).getByText('Rule #15')).toBeInTheDocument();
    expect(within(card).getAllByText('DROP DATABASE')).toHaveLength(2); // chip + code box
    expect(within(card).getByText('ENFORCED')).toBeInTheDocument();
    expect(within(card).getByText('BLOCK · 0 matches')).toBeInTheDocument();
    expect(within(card).getByText('target: prod-*')).toBeInTheDocument();
    expect(within(card).getByText('terminates session')).toBeInTheDocument();
    expect(within(card).getByText('Action On Trigger')).toBeInTheDocument();
    expect(within(card).getByText('command refused, kept as evidence')).toBeInTheDocument();
    expect(within(card).getByText('Match Pattern')).toBeInTheDocument();
    expect(within(card).getByText('substring, case-insensitive')).toBeInTheDocument();
    expect(
      within(card).getByText(
        /Updated (?:just now|\d+[mhd] ago) by admin · Architecture 9 context-aware example/,
      ),
    ).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Delete' })).toBeInTheDocument();

    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(15);
  });

  it('approvals tab: the two held commands with session and event evidence', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    await selectTab('Approvals (0)');
    expect(
      await screen.findByText('2 held commands awaiting a decision'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('resolve: approve releases · deny records the refusal'),
    ).toBeInTheDocument();

    const two = (await screen.findByRole('heading', { name: 'vypam-held probe two' }))
      .parentElement as HTMLElement;
    expect(within(two).getByText('Seq #3')).toBeInTheDocument();
    expect(within(two).getByText('sess-789057ea')).toBeInTheDocument();
    expect(within(two).getByText('fx-policy-fixture-7:22')).toBeInTheDocument();
    expect(within(two).getByText('HELD FOR APPROVAL')).toBeInTheDocument();
    expect(
      within(two).getByText(
        /held (?:just now|\d+[mhd] ago) by open · ssh · command held with allowed=false/,
      ),
    ).toBeInTheDocument();
    expect(within(two).getByRole('button', { name: 'Approve' })).toBeInTheDocument();
    expect(within(two).getByRole('button', { name: 'Deny' })).toBeInTheDocument();

    expect(
      screen.getByRole('heading', { name: 'vypam-held probe one' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Seq #2')).toBeInTheDocument();
  });

  it('approve posts the resolution row with the signed-in principal', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    await selectTab('Approvals (0)');
    const card = (await screen.findByRole('heading', { name: 'vypam-held probe one' }))
      .parentElement as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: 'Approve' }));

    expect(
      await screen.findByText('Command approved - resolution recorded (append-only)'),
    ).toBeInTheDocument();
    expectWrite(fetchMock, '/sessions/15/events/2/approve', 'POST');
  });

  it('deny records the refusal on the append-only event trail', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    await selectTab('Approvals (0)');
    const card = (await screen.findByRole('heading', { name: 'vypam-held probe two' }))
      .parentElement as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: 'Deny' }));

    expect(
      await screen.findByText('Command denied - resolution recorded (append-only)'),
    ).toBeInTheDocument();
    expectWrite(fetchMock, '/sessions/15/events/3/deny', 'POST');
  });

  it('incidents tab: evidence, rule snapshot, and the close write', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    await selectTab('SOC Incidents (0)');
    expect(await screen.findByText('1 escalation incidents')).toBeInTheDocument();
    expect(
      screen.getByText('evidence preserved with the blocked command'),
    ).toBeInTheDocument();

    const card = (await screen.findByRole('heading', { name: 'vypam-blocked probe' }))
      .parentElement as HTMLElement;
    expect(within(card).getByText('inc-23e83e42')).toBeInTheDocument();
    expect(within(card).getByText('vypam-blocked')).toBeInTheDocument();
    expect(within(card).getByText('OPEN')).toBeInTheDocument();
    expect(within(card).getByText('escalated · session ended')).toBeInTheDocument();
    expect(within(card).getByText('Evidence')).toBeInTheDocument();
    expect(within(card).getByText('session #15 seq 6')).toBeInTheDocument();
    expect(within(card).getByText('fx-policy-fixture-7:22')).toBeInTheDocument();
    expect(within(card).getByText('Rule Snapshot')).toBeInTheDocument();
    expect(within(card).getByText('Fixture blocked-command probe')).toBeInTheDocument();
    expect(
      within(card).getByText(/raised (?:just now|\d+[mhd] ago) by open/),
    ).toBeInTheDocument();

    fireEvent.click(within(card).getByRole('button', { name: 'Close incident' }));
    expect(await screen.findByText('Incident closed')).toBeInTheDocument();
    expectWrite(fetchMock, '/command-control/incidents/1/close', 'POST', {});
  });

  it('a closed incident renders the reviewed state without a close action', async () => {
    stubFetch([policyIncidentsRoute(INCIDENTS_CLOSED_RESPONSE), ...policyRoutes()]);
    renderApp('/policy');

    await selectTab('SOC Incidents (0)');
    const card = (await screen.findByRole('heading', { name: 'vypam-blocked probe' }))
      .parentElement as HTMLElement;
    expect(within(card).getByText('CLOSED')).toBeInTheDocument();
    expect(within(card).getByText('reviewed')).toBeInTheDocument();
    expect(within(card).getByText('Reviewed')).toBeInTheDocument();
    expect(
      within(card).getByText(/closed (?:just now|\d+[mhd] ago) by policy-fixture-approver/),
    ).toBeInTheDocument();
    expect(
      within(card).queryByRole('button', { name: 'Close incident' }),
    ).not.toBeInTheDocument();
  });

  it('the incident-trail teaser jumps to the incidents tab', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    fireEvent.click(await screen.findByRole('button', { name: 'Show incident trail' }));

    const incidentsTab = await screen.findByRole('tab', { name: 'SOC Incidents (0)' });
    expect(incidentsTab).toHaveAttribute('aria-selected', 'true');
    expect(
      await screen.findByRole('heading', { name: 'vypam-blocked probe' }),
    ).toBeInTheDocument();
  });

  it('dry-run default-allow: posts the payload and renders the engine decision', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    expect(await screen.findByText('NOT YET EVALUATED')).toBeInTheDocument();
    expect(screen.getByText('rule —')).toBeInTheDocument();
    expect(
      screen.getByText('Evaluate a payload to see the live policy decision.'),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Test Command Payload'), {
      target: { value: 'ls -la /var/log' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate Decision Pipeline' }));

    expect(await screen.findByText('ALLOWED')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/command-control/evaluate', 'POST', {
      command: 'ls -la /var/log',
      target: '',
    });
    expect(screen.getByText('no rule matched (default allow)')).toBeInTheDocument();
    expect(
      screen.getByText(
        'No rule matched this command - the engine defaults to allow (it flags known-dangerous commands, it is not a whitelist).',
      ),
    ).toBeInTheDocument();
    expect(screen.getByText('(any)')).toBeInTheDocument();
    expect(screen.getByText('allow (default)')).toBeInTheDocument();
    expect(screen.getByText('none')).toBeInTheDocument();
    expect(screen.getByText('ls -la /var/log')).toBeInTheDocument();
  });

  it('dry-run blocked branch: terminate flag, matched rule and escalation row', async () => {
    const fetchMock = stubFetch([
      policyEvaluateRoute(EVALUATE_BLOCK_RESPONSE),
      ...policyRoutes(),
    ]);
    renderApp('/policy');

    fireEvent.change(await screen.findByLabelText('Test Command Payload'), {
      target: { value: 'vypam-blocked probe' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate Decision Pipeline' }));

    expect(await screen.findByText('BLOCKED + TERMINATE SESSION')).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/command-control/evaluate', 'POST', {
      command: 'vypam-blocked probe',
      target: '',
    });
    expect(screen.getByText('rule #17 vypam-blocked')).toBeInTheDocument();
    expect(screen.getByText('Fixture blocked-command probe')).toBeInTheDocument();
    expect(screen.getByText(/block for any target/)).toBeInTheDocument();
    expect(screen.getByText('ends the session, raises an incident')).toBeInTheDocument();
  });

  it('dry-run guard: an empty payload never posts', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    fireEvent.click(
      await screen.findByRole('button', { name: 'Evaluate Decision Pipeline' }),
    );

    expect(await screen.findByText('Type a command line to evaluate')).toBeInTheDocument();
    const evaluateCalls = fetchMock.mock.calls.filter(
      ([input, init]) =>
        String(input).includes('/command-control/evaluate') &&
        ((init as RequestInit | undefined)?.method ?? 'GET') === 'POST',
    );
    expect(evaluateCalls).toHaveLength(0);
  });

  it('create rule: zod guard first, then the full contract payload and server id', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    fireEvent.click(await screen.findByRole('button', { name: 'Create New Policy Rule' }));
    const dialog = await screen.findByRole('dialog');

    // Client-side UX guard (ADR-0006): empty fields never reach the server.
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }));
    expect(
      await within(dialog).findByText(
        'Check the highlighted fields - limits mirror the contract.',
      ),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(
        ([input, init]) =>
          String(input).endsWith('/command-control/rules') &&
          ((init as RequestInit | undefined)?.method ?? 'GET') === 'POST',
      ),
    ).toHaveLength(0);

    fireEvent.change(within(dialog).getByLabelText('Name'), {
      target: { value: 'Fixture held-command probe' },
    });
    fireEvent.change(
      within(dialog).getByLabelText('Pattern (case-insensitive substring)'),
      {
        target: { value: 'vypam-held' },
      },
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }));

    expect(await screen.findByText('Rule #16 created')).toBeInTheDocument();
    expectWrite(fetchMock, '/command-control/rules', 'POST', {
      name: 'Fixture held-command probe',
      pattern: 'vypam-held',
      action: 'allow',
      target_pattern: '',
      description: '',
      terminate_on_match: false,
      enabled: true,
    });
  });

  it('edit rule: dialog prefills from the live rule and PUTs the payload', async () => {
    const fetchMock = stubFetch([
      policyRuleDetailRoute(15, { put: RULE_UPDATE_RESPONSE }),
      ...policyRoutes(),
    ]);
    renderApp('/policy');

    const card = (
      await screen.findByRole('heading', {
        name: 'Production database drop kills the session',
      })
    ).closest('div') as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: 'Edit' }));

    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByRole('heading', { name: 'Edit Policy Rule' }),
    ).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Name')).toHaveValue(
      'Production database drop kills the session',
    );
    expect(
      within(dialog).getByLabelText('Pattern (case-insensitive substring)'),
    ).toHaveValue('DROP DATABASE');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));

    expect(await screen.findByText('Rule #15 updated')).toBeInTheDocument();
    expectWrite(fetchMock, '/command-control/rules/15', 'PUT', {
      name: 'Production database drop kills the session',
      pattern: 'DROP DATABASE',
      action: 'block',
      target_pattern: 'prod-*',
      description:
        'Architecture 9 context-aware example: production target -> block, terminate the session, raise the incident, preserve the evidence',
      terminate_on_match: true,
      enabled: true,
    });
  });

  it('delete rule posts DELETE and reports the id on the status line', async () => {
    const fetchMock = stubFetch([
      policyRuleDetailRoute(15, { del: RULE_DELETE_RESPONSE }),
      ...policyRoutes(),
    ]);
    renderApp('/policy');

    const card = (
      await screen.findByRole('heading', {
        name: 'Production database drop kills the session',
      })
    ).closest('div') as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: 'Delete' }));

    expect(
      await screen.findByText('Rule #15 deleted - recorded events keep their rule_id'),
    ).toBeInTheDocument();
    expectAnonymousWrite(fetchMock, '/command-control/rules/15', 'DELETE');
  });

  it('risk scorer: zod guard, then the real evaluation and component breakdown', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    fireEvent.click(await screen.findByRole('button', { name: 'Score Request' }));
    expect(
      await screen.findByText('Check the highlighted fields - limits mirror the contract.'),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.filter(([input]) => String(input).includes('/risk/evaluate')),
    ).toHaveLength(0);

    fireEvent.change(await screen.findByLabelText('Subject (required)'), {
      target: { value: 'fixture-principal' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Score Request' }));

    expect(await screen.findByText('Scored 15/100 - low (allow)')).toBeInTheDocument();
    expectWrite(fetchMock, '/risk/evaluate', 'POST', { subject: 'fixture-principal' });

    const result = screen.getByText('Evaluation').parentElement
      ?.parentElement as HTMLElement;
    expect(within(result).getByText('low')).toBeInTheDocument();
    expect(within(result).getByText('15 / 100')).toBeInTheDocument();
    expect(within(result).getByText('advisory · manual')).toBeInTheDocument();

    // The eight-component breakdown: real points, verbatim measured input.
    const table = screen.getByRole('table');
    const deviceRow = within(table).getByText('Device').closest('tr') as HTMLElement;
    expect(within(deviceRow).getByText('15')).toBeInTheDocument();
    expect(
      within(deviceRow).getByText(
        "device 'fx-laptop-3' is not in the discovered inventory",
      ),
    ).toBeInTheDocument();
  });

  it('risk KPIs, band legend and the recent-evaluations trail', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    expect(await screen.findByText('RISK ENGINE · ARCH7')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Risk-Based Access Engine' }),
    ).toBeInTheDocument();
    expect(screen.getByText('EVALUATIONS RECORDED:')).toBeInTheDocument();

    const evaluations = await kpiCard('Evaluations');
    expect(await within(evaluations).findByText('17')).toBeInTheDocument();
    expect(
      await within(evaluations).findByText(/recorded · last (?:just now|\d+[mhd] ago)/),
    ).toBeInTheDocument();

    const average = await kpiCard('Average Score');
    expect(await within(average).findByText('16.5 / 100')).toBeInTheDocument();
    expect(within(average).getByText('real mean over all evaluations')).toBeInTheDocument();

    const refused = await kpiCard('Refused Starts');
    expect(await within(refused).findByText('0')).toBeInTheDocument();
    expect(
      within(refused).getByText('session starts · evaluation kept as evidence'),
    ).toBeInTheDocument();
    expect(await screen.findByText('0 critical / 0 high')).toBeInTheDocument();

    expect(screen.getByText('Band legend · spec')).toBeInTheDocument();
    expect(screen.getByText('low 0-25')).toBeInTheDocument();
    expect(screen.getByText('allow - session proceeds as requested')).toBeInTheDocument();
    expect(screen.getByText('critical 76-100')).toBeInTheDocument();
    expect(screen.getByText('block - session start refused outright')).toBeInTheDocument();
    expect(
      screen.getByText(
        'caps: user 10 · device 15 · asset 30 · time 10 · location 5 · behavior 15 · ticket 5 · command 10',
      ),
    ).toBeInTheDocument();

    // Recent evaluations row 0 = the verbatim first capture (band, score, relTime).
    const recentRow = (await screen.findAllByText('advisory'))[0].closest(
      'div.border-b',
    ) as HTMLElement;
    expect(within(recentRow).getByText('low')).toBeInTheDocument();
    expect(within(recentRow).getByText('15')).toBeInTheDocument();
    expect(within(recentRow).getByText(REL)).toBeInTheDocument();
  });

  it('anomalies: trained baselines, honest empty incidents, and the train write', async () => {
    const fetchMock = stubFetch(policyRoutes());
    renderApp('/policy');

    expect(await screen.findByText('ANOMALIES · ARCH11')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Anomalies' })).toBeInTheDocument();

    const baselinesLine = await screen.findByText('BASELINES TRAINED:');
    expect(await within(baselinesLine).findByText('5')).toBeInTheDocument();
    const incidentsLine = screen.getByText('INCIDENTS:');
    expect(await within(incidentsLine).findByText('0')).toBeInTheDocument();

    expect(await screen.findByText('No anomaly incidents recorded.')).toBeInTheDocument();

    // Baseline row 0, scoped by its unique samples line.
    const baselineRow = (await screen.findByText('2 samples · 0 sess/day')).closest(
      'div.border-b',
    ) as HTMLElement;
    expect(within(baselineRow).getByText('fixture-principal')).toBeInTheDocument();
    expect(
      within(baselineRow).getByText(
        new RegExp(
          '^hours 17 · devices 1 · ips 1 · targets 1 · verbs 1 · trained (?:just now|\\d+[mhd] ago)$',
        ),
      ),
    ).toBeInTheDocument();

    fireEvent.click(await screen.findByRole('button', { name: 'Train baselines' }));
    expect(
      await screen.findByText('Trained 5 baseline(s) from real history'),
    ).toBeInTheDocument();
    expectWrite(fetchMock, '/risk/baselines/train', 'POST', {});
  });

  it('export Policy downloads the real JSON and reports the rule count', async () => {
    stubFetch(policyRoutes());
    renderApp('/policy');

    // The export reports the real loaded rule count - wait for the list first.
    await screen.findByText('15 of 15 rules');

    const createObjectURL = vi.fn(() => 'blob:vy-pam-policy');
    const revokeObjectURL = vi.fn();
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = revokeObjectURL;
    try {
      fireEvent.click(screen.getByRole('button', { name: 'Export Policy (JSON)' }));
      expect(await screen.findByText('Policy exported (15 rules)')).toBeInTheDocument();
      expect(createObjectURL).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:vy-pam-policy');
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
    }
  });

  it('honest empty states across every list', async () => {
    stubFetch([
      emptyRules(),
      emptyApprovals(),
      emptyIncidents(),
      emptyEvaluations(),
      emptyBaselines(),
      emptyAnomalies(),
      ...policyRoutes(),
    ]);
    renderApp('/policy');

    expect(
      await screen.findByText('No rules match - the policy is empty.'),
    ).toBeInTheDocument();
    expect(await screen.findByText('0 of 15 rules')).toBeInTheDocument();

    await selectTab('Approvals (0)');
    expect(
      await screen.findByText('No commands are awaiting approval.'),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('0 held commands awaiting a decision'),
    ).toBeInTheDocument();

    await selectTab('SOC Incidents (0)');
    expect(
      await screen.findByText('No escalation incidents on record.'),
    ).toBeInTheDocument();
    expect(await screen.findByText('0 escalation incidents')).toBeInTheDocument();

    expect(
      await screen.findByText('No evaluations recorded yet - score a request above.'),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(
        'No baselines trained yet - train from the real history above.',
      ),
    ).toBeInTheDocument();
    expect(await screen.findByText('No anomaly incidents recorded.')).toBeInTheDocument();
    const baselinesLine = screen.getByText('BASELINES TRAINED:');
    expect(await within(baselinesLine).findByText('0')).toBeInTheDocument();
  });

  it('a section error renders verbatim while the rest of the screen stays honest', async () => {
    stubFetch([
      policyRulesRoute({ status: 500, body: { error: 'rules exploded' } }),
      ...policyRoutes(),
    ]);
    renderApp('/policy');

    // The 500 retries twice (QueryProvider) - allow the backoff to settle.
    expect(
      await screen.findByText('Section unavailable: rules exploded', {}, { timeout: 8000 }),
    ).toBeInTheDocument();
    // The stats KPIs still render their real values - only the failed section degrades.
    const policies = await kpiCard('Active Policies');
    expect(await within(policies).findByText('15 of 15 rules enabled')).toBeInTheDocument();
  });

  it('backend down: honest banner, not-connected chips and em-dash KPIs', async () => {
    stubFetch([whoamiRoute(WHOAMI_OPEN_BODY), healthRoute()]);
    renderApp('/policy');

    expect(
      await screen.findByText(
        'Cannot reach the license server - live data is unavailable.',
      ),
    ).toBeInTheDocument();
    expect((await screen.findAllByText('not connected')).length).toBeGreaterThan(0);

    const policies = await kpiCard('Active Policies');
    expect(within(policies).getByText('—')).toBeInTheDocument();
    expect(within(policies).getByText('— of — rules enabled')).toBeInTheDocument();
    expect(screen.getByText('Policy Rules (—)')).toBeInTheDocument();
    const simulator = screen.getByText('Live Rule Simulator').parentElement as HTMLElement;
    expect(within(simulator).getByText('—')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Zero-Trust Access Policies & Rule Engine',
      }),
    ).toBeInTheDocument();
  });

  it('has no axe violations on the live screen', async () => {
    stubFetch(policyRoutes());
    const { container } = renderApp('/policy');

    await screen.findByRole('heading', {
      level: 1,
      name: 'Zero-Trust Access Policies & Rule Engine',
    });
    await expectNoAxeViolations(container);
  });
});
