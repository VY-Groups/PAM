// 6a gate: HA/DC/DR section on Platform Settings + cluster source chip.
// Keeps every 5d check (JIT agent section) and adds the 6a UI assertions.
// Exit code 1 on any failed assertion. Viewport 1920x1600, headless.
import { chromium } from 'playwright-core';

const BASE = process.env.BASE || 'http://127.0.0.1:5000';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
let failures = 0;
const check = (ok, label) => {
  console.log((ok ? 'PASS ' : 'FAIL ') + label);
  if (!ok) failures++;
};
const noise = (t) => /favicon/.test(t);

// ---- JIT screen: agent section ------------------------------------------
const jit = await browser.newPage({ viewport: { width: 1920, height: 1600 } });
const jitErrors = [];
const jitBad = [];
const badUrl = (u) => !/favicon/.test(u);
jit.on('pageerror', (e) => jitErrors.push('[pageerror] ' + e.message));
jit.on('console', (m) => {
  if (m.type() !== 'error') return;
  const url = (m.location() && m.location().url) || '';
  if (badUrl(url)) jitErrors.push('[console] ' + m.text() + ' @ ' + url);
});
jit.on('response', (r) => {
  if (r.status() >= 400 && badUrl(r.url())) jitBad.push(r.status() + ' ' + r.url());
});
await jit.goto(BASE + '/screens/jit_access_ephemeral_approvals/code.html', { waitUntil: 'load' });
await new Promise((r) => setTimeout(r, 3000));
const jitBits = await jit.evaluate(() => {
  const q = (s) => document.querySelector(s);
  const t = (s) => (q(s) || {}).textContent || '';
  return {
    section: !!q('[data-role="agent-section"]'),
    belowBroker: !!q('[data-role="broker-section"]')
      && !!q('[data-role="agent-section"]')
      && (q('[data-role="broker-section"]').compareDocumentPosition(q('[data-role="agent-section"]')) & 4) > 0,
    summary: t('[data-role="agent-summary"]').trim(),
    tileAgents: t('[data-role="agent-tile-agents"]').trim(),
    tileEvents: t('[data-role="agent-tile-events"]').trim(),
    agentRows: document.querySelectorAll('[data-role="agent-rows"] tr').length,
    reqRows: document.querySelectorAll('[data-role="agent-req-rows"] tr').length,
    exported: !!(window.jitLive && window.jitLive.agent
      && typeof window.jitLive.agent.load === 'function'
      && window.jitLive.agent.state),
    noIds: document.querySelectorAll('[data-role="agent-section"] [id]').length === 0,
    newIds: Array.from(document.querySelectorAll('[id]')).length,
  };
});
check(jitErrors.length === 0, 'JIT screen: no page/console errors '
  + JSON.stringify(jitErrors.slice(0, 3)));
check(jitBad.length === 0, 'JIT screen: no failed HTTP responses '
  + JSON.stringify(jitBad.slice(0, 3)));
check(jitBits.section, 'JIT screen: agent section present');
check(jitBits.belowBroker, 'JIT screen: agent section sits below the broker section');
check(jitBits.summary !== '' && !jitBits.summary.startsWith('\u2014 agents'),
  'JIT screen: agent summary is real data -> "' + jitBits.summary + '"');
check(/^\d+ agents \u00b7 \d+ open grants \u00b7 \d+ agent events$/.test(jitBits.summary),
  'JIT screen: summary shape honest zeros/counts -> "' + jitBits.summary + '"');
check(/^\d+$/.test(jitBits.tileAgents), 'JIT screen: AGENTS tile numeric -> "' + jitBits.tileAgents + '"');
check(/^\d+$/.test(jitBits.tileEvents), 'JIT screen: AGENT TRAIL tile numeric -> "' + jitBits.tileEvents + '"');
check(jitBits.agentRows >= 1, 'JIT screen: identity table has its row (real or honest empty state)');
check(jitBits.reqRows >= 1, 'JIT screen: request table has its row (real or honest empty state)');
check(jitBits.exported, 'JIT screen: jitLive.agent exported');
check(jitBits.noIds, 'JIT screen: no id= introduced under the agent section');
const staticBefore = await jit.evaluate(() => {
  // register modal opens from the header button
  const btn = document.querySelector('[data-role="btn-agent-add"]');
  if (btn) btn.click();
  return !!document.querySelector('[data-agent-modal]');
});
check(staticBefore, 'JIT screen: Register Agent button opens the modal');
await jit.close();

// ---- Compliance screen: 17 chips + cluster labels -----------------------
const comp = await browser.newPage({ viewport: { width: 1920, height: 1600 } });
const compErrors = [];
comp.on('pageerror', (e) => compErrors.push('[pageerror] ' + e.message));
comp.on('console', (m) => {
  if (m.type() === 'error' && !noise(m.text())) compErrors.push('[console] ' + m.text());
});
await comp.goto(BASE + '/screens/compliance_soc_2_audit_center/code.html', { waitUntil: 'load' });
await new Promise((r) => setTimeout(r, 3000));
const compBits = await comp.evaluate(() => {
  const chips = Array.from(document.querySelectorAll('[data-role="audit-source-filter"] [data-source]'))
    .map((c) => c.getAttribute('data-source'));
  return { chips: chips };
});
check(compErrors.length === 0, 'Compliance screen: no page/console errors '
  + JSON.stringify(compErrors.slice(0, 3)));
check(compBits.chips.length === 17,
  'Compliance screen: 17 source chips (got ' + compBits.chips.length + ')');
check(compBits.chips[compBits.chips.length - 1] === 'cluster',
  'Compliance screen: cluster chip appended last -> ' + JSON.stringify(compBits.chips.slice(-3)));
await comp.close();

// ---- Platform settings: HA / DC / DR section ----------------------------
const ps = await browser.newPage({ viewport: { width: 1920, height: 1600 } });
const psErrors = [];
const psBad = [];
ps.on('pageerror', (e) => psErrors.push('[pageerror] ' + e.message));
ps.on('console', (m) => {
  if (m.type() === 'error' && !noise(m.text())) psErrors.push('[console] ' + m.text());
});
ps.on('response', (r) => {
  if (r.status() >= 400 && !/favicon/.test(r.url())) psBad.push(r.status() + ' ' + r.url());
});
await ps.goto(BASE + '/screens/platform_settings_center/code.html', { waitUntil: 'load' });
await new Promise((r) => setTimeout(r, 3000));
const psBits = await ps.evaluate(() => {
  const q = (s) => document.querySelector(s);
  const t = (s) => (q(s) || {}).textContent || '';
  const section = q('[data-role="cluster-section"]');
  return {
    section: !!section,
    summary: t('[data-role="cluster-summary"]').trim(),
    role: t('[data-role="cluster-role"]').trim(),
    failover: t('[data-role="cluster-failover-label"]').trim(),
    tileSelf: t('[data-role="cluster-tile-self"]').trim(),
    tilePeers: t('[data-role="cluster-tile-peers"]').trim(),
    tileReplication: t('[data-role="cluster-tile-replication"]').trim(),
    tileBackups: t('[data-role="cluster-tile-backups"]').trim(),
    rows: document.querySelectorAll('[data-role="cluster-rows"] tr').length,
    replicaRows: document.querySelectorAll('[data-role="cluster-replica-rows"] tr').length,
    backupRows: document.querySelectorAll('[data-role="cluster-backup-rows"] tr').length,
    noIds: section ? section.querySelectorAll('[id]').length === 0 : false,
    exported: !!(window.settingsLive && window.settingsLive.cluster
      && typeof window.settingsLive.cluster.load === 'function'
      && window.settingsLive.cluster.state),
  };
});
check(psErrors.length === 0, 'Settings screen: no page/console errors '
  + JSON.stringify(psErrors.slice(0, 3)));
check(psBad.length === 0, 'Settings screen: no failed HTTP responses '
  + JSON.stringify(psBad.slice(0, 3)));
check(psBits.section, 'Settings screen: HA/DC/DR section present');
check(/^\S+ \((dc|dr)\) · (active|passive) · \d+ peers? · \d+ healthy · audit \d+ · vault \d+ · sessions \d+ · backups \d+$/
  .test(psBits.summary),
  'Settings screen: cluster summary is real data -> "' + psBits.summary + '"');
check(/^(active|passive)$/.test(psBits.role),
  'Settings screen: role badge honest -> "' + psBits.role + '"');
check(/^(Promote|Demote)$/.test(psBits.failover),
  'Settings screen: failover label matches the role -> "' + psBits.failover + '"');
check(/^\d+$/.test(psBits.tileSelf.split(' · ')[0] || '') || /\S/.test(psBits.tileSelf),
  'Settings screen: THIS NODE tile carries the name -> "' + psBits.tileSelf + '"');
check(/^\d+$/.test(psBits.tilePeers) && /^\d+$/.test(psBits.tileReplication)
  && /^\d+$/.test(psBits.tileBackups),
  'Settings screen: posture tiles numeric -> peers=' + psBits.tilePeers
  + ' replication=' + psBits.tileReplication + ' backups=' + psBits.tileBackups);
check(psBits.rows >= 1, 'Settings screen: node table has its row (self at minimum)');
check(psBits.replicaRows >= 1 && psBits.backupRows >= 1,
  'Settings screen: replica + backup tables render honest rows -> replica='
  + psBits.replicaRows + ' backups=' + psBits.backupRows);
check(psBits.noIds, 'Settings screen: no id= introduced under the cluster section');
check(psBits.exported, 'Settings screen: settingsLive.cluster exported');

// real register -> probe -> sync (honest failure) -> remove flow against the
// live server; the registry must come back to its baseline afterwards
const flow = await ps.evaluate(async () => {
  const h = { 'Content-Type': 'application/json', 'X-Actor': 'gate' };
  const api = '/api/v1/';
  const peersTotal = async () => (await (await fetch(api + 'cluster')).json()).peers.total;
  // clear any leftover from an interrupted gate run
  const existing = (await (await fetch(api + 'cluster/nodes')).json()).nodes || [];
  for (const n of existing) {
    if (n.name === 'gate-peer-6a') {
      await fetch(api + 'cluster/nodes/' + n.id, { method: 'DELETE', headers: h });
    }
  }
  const baseline = await peersTotal();
  const reg = await fetch(api + 'cluster/nodes', {
    method: 'POST', headers: h,
    body: JSON.stringify({ name: 'gate-peer-6a', site: 'dr', role: 'passive',
      base_url: 'https://gate-peer.invalid' }),
  });
  if (reg.status !== 201) return { step: 'register', status: reg.status };
  const node = (await reg.json()).node;
  const probeRes = await fetch(api + 'cluster/nodes/' + node.id + '/probe',
    { method: 'POST', headers: h, body: '{}' });
  const probeBody = await probeRes.json();
  const syncRes = await fetch(api + 'cluster/nodes/' + node.id + '/sync',
    { method: 'POST', headers: h, body: '{}' });
  const syncBody = await syncRes.json();
  const withPeer = await peersTotal();
  await fetch(api + 'cluster/nodes/' + node.id, { method: 'DELETE', headers: h });
  const cleaned = await peersTotal();
  return {
    step: 'ok',
    probeHealth: probeBody.probe && probeBody.probe.health,
    probeError: (probeBody.probe && probeBody.probe.error) || '',
    syncOk: syncBody.ok,
    syncError: syncBody.error || '',
    baseline: baseline,
    withPeer: withPeer,
    cleaned: cleaned,
  };
});
check(flow.step === 'ok', 'Settings screen: gate peer registers (201) -> ' + JSON.stringify(flow));
check(flow.probeHealth === 'unreachable' && /^connection failed/.test(flow.probeError),
  'Settings screen: real probe reports the unreachable peer verbatim -> "' + flow.probeError + '"');
check(flow.syncOk === false && /^connection failed/.test(flow.syncError),
  'Settings screen: sync failure reported verbatim -> "' + flow.syncError + '"');
check(flow.withPeer === flow.baseline + 1 && flow.cleaned === flow.baseline,
  'Settings screen: gate peer removed, registry back to baseline -> baseline='
  + flow.baseline + ' withPeer=' + flow.withPeer + ' cleaned=' + flow.cleaned);
const psAfter = await ps.evaluate(async () => {
  await window.settingsLive.cluster.load();
  await new Promise((r) => setTimeout(r, 500));
  return {
    summary: document.querySelector('[data-role="cluster-summary"]').textContent.trim(),
    rows: document.querySelectorAll('[data-role="cluster-rows"] tr').length,
  };
});
check(new RegExp('^\\S+ \\((dc|dr)\\) · (active|passive) · ' + flow.baseline
  + ' peers? · ').test(psAfter.summary) && psAfter.rows >= 1,
  'Settings screen: summary honest after cleanup -> "' + psAfter.summary + '"');
await ps.close();

await browser.close();
console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
process.exit(failures === 0 ? 0 : 1);
