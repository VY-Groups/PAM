// Temp 5d gate: AI-Agent Access section on the JIT screen + agent chips.
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

// ---- Compliance screen: 16 chips + agent labels -------------------------
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
check(compBits.chips.length === 16,
  'Compliance screen: 16 source chips (got ' + compBits.chips.length + ')');
check(compBits.chips[compBits.chips.length - 1] === 'agent',
  'Compliance screen: agent chip appended last -> ' + JSON.stringify(compBits.chips.slice(-3)));
await comp.close();

await browser.close();
console.log(failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED');
process.exit(failures === 0 ? 0 : 1);
