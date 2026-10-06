// Discovery screen e2e: real UI actions against a throwaway server instance
// (own port + own DB, so the dev database stays pristine), then a file://
// honesty sweep. Exit code 1 on any failed assertion.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHOTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(SHOTS_DIR); // shots_tool -> repo root
const PORT = 5108;
const BASE = `http://127.0.0.1:${PORT}`;
const SCREEN_PATH = '/screens/target_infrastructure_connectors/code.html';
const FILE_URL = `file:///${join(REPO, 'frontend', 'screens',
  'target_infrastructure_connectors', 'code.html').replace(/\\/g, '/')}`;

const FORBIDDEN = [
  // legacy discovery design values
  '2,875', '482 mTLS', '18 Unmanaged', '12ms', '99.98', '2,857', '1,420',
  'INGRESS SHIELD ACTIVE', 'v4.8.2', '10.140.0.0/16', '14 minutes ago',
  '+3 Ephemeral', 'ALL REGIONS ACTIVE', 'POLLING INTERVAL', '18 Connectors Active',
  'Zero-Trust Gateway', '0 standing admin', 'Session TLS 1.3', 'Audit Digest Verified',
  'SYN_SENT', 'HEARTBEAT', 'mTLS handshake', 'env:production', 'Zero-Touch',
  'Optimal', 'TLS 1.3 Strict', 'Showing 5 of', 'Degraded (0)', 'Enforced (',
  'Requires PAM Vault Ingestion', 'connector-east', 'k8s-prod', 'Scanning CIDR',
  'HIGH LOAD', 'Equinix', 'POLICY_VIOLATION', 'Standing Privileges',
  'US-East Gateway', 'EU-Central', 'Hybrid On-Prem', '7.8ms', 'TCP_ESTABLISHED',
  // shared chrome (purged suite-wide)
  'us-east-prod-cluster', 'Global Zone', 'SOC2 Type II', '120 evt/s',
  'Alex Mercer', 'Enterprise SecOps Lead', 'Zero Standing Privileges',
];

const failures = [];
function check(cond, label, extra) {
  const status = cond ? 'PASS' : 'FAIL';
  console.log(`${status} ${label}${!cond && extra ? ` :: ${extra}` : ''}`);
  if (!cond) failures.push(label);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 6000, step = 150) {
  const t0 = Date.now();
  for (;;) {
    try {
      if (await fn()) return true;
    } catch { /* transient DOM */ }
    if (Date.now() - t0 > ms) return false;
    await sleep(step);
  }
}
const bodyText = (page) => page.evaluate(() => document.body.innerText);
const rowOf = (page, addr) => page.locator('tr[data-id]', { hasText: addr });
const bodyHas = (page, needle) =>
  until(() => page.evaluate((n) => document.body.innerText.includes(n), needle));
const toastHas = (page, needle) =>
  until(() => page.evaluate((n) =>
    (document.getElementById('vy-toast')?.textContent || '').includes(n), needle));
const toastMatches = (page, src) =>
  until(() => page.evaluate((s) =>
    new RegExp(s).test(document.getElementById('vy-toast')?.textContent || ''), src), 60000);
async function sweep(page, mode) {
  const text = await bodyText(page);
  const hits = FORBIDDEN.filter((f) => text.includes(f));
  check(hits.length === 0, `${mode}: no forbidden strings`, hits.join(' | '));
  return text;
}

// --------------------------------------------------------------- server ----
const tmpDir = join(SHOTS_DIR, '.tmp');
mkdirSync(tmpDir, { recursive: true });
const dbPath = join(tmpDir, `discovery_ui_${process.pid}.db`);
const server = spawn('python', ['app.py'], {
  cwd: join(REPO, 'backend', 'phase2_license_server'),
  env: {
    ...process.env,
    LICENSE_SERVER_PORT: String(PORT),
    LICENSE_DATABASE_URI: `sqlite:///${dbPath.replace(/\\/g, '/')}`,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });

async function waitHealthy(ms = 40000) {
  const t0 = Date.now();
  for (;;) {
    if (server.exitCode !== null) {
      throw new Error(`server exited early (${server.exitCode}):\n${serverLog}`);
    }
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    if (Date.now() - t0 > ms) throw new Error(`server never healthy:\n${serverLog}`);
    await sleep(300);
  }
}

let browser;
try {
  await waitHealthy();
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage({ viewport: { width: 1252, height: 1600 } });

  // ---------------------------------------------------- initial honest state
  await page.goto(BASE + SCREEN_PATH, { waitUntil: 'load' });
  await sleep(1600);
  let text = await sweep(page, 'http initial');
  check(text.includes('License server: Healthy'), 'http: footer server filled');
  check(text.includes('auth: open'), 'http: header auth filled');
  check(text.includes('0 Nodes'), 'http: tile1 real total (0)');
  check(text.includes('Managed (0)'), 'http: pills real counts');
  check(text.includes('Showing 0 of 0 target assets'), 'http: empty table footer');
  check(text.includes('no scan yet'), 'http: reachability = no scan yet');
  check(text.includes('never scanned'), 'http: scan scope = never scanned');
  check(text.includes('Last scan: never'), 'http: table footer last scan');
  check(text.includes('No target assets yet'), 'http: honest empty row');

  // -------------------------------------------------- register target host --
  // POST /discovery/assets is the one-call register+ingest path: the target
  // lands MANAGED with a vault item. Unmanaged rows only come from scans.
  await page.getByRole('button', { name: 'Onboard Target Host' }).click();
  check(await until(async () => (await page.locator('.ob-address').count()) === 1),
    'modal: register modal opened');
  await page.locator('.ob-address').fill('10.99.0.10');
  await page.locator('.ob-hostname').fill('win-dc01');
  await page.locator('.ob-type').selectOption('windows');
  await page.locator('.ob-principal').fill('Administrator');
  await page.locator('.ob-tier').selectOption('Tier-0');
  await page.locator('.ok').click();
  check(await until(async () => (await page.locator('tr[data-id]').count()) === 1),
    'register: row rendered');
  text = await bodyText(page);
  check(text.includes('win-dc01'), 'register: hostname shown');
  check(text.includes('MANAGED'), 'register: posture = managed (one-call onboard)');
  check(text.includes('1 vaulted'), 'register: vaulted count = 1');
  check(text.includes('0 Unmanaged'), 'register: tile3 = 0 Unmanaged');
  check(await until(async () =>
    (await page.getByRole('button', { name: 'Managed (1)' }).count()) === 1),
  'register: pill = Managed (1)');

  // ------------------------------------------------------- real scan (modal) -
  // Scope 127.0.0.1 at this server's own listener port: open by construction,
  // so the scan yields exactly one real UNMANAGED row.
  await page.locator('#btn-scan').click();
  check(await until(async () =>
    (await page.getByText('Run Discovery Scan').count()) >= 1),
    'scan modal: opened');
  await page.locator('.sc-scope').fill('127.0.0.1');
  await page.locator('.sc-ports').fill(String(PORT));
  await page.getByRole('button', { name: 'Start scan' }).click();
  check(await toastMatches(page, 'Scan finished:'),
    'scan: real localhost scan finished');
  check(await until(async () => (await rowOf(page, '127.0.0.1').count()) === 1),
    'scan: unmanaged row rendered');
  text = await bodyText(page);
  check(text.includes('UNMANAGED DRIFT'), 'scan: row posture = unmanaged drift');
  check(text.includes('Drift / Unmanaged (1)'), 'scan: pill = 1 unmanaged');
  check(text.includes('1 Unmanaged'), 'scan: tile3 value = 1');
  check(text.includes('2 Nodes'), 'scan: tile1 total = 2');
  check(text.includes('127.0.0.1'), 'scan: scope shown in auto-discovery panel');
  check(text.includes('100% reachable (last scan)'), 'scan: reachability from last scan');
  check(text.includes('1 new on last scan'), 'scan: findings from last scan');
  check(!text.includes('never scanned'), 'scan: scope no longer "never scanned"');

  // ----------------------------------------------------- ignore / restore ----
  // Scoped to the unmanaged scan row.
  await rowOf(page, '127.0.0.1')
    .getByRole('button', { name: 'Ignore', exact: true }).click();
  check(await until(async () =>
    (await page.getByRole('button', { name: 'Ignored (1)' }).count()) === 1),
  'ignore: pill = Ignored (1)');
  text = await bodyText(page);
  check(text.includes('IGNORED'), 'ignore: posture badge');

  await rowOf(page, '127.0.0.1')
    .getByRole('button', { name: 'Restore', exact: true }).click();
  check(await until(async () =>
    (await page.getByRole('button', { name: 'Drift / Unmanaged (1)' }).count()) === 1),
  'restore: pill back to Drift (1)');

  // ------------------------------------------------------ adopt to vault ----
  await rowOf(page, '127.0.0.1')
    .getByRole('button', { name: 'Onboard to Vault Now' }).click();
  check(await until(async () => (await page.locator('.ob-principal').count()) === 1),
    'modal: adopt modal opened');
  text = await bodyText(page);
  check(text.includes('TARGET 127.0.0.1'), 'adopt: target shown in modal');
  await page.locator('.ob-principal').fill('root');
  await page.locator('.ok').click();
  check(await until(async () =>
    (await page.getByRole('button', { name: 'Managed (2)' }).count()) === 1),
  'adopt: pill = Managed (2)');
  text = await bodyText(page);
  check(text.includes('0 assets unmanaged'), 'adopt: footer unmanaged = 0');

  // ------------------------------------------------ policy / console toasts -
  await rowOf(page, '127.0.0.1')
    .getByRole('button', { name: 'Policy', exact: true }).click();
  check(await toastHas(page, 'Policy engine not connected'),
    'policy: honest not-connected toast');
  await rowOf(page, '127.0.0.1')
    .getByRole('button', { name: 'Console', exact: true }).click();
  check(await toastHas(page, 'Session console not connected'),
    'console: honest not-connected toast');

  // ------------------------------------------------------------- probe ------
  // Probe the dead registration address: deterministic, no new discoveries.
  await rowOf(page, '10.99.0.10')
    .getByRole('button', { name: 'Probe', exact: true }).click();
  check(await until(() => toastHas(page, 'Probe finished'), 20000),
    'probe: real scan toast');

  // ------------------------------------------------------------- filters ----
  await page.getByRole('button', { name: 'Databases' }).click();
  check(await bodyHas(page, 'No assets match the current filters.'),
    'tab filter: databases -> no-match message');
  await page.getByRole('button', { name: 'All Targets' }).click();
  check(await until(async () => (await page.locator('tr[data-id]').count()) === 2),
    'tab filter: all targets -> 2 rows');
  await page.locator('#target-search').fill('win-dc01');
  check(await until(async () => (await page.locator('tr[data-id]').count()) === 1),
    'search: hostname match -> 1 row');
  await page.locator('#target-search').fill('zzz-nope');
  check(await bodyHas(page, 'No assets match the current filters.'),
    'search: no match -> filter message');
  await page.locator('#target-search').fill('');
  check(await until(async () => (await page.locator('tr[data-id]').count()) === 2),
    'search: cleared -> 2 rows');

  // --------------------------------------------------------------- feed -----
  text = await bodyText(page);
  check(!text.includes('No discovery activity yet'), 'feed: real events present');
  check(/asset_|scan_/.test(text), 'feed: discovery event actions shown');
  check(text.includes('Audit: ') && !text.includes('Audit: 0 events'),
    'footer: real audit event count');

  // -------------------------------------------------------- final http sweep -
  text = await sweep(page, 'http final');
  check(text.includes('License server: Healthy'), 'http final: server status');
  check(text.includes('Showing 1–2 of 2 target assets'),
    'http final: table footer 1–2 of 2');
  check(text.includes('2 Nodes'), 'http final: tile1 total = 2');

  // ------------------------------------------------------------ file:// -----
  await page.goto(FILE_URL, { waitUntil: 'load' });
  await sleep(1800);
  text = await sweep(page, 'file://');
  check(text.includes('License server: —'), 'file://: server dash');
  check(text.includes('— Nodes'), 'file://: tile dash');
  check(text.includes('Managed (—)'), 'file://: pill dash');
  check(text.includes('auth: —'), 'file://: header auth dash');
  check(!text.includes('Healthy'), 'file://: no live status claim');
  check(!text.includes('auth: open'), 'file://: no live auth claim');
  check(text.includes('No target assets yet'), 'file://: honest empty row');
} catch (err) {
  failures.push(`unhandled error: ${err.message}`);
  console.error('ERROR', err);
} finally {
  if (browser) await browser.close().catch(() => {});
  server.kill();
  await sleep(400);
  try { rmSync(dbPath, { force: true }); } catch { /* lock may linger */ }
}

console.log('\n---------------------------------------------');
if (failures.length) {
  console.log(`FAILURES (${failures.length}):`);
  for (const f of failures) console.log('  -', f);
  process.exit(1);
} else {
  console.log('ALL CHECKS PASSED');
}
process.exit(0);
