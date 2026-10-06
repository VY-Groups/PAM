// Load the discovery screen and print every console/page error.
import { chromium } from 'playwright-core';

const URL = process.argv[2] ||
  'http://127.0.0.1:5108/screens/target_infrastructure_connectors/code.html';

const browser = await chromium.launch({ channel: 'msedge', headless: true });
const page = await browser.newPage();
page.on('console', (m) => {
  if (m.type() === 'error' || m.type() === 'warning') {
    console.log(`[console.${m.type()}] ${m.text()}`);
  }
});
page.on('pageerror', (e) => console.log(`[pageerror] ${e.message}`));
page.on('requestfailed', (r) => {
  if (!r.url().startsWith('data:')) {
    console.log(`[reqfail] ${r.url()} :: ${r.failure()?.errorText}`);
  }
});
await page.goto(URL, { waitUntil: 'load' });
await new Promise((r) => setTimeout(r, 2500));
const text = await page.evaluate(() => document.body.innerText);
console.log('--- key fills ---');
for (const needle of ['License server:', 'auth:', 'Nodes', 'Managed (', 'Healthy']) {
  const line = text.split('\n').find((l) => l.includes(needle));
  console.log(`  ${needle} -> ${line ? line.trim() : 'MISSING'}`);
}
await browser.close();
