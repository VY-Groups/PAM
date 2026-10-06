// Recapture every screen.png from the running server so previews show the
// purged chrome + honest (empty) live state. The logo asset folder is skipped:
// its screen.png IS the sidebar logo image, not a preview.
import { chromium } from 'playwright-core';
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHOTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(SHOTS_DIR);
const BASE = process.env.BASE || 'http://127.0.0.1:5000';
const SKIP = new Set(['aegispam_enterprise_security_logo']);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function pngSize(buf) {
  // IHDR chunk: width big-endian at offset 16, height at offset 20
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}

const screensDir = join(REPO, 'frontend', 'screens');
const folders = readdirSync(screensDir).filter((n) =>
  !SKIP.has(n) && statSync(join(screensDir, n)).isDirectory()
    && existsSync(join(screensDir, n, 'code.html')));

const browser = await chromium.launch({ channel: 'msedge', headless: true });
let ok = 0;
let fail = 0;
for (const name of folders) {
  const png = join(screensDir, name, 'screen.png');
  let dims = { w: 1440, h: 1600 };
  try { dims = pngSize(readFileSync(png)); } catch { /* first capture */ }
  const page = await browser.newPage({
    viewport: { width: dims.w, height: 1600 },
  });
  try {
    await page.goto(`${BASE}/screens/${name}/code.html`, { waitUntil: 'load' });
    await page.evaluate(async () => { await document.fonts.ready; });
    await sleep(2200);
    await page.screenshot({ path: png, fullPage: true });
    ok += 1;
    console.log(`shot ${name} (${dims.w} wide)`);
  } catch (err) {
    fail += 1;
    console.log(`FAIL ${name}: ${err.message}`);
  }
  await page.close();
}
await browser.close();
console.log(`${ok} captured, ${fail} failed`);
process.exit(fail ? 1 : 0);
