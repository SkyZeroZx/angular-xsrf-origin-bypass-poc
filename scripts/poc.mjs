import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const chrome = [
  process.env.CHROME_PATH,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].find((path) => path && existsSync(path));

if (!chrome) throw new Error('Set CHROME_PATH to your Chrome or Edge executable.');

const server = spawn(process.execPath, ['backend/server.mjs'], {
  cwd: root,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverOutput = '';
server.stdout.on('data', (chunk) => {
  serverOutput += chunk;
});
server.stderr.on('data', (chunk) => {
  serverOutput += chunk;
});
let browser;

try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (server.exitCode !== null) throw new Error(`Backend exited: ${serverOutput}`);
    try {
      ready = (await fetch('http://127.0.0.1:4200/health')).ok;
      if (ready) break;
    } catch {
      /* Wait for startup. */
    }
    await new Promise((done) => setTimeout(done, 100));
  }
  if (!ready) throw new Error(`Backend did not start: ${serverOutput}`);

  browser = await puppeteer.launch({
    executablePath: chrome,
    headless: true,
  });
  const page = await browser.newPage();
  page.on('pageerror', (error) => console.error('Browser:', error.message));
  const response = await page.goto('http://127.0.0.1:4200/', { waitUntil: 'networkidle0' });
  assert.equal(
    response?.status(),
    200,
    `Page HTTP ${response?.status()}: ${(await page.content()).slice(0, 300)}`,
  );
  await page.waitForSelector('[data-testid="run"]', { timeout: 10000 });
  await page.click('[data-testid="run"]');
  await page.waitForFunction(
    () => {
      const status = document.querySelector('[data-testid="status"]')?.textContent ?? '';
      return status === 'Done' || status.startsWith('Error:');
    },
    { timeout: 15000 },
  );

  const status = await page.$eval('[data-testid="status"]', (node) => node.textContent);
  assert.equal(status, 'Done', `App failed: ${status}; backend: ${serverOutput}`);

  const captures = await (await fetch('http://127.0.0.1:4200/api/results')).json();
  const victim = captures.victim.find((item) => item.id === 'same-origin');
  const attacker = Object.fromEntries(captures.attacker.map((item) => [item.id, item]));
  console.table([...captures.victim, ...captures.attacker]);

  assert.ok(victim?.xsrf, 'Same-origin control has no X-XSRF-TOKEN');
  assert.equal(attacker['protocol-relative']?.xsrf, null);
  assert.equal(attacker.absolute?.xsrf, null);
  assert.equal(attacker.backslash?.xsrf, victim.xsrf);
  assert.equal(attacker['leading-whitespace']?.xsrf, victim.xsrf);
  assert.ok(
    captures.attacker.every((item) => item.cookie === null),
    'Cookie sent to attacker',
  );
  console.log('CONFIRMED: two bypass URLs sent X-XSRF-TOKEN to the attacker origin.');
} finally {
  await browser?.close();
  server.kill();
}
