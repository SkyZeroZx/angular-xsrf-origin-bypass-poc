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
  page.on('requestfailed', (request) =>
    console.error('Request failed:', request.url(), request.failure()?.errorText),
  );
  page.on('response', (response) => {
    if (response.status() >= 400) console.error('HTTP error:', response.status(), response.url());
  });
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
      return status.startsWith('Done') || status.startsWith('Error:');
    },
    { timeout: 15000 },
  );

  const status = await page.$eval('[data-testid="status"]', (node) => node.textContent);
  const captures = await (await fetch('http://127.0.0.1:4200/api/results')).json();
  console.table([...captures.victim, ...captures.attacker]);
  const failures = JSON.parse(
    await page.$eval('[data-testid="failures"]', (node) => node.textContent).catch(() => '[]'),
  );
  assert.equal(status, 'Done', `App failed: ${status}; backend: ${serverOutput}`);
  assert.deepEqual(failures, [], `Requests failed: ${failures.join('; ')}`);
  const victim = captures.victim.find((item) => item.id === 'same-origin');
  const attacker = Object.fromEntries(captures.attacker.map((item) => [item.id, item]));
  const bypassIds = [
    'backslash',
    'backslash-slash',
    'leading-space',
    'leading-tab',
    'leading-whitespace',
    'inner-tab',
    'inner-lf',
    'inner-cr',
    'leading-null',
    'leading-unit-separator',
    'http-double-backslash',
    'http-slash-backslash',
    'http-scheme-tab',
    'same-host-port',
  ];

  assert.equal(captures.victim.length, 1);
  assert.equal(captures.attacker.length, bypassIds.length + 2);
  assert.equal(Object.keys(attacker).length, captures.attacker.length, 'Duplicate capture ID');
  assert.ok(victim?.xsrf, 'Same-origin control has no X-XSRF-TOKEN');
  assert.equal(victim.cookie, `XSRF-TOKEN=${victim.xsrf}`);
  assert.equal(attacker['protocol-relative']?.xsrf, null);
  assert.equal(attacker.absolute?.xsrf, null);
  for (const id of bypassIds) {
    assert.equal(attacker[id]?.xsrf, victim.xsrf, `${id} did not leak the token`);
  }
  assert.ok(
    captures.attacker.every((item) => item.cookie === null),
    'Cookie sent to attacker',
  );
  console.log(
    `CONFIRMED: ${bypassIds.length} bypass URLs sent X-XSRF-TOKEN to an attacker origin.`,
  );
} finally {
  await browser?.close();
  server.kill();
}
