// @securovix/defender/web — the Fetch-API adapter (Vercel Routing Middleware, Next.js middleware,
// Cloudflare Workers). Uses the Request/Response built into Node.
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { createWebDefender, vercelNext } = await import('./packages/defender-sdk/web.mjs');

const req = (path, { method = 'GET', body, headers = {}, ip = '203.0.113.50' } = {}) =>
  new Request(`https://www.example.test${path}`, {
    method,
    headers: {
      'x-forwarded-for': ip,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });

test('web: monitor mode never blocks; enforce mode blocks a confirmed attack with a 403', async () => {
  const seen = [];
  const monitor = createWebDefender({ onDetection: (d) => seen.push(d) });
  assert.equal(await monitor(req('/files?path=../../etc/passwd')), null);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].cls, 'path-traversal');
  assert.equal(seen[0].enforced, false);
  assert.equal(seen[0].srcIp, '203.0.113.50');
  assert.equal(seen[0].url, 'www.example.test/files?path=../../etc/passwd');

  const enforce = createWebDefender({ mode: 'enforce' });
  const blocked = await enforce(req('/search?q=%3Cscript%3Ealert(1)%3C/script%3E'));
  assert.equal(blocked.status, 403);
  assert.deepEqual(await blocked.json(), { error: 'Blocked by Securovix Defender' });
  assert.equal(await enforce(req('/pricing')), null, 'ordinary traffic continues');
  assert.equal(await enforce(req('/search?q=O%27Brien')), null, 'detect-only matches are never blocked');
  assert.deepEqual(
    { requests: enforce.stats().requests, detections: enforce.stats().detections, blocked: enforce.stats().blocked },
    { requests: 3, detections: 2, blocked: 1 },
  );
});

test('web: a JSON body is inspected and still readable by the application afterwards', async () => {
  const defend = createWebDefender({ mode: 'enforce' });
  const attack = req('/api/login', { method: 'POST', body: { email: "x' OR '1'='1", password: 'x' } });
  assert.equal((await defend(attack)).status, 403);

  const ordinary = req('/api/contact', {
    method: 'POST',
    body: { name: "O'Brien", message: 'Design & code; also coffee' },
  });
  assert.equal(await defend(ordinary), null);
  assert.deepEqual(await ordinary.json(), { name: "O'Brien", message: 'Design & code; also coffee' });
});

test('web: uploads and oversized bodies are not read', async () => {
  const defend = createWebDefender({ mode: 'enforce', maxBody: 64 });
  const upload = req('/api/upload', {
    method: 'POST',
    body: '../../etc/passwd',
    headers: { 'content-type': 'application/octet-stream' },
  });
  assert.equal(await defend(upload), null, 'binary bodies are skipped');
  const large = req('/api/notes', { method: 'POST', body: { note: `${'a'.repeat(200)} ../../etc/passwd` } });
  assert.equal(await defend(large), null, 'a body past the cap is not inspected');
});

test('web: honeypot and attack-tool checks are opt-in', async () => {
  const sqlmap = { 'user-agent': 'sqlmap/1.8.4#stable (https://sqlmap.org)' };
  const plain = createWebDefender({ mode: 'enforce' });
  assert.equal(await plain(req('/.env')), null);
  assert.equal(await plain(req('/', { headers: sqlmap })), null);

  const strict = createWebDefender({ mode: 'enforce', honeypot: true, scanners: true });
  const bait = await strict(req('/.env'));
  assert.equal(bait.status, 404, 'a honeypot hit looks like an ordinary missing page');
  assert.equal((await strict(req('/', { headers: sqlmap }))).status, 403);
  assert.equal(await strict(req('/')), null);
});

test('web: repeat offenders are refused once a ban policy is set', async () => {
  const defend = createWebDefender({
    mode: 'enforce',
    honeypot: true,
    ban: { threshold: 3, windowMs: 60_000, ttlMs: 60_000 },
  });
  const attacker = '198.51.100.77';
  for (let i = 0; i < 3; i++) {
    assert.equal((await defend(req('/f?p=../../etc/passwd', { ip: attacker }))).status, 403);
  }
  const refused = await defend(req('/pricing', { ip: attacker }));
  assert.equal(refused.status, 403);
  assert.match((await refused.json()).error, /repeat offender/);
  assert.equal(await defend(req('/pricing', { ip: '198.51.100.78' })), null, 'other visitors are unaffected');

  // A honeypot hit bans at once.
  assert.equal((await defend(req('/wp-login.php', { ip: '198.51.100.79' }))).status, 404);
  assert.equal((await defend(req('/pricing', { ip: '198.51.100.79' }))).status, 403);
  assert.equal(defend.stats().activeBans, 2);
});

test('web: skip paths, mode switching and fail-open', async () => {
  const defend = createWebDefender({ mode: 'enforce', skip: [/^\/internal\//] });
  assert.equal(await defend(req('/internal/tools?p=../../etc/passwd')), null);
  assert.equal(defend.setMode('monitor'), 'monitor');
  assert.equal(await defend(req('/f?p=../../etc/passwd')), null);

  // A request object we cannot read must pass, not throw.
  const broken = createWebDefender({ mode: 'enforce' });
  assert.equal(await broken({ url: 'not a url', method: 'GET', headers: new Headers() }), null);
});

test('web: detections are reported without delaying the response', async () => {
  const realFetch = globalThis.fetch;
  const sent = [];
  const waited = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url, init });
    return new Response('{}', { status: 200 });
  };
  try {
    const defend = createWebDefender({
      mode: 'enforce',
      apiKey: 'sk_test_key',
      endpoint: 'https://dash.example.test/',
    });
    const out = await defend(req('/f?p=../../etc/passwd'), { waitUntil: (p) => waited.push(p) });
    assert.equal(out.status, 403);
    assert.equal(waited.length, 1, 'the report is handed to waitUntil');
    await waited[0];
    assert.equal(sent[0].url, 'https://dash.example.test/api/defender/report');
    assert.equal(sent[0].init.headers.authorization, 'Bearer sk_test_key');
    const reported = JSON.parse(sent[0].init.body).detections[0];
    assert.equal(reported.cls, 'path-traversal');
    assert.equal(reported.enforced, true);
    assert.equal(defend.stats().reported, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('web: vercelNext() is the continue response Vercel expects', () => {
  const res = vercelNext();
  assert.equal(res.headers.get('x-middleware-next'), '1');
  assert.equal(res.status, 200);
});
