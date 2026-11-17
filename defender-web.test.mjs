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

test('web: media is not read, and a large body is inspected up to the cap', async () => {
  const defend = createWebDefender({ mode: 'enforce', maxBody: 64 });
  const post = (type, body) => req('/api/upload', { method: 'POST', body, headers: { 'content-type': type } });
  assert.equal(await defend(post('image/png', '../../etc/passwd')), null, 'media types are skipped');
  assert.equal(
    await defend(post('application/octet-stream', '\u0000\u0001\u0002PNG ../../etc/passwd')),
    null,
    'bytes that are not text are skipped',
  );
  // A handler can parse any body as JSON whatever the header says, so text is inspected as text.
  assert.equal((await defend(post('application/octet-stream', '{"file":"../../etc/passwd"}'))).status, 403);
  // Past the cap only the first part is inspected: better than nothing, and bounded.
  const early = req('/api/notes', { method: 'POST', body: { note: `../../etc/passwd ${'a'.repeat(200)}` } });
  assert.equal((await defend(early)).status, 403, 'a payload inside the first part of a large body is seen');
  const late = req('/api/notes', { method: 'POST', body: { note: `${'a'.repeat(200)} ../../etc/passwd` } });
  assert.equal(await defend(late), null, 'a payload past the cap is not');
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
    // The first request of an instance also asks the dashboard for this site's settings.
    assert.equal(sent[0].url, 'https://dash.example.test/api/defender/sdk/policy');
    assert.equal(sent[0].init.headers.authorization, 'Bearer sk_test_key');
    assert.equal(sent[1].url, 'https://dash.example.test/api/defender/report');
    assert.equal(sent[1].init.headers.authorization, 'Bearer sk_test_key');
    const reported = JSON.parse(sent[1].init.body).detections[0];
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

// ---------- settings from the dashboard ----------
// A site with a key takes its settings from the dashboard, so its owner can change them without
// redeploying the site. `withDashboard` stands in for it: `policy` is what it answers, or it is down.
async function withDashboard(policy, run) {
  const realFetch = globalThis.fetch;
  const calls = { policy: 0, reports: [] };
  const state = { policy, down: false };
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith('/api/defender/sdk/policy')) {
      calls.policy += 1;
      if (state.down) throw new Error('dashboard unreachable');
      return new Response(JSON.stringify({ policy: state.policy }), { status: 200 });
    }
    calls.reports.push(JSON.parse(init.body).detections[0]);
    return new Response('{}', { status: 200 });
  };
  try {
    await run(state, calls);
  } finally {
    globalThis.fetch = realFetch;
  }
}
const ATTACK = '/f?p=../../etc/passwd';
const SQLI = '/item?id=1%27%20OR%20%271%27=%271';
const base = {
  enabled: true,
  mode: 'enforce',
  disabled: [],
  skip: [],
  honeypot: false,
  scanners: false,
  ban: { enabled: false },
  rateLimit: { enabled: false },
};
const site = (extra = {}) =>
  createWebDefender({ apiKey: 'sk_test_key', endpoint: 'https://dash.example.test', ...extra });
// Lets the settings go stale, then makes one request and waits for the refresh it starts.
async function refresh(defend) {
  await new Promise((resolve) => setTimeout(resolve, 60));
  const waited = [];
  await defend(req('/'), { waitUntil: (p) => waited.push(p) });
  await Promise.all(waited);
}

test('web: blocking, switched-off rules and never-inspected pages come from the dashboard', async () => {
  await withDashboard(
    { ...base, disabled: ['sqli'], skip: ['/api/webhooks'], honeypot: true },
    async (_state, calls) => {
      // In code the site is watch-only; the dashboard says block.
      const defend = site();
      assert.equal((await defend(req(ATTACK))).status, 403, 'blocking was switched on in the dashboard');
      assert.equal(await defend(req(SQLI)), null, 'a rule the owner switched off does not block');
      assert.equal(calls.reports.at(-1).enforced, false, 'but it is still reported');
      assert.equal(await defend(req('/api/webhooks/stripe?p=../../etc/passwd')), null, 'a never-inspected page');
      assert.equal(await defend(req('/api/webhooks')), null);
      assert.equal(
        (await defend(req('/api/webhooks-other?p=../../etc/passwd'))).status,
        403,
        'only that page and what is under it',
      );
      assert.equal((await defend(req('/.env'))).status, 404, 'scanner-bait pages were switched on in the dashboard');
      assert.equal(calls.policy, 1, 'the settings are asked for once, not on every request');
      assert.equal(defend.stats().settings, 'dashboard');
      assert.equal(defend.stats().mode, 'enforce');
    },
  );
});

test('web: a change in the dashboard reaches the site, and protection can be switched off there', async () => {
  await withDashboard({ ...base, mode: 'monitor' }, async (state, calls) => {
    const defend = site({ policyTtlMs: 30 });
    assert.equal(await defend(req(ATTACK)), null, 'watch-only');
    state.policy = { ...base, mode: 'enforce' };
    await refresh(defend);
    assert.equal((await defend(req(ATTACK))).status, 403, 'blocking after the owner switched it on');
    assert.ok(calls.policy >= 2);
    state.policy = { ...base, enabled: false };
    await refresh(defend);
    assert.equal(await defend(req(ATTACK)), null, 'switched off in the dashboard');
  });
});

test('web: when the dashboard is unreachable the site keeps its settings and is not held up', async () => {
  await withDashboard({ ...base }, async (state) => {
    const defend = site({ policyTtlMs: 30 });
    assert.equal((await defend(req(ATTACK))).status, 403);
    state.down = true;
    await refresh(defend);
    assert.equal((await defend(req(ATTACK))).status, 403, 'the last settings received stay in force');
  });
  await withDashboard(null, async (state) => {
    state.down = true;
    // Never reached the dashboard at all: the options given in code apply.
    const local = site({ mode: 'enforce' });
    const started = Date.now();
    assert.equal((await local(req(ATTACK))).status, 403);
    assert.ok(Date.now() - started < 1500);
    assert.equal(local.stats().settings, 'local');
  });
  await withDashboard({ ...base, mode: 'monitor' }, async (_state, calls) => {
    const inCode = site({ mode: 'enforce', remotePolicy: false });
    assert.equal((await inCode(req(ATTACK))).status, 403, 'remotePolicy: false keeps the settings in code');
    assert.equal(calls.policy, 0);
  });
});

test('web: an address that sends too many requests in a minute is refused', async () => {
  await withDashboard({ ...base, rateLimit: { enabled: true, perMinute: 5 } }, async (_state, calls) => {
    const defend = site();
    for (let i = 0; i < 5; i++) assert.equal(await defend(req('/', { ip: '198.51.100.20' })), null);
    const sixth = await defend(req('/', { ip: '198.51.100.20' }));
    assert.equal(sixth.status, 429);
    assert.ok(Number(sixth.headers.get('retry-after')) >= 1);
    assert.equal((await defend(req('/', { ip: '198.51.100.20' }))).status, 429);
    assert.equal(await defend(req('/', { ip: '198.51.100.21' })), null, 'other addresses are not affected');
    const floods = calls.reports.filter((r) => r.cls === 'rate-limit');
    assert.equal(floods.length, 1, 'reported once per minute per address, not once per request');
    assert.equal(defend.stats().limited, 2);
  });
  // Watch-only: counted and reported, never refused.
  await withDashboard(
    { ...base, mode: 'monitor', rateLimit: { enabled: true, perMinute: 2 } },
    async (_state, calls) => {
      const defend = site();
      for (let i = 0; i < 4; i++) assert.equal(await defend(req('/', { ip: '198.51.100.30' })), null);
      assert.equal(calls.reports.filter((r) => r.cls === 'rate-limit').length, 1);
    },
  );
});
