import assert from 'node:assert/strict';
import { test } from 'node:test';

const { HONEYPOT_PATHS, inspect, matchHoneypot } = await import('./packages/defender-sdk/signatures.mjs');
const { SELF_SKIP, createSelfDefense } = await import('./defender/middleware.mjs');
const { shannonDefender } = await import('./packages/defender-sdk/index.mjs');

const mkReq = (method, url, { ip = '203.0.113.7', body } = {}) => ({
  method,
  url,
  originalUrl: url,
  path: url.split('?')[0],
  body,
  ip,
  socket: {},
});
const run = (mw, req) => {
  const res = {
    code: null,
    payload: null,
    status(c) {
      this.code = c;
      return this;
    },
    json(p) {
      this.payload = p;
      return this;
    },
  };
  let nexted = false;
  mw(req, res, () => {
    nexted = true;
  });
  return { res, nexted };
};

// ---------- strict SQL injection / XSS ----------

const ATTACKS = [
  ['/login?u=admin%27--&p=x', ''],
  ['/q?id=1%27%20OR%20%271%27=%271', ''],
  ['/', JSON.stringify({ email: "x' or 1=1--", password: 'y' })],
  ['/p?id=1 UNION SELECT null,null,version()', ''],
  ['/p?id=%27)%20union%20select%20password%20from%20users', ''],
  ['/p?id=1%27%20AND%20SLEEP(5)--', ''],
  ["/p?id=1;WAITFOR DELAY '0:0:5'", ''],
  ['/p?id=1%27;DROP TABLE users--', ''],
  ['/p?id=extractvalue(1,concat(0x7e,version()))', ''],
  ['/p?q=1 and (select 1 from information_schema.tables)', ''],
  ['/s?q=%3Cscript%3Ealert(1)%3C/script%3E', ''],
  ['/s?q=<img src=x onerror=alert(1)>', ''],
  ['/s?q=<svg/onload=alert(1)>', ''],
  ['/r?next=javascript:alert(document.domain)', ''],
  ['/', JSON.stringify({ bio: '<iframe srcdoc=x>' })],
  ['/s?u=<a href="data:text/html;base64,xx">', ''],
];

// Ordinary input that a stricter rule must never block.
const ORDINARY = [
  ['/search?q=O%27Brien', ''],
  ['/', JSON.stringify({ name: "Tom's diner -- great food" })],
  ['/', JSON.stringify({ msg: "It's 5 o'clock; update the doc" })],
  ['/cms', JSON.stringify({ html: '<p>Hello <b>world</b> <a href="https://x.com">link</a></p>' })],
  ['/', JSON.stringify({ t: "Rock 'n' roll" })],
  ['/', JSON.stringify({ q: 'SELECT * FROM users is a SQL statement' })],
  ['/', JSON.stringify({ q: 'we union select vendors yearly' })],
  ['/', JSON.stringify({ q: 'javascript: the good parts' })],
  ['/', JSON.stringify({ h: '<a href="javascript:void(0)">x</a>' })],
  ['/', JSON.stringify({ q: "say 'hello' #greetings" })],
  ['/', JSON.stringify({ q: 'price >= 10 and qty <= 5' })],
  ['/', JSON.stringify({ c: "if (a == 'x' || b) {}" })],
  ['/', JSON.stringify({ q: "please don't drop table salt" })],
  ['/', JSON.stringify({ q: 'Design & code; also coffee' })],
  ['/', JSON.stringify({ html: '<button class="btn" data-online="1">Go</button>' })],
  ['/', JSON.stringify({ note: "I'm on it -- will update later" })],
  ['/api/auth/login', JSON.stringify({ email: "o'brien@example.com", password: 'x' })],
  ['/products?page=2&sort=price', ''],
];

test('strict SQL injection and XSS signatures block real payloads', () => {
  for (const [url, body] of ATTACKS) {
    const v = inspect(url, body);
    assert.equal(v.enforce, true, `should block: ${url} ${body}`);
    assert.ok(['sqli', 'xss'].includes(v.cls), `${url} classified as ${v.cls}`);
  }
});

test('strict signatures never block ordinary input', () => {
  for (const [url, body] of ORDINARY) {
    assert.equal(inspect(url, body).enforce, false, `must not block: ${url} ${body}`);
  }
});

// ---------- honeypot paths ----------

test('honeypot list matches scanner bait and nothing a real visitor requests', () => {
  for (const path of [
    '/.env',
    '/.env.production',
    '/.git/config',
    '/wp-admin/',
    '/wp-login.php',
    '/xmlrpc.php',
    '/phpmyadmin/',
    '/.aws/credentials',
    '/backup.sql',
    '/shell.php',
    '/actuator/env',
    '/server-status',
  ]) {
    assert.ok(matchHoneypot(path), `should be bait: ${path}`);
  }
  for (const path of [
    '/',
    '/pricing',
    '/security-testing/llm-security',
    '/api/auth/login',
    '/env',
    '/environment',
    '/git-guide',
    '/blog/wordpress-tips',
    '/admin',
    '/.well-known/security.txt',
    '/favicon.png',
  ]) {
    assert.ok(!matchHoneypot(path), `must not be bait: ${path}`);
  }
  assert.ok(HONEYPOT_PATHS instanceof RegExp);
});

const BAN = { enabled: true, enforce: true, threshold: 5, windowMs: 60_000, ttlMs: 15 * 60_000 };

test('self-defense: a honeypot hit returns 404 and bans that IP at once', () => {
  const d = createSelfDefense({ mode: 'enforce', ban: BAN });
  const hit = run(d.middleware, mkReq('GET', '/.env', { ip: '198.51.100.9' }));
  assert.equal(hit.res.code, 404);
  assert.equal(hit.nexted, false);
  assert.equal(d.recent()[0].cls, 'honeypot');
  assert.deepEqual(
    d.bans().map((b) => b.ip),
    ['198.51.100.9'],
  );
  const after = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.9' }));
  assert.equal(after.res.code, 403, 'the scanner is now refused everywhere');
  assert.match(after.res.payload.error, /repeat offender/);
  const other = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.10' }));
  assert.equal(other.nexted, true, 'other visitors are unaffected');
  d.stop();
});

test('self-defense: in monitor mode a honeypot hit is recorded but nothing is refused', () => {
  const events = [];
  const d = createSelfDefense({ mode: 'monitor', ban: { ...BAN, enforce: false }, onDetection: (e) => events.push(e) });
  const hit = run(d.middleware, mkReq('GET', '/wp-login.php'));
  assert.equal(hit.nexted, true);
  assert.equal(hit.res.code, null);
  assert.ok(events.some((e) => e.type === 'ban' && e.reason === 'honeypot' && e.enforce === false));
  assert.equal(run(d.middleware, mkReq('GET', '/pricing')).nexted, true);
  d.stop();
});

test('self-defense: honeypot can be switched off', () => {
  const d = createSelfDefense({ mode: 'enforce', ban: BAN, honeypot: false });
  assert.equal(run(d.middleware, mkReq('GET', '/.env')).nexted, true);
  d.stop();
});

test('self-defense: strict SQLi/XSS are blocked inline, ordinary text is not', () => {
  const d = createSelfDefense({ mode: 'enforce' });
  assert.equal(
    run(d.middleware, mkReq('POST', '/api/auth/login', { body: { email: "x' OR '1'='1", password: 'x' } })).res.code,
    403,
  );
  assert.equal(run(d.middleware, mkReq('GET', '/?q=<img src=x onerror=alert(1)>')).res.code, 403);
  assert.equal(
    run(d.middleware, mkReq('POST', '/api/auth/login', { body: { email: "o'brien@example.com", password: 'x' } }))
      .nexted,
    true,
  );
  d.stop();
});

test('self-defense: the assistant and finding evidence routes carry attack text and are not inspected', () => {
  for (const path of [
    '/api/assistant/chat',
    '/api/team/org_1/findings',
    '/api/team/org_1/findings/fnd_1',
    '/api/v1/scans',
  ]) {
    assert.ok(
      SELF_SKIP.some((r) => r.test(path)),
      path,
    );
  }
  assert.ok(!SELF_SKIP.some((r) => r.test('/api/auth/login')));
  const d = createSelfDefense({ mode: 'enforce' });
  const out = run(
    d.middleware,
    mkReq('POST', '/api/assistant/chat', { body: { message: "How do I fix ' OR '1'='1 in my login?" } }),
  );
  assert.equal(out.nexted, true);
  d.stop();
});

// ---------- persistent bans ----------

function memoryStore(initial = []) {
  const rows = new Map(initial.map((r) => [r.ip, r]));
  return {
    rows,
    load: async () => [...rows.values()],
    save: async (r) => {
      rows.set(r.ip, r);
    },
    remove: async (ip) => {
      rows.delete(ip);
    },
  };
}

test('bans are saved, removed on unban, and restored after a restart', async () => {
  const store = memoryStore();
  const first = createSelfDefense({ mode: 'enforce', ban: BAN, banStore: store, banSyncMs: 0 });
  run(first.middleware, mkReq('GET', '/.git/config', { ip: '192.0.2.44' }));
  await new Promise((r) => setImmediate(r));
  assert.equal(store.rows.get('192.0.2.44')?.reason, 'honeypot');
  first.stop();

  // A fresh process (redeploy) loads the ban and keeps refusing the scanner.
  const second = createSelfDefense({ mode: 'enforce', ban: BAN, banStore: store, banSyncMs: 0 });
  await second.ready;
  assert.equal(run(second.middleware, mkReq('GET', '/pricing', { ip: '192.0.2.44' })).res.code, 403);

  assert.equal(second.unban('192.0.2.44'), true);
  await new Promise((r) => setImmediate(r));
  assert.equal(store.rows.has('192.0.2.44'), false);
  assert.equal(run(second.middleware, mkReq('GET', '/pricing', { ip: '192.0.2.44' })).nexted, true);
  second.stop();
});

test('expired stored bans are ignored, and a broken store never breaks requests', async () => {
  const store = memoryStore([{ ip: '192.0.2.1', until: Date.now() - 1000 }]);
  const d = createSelfDefense({ mode: 'enforce', ban: BAN, banStore: store, banSyncMs: 0 });
  await d.ready;
  assert.equal(run(d.middleware, mkReq('GET', '/pricing', { ip: '192.0.2.1' })).nexted, true);
  d.stop();

  const broken = {
    load: async () => {
      throw new Error('db down');
    },
    save: async () => {
      throw new Error('db down');
    },
    remove: async () => {},
  };
  const e = createSelfDefense({ mode: 'enforce', ban: BAN, banStore: broken, banSyncMs: 0 });
  await e.ready;
  assert.equal(run(e.middleware, mkReq('GET', '/.env', { ip: '192.0.2.2' })).res.code, 404);
  assert.equal(
    run(e.middleware, mkReq('GET', '/pricing', { ip: '192.0.2.2' })).res.code,
    403,
    'in-memory ban still applies',
  );
  e.stop();
});

// ---------- customer SDK ----------

test('sdk: honeypot is off by default and opt-in', () => {
  const plain = shannonDefender({ mode: 'enforce' });
  assert.equal(run(plain, mkReq('GET', '/.env')).nexted, true, 'a customer site may really serve some of these');
  plain.stop();
  const opted = shannonDefender({ mode: 'enforce', honeypot: true });
  const out = run(opted, mkReq('GET', '/.env'));
  assert.equal(out.res.code, 404);
  assert.equal(opted.stats().blocked, 1);
  plain.stop();
  opted.stop();
});
