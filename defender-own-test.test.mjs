// The AI Agent testing a site its own organization protects with Defender.
// What matters in the real world: the organization's own tests are filed as tests and not as
// critical attacks, nobody else can get an attack filed as a test, and the mark never lets a
// request past the protection.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

const SECRET = 'own-test-test-secret-that-is-long-enough';
const dataDir = mkdtempSync(join(tmpdir(), 'shannon-own-test-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = SECRET;
process.env.SHANNON_ENCRYPTION_KEY = 'own-test-test-encryption-key';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.SHANNON_EDGE_PLATFORM_TOKEN = 'own-test-edge-platform-token-long-enough';
process.env.SHANNON_OWN_TEST_SETTLE_MS = '20';
process.env.NODE_ENV = 'test';
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);

const { OWN_TEST_HEADER, OWN_TEST_TTL_MS, createOwnTestLedger, isOwnTest, signOwnTest, siteName, verifyOwnTest } =
  await import('./packages/dashboard/defender-own-test.mjs');
const { fetchT, setScanOrigin, setSessionHeaders, setTestMark } = await import('./purple-engine.mjs');
const { createWebDefender } = await import('./packages/defender-sdk/web.mjs');
const { shannonDefender } = await import('./packages/defender-sdk/index.mjs');
const database = await import('./packages/dashboard/db.mjs');
const { startDashboard, runDueMonitors } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
const sites = [];
after(async () => {
  for (const site of sites) {
    site.closeAllConnections?.();
    await new Promise((resolve) => site.close(resolve));
  }
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  await sleep(60); // let a held-back save finish before its folder goes
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    json: await response.json().catch(() => ({})),
    setCookie: response.headers.get('set-cookie') || '',
  };
}
let people = 0;
async function account() {
  people += 1;
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      email: `own-test-${people}@example.test`,
      name: `Owner ${people}`,
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  assert.equal(out.status, 200);
  const cookie = out.setCookie.split(';')[0];
  const key = (await request('/api/defender/policy', { cookie })).json.apiKey;
  assert.match(key, /^sk_/);
  return { cookie, key, orgId: out.json.organizations[0].id, userId: out.json.user.id };
}

// A small website with Defender in front of it, reporting to the dashboard with the owner's key.
// It takes its settings (watch-only unless the owner changed them) from the dashboard, like a real one.
async function protectedSite(key) {
  const waited = [];
  const seen = [];
  const detections = [];
  const defend = createWebDefender({ apiKey: key, endpoint: base, onDetection: (d) => detections.push(d) });
  const s = http.createServer(async (req, res) => {
    seen.push({ url: req.url, mark: req.headers[OWN_TEST_HEADER] || null });
    const refused = await defend(
      new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: req.headers }),
      { waitUntil: (p) => waited.push(p) },
    );
    if (refused) {
      res.writeHead(refused.status, { 'content-type': 'application/json' });
      return res.end(await refused.text());
    }
    const page = (body) => {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=63072000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'no-referrer',
      });
      res.end(`<!doctype html><html><head><title>Shop</title></head><body>${body}</body></html>`);
    };
    const path = req.url.split('?')[0];
    if (path === '/')
      return page(
        '<h1>Shop</h1><a href="/products?page=1">Products</a><form method="get" action="/search"><input name="q"><input name="email"><button>Search</button></form>',
      );
    if (path === '/products') return page('<h1>Products</h1><a href="/">Home</a>');
    if (path === '/search') return page('<h1>Results</h1><p>Nothing found.</p>');
    res.writeHead(404, { 'content-type': 'text/html' });
    res.end('<html><body>Not found</body></html>');
  });
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  sites.push(s);
  const url = `http://127.0.0.1:${s.address().port}`;
  return {
    url,
    host: new URL(url).host,
    seen,
    detections,
    // Every report the site has started has reached the dashboard.
    settled: async () => {
      while (waited.length) await waited.shift();
    },
  };
}
const eventsOf = async (cookie) => (await request('/api/defender/events?limit=500', { cookie })).json.events || [];
const ATTACK = `/search?q=${encodeURIComponent("' OR '1'='1")}`;
const sum = (counts) => Object.values(counts).reduce((a, b) => a + b, 0);

test('a mark is good only for the organization and the site it was signed for, and only for a while', () => {
  const now = Date.UTC(2026, 10, 17, 12);
  const mark = signOwnTest(SECRET, { orgId: 'org_a', target: 'https://securovix.com', kind: 'monitor', now });
  assert.equal(mark.header, 'x-securovix-test');
  assert.equal(mark.site, 'securovix.com');
  const at = (extra) => verifyOwnTest(SECRET, mark.value, { orgId: 'org_a', url: 'securovix.com/?q=1', now, ...extra });
  assert.deepEqual(at(), { kind: 'monitor' });
  assert.deepEqual(
    at({ url: "www.securovix.com/?name=' OR '1'='1" }),
    { kind: 'monitor' },
    'the www twin is the same site',
  );
  assert.deepEqual(at({ url: 'https://WWW.Securovix.com:443/x' }), { kind: 'monitor' });
  assert.equal(at({ orgId: 'org_b' }), null, 'another organization');
  assert.equal(at({ url: 'other.example/?q=1' }), null, 'another site');
  assert.equal(at({ url: 'securovix.com.evil.example/' }), null, 'a look-alike site');
  assert.equal(at({ now: now + OWN_TEST_TTL_MS + 1 }), null, 'out of date');
  assert.deepEqual(at({ now: now + OWN_TEST_TTL_MS - 1 }), { kind: 'monitor' });
  assert.equal(verifyOwnTest('another-secret', mark.value, { orgId: 'org_a', url: 'securovix.com/', now }), null);
  const parts = mark.value.split('.');
  const later = [parts[0], parts[1], (Number.parseInt(parts[2], 36) + 3_600_000).toString(36), parts[3]].join('.');
  assert.equal(verifyOwnTest(SECRET, later, { orgId: 'org_a', url: 'securovix.com/', now }), null, 'a stretched date');
  const renamed = [parts[0], 'agent', parts[2], parts[3]].join('.');
  assert.equal(verifyOwnTest(SECRET, renamed, { orgId: 'org_a', url: 'securovix.com/', now }), null);
  for (const junk of ['', 'v1', 'v1.monitor.zz.short', `v2.${parts.slice(1).join('.')}`, 'x'.repeat(500), null, 42, {}])
    assert.equal(verifyOwnTest(SECRET, junk, { orgId: 'org_a', url: 'securovix.com/', now }), null);
  assert.equal(signOwnTest('', { orgId: 'org_a', target: 'https://securovix.com' }), null, 'nothing to sign with');
  assert.equal(signOwnTest(SECRET, { orgId: 'org_a', target: 'https://securovix.com', kind: 'nonsense' }), null);
  assert.equal(siteName('http://[::1]:3000/x'), '[::1]');
  assert.equal(siteName(''), '');
  assert.equal(isOwnTest({ metadata: { ownTest: { kind: 'agent' } } }), true);
  assert.equal(isOwnTest({ metadata: {} }), false);
});

test('a run is stored once, and its later reports are counted on that one entry', async () => {
  const appended = [];
  const updated = [];
  let id = 0;
  const ledger = createOwnTestLedger({
    append: (event) => appended.push(event),
    update: (orgId, eventId, patch) => updated.push({ orgId, eventId, patch }),
    newId: () => `event-${++id}`,
    settleMs: 15,
  });
  const report = (token, detection, orgId = 'org_a') =>
    ledger.record({ orgId, userId: 'u1', source: 'sdk', token, kind: 'monitor', site: 'www.shop.example', detection });
  const first = report('mark-1', { cls: 'sqli', enforced: false, srcIp: '203.0.113.9' });
  assert.equal(appended.length, 1);
  assert.deepEqual(
    { ...first, id: 0, at: 0, createdAt: 0, metadata: 0 },
    {
      id: 0,
      orgId: 'org_a',
      userId: 'u1',
      at: 0,
      method: 'TEST',
      url: 'www.shop.example',
      cls: 'own-test',
      enforced: false,
      srcIp: '203.0.113.9',
      severity: 'info',
      source: 'sdk',
      status: 'closed',
      metadata: 0,
      createdAt: 0,
    },
  );
  assert.deepEqual(
    { ...first.metadata.ownTest, lastAt: 0 },
    { kind: 'monitor', requests: 1, blocked: 0, classes: { sqli: 1 }, lastAt: 0 },
  );
  report('mark-1', { cls: 'sqli', enforced: true });
  report('mark-1', { cls: 'xss', enforced: false });
  assert.equal(appended.length, 1, 'still one entry');
  assert.equal(report('mark-1', { cls: 'xss' }), first, 'the same entry');
  assert.deepEqual(
    { ...first.metadata.ownTest, lastAt: 0 },
    { kind: 'monitor', requests: 4, blocked: 1, classes: { sqli: 2, xss: 2 }, lastAt: 0 },
  );
  assert.equal(updated.length, 0, 'the save is held back while reports arrive');
  await sleep(60);
  assert.equal(updated.length, 1, 'and then made once');
  assert.equal(updated[0].eventId, first.id);
  assert.equal(updated[0].patch.metadata.ownTest.requests, 4);
  // Another run, and another organization's run, are entries of their own.
  report('mark-2', { cls: 'sqli' });
  report('mark-1', { cls: 'sqli' }, 'org_b');
  assert.equal(appended.length, 3);
  assert.deepEqual(
    appended.map((e) => e.orgId),
    ['org_a', 'org_a', 'org_b'],
  );
  assert.equal(first.metadata.ownTest.requests, 4);
});

test('the engine sends the mark to the site under test and nowhere else, and drops it after the run', async () => {
  const got = [];
  const listen = async (name, handler) => {
    const s = http.createServer((req, res) => {
      got.push({ name, url: req.url, mark: req.headers[OWN_TEST_HEADER] || null, cookie: req.headers.cookie || null });
      handler(req, res);
    });
    await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
    sites.push(s);
    return `http://127.0.0.1:${s.address().port}`;
  };
  const ok = (req, res) => res.end('ok');
  const other = await listen('other', ok);
  const main = await listen('main', (req, res) => {
    if (req.url.startsWith('/go')) {
      res.writeHead(302, { location: `${other}/landed` });
      return res.end();
    }
    res.end('ok');
  });
  try {
    setScanOrigin(main);
    setSessionHeaders({ cookie: 'session=1' });
    // Both servers share a host name here, so the mark is told apart by port: main only.
    const mainPort = new URL(main).port;
    setTestMark({ header: OWN_TEST_HEADER, value: 'v1.agent.x.y', applies: (url) => new URL(url).port === mainPort });
    await fetchT(`${main}/page`);
    await fetchT(`${other}/elsewhere`);
    assert.deepEqual(got.splice(0), [
      { name: 'main', url: '/page', mark: 'v1.agent.x.y', cookie: 'session=1' },
      { name: 'other', url: '/elsewhere', mark: null, cookie: null },
    ]);
    // A redirect inside the same site (plain name to its www twin) keeps the mark, never the login.
    setTestMark({ header: OWN_TEST_HEADER, value: 'v1.agent.x.y', applies: (url) => siteName(url) === '127.0.0.1' });
    await fetchT(`${main}/go`);
    assert.deepEqual(got.splice(0), [
      { name: 'main', url: '/go', mark: 'v1.agent.x.y', cookie: 'session=1' },
      { name: 'other', url: '/landed', mark: 'v1.agent.x.y', cookie: null },
    ]);
    // A mark that is not complete is no mark, and a failing rule never breaks a request.
    setTestMark({ header: OWN_TEST_HEADER, value: 'v1.agent.x.y' });
    await fetchT(`${main}/page`);
    setTestMark({
      header: OWN_TEST_HEADER,
      value: 'v1.agent.x.y',
      applies: () => {
        throw new Error('boom');
      },
    });
    assert.equal((await fetchT(`${main}/page`)).status, 200);
    setTestMark(null);
    await fetchT(`${main}/page`);
    assert.deepEqual(
      got.splice(0).map((g) => g.mark),
      [null, null, null],
    );
  } finally {
    setTestMark(null);
    setSessionHeaders({});
    setScanOrigin(null);
  }
});

test('the AI Agent’s own run is filed as one test; anyone else’s attack is still an attack', async () => {
  const owner = await account();
  const shop = await protectedSite(owner.key);

  const out = await request('/api/agent/run', { method: 'POST', cookie: owner.cookie, body: { target: shop.url } });
  assert.equal(out.status, 200, JSON.stringify(out.json).slice(0, 300));
  await shop.settled();
  const afterRun = await eventsOf(owner.cookie);
  assert.equal(afterRun.length, 1, 'one entry for the whole run');
  const [entry] = afterRun;
  assert.equal(entry.cls, 'own-test');
  assert.equal(entry.method, 'TEST');
  assert.equal(entry.url, shop.host);
  assert.equal(entry.severity, 'info');
  assert.equal(entry.status, 'closed');
  assert.equal(entry.source, 'sdk');
  const filed = entry.metadata.ownTest;
  assert.equal(filed.kind, 'agent');
  assert.ok(filed.requests >= 2, 'several attack-shaped requests were caught');
  assert.equal(filed.requests, shop.detections.length, 'every one of them is on the entry');
  assert.ok(
    shop.detections.every((d) => d.test),
    'and every one carried the mark',
  );
  assert.equal(sum(filed.classes), filed.requests);
  assert.equal(filed.blocked, 0);
  const mark = shop.seen.find((r) => r.mark).mark;
  assert.deepEqual(verifyOwnTest(SECRET, mark, { orgId: owner.orgId, url: shop.url }), { kind: 'agent' });
  // After the run the engine carries no mark: the next request to the site is unmarked.
  shop.seen.length = 0;

  // 1. An attacker, with no mark.
  await fetch(shop.url + ATTACK);
  // 2. An attacker who makes a mark up.
  await fetch(shop.url + ATTACK, {
    headers: { [OWN_TEST_HEADER]: 'v1.agent.zzzzzzzz.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  });
  // 3. A real mark, but one signed for another organization (its own Agent testing its own site).
  const stranger = signOwnTest(SECRET, { orgId: 'org_someone_else', target: shop.url, kind: 'agent' });
  await fetch(shop.url + ATTACK, { headers: { [OWN_TEST_HEADER]: stranger.value } });
  // 4. This organization's mark, but for a different site of theirs.
  const elsewhere = signOwnTest(SECRET, { orgId: owner.orgId, target: 'https://shop.example.test', kind: 'agent' });
  await fetch(shop.url + ATTACK, { headers: { [OWN_TEST_HEADER]: elsewhere.value } });
  // 5. This organization's mark for this site, kept from an old run.
  const old = signOwnTest(SECRET, {
    orgId: owner.orgId,
    target: shop.url,
    kind: 'agent',
    now: Date.now() - OWN_TEST_TTL_MS - 60_000,
  });
  await fetch(shop.url + ATTACK, { headers: { [OWN_TEST_HEADER]: old.value } });
  await shop.settled();

  const all = await eventsOf(owner.cookie);
  const attacks = all.filter((e) => !e.metadata?.ownTest);
  assert.equal(all.length, 6);
  assert.equal(attacks.length, 5, 'none of the five was filed as a test');
  for (const event of attacks) {
    assert.equal(event.cls, 'sqli');
    assert.equal(event.severity, 'critical');
    assert.equal(event.status, 'open');
  }

  // The Defender page: the numbers and the incident list are attacks; the tests are summed up apart.
  const overview = (await request('/api/defender/overview', { cookie: owner.cookie })).json;
  assert.equal(overview.stats.total, 5);
  assert.equal(overview.stats.critical, 5);
  assert.equal(overview.stats.open, 5);
  assert.equal(overview.stats.last24h, 5);
  assert.equal(overview.events.length, 5);
  assert.ok(overview.events.every((e) => !e.metadata?.ownTest));
  assert.deepEqual(
    overview.topClasses.map((c) => [c.name, c.count]),
    [['sqli', 5]],
  );
  assert.deepEqual(
    { ...overview.ownTests, lastAt: 0, recent: overview.ownTests.recent.map((e) => e.id) },
    { runs: 1, runs24h: 1, requests: filed.requests, blocked: 0, lastAt: 0, recent: [entry.id] },
  );
});

test('the scheduled monitor’s run is filed as a test too, one entry each time it runs', async () => {
  const owner = await account();
  const shop = await protectedSite(owner.key);
  const added = await request('/api/agent/monitors', {
    method: 'POST',
    cookie: owner.cookie,
    body: { target: shop.url, intervalHours: 1 },
  });
  assert.equal(added.status, 200);
  await runDueMonitors();
  await shop.settled();
  const events = await eventsOf(owner.cookie);
  assert.equal(events.length, 1);
  assert.equal(events[0].metadata.ownTest.kind, 'monitor');
  assert.equal(events[0].metadata.ownTest.requests, shop.detections.length);

  const monitors = (await request('/api/agent/monitors', { cookie: owner.cookie })).json.monitors;
  database.touchMonitor(owner.userId, monitors[0].id, 1);
  await runDueMonitors();
  await shop.settled();
  const again = await eventsOf(owner.cookie);
  assert.equal(again.length, 2, 'the next hour’s run is a second entry');
  assert.ok(again.every((e) => e.metadata.ownTest.kind === 'monitor'));
  const overview = (await request('/api/defender/overview', { cookie: owner.cookie })).json;
  assert.equal(overview.stats.total, 0);
  assert.equal(overview.stats.critical, 0);
  assert.equal(overview.events.length, 0);
  assert.equal(overview.ownTests.runs, 2);
  assert.equal(overview.ownTests.requests, shop.detections.length);
});

test('the mark gets nothing through: with blocking on, a marked attack is refused like any other', async () => {
  const owner = await account();
  const mark = signOwnTest(SECRET, { orgId: owner.orgId, target: 'https://www.example.test', kind: 'agent' });
  const seen = [];
  const defend = createWebDefender({ mode: 'enforce', onDetection: (d) => seen.push(d) });
  const attack = (headers) => new Request(`https://www.example.test${ATTACK}`, { headers });
  assert.equal((await defend(attack({})))?.status, 403);
  assert.equal((await defend(attack({ [OWN_TEST_HEADER]: mark.value })))?.status, 403, 'a valid mark is not a pass');
  assert.equal(seen[0].test, undefined);
  assert.equal(seen[1].test, mark.value);
  assert.equal(seen[1].enforced, true);
  // An ordinary request is never reported, marked or not.
  assert.equal(
    await defend(
      new Request('https://www.example.test/search?q=shoes', { headers: { [OWN_TEST_HEADER]: mark.value } }),
    ),
    null,
  );
  assert.equal(seen.length, 2);

  // The same through the dashboard: a blocked test is filed as a test that was blocked.
  const saved = await request('/api/defender/policy', {
    method: 'PUT',
    cookie: owner.cookie,
    body: { policy: { mode: 'enforce' } },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.json).slice(0, 200));
  const shop = await protectedSite(owner.key);
  const fresh = signOwnTest(SECRET, { orgId: owner.orgId, target: shop.url, kind: 'agent' });
  assert.equal((await fetch(shop.url + ATTACK, { headers: { [OWN_TEST_HEADER]: fresh.value } })).status, 403);
  await shop.settled();
  const events = await eventsOf(owner.cookie);
  assert.equal(events.length, 1);
  assert.deepEqual(
    { ...events[0].metadata.ownTest, lastAt: 0 },
    { kind: 'agent', requests: 1, blocked: 1, classes: { sqli: 1 }, lastAt: 0 },
  );
  assert.equal(events[0].status, 'closed');
  const overview = (await request('/api/defender/overview', { cookie: owner.cookie })).json;
  assert.equal(overview.stats.blocked, 0, 'a blocked test is not a blocked attack');
  assert.equal(overview.ownTests.blocked, 1);
});

test('the Express package passes the mark on with the site’s name, and the dashboard files it', async () => {
  const owner = await account();
  const seen = [];
  const guard = shannonDefender({ apiKey: owner.key, endpoint: base, onDetection: (d) => seen.push(d) });
  try {
    const mark = signOwnTest(SECRET, { orgId: owner.orgId, target: 'https://app.example.test', kind: 'team' });
    const call = (headers) =>
      new Promise((resolve) => {
        guard({ method: 'GET', url: ATTACK, originalUrl: ATTACK, path: '/search', headers, socket: {} }, {}, resolve);
      });
    await call({ host: 'www.app.example.test', [OWN_TEST_HEADER]: mark.value });
    await call({ host: 'www.app.example.test' });
    assert.equal(seen[0].test, mark.value);
    assert.equal(seen[0].host, 'www.app.example.test');
    assert.equal(seen[1].test, undefined);
    assert.equal(seen[1].host, undefined);
    await guard.flush();
    const events = await eventsOf(owner.cookie);
    assert.equal(events.length, 2);
    const own = events.find((e) => e.metadata?.ownTest);
    assert.equal(own.metadata.ownTest.kind, 'team');
    assert.equal(own.url, 'www.app.example.test');
    assert.equal(events.filter((e) => e.severity === 'critical' && e.status === 'open').length, 1);
  } finally {
    guard.stop();
  }
});

test('a site behind the shared edge: its own test is filed as a test, per organization', async () => {
  const owner = await account();
  const neighbour = await account();
  const route = (host, who) =>
    database.saveEdgeRoute({
      host,
      origin: 'https://origin.example.test',
      mode: 'monitor',
      orgId: who.orgId,
      userId: who.userId,
      createdAt: Date.now(),
    });
  route('shop.edge.example.test', owner);
  route('next.edge.example.test', neighbour);
  const mine = signOwnTest(SECRET, { orgId: owner.orgId, target: 'https://shop.edge.example.test', kind: 'agent' });
  const report = await fetch(`${base}/api/platform/defender/edge/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.SHANNON_EDGE_PLATFORM_TOKEN}` },
    body: JSON.stringify({
      detections: [
        {
          host: 'shop.edge.example.test',
          method: 'GET',
          url: 'shop.edge.example.test/?q=1',
          cls: 'sqli',
          enforced: false,
          test: mine.value,
        },
        {
          host: 'shop.edge.example.test',
          method: 'GET',
          url: 'shop.edge.example.test/?q=2',
          cls: 'sqli',
          enforced: false,
        },
        // The owner's mark arriving at the neighbour's site belongs to nobody there.
        {
          host: 'next.edge.example.test',
          method: 'GET',
          url: 'next.edge.example.test/?q=3',
          cls: 'sqli',
          enforced: false,
          test: mine.value,
        },
      ],
    }),
  });
  assert.equal((await report.json()).accepted, 3);
  const own = await eventsOf(owner.cookie);
  assert.equal(own.length, 2);
  const filed = own.find((e) => e.metadata?.ownTest);
  assert.equal(filed.source, 'edge');
  assert.equal(filed.metadata.host, 'shop.edge.example.test');
  assert.equal(filed.metadata.ownTest.kind, 'agent');
  assert.equal(filed.metadata.ownTest.requests, 1);
  assert.equal(own.find((e) => !e.metadata?.ownTest).severity, 'critical');
  const theirs = await eventsOf(neighbour.cookie);
  assert.equal(theirs.length, 1);
  assert.equal(theirs[0].severity, 'critical');
  assert.equal(theirs[0].metadata.ownTest, undefined);
});
