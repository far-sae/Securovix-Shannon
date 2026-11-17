// What a protected site may send to the dashboard, how much of it is kept, and what a ban covers.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { BAN_EXEMPT, createSelfDefense } from './defender/middleware.mjs';
import { cleanDetection, createIntakeGate } from './packages/dashboard/defender-intake.mjs';
import { isPrivateAddress } from './packages/defender-edge/server.mjs';

test('a reported detection is stored only as fields of a known type and shape', () => {
  const clean = cleanDetection({
    method: 'get',
    url: 'www.example.test/?a=1',
    cls: 'SQLi',
    enforced: true,
    srcIp: '203.0.113.9',
    at: '2026-11-17T10:00:00Z',
  });
  assert.deepEqual(clean, {
    method: 'GET',
    url: 'www.example.test/?a=1',
    cls: 'sqli',
    enforced: true,
    srcIp: '203.0.113.9',
    at: '2026-11-17T10:00:00.000Z',
  });
  const hostile = cleanDetection({
    method: { toString: () => 'GET' },
    url: ['x'],
    cls: '<img src=x onerror=alert(1)>',
    enforced: 'true',
    srcIp: '203.0.113.9"><script>',
    at: 'yesterday',
  });
  assert.equal(hostile.method, '');
  assert.equal(hostile.url, '', 'only a string is a URL');
  assert.equal(hostile.cls, 'unknown', 'a class is a short name, never markup');
  assert.equal(hostile.enforced, false);
  assert.equal(hostile.srcIp, null, 'only an address is an address');
  assert.ok(Number.isFinite(Date.parse(hostile.at)));
  assert.equal(cleanDetection({ url: 'u'.repeat(5000) }).url.length, 300);
  assert.equal(cleanDetection({ srcIp: '2001:db8::1' }).srcIp, '2001:db8::1');
  assert.equal(cleanDetection(null).cls, 'unknown');
});

test('the per-minute allowance stores, then says once that it is full, then drops', () => {
  let t = 0;
  const gate = createIntakeGate({ perMinute: 3, now: () => t });
  assert.deepEqual(
    [1, 2, 3, 4, 5, 6].map(() => gate.admit('org-a', 'sdk')),
    ['store', 'store', 'store', 'overflow', 'drop', 'drop'],
  );
  assert.equal(gate.admit('org-b', 'sdk'), 'store', 'another organization has its own allowance');
  assert.equal(gate.admit('org-a', 'edge'), 'store', 'and so has another source');
  t = 60_000;
  assert.equal(gate.admit('org-a', 'sdk'), 'store', 'a new minute starts again');
});

test('one alert per kind of attack per minute, and memory stays bounded', () => {
  let t = 0;
  const gate = createIntakeGate({ now: () => t, maxKeys: 50 });
  assert.equal(gate.alertOnce('org-a', 'sdk|shop.example.test|sqli'), true);
  assert.equal(gate.alertOnce('org-a', 'sdk|shop.example.test|sqli'), false);
  assert.equal(gate.alertOnce('org-a', 'sdk|shop.example.test|xss'), true, 'a different kind is a different alert');
  assert.equal(gate.alertOnce('org-b', 'sdk|shop.example.test|sqli'), true);
  t = 60_000;
  assert.equal(gate.alertOnce('org-a', 'sdk|shop.example.test|sqli'), true);
  for (let i = 0; i < 500; i++) {
    gate.alertOnce(`org-${i}`, 'k');
    gate.admit(`org-${i}`, 'sdk');
  }
  assert.ok(gate.size() <= 100, `kept ${gate.size()} entries`);
});

test('private addresses are recognised however they are written', () => {
  for (const address of [
    '127.0.0.1',
    '10.1.2.3',
    '192.168.1.1',
    '172.20.0.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '198.18.0.1',
    '::1',
    '::',
    'fd00::1',
    'fe80::1',
    '[::1]',
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe',
    '0:0:0:0:0:ffff:7f00:1',
    '64:ff9b::a9fe:a9fe',
  ])
    assert.equal(isPrivateAddress(address), true, address);
  for (const address of ['8.8.8.8', '203.0.113.9', '2606:4700::1111', '::ffff:8.8.8.8', 'example.test', ''])
    assert.equal(isPrivateAddress(address), false, address);
});

// ---------- the dashboard's own filter: what a ban covers ----------
const mkReq = (method, url, { ip = '203.0.113.7' } = {}) => ({
  method,
  url,
  originalUrl: url,
  path: url.split('?')[0],
  body: undefined,
  headers: {},
  ip,
  socket: {},
});
const run = (mw, req) => {
  const res = { code: null, payload: null };
  res.status = (c) => {
    res.code = c;
    return res;
  };
  res.json = (p) => {
    res.payload = p;
    return res;
  };
  let nexted = false;
  mw(req, res, () => {
    nexted = true;
  });
  return { code: res.code, nexted };
};

test('a banned address is refused on the never-inspected paths too, but signed machine traffic gets through', () => {
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => 1_000_000,
    ban: { enabled: true, enforce: true, threshold: 3, windowMs: 60_000, ttlMs: 600_000 },
  });
  for (let i = 0; i < 3; i++)
    run(d.middleware, mkReq('GET', `/files?path=../../etc/passwd&i=${i}`, { ip: '198.51.100.3' }));
  for (const path of [
    '/api/scans',
    '/api/agent/run',
    '/api/assistant/chat',
    '/api/defender/overview',
    '/api/code-scan/run',
    '/pricing',
  ]) {
    const banned = run(d.middleware, mkReq('GET', path, { ip: '198.51.100.3' }));
    assert.equal(banned.code, 403, `${path} is refused for a banned address`);
    assert.equal(banned.nexted, false);
  }
  for (const path of [
    '/api/defender/report',
    '/api/defender/sdk/policy',
    '/api/platform/defender/edge/report',
    '/api/endpoint-agent/v1/checkin',
  ]) {
    assert.ok(BAN_EXEMPT.some((r) => r.test(path)));
    assert.equal(
      run(d.middleware, mkReq('POST', path, { ip: '198.51.100.3' })).nexted,
      true,
      `${path} still reaches its own key check`,
    );
  }
  assert.equal(
    run(d.middleware, mkReq('GET', '/api/scans', { ip: '198.51.100.4' })).nexted,
    true,
    'another address is untouched',
  );
});

test('the tables of addresses do not grow without limit', () => {
  let t = 1_000_000;
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => t,
    ban: { enabled: true, enforce: true, threshold: 3, windowMs: 60_000, ttlMs: 600_000 },
  });
  // 25,000 different addresses, one offence each (below the ban threshold).
  for (let i = 0; i < 25_000; i++) {
    t += 1;
    run(d.middleware, mkReq('GET', '/files?path=../../etc/passwd', { ip: `2001:db8::${i.toString(16)}` }));
  }
  assert.ok(d.stats().trackedAddresses <= 20_000, `tracking ${d.stats().trackedAddresses} addresses`);
});

// ---------- the real report route ----------
const dataDir = mkdtempSync(join(tmpdir(), 'shannon-intake-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'intake-test-secret-that-is-long-enough-0123',
  SHANNON_ENCRYPTION_KEY: 'intake-test-encryption-key',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_DEFENDER_INTAKE_PER_MINUTE: '50',
  NODE_ENV: 'test',
});
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);
const { startDashboard } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});
async function owner(email) {
  const signup = await fetch(`${base}/api/auth/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, name: 'Owner', password: 'correct-horse-battery-staple', acceptedTerms: true }),
  });
  const cookie = (signup.headers.get('set-cookie') || '').split(';')[0];
  const key = (await (await fetch(`${base}/api/defender/policy`, { headers: { cookie } })).json()).apiKey;
  return { cookie, key };
}
const report = (key, detections) =>
  fetch(`${base}/api/defender/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
    body: JSON.stringify({ detections }),
  });
const overview = async (cookie) => (await fetch(`${base}/api/defender/overview`, { headers: { cookie } })).json();
const hit = (n, extra = {}) => ({
  method: 'GET',
  url: `shop.example.test/?id=${n}`,
  cls: 'sqli',
  enforced: false,
  srcIp: '203.0.113.7',
  ...extra,
});

test('a flood of reports cannot push an organization’s history out: the rest of the minute is one notice', async () => {
  const site = await owner('flooded-site@example.test');
  // One real attack first, then a flood through the same key.
  await report(site.key, [hit('first', { cls: 'path-traversal', url: 'shop.example.test/?file=../../etc/passwd' })]);
  const answers = [];
  for (let i = 0; i < 4; i++)
    answers.push(
      await (
        await report(
          site.key,
          Array.from({ length: 200 }, (_, n) => hit(`${i}-${n}`)),
        )
      ).json(),
    );
  assert.equal(
    answers.reduce((sum, a) => sum + a.accepted, 0),
    49,
    'only the minute’s allowance is stored',
  );
  const seen = await overview(site.cookie);
  assert.equal(seen.stats.total, 51, '1 earlier attack + 49 stored + 1 notice');
  const notice = seen.events.find((event) => event.cls === 'report-flood');
  assert.ok(notice, 'the owner is told once');
  assert.match(notice.url, /more than 50 detections in one minute/);
  assert.equal(seen.events.filter((event) => event.cls === 'report-flood').length, 1);
  assert.ok(
    seen.events.some((event) => event.cls === 'path-traversal'),
    'the earlier attack is still in view',
  );
});

test('what a report says is stored as plain, bounded fields', async () => {
  const site = await owner('odd-reports@example.test');
  await report(site.key, [
    {
      method: 'get',
      url: 'shop.example.test/?q=1',
      cls: '<svg onload=alert(1)>',
      srcIp: 'not-an-address',
      enforced: 'yes',
    },
    'text',
    null,
    [1],
  ]);
  const seen = await overview(site.cookie);
  assert.equal(seen.events.length, 1, 'things that are not detections are ignored');
  const [event] = seen.events;
  assert.equal(event.cls, 'unknown');
  assert.equal(event.method, 'GET');
  assert.equal(event.srcIp, null);
  assert.equal(event.enforced, false);
  assert.equal(event.severity, 'low');
});

test('reports are limited per organization, whatever address they come from', async () => {
  const site = await owner('chatty-site@example.test');
  const statuses = [];
  for (let i = 0; i < 260; i++) statuses.push((await report(site.key, [])).status);
  assert.equal(statuses.filter((s) => s === 200).length, 240);
  assert.equal(statuses.filter((s) => s === 429).length, 20);
  const other = await owner('quiet-site@example.test');
  assert.equal((await report(other.key, [hit(1)])).status, 200, 'another organization is not affected');
});
