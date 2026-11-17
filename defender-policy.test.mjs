// Website protection settings: each organization sets its own in the dashboard, and its websites
// read them with the organization's key.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { pathToFileURL } from 'node:url';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-defender-policy-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'defender-policy-test-secret-that-is-long-enough';
process.env.SHANNON_ENCRYPTION_KEY = 'defender-policy-test-encryption-key';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.NODE_ENV = 'test';

const { DEFAULT_POLICY, DEFENDER_RULES, normalizePolicy, policyFor, sdkBundle } = await import(
  './packages/dashboard/defender-policy.mjs'
);
const { ENFORCE_CLASSES } = await import('./packages/defender-sdk/signatures.mjs');
const { startDashboard } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, key, body } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (key) headers.authorization = `Bearer ${key}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json = {};
  try {
    json = JSON.parse(text);
  } catch {}
  return {
    status: response.status,
    json,
    text,
    headers: response.headers,
    setCookie: response.headers.get('set-cookie') || '',
  };
}
let people = 0;
async function account() {
  people += 1;
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      email: `site-owner-${people}@example.test`,
      name: `Owner ${people}`,
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  assert.equal(out.status, 200);
  return { cookie: out.setCookie.split(';')[0] };
}

test('every blocking rule has a plain name, and the defaults are watch-only', () => {
  assert.deepEqual(DEFENDER_RULES.map((r) => r.id).sort(), [...ENFORCE_CLASSES].sort());
  for (const rule of DEFENDER_RULES) assert.ok(rule.label.length > 5 && rule.what.length > 20, rule.id);
  assert.equal(DEFAULT_POLICY.mode, 'monitor');
  assert.equal(DEFAULT_POLICY.enabled, true);
  assert.deepEqual(policyFor(null), policyFor({}));
  assert.equal(policyFor({ mode: 'enforce', junk: 1 }).mode, 'enforce');
  assert.equal(policyFor({ mode: 'nonsense' }).mode, 'monitor', 'a damaged record falls back to the safe defaults');
});

test('settings are checked before they are saved', () => {
  const ok = normalizePolicy({
    mode: 'enforce',
    disabled: ['sqli', 'sqli'],
    skip: '/api/webhooks\n  /health  \n\n',
    ban: { enabled: true, threshold: 999, minutes: 0 },
    rateLimit: { enabled: true, perMinute: 3 },
  });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.policy.disabled, ['sqli']);
  assert.deepEqual(ok.policy.skip, ['/api/webhooks', '/health']);
  assert.deepEqual(ok.policy.ban, { enabled: true, threshold: 50, minutes: 1 });
  assert.deepEqual(ok.policy.rateLimit, { enabled: true, perMinute: 10 });
  assert.match(normalizePolicy({ skip: ['api/x'] }).error, /must start with "\/"/);
  assert.match(normalizePolicy({ skip: ['/a b'] }).error, /not a page path/);
  assert.match(normalizePolicy({ skip: ['/'] }).error, /whole site/);
  assert.match(normalizePolicy({ skip: Array.from({ length: 51 }, (_, i) => `/p${i}`) }).error, /At most 50/);
  assert.match(normalizePolicy({ disabled: ['nope'] }).error, /not a rule/);
  assert.match(normalizePolicy({ mode: 'off' }).error, /watch only/);
  assert.equal(normalizePolicy(null).policy.mode, 'monitor');
});

test('each organization has its own settings, and its websites read them with its key', async () => {
  const a = await account();
  const b = await account();
  const first = await request('/api/defender/policy', { cookie: a.cookie });
  assert.equal(first.status, 200);
  assert.equal(first.json.policy.mode, 'monitor');
  assert.equal(first.json.rules.length, ENFORCE_CLASSES.length);
  assert.match(first.json.apiKey, /^sk_/);
  assert.equal(first.json.lastReportAt, null);

  const saved = await request('/api/defender/policy', {
    method: 'PUT',
    cookie: a.cookie,
    body: {
      policy: {
        mode: 'enforce',
        disabled: ['llm-prompt-injection'],
        skip: ['/api/webhooks'],
        honeypot: true,
        ban: { enabled: true, threshold: 4, minutes: 30 },
      },
    },
  });
  assert.equal(saved.status, 200);
  assert.equal(saved.json.policy.mode, 'enforce');

  // The website's view, with organization A's key.
  const site = await request('/api/defender/sdk/policy', { key: first.json.apiKey });
  assert.equal(site.status, 200);
  assert.equal(site.json.policy.mode, 'enforce');
  assert.deepEqual(site.json.policy.disabled, ['llm-prompt-injection']);
  assert.deepEqual(site.json.policy.skip, ['/api/webhooks']);
  assert.deepEqual(site.json.policy.ban, { enabled: true, threshold: 4, minutes: 30 });
  assert.ok(site.json.version > 0);
  assert.equal(site.headers.get('cache-control'), 'no-store');

  // Organization B is untouched, and its key gives its own settings.
  const other = await request('/api/defender/policy', { cookie: b.cookie });
  assert.equal(other.json.policy.mode, 'monitor');
  assert.notEqual(other.json.apiKey, first.json.apiKey);
  assert.equal((await request('/api/defender/sdk/policy', { key: other.json.apiKey })).json.policy.mode, 'monitor');

  // No key, a wrong key, no login.
  assert.equal((await request('/api/defender/sdk/policy')).status, 401);
  assert.equal((await request('/api/defender/sdk/policy', { key: 'sk_abc.def' })).status, 401);
  assert.equal((await request('/api/defender/policy')).status, 401);
  assert.equal((await request('/api/defender/policy', { method: 'PUT', body: { policy: {} } })).status, 401);

  const bad = await request('/api/defender/policy', {
    method: 'PUT',
    cookie: a.cookie,
    body: { policy: { skip: ['webhooks'] } },
  });
  assert.equal(bad.status, 400);
  assert.match(bad.json.error, /must start with/);
  assert.equal(
    (await request('/api/defender/sdk/policy', { key: first.json.apiKey })).json.policy.mode,
    'enforce',
    'a refused change leaves the settings as they were',
  );

  // A report from the website shows up as "last heard from".
  const reported = await request('/api/defender/report', {
    method: 'POST',
    key: first.json.apiKey,
    body: { detections: [{ method: 'GET', url: 'www.example.test/x', cls: 'sqli', enforced: true }] },
  });
  assert.equal(reported.json.accepted, 1);
  assert.ok((await request('/api/defender/policy', { cookie: a.cookie })).json.lastReportAt);
});

test('the one-file download is a working module for each kind of site', async () => {
  const who = await account();
  for (const [kind, name] of [
    ['web', 'createWebDefender'],
    ['express', 'shannonDefender'],
  ]) {
    const out = await request(`/api/defender/sdk/download/${kind}`, { cookie: who.cookie });
    assert.equal(out.status, 200);
    assert.match(out.headers.get('content-disposition'), /attachment; filename="securovix-defender/);
    assert.ok(!out.text.includes("from './signatures.mjs'"), 'it does not need a second file');
    assert.equal(out.text, sdkBundle(kind));
    const file = join(dataDir, `bundle-${kind}.mjs`);
    writeFileSync(file, out.text);
    const mod = await import(pathToFileURL(file).href);
    assert.equal(typeof mod[name], 'function');
    assert.equal(mod.inspect('/f?p=../../etc/passwd', '').enforce, true);
  }
  const web = await import(pathToFileURL(join(dataDir, 'bundle-web.mjs')).href);
  const defend = web.createWebDefender({ mode: 'enforce' });
  assert.equal((await defend(new Request('https://shop.example.test/f?p=../../etc/passwd'))).status, 403);
  assert.equal(await defend(new Request('https://shop.example.test/pricing')), null);
  assert.equal((await request('/api/defender/sdk/download/other', { cookie: who.cookie })).status, 404);
  assert.equal((await request('/api/defender/sdk/download/web')).status, 401);
});
