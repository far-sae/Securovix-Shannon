// The AI Agent's run, through its real routes, against small sites served on this machine.
// What matters in the real world: runs do not disturb each other, and a site that could not be
// checked is never reported as clean.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-agent-run-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'agent-run-test-secret-that-is-long-enough';
process.env.SHANNON_ENCRYPTION_KEY = 'agent-run-test-encryption-key';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.NODE_ENV = 'test';
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);

const { countProbeTasks, runAgentCampaign, runAgentLoop } = await import('./packages/dashboard/agent-loop.mjs');
const { startDashboard, withEngine } = await import('./packages/dashboard/server.mjs');
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
  rmSync(dataDir, { recursive: true, force: true });
});

// A small website. `answer(req, n)` may return a status to refuse request number n.
async function site(answer = () => null) {
  let n = 0;
  const s = http.createServer((req, res) => {
    n += 1;
    const refuse = answer(req, n);
    if (refuse) {
      res.writeHead(refuse, { 'content-type': 'text/html' });
      return res.end('<html><body>Access denied</body></html>');
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
        '<h1>Shop</h1><a href="/products?page=1">Products</a> <a href="/about">About</a><form method="get" action="/search"><input name="q"><button>Search</button></form>',
      );
    if (path === '/products') return page('<h1>Products</h1><a href="/products?page=2">Next</a> <a href="/">Home</a>');
    if (path === '/about') return page('<h1>About us</h1><a href="/">Home</a>');
    if (path === '/search') return page('<h1>Results</h1><p>Nothing found.</p>');
    res.writeHead(404, { 'content-type': 'text/html' });
    res.end('<html><body>Not found</body></html>');
  });
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  sites.push(s);
  return { url: `http://127.0.0.1:${s.address().port}`, requests: () => n };
}

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
      email: `agent-run-${people}@example.test`,
      name: `Tester ${people}`,
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  assert.equal(out.status, 200);
  return out.setCookie.split(';')[0];
}

const SURFACE = {
  origin: 'https://shop.example.test',
  pages: Array.from({ length: 12 }, (_, i) => ({ url: `https://shop.example.test/p${i}?id=${i}` })),
  forms: [],
  apiPaths: [],
};

test('a check that could not run is counted, and the result is not called clean', async () => {
  const failing = async (key) => {
    if (key === 'sqli' || key === 'xss') throw new Error('socket hang up');
    return [];
  };
  const loop = await runAgentLoop({ surface: SURFACE, probe: failing });
  assert.ok(loop.stats.errors > 0);
  assert.match(loop.steps.at(-1).detail, /could not run\. This is not a clean result\./);
  const clean = await runAgentLoop({ surface: SURFACE, probe: async () => [] });
  assert.equal(clean.stats.errors, 0);
  assert.match(clean.steps.at(-1).detail, /No vulnerabilities confirmed/);
  const found = await runAgentLoop({
    surface: SURFACE,
    probe: async (key) =>
      key === 'ssrf' ? [{ detail: 'proven', severity: 'high' }] : key === 'xss' ? Promise.reject(new Error('x')) : [],
  });
  assert.match(found.steps.at(-1).detail, /PROVEN with a benign proof marker\. \d+ of \d+ checks could not run\./);
});

test('a run says how much of the site it covered', async () => {
  const quick = await runAgentCampaign({ surface: SURFACE, probe: async () => [], maxRounds: 1 });
  assert.equal(quick.stats.possible, countProbeTasks(SURFACE));
  assert.ok(quick.stats.tested < quick.stats.possible, 'the quick depth leaves checks out, and says so');
  const deep = await runAgentCampaign({
    surface: SURFACE,
    probe: async () => [],
    maxRounds: 1,
    maxTasks: 240,
    maxPer: 40,
  });
  assert.equal(deep.stats.tested, deep.stats.possible, 'a deeper run covers them all');
  assert.equal(deep.stats.errors, 0);
});

test('runs take turns with the checking engine, and one failing does not block the next', async () => {
  const order = [];
  const waits = [];
  const slow = (name, ms, fail) => async () => {
    order.push(`${name}:start`);
    await new Promise((resolve) => setTimeout(resolve, ms));
    order.push(`${name}:end`);
    if (fail) throw new Error(`${name} failed`);
    return name;
  };
  const a = withEngine(slow('a', 60, true));
  const b = withEngine(slow('b', 10), { onWait: (ahead) => waits.push(ahead) });
  const c = withEngine(slow('c', 1), { onWait: (ahead) => waits.push(ahead) });
  await assert.rejects(a, /a failed/);
  assert.equal(await b, 'b');
  assert.equal(await c, 'c');
  assert.deepEqual(order, ['a:start', 'a:end', 'b:start', 'b:end', 'c:start', 'c:end']);
  assert.deepEqual(waits, [1, 2], 'a waiting run is told how many are ahead of it');
});

test('a healthy site: the run reports its coverage and nothing invented', async () => {
  const cookie = await account();
  const shop = await site();
  const out = await request('/api/agent/run', { method: 'POST', cookie, body: { target: shop.url } });
  assert.equal(out.status, 200, JSON.stringify(out.json).slice(0, 300));
  const run = out.json.run;
  assert.equal(run.coverage.depth, 'quick');
  assert.ok(run.coverage.pages >= 3, `pages ${run.coverage.pages}`);
  assert.ok(run.coverage.checksRun >= 5, `checks ${run.coverage.checksRun}`);
  assert.equal(run.coverage.blocked, false);
  assert.equal(run.coverage.siteStatus, 200);
  assert.equal(run.coverage.checksFailed, 0);
  assert.ok(Array.isArray(run.findings) && Array.isArray(run.leads));
  assert.ok(!run.surface, 'the mapped site is not sent back');
  assert.ok(run.savedId);
  const saved = await request(`/api/agent/runs/${run.savedId}`, { cookie });
  assert.equal(saved.status, 200);

  const deeper = await request('/api/agent/run', {
    method: 'POST',
    cookie,
    body: { target: shop.url, depth: 'standard' },
  });
  assert.equal(deeper.json.run.coverage.depth, 'standard');
  const odd = await request('/api/agent/run', {
    method: 'POST',
    cookie,
    body: { target: shop.url, depth: 'everything' },
  });
  assert.equal(odd.json.run.coverage.depth, 'quick', 'an unknown depth is the quick one');
});

test('a site that refuses every request is an error with the reason, not a clean result', async () => {
  const cookie = await account();
  const walled = await site(() => 403);
  const out = await request('/api/agent/run', { method: 'POST', cookie, body: { target: walled.url } });
  assert.equal(out.status, 502);
  assert.match(
    out.json.error,
    /No page of http:\/\/127\.0\.0\.1:\d+ could be read \(it answered 403, which usually means a firewall/,
  );
  assert.equal(out.json.run, undefined);
});

test('a site that starts refusing part-way gives an incomplete result that says so', async () => {
  const cookie = await account();
  // Lets the site be mapped, then refuses everything, as a rate limit does.
  const limited = await site((_req, n) => (n > 12 ? 429 : null));
  const response = await fetch(`${base}/api/agent/run/stream?target=${encodeURIComponent(limited.url)}`, {
    headers: { cookie },
  });
  assert.equal(response.status, 200);
  const blocks = (await response.text()).split('\n\n').filter((block) => block.trim() && !block.startsWith(':'));
  const events = blocks.map((block) => ({
    event: /^event: (.*)$/m.exec(block)?.[1] || 'step',
    data: JSON.parse(/^data: (.*)$/m.exec(block)[1]),
  }));
  const done = events.find((e) => e.event === 'done');
  assert.ok(done, `no "done" event: ${JSON.stringify(events.slice(-2)).slice(0, 300)}`);
  assert.equal(done.data.run.coverage.blocked, true);
  assert.equal(done.data.run.coverage.siteStatus, 429);
  const warning = events.find((e) => e.data.phase === 'warning');
  assert.match(warning.data.detail, /does not mean the site is clean/);
});

test('scheduled monitoring records what it finds once, in the organization’s findings', async () => {
  const { runDueMonitors } = await import('./packages/dashboard/server.mjs');
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      email: 'agent-monitor@example.test',
      name: 'Monitor Owner',
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  const cookie = signup.setCookie.split(';')[0];
  const orgId = signup.json.organizations[0].id;
  // A site with no security headers at all: the header check has something real to report.
  const bare = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(
      '<!doctype html><html><head><title>Bare</title></head><body><h1>Bare</h1><a href="/">Home</a></body></html>',
    );
  });
  await new Promise((resolve) => bare.listen(0, '127.0.0.1', resolve));
  sites.push(bare);
  const target = `http://127.0.0.1:${bare.address().port}`;

  const added = await request('/api/agent/monitors', { method: 'POST', cookie, body: { target, intervalHours: 1 } });
  assert.equal(added.status, 200);
  const findings = async () => (await request(`/api/team/${orgId}/findings`, { cookie })).json.findings || [];
  assert.equal((await findings()).length, 0);

  await runDueMonitors();
  const first = await findings();
  assert.ok(first.length >= 1, 'the first scheduled run records what it found');
  assert.ok(first.every((f) => f.source === 'agent-monitor'));
  const runs = await request('/api/agent/runs', { cookie });
  assert.ok((runs.json.runs || []).some((r) => r.target === target));

  // The same finding an hour later is not recorded again.
  const monitors = (await request('/api/agent/monitors', { cookie })).json.monitors;
  assert.ok(monitors[0].lastRunAt > 0);
  const { touchMonitor } = await import('./packages/dashboard/db.mjs');
  touchMonitor(signup.json.user.id, monitors[0].id, 1);
  await runDueMonitors();
  assert.equal((await findings()).length, first.length, 'an unchanged finding is not added twice');
});
