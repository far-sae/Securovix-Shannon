import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { applyLlmJudgment, classify } from './defender/classify.mjs';
import { httpProxyConnector } from './defender/connectors.mjs';
import { applyResponse, makeRateLimiter } from './defender/respond.mjs';
import { buildCompositeFilter } from './purple-engine.mjs';

// ---------- composite signature matcher ----------
test('composite filter: flags an SSTI payload with its class', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/?q={{7*7}}', ''), 'rce-ssti');
});
test('composite filter: flags an XSS payload', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/search?q=<script>alert(1)</script>', ''), 'xss');
});
test('composite filter: matches on the request BODY too', () => {
  const match = buildCompositeFilter();
  assert.ok(match('/login', 'user=admin&note={{7*7}}'));
});
test('composite filter: abstains on benign traffic (zero-FP)', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/products?page=2&sort=price', ''), null);
  assert.equal(match('/api/users/42', '{"name":"Ada Lovelace"}'), null);
});
test('composite filter: a throwing prober filter never breaks matching', () => {
  const match = buildCompositeFilter();
  assert.doesNotThrow(() => match('/%E0%A4%A', ''));
});

const httpEvent = (url, body = '') => ({
  at: '2026-09-15T00:00:00.000Z',
  source: 'http-proxy',
  srcIp: '10.0.0.9',
  method: 'GET',
  url,
  headers: {},
  body,
  connId: null,
  raw: `GET ${url}`,
});

// ---------- classifier ----------
test('classify: confirms a signature-matching request and recommends an inline block', () => {
  const v = classify(httpEvent('/?q={{7*7}}'));
  assert.equal(v.attack, true);
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.cls, 'rce-ssti');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('classify: abstains on benign traffic (zero-FP)', () => {
  const v = classify(httpEvent('/products?page=2&sort=price'));
  assert.equal(v.attack, false);
  assert.equal(v.confidence, 'benign');
  assert.equal(v.recommendedAction, 'observe');
});
test('classify: non-http sources get no HTTP signature verdict', () => {
  const v = classify({ ...httpEvent('/?q={{7*7}}'), source: 'log-stream' });
  assert.equal(v.confidence, 'benign');
});
test('LLM judgment: suspicion escalates a benign verdict to ALERT only — never a block', () => {
  const base = classify(httpEvent('/products?page=2'));
  const v = applyLlmJudgment(base, { suspicious: true, reason: 'odd user agent' });
  assert.equal(v.confidence, 'suspected');
  assert.equal(v.recommendedAction, 'alert');
  assert.notEqual(v.confidence, 'confirmed', 'LLM must never produce a confirmed verdict');
});
test('LLM judgment: cannot weaken a deterministic confirmation', () => {
  const base = classify(httpEvent('/?q={{7*7}}'));
  const v = applyLlmJudgment(base, { suspicious: false, reason: 'looks fine to me' });
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('LLM judgment: absent opinion is a no-op', () => {
  const base = classify(httpEvent('/products'));
  assert.deepEqual(applyLlmJudgment(base, null), base);
});
test('classify: FAILS OPEN — a throwing matcher can never block traffic', () => {
  const v = classify(httpEvent('/?q={{7*7}}'), {
    match: () => {
      throw new Error('boom');
    },
  });
  assert.equal(v.attack, false);
  assert.equal(v.confidence, 'benign');
  assert.equal(v.recommendedAction, 'observe');
  assert.match(v.signal, /boom/);
});

// ---------- responder ----------
const blockVerdict = {
  attack: true,
  cls: 'rce-ssti',
  confidence: 'confirmed',
  signal: 's',
  recommendedAction: 'block-inline',
};
const benignVerdict = { attack: false, cls: null, confidence: 'benign', signal: 's', recommendedAction: 'observe' };

test('respond: MONITOR mode never enforces — it alerts instead', () => {
  const calls = [];
  const r = applyResponse(
    blockVerdict,
    {},
    { mode: 'monitor', deps: { alert: () => calls.push('alert'), enforce: () => calls.push('enforce') } },
  );
  assert.equal(r.enforced, false);
  assert.equal(r.action, 'alert');
  assert.deepEqual(calls, ['alert'], 'alerted but did not enforce');
});
test('respond: ENFORCE mode blocks and calls the enforcer', () => {
  const calls = [];
  const r = applyResponse(
    blockVerdict,
    {},
    { mode: 'enforce', deps: { alert: () => calls.push('alert'), enforce: (a) => calls.push(`enforce:${a}`) } },
  );
  assert.equal(r.enforced, true);
  assert.equal(r.action, 'block-inline');
  assert.deepEqual(calls, ['alert', 'enforce:block-inline']);
});
test('respond: a benign verdict does nothing at all', () => {
  const calls = [];
  const r = applyResponse(benignVerdict, {}, { mode: 'enforce', deps: { alert: () => calls.push('alert') } });
  assert.equal(r.action, 'observe');
  assert.equal(r.enforced, false);
  assert.deepEqual(calls, []);
});
test('respond: a throwing enforcer never propagates (defender must not crash)', () => {
  assert.doesNotThrow(() =>
    applyResponse(
      blockVerdict,
      {},
      {
        mode: 'enforce',
        deps: {
          enforce: () => {
            throw new Error('firewall down');
          },
        },
      },
    ),
  );
});
test('respond: rate limiting suppresses action storms', () => {
  const r = applyResponse(blockVerdict, {}, { mode: 'enforce', allow: () => false, deps: {} });
  assert.equal(r.enforced, false);
  assert.match(r.reason, /rate limited/);
});
test('rate limiter: allows up to max per window, then refuses', () => {
  let t = 0;
  const allow = makeRateLimiter({ max: 2, windowMs: 1000, now: () => t });
  assert.equal(allow(), true);
  assert.equal(allow(), true);
  assert.equal(allow(), false, 'budget spent');
  t = 1001;
  assert.equal(allow(), true, 'window rolled over');
});
test('respond: an async-throwing responder never becomes an unhandled rejection', async () => {
  const r = applyResponse(
    blockVerdict,
    {},
    {
      mode: 'enforce',
      deps: {
        alert: async () => {
          throw new Error('webhook down');
        },
        enforce: async () => {
          throw new Error('firewall down');
        },
      },
    },
  );
  assert.equal(r.enforced, true, 'still returns synchronously');
  await new Promise((resolve) => setImmediate(resolve)); // let the rejections settle
});
test('respond: omitting mode entirely defaults to monitor (never enforces)', () => {
  const calls = [];
  const r = applyResponse(
    blockVerdict,
    {},
    { deps: { alert: () => calls.push('alert'), enforce: () => calls.push('enforce') } },
  );
  assert.equal(r.enforced, false);
  assert.equal(r.action, 'alert');
  assert.deepEqual(calls, ['alert'], 'default mode must not enforce');
});

// Minimal upstream "customer app" for proxy tests (loopback only, no network).
async function upstream(
  handler = (_req, res) => {
    res.writeHead(200);
    res.end('upstream-ok');
  },
) {
  const srv = http.createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { origin: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}

// ---------- http proxy connector ----------
test('connector: forwards a benign request to the upstream app', async () => {
  const app = await upstream();
  const seen = [];
  const c = await httpProxyConnector({
    origin: app.origin,
    onEvent: (e) => {
      seen.push(e);
      return { block: false };
    },
  });
  const res = await fetch(`${c.meta.url}/products?page=2`);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'upstream-ok');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].source, 'http-proxy');
  assert.equal(seen[0].url, '/products?page=2');
  await c.stop();
  await app.close();
});
test('connector: returns 403 and does NOT reach upstream when told to block', async () => {
  let hits = 0;
  const app = await upstream((_req, res) => {
    hits++;
    res.writeHead(200);
    res.end('upstream-ok');
  });
  const c = await httpProxyConnector({ origin: app.origin, onEvent: () => ({ block: true }) });
  const res = await fetch(`${c.meta.url}/?q={{7*7}}`);
  assert.equal(res.status, 403);
  assert.equal(hits, 0, 'attack never reached the protected app');
  await c.stop();
  await app.close();
});
test('connector: FAILS OPEN — a throwing decision forwards rather than breaking the app', async () => {
  const app = await upstream();
  const c = await httpProxyConnector({
    origin: app.origin,
    onEvent: () => {
      throw new Error('classifier exploded');
    },
  });
  const res = await fetch(`${c.meta.url}/checkout`);
  assert.equal(res.status, 200, 'must never fail closed');
  await c.stop();
  await app.close();
});
test('connector: captures the request body in the event', async () => {
  const app = await upstream();
  const seen = [];
  const c = await httpProxyConnector({
    origin: app.origin,
    onEvent: (e) => {
      seen.push(e);
    },
  });
  await fetch(`${c.meta.url}/login`, { method: 'POST', body: 'user=admin&note=hi' });
  assert.equal(seen[0].method, 'POST');
  assert.equal(seen[0].body, 'user=admin&note=hi');
  await c.stop();
  await app.close();
});
