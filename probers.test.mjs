// Committed integration tests for the detection probers — each stands up a local mock server
// (no network) and asserts the prober confirms on a vulnerable response and abstains on a safe one.
// This gives CI real coverage of the zero-FP detection logic (the pure-logic modules live in
// advanced.test.mjs; the crawler/engine unit bits in engine.test.mjs).
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';
import { checkElasticsearch, checkFtpAnon, checkMemcached, checkRedis } from './network-scan.mjs';
import { PROBERS, fetchT, injReq, setScanOrigin } from './purple-engine.mjs';

const servers = [];
after(() => servers.forEach((s) => s.close()));

function mkHttp(handler) {
  const s = http.createServer(handler);
  servers.push(s);
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));
}
function mkTcp(onConn) {
  const s = net.createServer(onConn);
  servers.push(s);
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(s.address().port)));
}
const html = (res, body, extra = {}) => (res.writeHead(200, { 'content-type': 'text/html', ...extra }), res.end(body));
const json = (res, obj) => (res.writeHead(200, { 'content-type': 'application/json' }), res.end(JSON.stringify(obj)));
const found = (fs) => fs.length > 0;

test('sqli: error-based confirms on DB error, abstains on clean', async () => {
  const origin = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    if (req.url.startsWith('/vuln')) return q.includes("'") ? html(res, 'You have an error in your SQL syntax') : html(res, 'ok');
    return html(res, `results for ${q}`); // /safe reflects but never errors
  });
  setScanOrigin(origin);
  assert.ok(found(await PROBERS.sqli.probe(`${origin}/vuln?q=1`)), 'confirms on DB error');
  assert.ok(!found(await PROBERS.sqli.probe(`${origin}/safe?q=1`)), 'abstains on clean');
});

test('sqli: boolean-blind confirms on stable TRUE/FALSE differential', async () => {
  const origin = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    if (/'1'='1/.test(q)) return html(res, '<ul><li>a</li><li>b</li><li>c</li></ul>');
    if (/'1'='2/.test(q)) return html(res, '<ul></ul>');
    return html(res, '<ul></ul>');
  });
  setScanOrigin(origin);
  assert.ok(found(await PROBERS.sqli.probe(`${origin}/x?q=1`)));
});

test('nosql: operator injection changes the result set', async () => {
  const origin = await mkHttp((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.searchParams.get('user[$ne]') !== null) return html(res, '<ul><li>a</li><li>b</li><li>c</li></ul>');
    if (u.searchParams.get('user[$eq]') !== null) return html(res, '<ul></ul>');
    return html(res, '<ul></ul>');
  });
  setScanOrigin(origin);
  assert.ok(found(await PROBERS.nosql.probe(`${origin}/a?user=x`)));
  const safe = await mkHttp((_q, res) => html(res, '<ul></ul>'));
  setScanOrigin(safe);
  assert.ok(!found(await PROBERS.nosql.probe(`${safe}/a?user=x`)), 'inert app abstains');
});

test('crlf: injected header materializes', async () => {
  const origin = await mkHttp((req, res) => {
    const decoded = decodeURIComponent(new URL(req.url, 'http://x').searchParams.get('next') || '');
    const [first, ...rest] = decoded.split(/\r\n/);
    res.setHeader('Location', first);
    for (const line of rest) {
      const i = line.indexOf(':');
      if (i > 0) res.setHeader(line.slice(0, i).trim(), line.slice(i + 1).trim());
    }
    res.writeHead(302, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  setScanOrigin(origin);
  assert.ok(found(await PROBERS.crlf.probe(`${origin}/r?next=/home`)));
});

test('host-header: attacker Host reflected', async () => {
  const origin = await mkHttp((req, res) => html(res, `<a href="https://${req.headers.host}/reset">r</a>`));
  setScanOrigin(origin);
  assert.ok(found(await PROBERS['host-header'].probe(`${origin}/`)));
});

test('csrf: no token + SameSite=None flagged; token / Lax not', async () => {
  const vuln = await mkHttp((_q, res) => html(res, 'form', { 'set-cookie': 'sessionid=a; SameSite=None' }));
  const lax = await mkHttp((_q, res) => html(res, 'form', { 'set-cookie': 'sessionid=a; SameSite=Lax' }));
  setScanOrigin(vuln);
  assert.ok(found(await PROBERS.csrf.probe({ url: `${vuln}/pay`, method: 'post', params: ['amount'] })));
  setScanOrigin(lax);
  assert.ok(!found(await PROBERS.csrf.probe({ url: `${lax}/pay`, method: 'post', params: ['amount'] })));
  assert.ok(!found(await PROBERS.csrf.probe({ url: `${vuln}/pay`, method: 'post', params: ['amount', 'csrf_token'] })), 'token present → no FP');
});

test('mass-assignment: selective bind flagged, echo-all abstains', async () => {
  const MODEL = new Set(['amount', 'role']);
  const vuln = await mkHttp(async (req, res) => {
    let b = '';
    for await (const c of req) b += c;
    const f = new URLSearchParams(b);
    html(res, [...f].filter(([k]) => MODEL.has(k)).map(([k, v]) => `<div>${k}:${v}</div>`).join(''));
  });
  const echo = await mkHttp(async (req, res) => {
    let b = '';
    for await (const c of req) b += c;
    html(res, b);
  });
  setScanOrigin(vuln);
  assert.ok(found(await PROBERS['mass-assignment'].probe({ url: `${vuln}/u`, method: 'post', params: ['amount'] })));
  setScanOrigin(echo);
  assert.ok(!found(await PROBERS['mass-assignment'].probe({ url: `${echo}/u`, method: 'post', params: ['amount'] })), 'echo-all abstains');
});

test('verbose-errors: stack trace on malformed input', async () => {
  const origin = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    return /['"{}\[\]<>]/.test(q) ? res.end('Traceback (most recent call last):\n  File "/app/x.py", line 9') : res.end('ok');
  });
  setScanOrigin(origin);
  assert.ok(found(await PROBERS['verbose-errors'].probe(`${origin}/e?q=1`)));
});

test('api-data-exposure: sensitive JSON field flagged, JSON-looking HTML ignored', async () => {
  const leak = await mkHttp((_q, res) => json(res, { id: 1, password_hash: '$2b$10$abcdefghijklmnop' }));
  const htmlPw = await mkHttp((_q, res) => html(res, '{"password":"leaked"}'));
  setScanOrigin(leak);
  assert.ok(found(await PROBERS['api-data-exposure'].probe(`${leak}/u`)));
  setScanOrigin(htmlPw);
  assert.ok(!found(await PROBERS['api-data-exposure'].probe(`${htmlPw}/u`)), 'JSON-looking HTML ignored');
});

test('graphql-advanced: field suggestion + batching', async () => {
  const origin = await mkHttp(async (req, res) => {
    let b = '';
    for await (const c of req) b += c;
    const p = JSON.parse(b || 'null');
    if (Array.isArray(p)) return json(res, p.map(() => ({ data: {} })));
    if (/usr/.test(p?.query || '')) return json(res, { errors: [{ message: 'Cannot query field "usr". Did you mean "user"?' }] });
    return json(res, { data: {} });
  });
  setScanOrigin(origin);
  const fs = await PROBERS['graphql-advanced'].probe(`${origin}/graphql`);
  assert.ok(fs.some((f) => /suggestion/.test(f.raw)) && fs.some((f) => /batching/.test(f.raw)));
});

test('auth-testing: no rate-limit flagged on an open login form', async () => {
  const origin = await mkHttp(async (req, res) => {
    if (req.method === 'GET') return html(res, '<form method=post><input name=username><input name=password type=password></form>');
    let b = '';
    for await (const c of req) b += c;
    const f = new URLSearchParams(b);
    return f.get('username') === 'realuser' ? html(res, 'ok', { 'set-cookie': 'sessionid=x' }) : html(res, 'Invalid credentials');
  });
  setScanOrigin(origin);
  const fs = await PROBERS['auth-testing'].probe({ url: `${origin}/login`, method: 'post', params: ['username', 'password'] });
  assert.ok(fs.some((f) => /rate-limit/i.test(f.detail)));
});

test('network-scan: unauth services flagged, auth/closed ignored', async () => {
  const redis = await mkTcp((s) => s.on('data', (d) => /PING/.test(d) && s.write('+PONG\r\n')));
  const redisAuth = await mkTcp((s) => s.on('data', (d) => /PING/.test(d) && s.write('-NOAUTH Authentication required.\r\n')));
  const memc = await mkTcp((s) => s.on('data', (d) => /stats/.test(d) && s.write('STAT version 1.6\r\nEND\r\n')));
  const es = await mkHttp((_q, res) => json(res, { cluster_name: 'c', version: { lucene_version: '9' }, tagline: 'You Know, for Search' }));
  const ftp = await mkTcp((s) => (s.write('220 ok\r\n'), s.on('data', (d) => s.write(/USER/i.test(d) ? '331 need pass\r\n' : /PASS/i.test(d) ? '230 in\r\n' : ''))));
  assert.ok(await checkRedis('127.0.0.1', redis));
  assert.ok(!(await checkRedis('127.0.0.1', redisAuth)), 'auth-required Redis ignored');
  assert.ok(await checkMemcached('127.0.0.1', memc));
  assert.ok(await checkElasticsearch('127.0.0.1', Number(new URL(es).port)));
  assert.ok(await checkFtpAnon('127.0.0.1', ftp));
  assert.ok(!(await checkRedis('127.0.0.1', 6390)), 'closed port ignored');
});
