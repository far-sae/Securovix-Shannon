// Committed integration tests for the multi-step FLOW modules (access-control, impact,
// cloud-exposure, attack-surface). HTTP-backed ones use local mock servers; the rest inject deps.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, test } from 'node:test';
import { runAccessControl } from './access-control.mjs';
import { runAttackSurface } from './attack-surface.mjs';
import { runCloudExposure } from './cloud-exposure.mjs';
import { cmdContext, sqliExtract } from './impact.mjs';
import { fetchT, injReq, setScanOrigin } from './purple-engine.mjs';

const servers = [];
after(() => servers.forEach((s) => s.close()));
function mkHttp(handler) {
  const s = http.createServer(handler);
  servers.push(s);
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));
}

test('access-control: horizontal BOLA + vertical BFLA proven; secure endpoints no FP', async () => {
  const ORDERS = {
    1001: 'alice-secret-9f3a alice@demo.test invoice-a-77 balance-1200',
    1002: 'bob-secret-4c8d bob@demo.test invoice-b-33 balance-9310',
  };
  const OWN = { 1001: 'alice', 1002: 'bob' };
  const sid = (req) => (req.headers.cookie || '').match(/sid=([a-z]+)/)?.[1];
  const origin = await mkHttp((req, res) => {
    const u = new URL(req.url, 'http://x');
    const s = sid(req);
    const send = (c, b) => (res.writeHead(c, { 'content-type': 'text/html' }), res.end(b));
    if (u.pathname === '/order') {
      if (!s) return send(401, 'login');
      const d = ORDERS[u.searchParams.get('id')];
      return d ? send(200, `<div>${d}</div>`) : send(404, 'nf'); // VULNERABLE: no owner check
    }
    if (u.pathname === '/secure-order') {
      if (!s) return send(401, 'login');
      const id = u.searchParams.get('id');
      return OWN[id] === s ? send(200, `<div>${ORDERS[id]}</div>`) : send(403, 'forbidden');
    }
    if (u.pathname === '/admin') {
      if (!s) return send(401, 'login');
      return send(200, '<div>admin-dashboard revenue-xk92 all-users secret-panel-7731</div>'); // VULNERABLE BFLA
    }
    if (u.pathname === '/secure-admin') {
      if (!s) return send(401, 'login');
      return s === 'admin'
        ? send(200, '<div>admin-dashboard revenue-xk92 all-users secret-panel-7731</div>')
        : send(403, 'no');
    }
    send(404, 'x');
  });
  const identities = [
    {
      label: 'alice',
      role: 'user',
      headers: { Cookie: 'sid=alice' },
      resources: [`${origin}/order?id=1001`, `${origin}/secure-order?id=1001`],
    },
    {
      label: 'bob',
      role: 'user',
      headers: { Cookie: 'sid=bob' },
      resources: [`${origin}/order?id=1002`, `${origin}/secure-order?id=1002`],
    },
    { label: 'admin', role: 'admin', headers: { Cookie: 'sid=admin' }, resources: [] },
  ];
  const { findings } = await runAccessControl({
    origin,
    identities,
    adminEndpoints: [`${origin}/admin`, `${origin}/secure-admin`],
    judge: null,
  });
  assert.equal(findings.filter((f) => f.severity === 'high').length, 2, '2 horizontal BOLA');
  assert.equal(findings.filter((f) => f.severity === 'critical').length, 2, '2 vertical BFLA');
  assert.ok(!findings.some((f) => /secure/.test(f.target)), 'no FP on secure endpoints');
});

test('impact: SQLi extracts DB version; cmd shows root; safe silent', async () => {
  const origin = await mkHttp((req, res) => {
    const u = new URL(req.url, 'http://x');
    const val = [...u.searchParams.values()].join(' ');
    res.writeHead(200, { 'content-type': 'text/html' });
    if (u.pathname === '/sqli')
      return res.end(/extractvalue|version\(\)/i.test(val) ? "XPATH syntax error: '~10.5.2-MariaDB'" : 'ok');
    if (u.pathname === '/cmd') return res.end(/(^|[;|`&])\s*id\b/i.test(val) ? 'uid=0(root) gid=0(root)' : 'ok');
    res.end('safe');
  });
  setScanOrigin(origin);
  const s = await sqliExtract(`${origin}/sqli?q=1`, { fetchT, injReq });
  assert.ok(s && /10\.5\.2-MariaDB/.test(s.detail));
  const c = await cmdContext(`${origin}/cmd?x=1`, { fetchT, injReq });
  assert.ok(c && /uid=0\(root\)/.test(c.detail) && /ROOT/.test(c.detail));
  assert.equal(await sqliExtract(`${origin}/safe?q=1`, { fetchT, injReq }), null);
});

test('cloud-exposure: referenced public bucket flagged; private ignored', async () => {
  const origin = 'https://client.example';
  const BODIES = {
    [`${origin}/`]:
      '<img src="https://acme.s3.amazonaws.com/l.png"><script src="https://priv.s3.amazonaws.com/a.js"></script>',
    'https://acme.s3.amazonaws.com/': '<ListBucketResult><Name>acme</Name></ListBucketResult>',
    'https://priv.s3.amazonaws.com/': '<Error><Code>AccessDenied</Code></Error>',
  };
  const fetchUrl = async (url) => ({ status: 200, body: BODIES[url] ?? '' });
  const { findings } = await runCloudExposure({ origin, pages: [], fetchUrl });
  assert.ok(findings.some((f) => /acme/.test(f.detail)));
  assert.ok(!findings.some((f) => /priv/.test(f.detail)), 'private bucket not flagged');
});

test('attack-surface: S3 subdomain takeover proven; live/non-service ignored', async () => {
  const deps = {
    fetchCrt: async () => ['dangling.example.com', 'live.example.com', 'mail.example.com'],
    resolveCname: async (h) =>
      ({
        'dangling.example.com': ['x.s3.amazonaws.com'],
        'live.example.com': ['y.s3.amazonaws.com'],
        'mail.example.com': ['ghs.googlehosted.com'],
      })[h] || [],
    fetchUrl: async (u) => ({ status: 200, body: /dangling/.test(u) ? '<Code>NoSuchBucket</Code>' : 'live site' }),
  };
  const { subdomains, findings } = await runAttackSurface('example.com', deps);
  assert.equal(subdomains.length, 3);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].target, 'dangling.example.com');
});
