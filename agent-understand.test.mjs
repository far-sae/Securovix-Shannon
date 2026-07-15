// Tests for the AI Agent's deterministic "understanding" — the surface→plan mapping that drives the
// dashboard's AI Agent page. Pure-logic assertions plus one real crawl against a local mock target.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, test } from 'node:test';
import { crawl } from './crawler.mjs';
import { analyzeSurface } from './packages/dashboard/agent-understand.mjs';

const clsOf = (u) => u.plan.map((p) => p.cls);
const find = (u, re) => u.plan.find((p) => re.test(p.cls));

test('analyzeSurface: maps parameter shapes to the right proof classes, severity-ordered', () => {
  const u = analyzeSurface({
    origin: 'https://shop.example',
    pages: [{ url: 'https://shop.example/' }, { url: 'https://shop.example/search' }],
    paramNames: ['q', 'order_id', 'redirect', 'file', 'theme'],
    forms: [
      { url: 'https://shop.example/login', method: 'post', params: ['username', 'password'] },
      { url: 'https://shop.example/contact', method: 'post', params: ['message'] },
    ],
    apiPaths: ['/api/v1/orders', '/graphql'],
    requests: 30,
  });
  const cls = clsOf(u);
  assert.ok(
    cls.some((c) => /SQL injection/.test(c)),
    'q + order_id → SQLi',
  );
  assert.ok(
    cls.some((c) => /IDOR/.test(c)),
    'order_id → IDOR',
  );
  assert.ok(
    cls.some((c) => /SSRF/.test(c)),
    'redirect → SSRF/url param',
  );
  assert.ok(
    cls.some((c) => /Path traversal/.test(c)),
    'file → LFI',
  );
  assert.ok(
    cls.some((c) => /Auth testing/.test(c)),
    'login form → auth testing',
  );
  assert.ok(
    cls.some((c) => /GraphQL/.test(c)),
    '/graphql → GraphQL abuse',
  );
  assert.ok(
    cls.some((c) => /CSRF/.test(c)),
    'POST forms → CSRF',
  );
  // severity-ordered (critical first)
  assert.equal(u.plan[0].severity, 'critical');
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  for (let i = 1; i < u.plan.length; i++) assert.ok(rank[u.plan[i].severity] >= rank[u.plan[i - 1].severity]);
  // login form is captured as a concrete target + trait
  assert.ok(find(u, /Auth testing/).targets.includes('https://shop.example/login'));
  assert.ok(u.traits.some((t) => /authentication/.test(t)) && u.traits.some((t) => /GraphQL/.test(t)));
});

test('analyzeSurface: an inert brochure site yields an (almost) empty plan — no invented risk', () => {
  const u = analyzeSurface({
    origin: 'https://brochure.example',
    pages: [{ url: 'https://brochure.example/' }, { url: 'https://brochure.example/about' }],
    paramNames: [],
    forms: [],
    apiPaths: [],
    requests: 5,
  });
  assert.equal(u.plan.length, 0, 'no params/forms/apis → nothing to test');
  assert.equal(u.traits.length, 0);
  assert.equal(u.stats.pages, 2);
});

test('analyzeSurface: over a REAL crawl of a mock target, the plan reflects the live surface', async () => {
  const servers = [];
  after(() => servers.forEach((s) => s.close()));
  const html = (res, body) => (res.writeHead(200, { 'content-type': 'text/html' }), res.end(body));
  const s = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/') {
      return html(
        res,
        `<a href="/product?id=1">p</a> <a href="/search?q=x">s</a>
         <form action="/login" method="post"><input name="username"><input name="password"></form>`,
      );
    }
    if (u.pathname === '/product' || u.pathname === '/search') return html(res, '<p>page</p>');
    return html(res, 'ok');
  });
  servers.push(s);
  const origin = await new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));

  const surface = await crawl({ target: `${origin}/`, maxPages: 10, timeoutMs: 4000, maxRequests: 40 });
  const u = analyzeSurface(surface);
  assert.ok(u.stats.pages >= 2, 'crawled multiple pages');
  assert.ok(
    clsOf(u).some((c) => /SQL injection/.test(c)),
    'discovered id/q params → SQLi in the plan',
  );
  assert.ok(
    clsOf(u).some((c) => /Auth testing/.test(c)),
    'discovered the login form → auth testing',
  );
});
