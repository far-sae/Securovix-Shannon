// Tests for the autonomous agent loop — understand → decide tasks → run probes → report. The probe
// function is injected (fake), so we verify the loop's DECISION + AGGREGATION + NARRATION logic
// deterministically, without needing a live target. Real wiring uses PROBERS[key].probe.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildProbeTasks, runAgentLoop } from './packages/dashboard/agent-loop.mjs';

const SURFACE = {
  origin: 'https://shop.example',
  pages: [
    { url: 'https://shop.example/' },
    { url: 'https://shop.example/search?q=x' },
    { url: 'https://shop.example/item?id=7' },
  ],
  paramNames: ['q', 'id'],
  forms: [
    { url: 'https://shop.example/login', method: 'post', params: ['username', 'password'] },
    { url: 'https://shop.example/find', method: 'get', params: ['term'] },
  ],
  apiPaths: ['/api/v1/orders'],
  requests: 40,
};

test('buildProbeTasks: routes GET urls, POST forms, GET forms, origin and API to the right probers', () => {
  const tasks = buildProbeTasks(SURFACE);
  const has = (key, re) =>
    tasks.some((t) => t.key === key && re.test(typeof t.target === 'string' ? t.target : t.target.url));
  assert.ok(has('sqli', /\/search\?q=x/), 'sqli on the GET query URL');
  assert.ok(has('ssrf', /\/item\?id=7/), 'ssrf on the GET query URL');
  assert.ok(
    tasks.some((t) => t.key === 'csrf' && t.target.url === 'https://shop.example/login'),
    'csrf on the POST login form (descriptor)',
  );
  assert.ok(
    tasks.some((t) => t.key === 'auth-testing' && t.target.method === 'post'),
    'auth-testing gets a form descriptor',
  );
  assert.ok(has('sqli', /\/find\?term=1/), 'GET form synthesized into a query URL');
  assert.ok(
    tasks.some((t) => t.key === 'security-headers' && t.target === SURFACE.origin),
    'origin-level probe',
  );
  assert.ok(
    tasks.some((t) => t.key === 'api-data-exposure' && /\/api\/v1\/orders$/.test(t.target)),
    'API endpoint probe',
  );
  // bounded + de-duplicated
  assert.ok(tasks.length <= 30);
  assert.equal(
    new Set(tasks.map((t) => `${t.key}|${typeof t.target === 'string' ? t.target : t.target.url}`)).size,
    tasks.length,
  );
});

test('runAgentLoop: runs the injected probes, aggregates only confirmed findings, narrates the timeline', async () => {
  // Fake engine: SQLi confirms on the search URL; everything else abstains (zero-FP).
  const probe = async (key, target) => {
    const url = typeof target === 'string' ? target : target.url;
    if (key === 'sqli' && /\/search\?q=x/.test(url))
      return [
        { tool: 'sqli-probe', severity: 'critical', target: url, detail: 'boolean-blind differential confirmed' },
      ];
    return [];
  };
  const seen = [];
  const { understanding, steps, findings, stats } = await runAgentLoop({
    surface: SURFACE,
    probe,
    onStep: (s) => seen.push(s.phase),
  });

  assert.ok(understanding.plan.length > 0, 'produced an understanding');
  assert.equal(findings.length, 1, 'exactly the one confirmed finding');
  assert.equal(findings[0].cls, 'sqli');
  assert.equal(stats.confirmed, 1);
  // timeline narrates the full loop in order
  assert.deepEqual(
    ['understand', 'plan', 'act', 'confirm', 'report'].filter((p) => seen.includes(p)),
    ['understand', 'plan', 'act', 'confirm', 'report'],
  );
  assert.ok(steps.find((s) => s.phase === 'confirm').detail.includes('sqli'));
  assert.ok(/PROVEN/.test(steps.at(-1).detail));
});

test('runAgentLoop: when every probe abstains, it reports nothing (no invented findings)', async () => {
  const probe = async () => []; // nothing is provable
  const { findings, stats, steps } = await runAgentLoop({ surface: SURFACE, probe });
  assert.equal(findings.length, 0);
  assert.equal(stats.confirmed, 0);
  assert.ok(/abstained|No vulnerabilities/i.test(steps.at(-1).detail));
});

test('runAgentLoop: a throwing probe is contained, not fatal', async () => {
  const probe = async (key) => {
    if (key === 'sqli') throw new Error('boom');
    return [];
  };
  const { findings, stats } = await runAgentLoop({ surface: SURFACE, probe });
  assert.equal(findings.length, 0, 'a crashing probe drops to no-finding, loop continues');
  assert.ok(stats.tasks > 0);
});
