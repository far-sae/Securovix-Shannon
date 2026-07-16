// Tests for the autonomous agent loop — understand → decide tasks → run probes → report. The probe
// function is injected (fake), so we verify the loop's DECISION + AGGREGATION + NARRATION logic
// deterministically, without needing a live target. Real wiring uses PROBERS[key].probe.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildProbeTasks, runAgentCampaign, runAgentLoop, runConcurrent } from './packages/dashboard/agent-loop.mjs';

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

test('runAgentLoop: a confirmed finding is ESCALATED into an impact demonstrator', async () => {
  const probe = async (key, target) =>
    key === 'sqli' && /search\?q=x/.test(typeof target === 'string' ? target : target.url)
      ? [{ tool: 'sqli-probe', severity: 'critical', target: 'u', detail: 'boolean-blind confirmed' }]
      : [];
  const escalate = async (cls) =>
    cls === 'sqli'
      ? { tool: 'impact-sqli-extract', severity: 'critical', target: 'u', detail: 'DB version="10.5.2-MariaDB"' }
      : null;
  const { findings, steps } = await runAgentLoop({ surface: SURFACE, probe, escalate });
  assert.equal(findings.length, 2, 'the probe finding plus the escalated impact finding');
  assert.ok(
    findings.some((f) => f.impact && /MariaDB/.test(f.detail)),
    'impact finding is tagged and present',
  );
  assert.ok(
    steps.some((s) => s.phase === 'escalate'),
    'an escalate step is narrated',
  );
});

test('runAgentCampaign: multi-round — re-crawl exposes a new vector, then stops when dry (no spinning)', async () => {
  const round2 = { ...SURFACE, pages: [...SURFACE.pages, { url: 'https://shop.example/admin?id=9' }] };
  const probe = async (key, target) => {
    const u = typeof target === 'string' ? target : target.url;
    return key === 'sqli' && /\/admin\?id=9/.test(u)
      ? [{ tool: 'sqli', severity: 'high', target: u, detail: 'x' }]
      : [];
  };
  // round 2 crawl reveals /admin; round 3 crawl reveals nothing new → campaign must stop.
  const recrawl = async () => round2;
  const rounds = [];
  const { stats, steps, findings } = await runAgentCampaign({
    surface: SURFACE,
    probe,
    recrawl,
    maxRounds: 4,
    onStep: (s) => s.phase === 'round' && rounds.push(s),
  });
  assert.equal(stats.rounds, 2, 'ran round 1 + round 2, then stopped (round 3 crawl added no fresh task)');
  assert.equal(rounds.length, 2, 'two round markers streamed');
  assert.equal(stats.confirmed, 1, 'the vector revealed only in round 2 was found');
  assert.ok(findings[0].round === 2, 'finding attributed to round 2');
  assert.ok(steps.some((s) => s.phase === 'report'));
});

test('runAgentCampaign: with no recrawl it runs exactly one round', async () => {
  const { stats } = await runAgentCampaign({ surface: SURFACE, probe: async () => [], maxRounds: 3 });
  assert.equal(stats.rounds, 1);
});

test('runConcurrent: preserves order, runs all items, and never exceeds the concurrency limit', async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const worker = async (n) => {
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return n * 2;
  };
  const items = [1, 2, 3, 4, 5, 6, 7];
  const out = await runConcurrent(items, worker, 3);
  assert.deepEqual(out, [2, 4, 6, 8, 10, 12, 14], 'results in original order');
  assert.ok(maxInFlight <= 3, `never more than 3 in flight (saw ${maxInFlight})`);
  assert.ok(maxInFlight >= 2, 'actually ran concurrently');
});

test('runAgentLoop: parallel dispatch — findings still aggregate; agents are labelled', async () => {
  const probe = async (key, target) => {
    const url = typeof target === 'string' ? target : target.url;
    return key === 'sqli' && /search|item/.test(url)
      ? [{ tool: 'sqli', severity: 'critical', target: url, detail: 'confirmed' }]
      : [];
  };
  const { findings, steps } = await runAgentLoop({ surface: SURFACE, probe, concurrency: 4 });
  assert.ok(findings.length >= 2, 'both sqli vectors confirmed under concurrency');
  assert.ok(steps.some((s) => s.phase === 'act' && /parallel agents/.test(s.detail)));
  assert.ok(
    steps.some((s) => s.phase === 'confirm' && /\[agent \d\]/.test(s.detail)),
    'confirm steps carry an agent label',
  );
});
