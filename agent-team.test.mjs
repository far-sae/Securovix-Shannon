// Tests for the Multi-Agent Security Team — a blackboard architecture where role-specialized agents
// (recon, exploit pool, remediation, report) coordinate through a shared board with autonomous
// handoffs. All offline, no API key: probe/locate/patch/report deps are injected fakes. The zero-FP
// contract is asserted (no finding is posted when the prober abstains).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  coordinatorTasks,
  makeBlackboard,
  reconAgent,
  remediationAgent,
  reportAgent,
  runExploitPool,
  runSecurityTeam,
} from './packages/dashboard/agent-team.mjs';

// A surface with one injectable GET url (id param) and one origin — buildProbeTasks turns it into
// real prober-keyed tasks.
const surface = () => ({
  origin: 'http://x',
  pages: [{ url: 'http://x/item?id=1' }, { url: 'http://x/' }],
  forms: [],
  apiPaths: [],
  paramNames: ['id'],
});

// Fake engine deps. The probe confirms ONLY for 'sqli' on the id url; everything else abstains.
const makeDeps = () => ({
  probe: async (key, target) => {
    const url = typeof target === 'string' ? target : target.url;
    if (key === 'sqli' && url.includes('/item'))
      return [{ tool: 'sqli-probe', severity: 'critical', target: url, detail: 'SQLi confirmed', cls: 'sqli' }];
    return [];
  },
  escalate: async (cls, target) =>
    cls === 'sqli'
      ? [{ tool: 'impact', severity: 'critical', target, detail: 'extracted DB version', cls: 'impact' }]
      : [],
  locate: async (finding) => ({ file: 'routes/item.js', line: 12, snippet: "db.query('...'+id)" }),
  patch: async (finding, cand) => ({ note: 'Use a parameterized query', file: cand?.file, line: cand?.line }),
  report: async (run) => ({ markdown: `# Report\n${(run.findings || []).length} confirmed`, findings: run.findings }),
});

test('blackboard: post/all/subscribe deliver, and claim yields a single winner', () => {
  const bb = makeBlackboard();
  const seen = [];
  bb.subscribe('finding', (e) => seen.push(e.data.detail));
  bb.post('finding', { detail: 'a' }, 'exploit-1');
  bb.post('finding', { detail: 'b' }, 'exploit-2');
  assert.equal(bb.all('finding').length, 2);
  assert.deepEqual(seen, ['a', 'b']);
  const wins = ['w1', 'w2', 'w3'].map((w) => bb.claim('task-42', w));
  assert.equal(wins.filter(Boolean).length, 1, 'exactly one agent claims a task');
});

test('recon agent posts targets and a prioritized plan', () => {
  const bb = makeBlackboard();
  const plan = reconAgent(bb, { surface: surface() });
  assert.ok(bb.all('target').length >= 1, 'posts at least one target');
  assert.ok(bb.all('plan').length === 1, 'posts one plan');
  assert.ok(Array.isArray(plan) && plan.length >= 1, 'returns the plan rows');
});

test('coordinator turns the surface into claimable prober-keyed tasks', () => {
  const bb = makeBlackboard();
  reconAgent(bb, { surface: surface() });
  const tasks = coordinatorTasks(bb, { surface: surface() });
  assert.ok(tasks.length >= 1, 'creates tasks');
  assert.ok(
    tasks.every((t) => t.key && t.target && t.id),
    'each task has key/target/id',
  );
  assert.ok(
    tasks.some((t) => t.key === 'sqli'),
    'includes a sqli task for the id url',
  );
});

test('exploit pool: claims tasks, posts confirmed findings + impact, abstains cleanly (zero-FP)', async () => {
  const bb = makeBlackboard();
  reconAgent(bb, { surface: surface() });
  coordinatorTasks(bb, { surface: surface() });
  await runExploitPool(bb, { deps: makeDeps(), agents: 3 });
  const findings = bb.all('finding');
  assert.ok(findings.length >= 1, 'confirmed at least the sqli finding');
  assert.ok(
    findings.every((f) => f.data.cls),
    'findings carry a class',
  );
  assert.ok(bb.all('impact').length >= 1, 'escalated the sqli finding into an impact');
  // Zero-FP: number of findings never exceeds the number of tasks that actually confirm.
  assert.ok(findings.length <= bb.all('task').length, 'no finding without a task');
});

test('remediation agent turns each finding into a suggested (labeled) fix', async () => {
  const bb = makeBlackboard();
  bb.post('finding', { tool: 'sqli-probe', target: 'http://x/item?id=1', detail: 'SQLi', cls: 'sqli' }, 'exploit-1');
  await remediationAgent(bb, { deps: makeDeps() });
  const fixes = bb.all('fix');
  assert.equal(fixes.length, 1, 'one fix per finding');
  assert.match(fixes[0].data.label, /suggested/i, 'fix is labeled suggested');
  assert.ok(fixes[0].data.patch, 'fix carries a patch');
});

test('report agent aggregates findings + fixes into a report', async () => {
  const bb = makeBlackboard();
  bb.post('finding', { detail: 'SQLi', cls: 'sqli' }, 'exploit-1');
  bb.post('fix', { label: 'suggested', patch: { note: 'x' } }, 'remediation');
  const report = await reportAgent(bb, { deps: makeDeps() });
  assert.ok(report && (report.markdown || report.content), 'produces a report');
  assert.equal(bb.all('report').length, 1, 'posts the report to the board');
});

test('runSecurityTeam: end-to-end hands-off run with a handoff graph', async () => {
  const events = [];
  const out = await runSecurityTeam({
    surface: surface(),
    deps: makeDeps(),
    roster: { exploitAgents: 3 },
    onEvent: (e) => events.push(e),
  });
  assert.ok(out.findings.length >= 1, 'produced confirmed findings');
  assert.ok(out.fixes.length >= 1, 'produced suggested fixes');
  assert.ok(out.report, 'produced a report');
  assert.ok(out.timeline.length >= 4, 'narrated the run');
  // Graph is a first-class artifact with role nodes + handoff edges.
  const roles = new Set(out.graph.nodes.map((n) => n.role));
  for (const r of ['recon', 'exploit', 'remediation', 'report']) assert.ok(roles.has(r), `graph has a ${r} node`);
  const edgeTypes = out.graph.edges.map((e) => e.type);
  assert.ok(out.graph.edges.length >= 3, 'records handoff edges');
  assert.ok(edgeTypes.includes('finding') || edgeTypes.includes('handoff'), 'edges describe handoffs');
  assert.ok(events.length >= 4, 'streamed events');
});

test('runSecurityTeam: zero findings when every probe abstains (zero-FP intact)', async () => {
  const deps = { ...makeDeps(), probe: async () => [] };
  const out = await runSecurityTeam({ surface: surface(), deps, roster: { exploitAgents: 2 } });
  assert.equal(out.findings.length, 0, 'no findings');
  assert.equal(out.fixes.length, 0, 'no fixes without findings');
});
