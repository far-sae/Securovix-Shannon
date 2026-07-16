// Tests for the agent-run report formatter — the two tiers stay separated and labeled.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toJson, toMarkdown, toSarif } from './packages/dashboard/agent-report.mjs';

const RUN = {
  stats: { confirmed: 2, rounds: 2, tested: 24 },
  findings: [
    { cls: 'security-headers', severity: 'low', target: 'https://x/', detail: 'missing CSP', fix: 'Set CSP.' },
    {
      cls: 'sqli',
      severity: 'critical',
      target: 'https://x/search?q=1',
      detail: 'blind differential',
      fix: 'Parameterize.',
    },
    {
      cls: 'impact-sqli-extract',
      severity: 'critical',
      target: 'https://x/search?q=1',
      detail: 'DB=MariaDB',
      impact: true,
    },
  ],
  leads: [
    { kind: 'sensitive-path', tier: 'potential', target: 'https://x/admin/', note: 'Admin interface discovered.' },
  ],
};

test('toMarkdown: severity-ordered proven section, separate labeled potential section', () => {
  const md = toMarkdown(RUN, { target: 'https://x', date: '2026-07-16' });
  assert.ok(md.includes('# Securovix Shannon — Agent Report'));
  assert.ok(md.includes('**Target:** https://x'));
  // critical sorts above low
  assert.ok(md.indexOf('### sqli — CRITICAL') < md.indexOf('### security-headers — LOW'), 'severity-ordered');
  assert.ok(md.includes('**Fix:** Parameterize.'));
  assert.ok(/\(impact\)/.test(md), 'impact finding tagged');
  // the two tiers are separated and the potential one is labeled UNPROVEN
  assert.ok(md.indexOf('## Proven findings') < md.indexOf('## Potential — needs review'));
  assert.ok(/Potential — needs review \(1, UNPROVEN\)/.test(md));
  assert.ok(md.includes('Admin interface discovered.'));
});

test('toMarkdown: an empty run says nothing was proven (no invented content)', () => {
  const md = toMarkdown({ stats: { confirmed: 0, rounds: 1, tested: 10 }, findings: [], leads: [] }, {});
  assert.ok(/No proof, no finding/.test(md));
  assert.ok(!/## Potential/.test(md), 'no potential section when there are no leads');
});

test('toSarif: valid SARIF 2.1.0 with a result + rule per finding and mapped severity', () => {
  const s = toSarif(RUN, { target: 'https://x', date: '2026-07-16' });
  assert.equal(s.version, '2.1.0');
  assert.ok(/sarif-2\.1\.0/.test(s.$schema));
  const run0 = s.runs[0];
  assert.equal(run0.results.length, 3, 'one result per finding');
  // rules deduped by class (sqli appears twice: sqli + impact-sqli-extract are distinct ids)
  const ids = new Set(run0.tool.driver.rules.map((r) => r.id));
  assert.ok(ids.has('sqli') && ids.has('security-headers'));
  // severity → SARIF level
  const sqliResult = run0.results.find((r) => r.ruleId === 'sqli');
  assert.equal(sqliResult.level, 'error', 'critical → error');
  assert.equal(run0.results.find((r) => r.ruleId === 'security-headers').level, 'note', 'low → note');
  // security-severity present for GitHub
  assert.ok(run0.tool.driver.rules.every((r) => r.properties['security-severity'] !== undefined));
  assert.ok(run0.results.every((r) => r.locations[0].physicalLocation.artifactLocation.uri));
});

test('toJson: round-trips the run with tier separation intact', () => {
  const j = JSON.parse(toJson(RUN, { target: 'https://x', date: '2026-07-16' }));
  assert.equal(j.tool, 'securovix-shannon');
  assert.equal(j.target, 'https://x');
  assert.equal(j.findings.length, 3);
  assert.equal(j.leads.length, 1);
  assert.equal(j.leads[0].tier, 'potential');
});
