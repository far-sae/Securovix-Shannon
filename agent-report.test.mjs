// Tests for the agent-run report formatter — the two tiers stay separated and labeled.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toJson, toMarkdown } from './packages/dashboard/agent-report.mjs';

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

test('toJson: round-trips the run with tier separation intact', () => {
  const j = JSON.parse(toJson(RUN, { target: 'https://x', date: '2026-07-16' }));
  assert.equal(j.tool, 'securovix-shannon');
  assert.equal(j.target, 'https://x');
  assert.equal(j.findings.length, 3);
  assert.equal(j.leads.length, 1);
  assert.equal(j.leads[0].tier, 'potential');
});
