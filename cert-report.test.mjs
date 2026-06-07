import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildCertReport, buildFindings } from './cert-report.mjs';

const report = {
  target: 'https://x.com',
  label: 'scan',
  startedAt: '2026-06-07T00:00:00Z',
  completedAt: '2026-06-07T00:05:00Z',
  crawl: { pages: 5, params: 2, forms: 1, apiPaths: 0 },
  exploits: [
    {
      cls: 'rce-ssti',
      confirmed: 1,
      findings: [
        {
          tool: 'ssti',
          severity: 'critical',
          target: 'https://x.com/p?q=',
          detail: 'SSTI: {{9931*9817}}',
          raw: '{"x":1}',
        },
      ],
    },
    {
      cls: 'security-headers',
      confirmed: 1,
      findings: [{ tool: 'h', severity: 'low', target: 'https://x.com/', detail: 'Missing CSP', raw: '{}' }],
    },
    { cls: 'rce-deser', confirmed: 0, findings: [] },
  ],
  defenses: [
    {
      cls: 'rce-ssti',
      finding: 'SSTI: {{9931*9817}}',
      detectionRule: 'WAF rule',
      remediation: 'Use a sandboxed template engine.',
      inline: { applicable: true, blocked: true },
    },
  ],
};
const COMP = {
  'rce-ssti': { owasp: 'A03:2021-Injection', cwe: 'CWE-1336', mitre: ['TA0002', 'TA0003'] },
  'security-headers': { owasp: 'A05:2021-Security Misconfiguration', cwe: 'CWE-693', mitre: [] },
};

test('buildFindings: scores, sorts by severity, maps methodology, honors inline proof', () => {
  const f = buildFindings(report, COMP);
  assert.equal(f.length, 2); // unconfirmed deser excluded
  assert.equal(f[0].cls, 'rce-ssti'); // critical sorts first
  assert.equal(f[0].cvssScore, 9.8);
  assert.equal(f[0].wstg, 'WSTG-INPV-18');
  assert.equal(f[0].cwe, 'CWE-1336');
  assert.equal(f[0].inlineProven, true);
  assert.equal(f[1].severity, 'low');
});

test('buildCertReport: md + html include CVSS, methodology, compliance, sign-off', () => {
  const r = buildCertReport(report, { compliance: COMP, classesTested: ['rce-ssti', 'security-headers', 'rce-deser'] });
  assert.equal(r.risk, 'Critical');
  for (const needle of ['CVSS 3.1', 'WSTG-INPV-18', 'ASVS', 'PCI DSS', 'ISO 27001', 'Sign-off', 'OSCP'])
    assert.match(r.md, new RegExp(needle.replace(/[.]/g, '\\.')));
  for (const needle of ['Penetration Test Report', '9.8', 'Overall risk'])
    assert.match(r.html, new RegExp(needle.replace(/[.]/g, '\\.')));
});
