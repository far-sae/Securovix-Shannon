import { describe, expect, it } from 'vitest';
import type { VulnCategory } from '../attack-graph/types.js';
import { COMPLIANCE_MAP, buildComplianceReport, mapCategory } from './mapper.js';

// Every category in the union (the COMPLIANCE_MAP is exhaustive by Record<VulnCategory>).
const ALL: VulnCategory[] = [
  'sqli',
  'xss',
  'ssrf',
  'auth-bypass',
  'authz-bypass',
  'rce',
  'credential-theft',
  'business-logic',
  'rce-ssti',
  'rce-deser',
  'token-forgery',
  'prompt-injection',
  'graphql-idor',
  'request-smuggling',
];

describe('COMPLIANCE_MAP', () => {
  it('maps every vuln category to OWASP + CWE + MITRE', () => {
    for (const c of ALL) {
      const m = mapCategory(c);
      expect(m.owasp).toMatch(/^(A\d{2}:2021|OWASP-LLM)/);
      expect(m.cwe).toMatch(/^CWE-\d+$/);
      expect(m.mitre.length).toBeGreaterThan(0);
    }
    expect(Object.keys(COMPLIANCE_MAP)).toHaveLength(ALL.length);
  });

  it('maps known categories correctly', () => {
    expect(mapCategory('sqli').cwe).toBe('CWE-89');
    expect(mapCategory('ssrf').owasp).toContain('A10:2021');
    expect(mapCategory('authz-bypass').owasp).toContain('A01:2021');
    expect(mapCategory('rce-deser').cwe).toBe('CWE-502');
    expect(mapCategory('prompt-injection').owasp).toContain('OWASP-LLM01');
  });
});

describe('buildComplianceReport', () => {
  it('aggregates OWASP/CWE coverage and emits rows', () => {
    const report = buildComplianceReport([
      { category: 'sqli', severity: 'high', endpoint: '/a' },
      { category: 'xss', severity: 'medium', endpoint: '/b' },
      { category: 'authz-bypass', severity: 'high', endpoint: '/c' },
    ]);
    // sqli + xss both map to A03 Injection
    expect(report.owaspCoverage['A03:2021-Injection']).toBe(2);
    expect(report.owaspCoverage['A01:2021-Broken Access Control']).toBe(1);
    expect(report.cweCoverage['CWE-89']).toBe(1);
    expect(report.rows).toHaveLength(3);
    expect(report.rows[0]).toMatchObject({ category: 'sqli', owasp: 'A03:2021-Injection', cwe: 'CWE-89' });
  });

  it('returns empty coverage for no findings', () => {
    const report = buildComplianceReport([]);
    expect(report.rows).toEqual([]);
    expect(report.owaspCoverage).toEqual({});
  });
});
