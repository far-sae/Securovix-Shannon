import type { VulnCategory } from '../attack-graph/types.js';

// Track C — Enterprise. Maps each vuln category to compliance frameworks so findings can
// be reported against OWASP Top 10 (2021), CWE, and MITRE ATT&CK tactics. Using a
// Record<VulnCategory, …> makes coverage COMPILE-TIME exhaustive: adding a new category
// to the union without a mapping here is a build error.

export interface ComplianceMapping {
  owasp: string; // OWASP Top 10 2021 category (or OWASP-LLM for AI-native)
  cwe: string; // primary CWE
  mitre: string[]; // MITRE ATT&CK tactic IDs
}

export const COMPLIANCE_MAP: Record<VulnCategory, ComplianceMapping> = {
  sqli: { owasp: 'A03:2021-Injection', cwe: 'CWE-89', mitre: ['TA0006', 'TA0009'] },
  xss: { owasp: 'A03:2021-Injection', cwe: 'CWE-79', mitre: ['TA0001', 'TA0006'] },
  ssrf: { owasp: 'A10:2021-Server-Side Request Forgery', cwe: 'CWE-918', mitre: ['TA0007', 'TA0008'] },
  'auth-bypass': {
    owasp: 'A07:2021-Identification and Authentication Failures',
    cwe: 'CWE-287',
    mitre: ['TA0001', 'TA0006'],
  },
  'authz-bypass': { owasp: 'A01:2021-Broken Access Control', cwe: 'CWE-285', mitre: ['TA0004', 'TA0005'] },
  rce: { owasp: 'A03:2021-Injection', cwe: 'CWE-94', mitre: ['TA0002', 'TA0003'] },
  'credential-theft': {
    owasp: 'A07:2021-Identification and Authentication Failures',
    cwe: 'CWE-522',
    mitre: ['TA0006'],
  },
  'business-logic': { owasp: 'A04:2021-Insecure Design', cwe: 'CWE-840', mitre: ['TA0001', 'TA0040'] },
  'rce-ssti': { owasp: 'A03:2021-Injection', cwe: 'CWE-1336', mitre: ['TA0002', 'TA0003'] },
  'rce-deser': {
    owasp: 'A08:2021-Software and Data Integrity Failures',
    cwe: 'CWE-502',
    mitre: ['TA0002', 'TA0003'],
  },
  'token-forgery': {
    owasp: 'A07:2021-Identification and Authentication Failures',
    cwe: 'CWE-347',
    mitre: ['TA0001', 'TA0004', 'TA0006'],
  },
  'prompt-injection': { owasp: 'OWASP-LLM01:2025-Prompt Injection', cwe: 'CWE-1427', mitre: ['TA0001', 'TA0002'] },
  'graphql-idor': { owasp: 'A01:2021-Broken Access Control', cwe: 'CWE-639', mitre: ['TA0007', 'TA0009'] },
  'request-smuggling': { owasp: 'A04:2021-Insecure Design', cwe: 'CWE-444', mitre: ['TA0001', 'TA0005'] },
};

export function mapCategory(category: VulnCategory): ComplianceMapping {
  return COMPLIANCE_MAP[category];
}

export interface FindingForReport {
  category: VulnCategory;
  severity: string;
  endpoint: string;
}

export interface ComplianceRow extends ComplianceMapping {
  category: VulnCategory;
  severity: string;
  endpoint: string;
}

export interface ComplianceReport {
  owaspCoverage: Record<string, number>; // OWASP category → number of findings
  cweCoverage: Record<string, number>;
  rows: ComplianceRow[];
}

export function buildComplianceReport(findings: FindingForReport[]): ComplianceReport {
  const owaspCoverage: Record<string, number> = {};
  const cweCoverage: Record<string, number> = {};
  const rows: ComplianceRow[] = findings.map((f) => {
    const m = mapCategory(f.category);
    owaspCoverage[m.owasp] = (owaspCoverage[m.owasp] ?? 0) + 1;
    cweCoverage[m.cwe] = (cweCoverage[m.cwe] ?? 0) + 1;
    return { ...m, category: f.category, severity: f.severity, endpoint: f.endpoint };
  });
  return { owaspCoverage, cweCoverage, rows };
}
