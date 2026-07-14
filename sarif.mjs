#!/usr/bin/env node
/**
 * SARIF 2.1.0 export — makes Shannon's confirmed findings consumable by CI/CD and code-scanning
 * tools (GitHub Advanced Security "Code scanning", Azure DevOps, etc.). Reuses the same scored,
 * methodology-tagged findings as the certification report, so a SARIF result carries the CVSS
 * security-severity, CWE, OWASP tags, and remediation GitHub expects.
 */

import { buildFindings } from './cert-report.mjs';

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note', none: 'note' };

export function buildSarif(report, compliance = {}, opts = {}) {
  const findings = buildFindings(report, compliance);
  const rules = new Map();
  const results = findings.map((f) => {
    if (!rules.has(f.cls))
      rules.set(f.cls, {
        id: f.cls,
        name: f.cls,
        shortDescription: { text: String(f.title || f.cls).slice(0, 120) },
        helpUri: 'https://owasp.org/Top10/',
        help: { text: f.remediation || f.detectionRule || 'See the Shannon report for remediation.' },
        properties: {
          'security-severity': String(f.cvssScore ?? 0),
          cwe: f.cwe,
          owasp: f.owasp,
          tags: ['security', f.owasp].filter((t) => t && t !== '—'),
        },
      });
    let uri = f.endpoint;
    try {
      new URL(uri);
    } catch {
      uri = report.target;
    }
    return {
      ruleId: f.cls,
      level: SARIF_LEVEL[f.severity] || 'warning',
      message: { text: f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      properties: {
        cvss: f.cvssScore,
        cvssVector: f.cvssVector,
        severity: f.severity,
        cwe: f.cwe,
        owasp: f.owasp,
        remediation: String(f.remediation || f.detectionRule || '').slice(0, 500),
      },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Securovix Shannon',
            version: opts.version || '1.0.0',
            informationUri: 'https://securovix.com',
            rules: [...rules.values()],
          },
        },
        results,
        properties: { target: report.target, scannedAt: report.completedAt || report.startedAt || null },
      },
    ],
  };
}
