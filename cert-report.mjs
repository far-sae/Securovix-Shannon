#!/usr/bin/env node
/**
 * Certification-grade report generator. Turns confirmed findings into a professional pentest
 * report (Markdown + self-contained HTML) aligned to recognized methodology so a CERTIFIED human
 * pentester can review and sign it, and auditors can accept it as evidence:
 *   - CVSS v3.1 score + vector per finding (via cvss.mjs)
 *   - OWASP WSTG (test IDs) + OWASP ASVS (requirements) mapping  [methodology coverage]
 *   - OWASP Top 10 / CWE / MITRE ATT&CK + PCI DSS / ISO 27001 compliance appendix
 *   - Evidence + integrity note, scope/authorization statement, limitations, and a SIGN-OFF block
 *
 * NOTE: this makes the OUTPUT certification-grade. The "certified" status of the final deliverable
 * comes from an accredited human (OSCP/CREST) signing it and/or vendor accreditation (PCI ASV/CREST).
 */

import { cvssForClass } from './cvss.mjs';

// OWASP WSTG (v4.2) test IDs + ASVS (v4.0) requirements + PCI DSS 4.0 + ISO 27001:2022 control refs.
export const METHODOLOGY = {
  'rce-ssti': {
    name: 'Server-Side Template Injection',
    wstg: 'WSTG-INPV-18',
    asvs: 'V5.2.5',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'rce-deser': {
    name: 'Insecure Deserialization',
    wstg: 'WSTG-INPV-(Deserialization)',
    asvs: 'V5.5.1–5.5.3',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'cmd-injection': { name: 'OS Command Injection', wstg: 'WSTG-INPV-12', asvs: 'V5.3.8', pci: '6.2.4', iso: 'A.8.28' },
  sqli: { name: 'SQL Injection', wstg: 'WSTG-INPV-05', asvs: 'V5.3.4', pci: '6.2.4', iso: 'A.8.28' },
  xss: { name: 'Cross-Site Scripting (Reflected)', wstg: 'WSTG-INPV-01', asvs: 'V5.3.3', pci: '6.2.4', iso: 'A.8.28' },
  'path-traversal': { name: 'Path Traversal / LFI', wstg: 'WSTG-ATHZ-01', asvs: 'V12.3.1', pci: '6.2.4', iso: 'A.8.3' },
  ssrf: { name: 'Server-Side Request Forgery', wstg: 'WSTG-INPV-19', asvs: 'V5.2.6', pci: '6.2.4', iso: 'A.8.28' },
  'authz-bypass': {
    name: 'Broken Object-Level Authorization (IDOR)',
    wstg: 'WSTG-ATHZ-04',
    asvs: 'V4.2.1',
    pci: '7.2',
    iso: 'A.8.3',
  },
  'token-forgery': { name: 'JWT / Token Forgery', wstg: 'WSTG-SESS-10', asvs: 'V3.5.3', pci: '8.3', iso: 'A.8.5' },
  'graphql-idor': {
    name: 'GraphQL Introspection / API Authorization',
    wstg: 'WSTG-APIT-01',
    asvs: 'V13.4.1',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'open-redirect': { name: 'Open Redirect', wstg: 'WSTG-CLNT-04', asvs: 'V5.1.5', pci: '6.2.4', iso: 'A.8.28' },
  'cors-misconfig': {
    name: 'CORS Misconfiguration',
    wstg: 'WSTG-CLNT-07',
    asvs: 'V14.5.3',
    pci: '6.2.4',
    iso: 'A.8.26',
  },
  'secrets-exposure': {
    name: 'Sensitive File / Secret Exposure',
    wstg: 'WSTG-CONF-04',
    asvs: 'V14.3.2',
    pci: '6.2.4',
    iso: 'A.8.12',
  },
  'security-headers': {
    name: 'Missing Security Headers',
    wstg: 'WSTG-CONF-07',
    asvs: 'V14.4.1',
    pci: '6.2.4',
    iso: 'A.8.26',
  },
  templates: { name: 'Configuration / Exposure Checks', wstg: 'WSTG-CONF', asvs: 'V14', pci: '2.2', iso: 'A.8.9' },
  nosql: { name: 'NoSQL Injection', wstg: 'WSTG-INPV-05', asvs: 'V5.3.4', pci: '6.2.4', iso: 'A.8.28' },
  xxe: { name: 'XML External Entity (XXE)', wstg: 'WSTG-INPV-07', asvs: 'V5.5.2', pci: '6.2.4', iso: 'A.8.28' },
  'host-header': { name: 'Host Header Injection', wstg: 'WSTG-INPV-17', asvs: 'V5.1.1', pci: '6.2.4', iso: 'A.8.28' },
  crlf: { name: 'CRLF / HTTP Response Splitting', wstg: 'WSTG-INPV-16', asvs: 'V5.1.5', pci: '6.2.4', iso: 'A.8.28' },
  'access-control': {
    name: 'Broken Access Control (BOLA / BFLA)',
    wstg: 'WSTG-ATHZ-02/04',
    asvs: 'V4.1.3 / V4.2.1',
    pci: '7.1',
    iso: 'A.8.3',
  },
  'sqli-auth-bypass': {
    name: 'SQL Injection Authentication Bypass',
    wstg: 'WSTG-ATHN-04',
    asvs: 'V5.3.4',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'auth-testing': {
    name: 'Authentication Weaknesses (brute-force / default creds / user enumeration)',
    wstg: 'WSTG-ATHN-02/03',
    asvs: 'V2.2.1',
    pci: '8.3.6',
    iso: 'A.8.5',
  },
  'stored-dom-xss': {
    name: 'Stored & DOM-based Cross-Site Scripting',
    wstg: 'WSTG-INPV-02 / WSTG-CLNT-01',
    asvs: 'V5.3.3',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  csrf: { name: 'Cross-Site Request Forgery', wstg: 'WSTG-SESS-05', asvs: 'V4.2.2', pci: '6.2.4', iso: 'A.8.28' },
  'mass-assignment': {
    name: 'Mass Assignment / Over-posting',
    wstg: 'WSTG-INPV-(Mass Assignment)',
    asvs: 'V5.1.2',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'verbose-errors': {
    name: 'Information Disclosure via Verbose Errors',
    wstg: 'WSTG-ERRH-01',
    asvs: 'V7.4.1',
    pci: '6.2.4',
    iso: 'A.8.9',
  },
  'api-data-exposure': {
    name: 'Excessive Data Exposure (API)',
    wstg: 'WSTG-APIT-01',
    asvs: 'V13.1.3',
    pci: '3.4',
    iso: 'A.8.12',
  },
  'graphql-advanced': {
    name: 'GraphQL Abuse (suggestions / batching)',
    wstg: 'WSTG-APIT-01',
    asvs: 'V13.4.1',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'tls-config': { name: 'TLS/SSL Configuration', wstg: 'WSTG-CRYP-01', asvs: 'V9.1.1', pci: '4.2.1', iso: 'A.8.24' },
  'attack-surface': {
    name: 'Subdomain Takeover / Attack Surface',
    wstg: 'WSTG-CONF-10',
    asvs: 'V1.11.1',
    pci: '2.2',
    iso: 'A.8.9',
  },
  'cloud-exposure': {
    name: 'Cloud Storage Exposure',
    wstg: 'WSTG-CONF-11',
    asvs: 'V1.11.1',
    pci: '2.2',
    iso: 'A.8.9',
  },
  'exposed-service': {
    name: 'Exposed Unauthenticated Services',
    wstg: 'WSTG-CONF-01',
    asvs: 'V1.14.3',
    pci: '1.3',
    iso: 'A.8.20',
  },
  'attack-chain': { name: 'Attack Path / Exploit Chain (correlated)', wstg: '—', asvs: '—', pci: '—', iso: '—' },
  impact: {
    name: 'Exploitation Impact / Post-Exploitation',
    wstg: 'WSTG-INPV-05',
    asvs: 'V5.3.4',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
  'ai-verified': {
    name: 'AI-Proposed, Deterministically-Verified Finding',
    wstg: 'WSTG-BUSL',
    asvs: 'V5.1.2',
    pci: '6.2.4',
    iso: 'A.8.28',
  },
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };
const esc = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

// Flatten the run into scored, methodology-tagged findings.
export function buildFindings(report, compliance = {}) {
  const defByKey = new Map();
  for (const d of report.defenses || []) defByKey.set(`${d.cls}|${d.finding}`, d);
  const out = [];
  for (const e of report.exploits || []) {
    if (!e.confirmed) continue;
    const seen = new Set();
    for (const f of e.findings) {
      if (seen.has(f.detail)) continue;
      seen.add(f.detail);
      const cvss = cvssForClass(e.cls, f.severity);
      const meth = METHODOLOGY[e.cls] || {};
      const comp = compliance[e.cls] || {};
      const def = defByKey.get(`${e.cls}|${f.detail}`) || {};
      out.push({
        cls: e.cls,
        title: f.detail,
        endpoint: f.target,
        evidence: f.raw,
        severity: cvss.severity,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        wstg: meth.wstg || '—',
        asvs: meth.asvs || '—',
        owasp: comp.owasp || '—',
        cwe: comp.cwe || '—',
        mitre: (comp.mitre || []).join(', ') || '—',
        pci: meth.pci || '—',
        iso: meth.iso || '—',
        detectionRule: def.detectionRule || '',
        remediation: def.remediation || '',
        inlineProven: def.inline?.blocked === true,
        retest: 'Open',
      });
    }
  }
  out.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.cvssScore - a.cvssScore);
  return out;
}

function counts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}
function overallRisk(c) {
  if (c.critical) return 'Critical';
  if (c.high) return 'High';
  if (c.medium) return 'Medium';
  if (c.low) return 'Low';
  return 'Informational / Clean';
}

export function buildCertReport(
  report,
  { compliance = {}, classesTested = [], engine = 'Shannon Purple Engine' } = {},
) {
  const findings = buildFindings(report, compliance);
  const c = counts(findings);
  const risk = overallRisk(c);
  // Advanced layers surfaced as their own report sections (they are also findings above).
  const chainF = (report.exploits || [])
    .filter((e) => e.cls === 'attack-chain' && e.confirmed > 0)
    .flatMap((e) => e.findings || []);
  const impactF = (report.exploits || [])
    .filter((e) => e.cls === 'impact' && e.confirmed > 0)
    .flatMap((e) => e.findings || []);
  const mon = report.monitoring;
  const started = report.startedAt || '';
  const finished = report.completedAt || '';
  const crawl = report.crawl
    ? `${report.crawl.pages} pages, ${report.crawl.params} params, ${report.crawl.forms} forms`
    : 'n/a';

  // ---------- Markdown ----------
  const md = [
    '# Penetration Test Report',
    '',
    `**Target:** ${report.target}`,
    `**Engagement:** ${report.label || 'scan'}`,
    `**Started:** ${started}  **Completed:** ${finished}`,
    `**Engine:** ${engine}`,
    `**Overall risk:** ${risk}`,
    '',
    '## 1. Scope & Authorization',
    `- Target in scope: ${report.target}`,
    `- Surface discovered (crawl): ${crawl}`,
    `- Authorization: testing performed under the client's attested ownership / written authorization for the target domain (verified via DNS / well-known file / meta tag before testing).`,
    '',
    '## 2. Methodology',
    'Testing followed OWASP Web Security Testing Guide (WSTG v4.2), OWASP ASVS v4.0, and NIST SP 800-115. Each finding is mapped to its WSTG test ID and ASVS requirement below. Findings are confirmed by a benign proof marker (arithmetic eval, planted canary, DB error, out-of-band callback, exposed-file signature) — **zero false positives by construction**.',
    '',
    `**Automated classes executed (${classesTested.length}):** ${classesTested.join(', ') || '—'}`,
    '',
    '## 3. Executive Summary',
    '| Severity | Count |',
    '|---|---|',
    `| Critical | ${c.critical} |`,
    `| High | ${c.high} |`,
    `| Medium | ${c.medium} |`,
    `| Low | ${c.low} |`,
    `| Info | ${c.info} |`,
    '',
    ...(mon
      ? [
          mon.firstRun
            ? `_Monitoring: baseline established (${mon.total || 0} confirmed finding(s)). Re-scan to detect changes._`
            : `_Monitoring: since the last scan — **${(mon.new || []).length} new**, ${(mon.resolved || []).length} resolved._`,
          '',
        ]
      : []),
    '## 3a. Attack Paths (correlated exploit chains)',
    chainF.length
      ? chainF.map((f) => `- **${(f.severity || '').toUpperCase()}** — ${f.detail}`).join('\n')
      : '_No multi-finding attack chains correlated._',
    '',
    '## 3b. Demonstrated Impact (post-exploitation)',
    impactF.length
      ? impactF.map((f) => `- ${f.detail}`).join('\n')
      : '_No post-exploitation impact demonstrated (or not applicable to the confirmed findings)._',
    '',
    '## 4. Findings',
    findings.length
      ? findings
          .map(
            (f, i) =>
              `### 4.${i + 1} ${f.title}\n` +
              `- **Severity:** ${f.severity.toUpperCase()} — **CVSS 3.1:** ${f.cvssScore} (\`${f.cvssVector}\`)\n` +
              `- **Endpoint:** ${f.endpoint}\n` +
              `- **OWASP WSTG:** ${f.wstg} | **ASVS:** ${f.asvs} | **CWE:** ${f.cwe} | **OWASP Top 10:** ${f.owasp} | **MITRE:** ${f.mitre}\n` +
              `- **Compliance:** PCI DSS ${f.pci} | ISO 27001 ${f.iso}\n` +
              `- **Evidence:** \`${(f.evidence || '').slice(0, 300)}\`\n` +
              `- **Mitigation proven (inline WAF re-test):** ${f.inlineProven ? 'YES — payload blocked on re-test' : 'n/a / not inline-blockable'}\n` +
              `- **Remediation:**\n\n${f.remediation || f.detectionRule || '_See detection rule._'}\n` +
              `- **Retest status:** ${f.retest}`,
          )
          .join('\n\n')
      : '_No vulnerabilities confirmed within the tested classes._',
    '',
    '## 5. Compliance Appendix',
    'Findings map to OWASP Top 10 (2021), CWE, MITRE ATT&CK, PCI DSS 4.0, and ISO 27001:2022 Annex A as tabled per-finding above. A clean result indicates no issues **within the tested classes**, not a guarantee of overall security.',
    '',
    '## 6. Evidence & Integrity',
    'Every finding was produced by a tool-confirmed, reproducible probe; raw evidence is retained per finding. (Worker-mode scans additionally maintain a hash-chained forensic log / chain-of-custody.)',
    '',
    '## 7. Limitations',
    `This report covers ${classesTested.length} automated vulnerability classes. It is **not** a substitute for full manual penetration testing (complex business logic, chained exploits, and classes outside the tested set require a human tester). Use alongside manual testing for a complete assessment.`,
    '',
    '## 8. Sign-off',
    '| Field | Value |',
    '|---|---|',
    '| Tester (name) | __________________________ |',
    '| Certifications (OSCP / CREST / GWAPT) | __________________________ |',
    '| Reviewed & validated | ☐ |',
    '| Signature | __________________________ |',
    '| Date | __________________________ |',
    '',
    `_Automated findings above were generated by ${engine}. A certified tester must review and sign this report for it to constitute a certified penetration test._`,
  ].join('\n');

  // ---------- HTML (self-contained) ----------
  const sevColor = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280',
    none: '#6b7280',
  };
  const rows = findings
    .map(
      (f, i) => `<tr>
      <td>4.${i + 1}</td>
      <td>${esc(f.title)}<div class="ep">${esc(f.endpoint)}</div></td>
      <td><span class="sev" style="background:${sevColor[f.severity]}">${esc(f.severity.toUpperCase())}</span></td>
      <td class="num">${f.cvssScore}<div class="vec">${esc(f.cvssVector.replace('CVSS:3.1/', ''))}</div></td>
      <td>${esc(f.wstg)}<div class="vec">ASVS ${esc(f.asvs)}</div></td>
      <td>${esc(f.cwe)}<div class="vec">${esc(f.owasp)}</div></td>
      <td>${f.inlineProven ? '✔ blocked' : '—'}</td>
    </tr>`,
    )
    .join('');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Pentest Report — ${esc(report.target)}</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:32px auto;padding:0 20px;color:#111;line-height:1.5}
h1{margin-bottom:4px}h2{margin-top:34px;border-bottom:2px solid #eee;padding-bottom:6px}
.meta{color:#555;font-size:14px}
.cards{display:flex;gap:10px;margin:14px 0}
.card{flex:1;border:1px solid #e5e7eb;border-radius:10px;padding:12px;text-align:center}
.card .n{font-size:26px;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th,td{border:1px solid #e5e7eb;padding:8px 10px;text-align:left;vertical-align:top}
th{background:#f9fafb}
.sev{color:#fff;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:700}
.num{font-weight:700}.ep{color:#6b7280;font-size:11px;margin-top:3px;word-break:break-all}
.vec{color:#6b7280;font-size:10px;margin-top:3px}
.banner{background:${sevColor[risk.toLowerCase().split(' ')[0]] || '#6b7280'};color:#fff;padding:10px 14px;border-radius:8px;font-weight:700;display:inline-block}
.signoff td{height:30px}
.disc{font-size:12px;color:#6b7280;border-left:3px solid #ddd;padding-left:12px;margin-top:8px}
</style></head><body>
<h1>Penetration Test Report</h1>
<div class="meta">${esc(report.target)} &middot; ${esc(report.label || 'scan')} &middot; ${esc(started)}</div>
<p><span class="banner">Overall risk: ${esc(risk)}</span></p>
<div class="cards">
  <div class="card"><div class="n" style="color:${sevColor.critical}">${c.critical}</div>Critical</div>
  <div class="card"><div class="n" style="color:${sevColor.high}">${c.high}</div>High</div>
  <div class="card"><div class="n" style="color:${sevColor.medium}">${c.medium}</div>Medium</div>
  <div class="card"><div class="n" style="color:${sevColor.low}">${c.low}</div>Low</div>
  <div class="card"><div class="n">${c.info}</div>Info</div>
</div>
${mon ? `<p class="meta">${mon.firstRun ? `Monitoring baseline established (${mon.total || 0} confirmed findings).` : `<b>Since last scan:</b> <b style="color:${sevColor.critical}">${(mon.new || []).length} new</b>, ${(mon.resolved || []).length} resolved.`}</p>` : ''}
${chainF.length ? `<h2>Attack Paths</h2><ul>${chainF.map((f) => `<li><span class="sev" style="background:${sevColor[f.severity] || '#6b7280'}">${esc((f.severity || '').toUpperCase())}</span> ${esc(f.detail)}</li>`).join('')}</ul>` : ''}
${impactF.length ? `<h2>Demonstrated Impact</h2><ul>${impactF.map((f) => `<li>${esc(f.detail)}</li>`).join('')}</ul>` : ''}
<h2>Scope &amp; Methodology</h2>
<p class="meta">Surface: ${esc(crawl)}. Standards: OWASP WSTG v4.2, OWASP ASVS v4.0, NIST SP 800-115. Findings are tool-confirmed (zero false positives). Classes executed (${classesTested.length}): ${esc(classesTested.join(', ') || '—')}.</p>
<h2>Findings</h2>
<table><thead><tr><th>#</th><th>Finding / Endpoint</th><th>Severity</th><th>CVSS 3.1</th><th>WSTG / ASVS</th><th>CWE / OWASP</th><th>Mitigation</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">No vulnerabilities confirmed within the tested classes.</td></tr>'}</tbody></table>
<h2>Compliance</h2>
<p class="meta">Per-finding mapping to OWASP Top 10 (2021), CWE, MITRE ATT&amp;CK, PCI DSS 4.0, and ISO 27001:2022 is included above. A clean result covers only the tested classes.</p>
<h2>Sign-off</h2>
<table class="signoff"><tbody>
<tr><th>Tester (name)</th><td></td></tr>
<tr><th>Certifications (OSCP / CREST / GWAPT)</th><td></td></tr>
<tr><th>Reviewed &amp; validated</th><td>☐</td></tr>
<tr><th>Signature</th><td></td></tr>
<tr><th>Date</th><td></td></tr>
</tbody></table>
<p class="disc">Automated findings generated by ${esc(engine)}. This becomes a <b>certified</b> penetration test only once a certified tester (OSCP/CREST) reviews, validates, and signs it. Automated coverage (${classesTested.length} classes) is not a substitute for full manual testing.</p>
</body></html>`;

  return { md, html, findings, counts: c, risk };
}
