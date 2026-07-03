#!/usr/bin/env node
/**
 * CVSS v3.1 base-score calculator (official formula) + per-vuln-class base vectors.
 * Used to give every confirmed finding an industry-standard CVSS score + vector string for
 * certification-grade reports. Verified against the FIRST/NVD spec examples in cvss.test.mjs.
 */

const IMPACT = { H: 0.56, L: 0.22, N: 0 };
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.5 }, // scope changed
};

// Official CVSS 3.1 "roundup": smallest 1-decimal number >= x (handles float error).
function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10.0;
}

export function severityFromScore(s) {
  if (s === 0) return 'none';
  if (s < 4) return 'low';
  if (s < 7) return 'medium';
  if (s < 9) return 'high';
  return 'critical';
}

export function cvss31(vector) {
  const m = {};
  for (const part of vector.replace(/^CVSS:3\.[01]\//, '').split('/')) {
    const [k, v] = part.split(':');
    if (k) m[k] = v;
  }
  const changed = m.S === 'C';
  const av = W.AV[m.AV];
  const ac = W.AC[m.AC];
  const ui = W.UI[m.UI];
  const pr = (changed ? W.PR_C : W.PR_U)[m.PR];
  const isc = 1 - (1 - IMPACT[m.C]) * (1 - IMPACT[m.I]) * (1 - IMPACT[m.A]);
  const impact = changed ? 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15 : 6.42 * isc;
  const expl = 8.22 * av * ac * pr * ui;
  let score = 0;
  if (impact > 0) score = roundup(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
  return {
    score,
    severity: severityFromScore(score),
    vector: vector.startsWith('CVSS:') ? vector : `CVSS:3.1/${vector}`,
  };
}

// Representative base vectors per vuln class (a pentester can refine per-finding).
export const CVSS_VECTORS = {
  'rce-ssti': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'rce-deser': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'cmd-injection': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  sqli: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'path-traversal': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  ssrf: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  'secrets-exposure': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  'token-forgery': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  'authz-bypass': 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  'graphql-idor': 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  xss: 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  'cors-misconfig': 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
  'open-redirect': 'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
  'security-headers': 'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
  nosql: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  xxe: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
  'host-header': 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  crlf: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N',
};

export const CVSS_BY_SEVERITY = {
  critical: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  high: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  medium: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  low: 'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
  info: 'AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N',
};

// Resolve a CVSS score for a finding: prefer the class vector, fall back to its severity label.
export function cvssForClass(cls, severity = 'medium') {
  const v = CVSS_VECTORS[cls] || CVSS_BY_SEVERITY[(severity || 'medium').toLowerCase()] || CVSS_BY_SEVERITY.medium;
  return cvss31(v);
}
