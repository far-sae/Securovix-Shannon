// The "POTENTIAL" tier — labeled, UNPROVEN leads, kept strictly separate from confirmed (zero-FP)
// findings. This is how Shannon gets breadth (Strix-style coverage) without ever calling something
// confirmed that it hasn't proven. Every lead is marked tier:'potential' and says, in plain words,
// that it is NOT proven and needs manual review. Deterministic — no LLM/credits.
//
// Two sources, both cheap:
//   surfaceLeads   — from the crawled surface only (sensitive paths/params, exposed dev endpoints).
//   reflectionLeads — active: a param that reflects a benign marker verbatim → POTENTIAL reflected
//                     XSS/injection (reflection ≠ execution, so it is a lead, not a confirmed finding;
//                     the confirmed XSS prober is what proves or refutes it).

const SENSITIVE_PATHS = [
  [/\/\.git(\/|$)/i, 'Possible exposed .git directory'],
  [/\/\.env(\.|$|\/)/i, 'Possible exposed .env file'],
  [/\/(admin|administrator|wp-admin)(\/|$)/i, 'Admin interface'],
  [/\/(debug|console|actuator|_debug|_profiler)(\/|$)/i, 'Debug / management endpoint'],
  [/\/(swagger|api-docs|openapi|graphiql|redoc)(\/|$)/i, 'API schema / docs endpoint'],
  [/\/[^?]*\.(bak|old|sql|dump|zip|tar\.gz)($|\?)/i, 'Backup / dump artifact'],
  [/\/(phpinfo|info\.php|server-status|server-info)(\/|$)/i, 'Server-info endpoint'],
  [/\/(login|signin|auth|oauth)(\/|$)/i, 'Authentication endpoint'],
];
const SENSITIVE_PARAM =
  /(^|[_-])(token|api[_-]?key|secret|password|passwd|pwd|session|auth|access[_-]?token|private[_-]?key)($|[_-])/i;
const REFLECT_NONCE = 'sxLEADr9x73qz';

const pathname = (u) => {
  try {
    return new URL(u).pathname;
  } catch {
    return u;
  }
};

export function surfaceLeads(surface = {}) {
  const leads = [];
  const seen = new Set();
  const add = (kind, target, note) => {
    const id = `${kind}|${target}`;
    if (seen.has(id)) return;
    seen.add(id);
    leads.push({ kind, tier: 'potential', severity: 'info', target, note });
  };
  for (const p of surface.pages || []) {
    const u = p.url || '';
    for (const [re, label] of SENSITIVE_PATHS)
      if (re.test(u)) add('sensitive-path', u, `${label} discovered — review access controls or remove if unintended.`);
  }
  for (const pn of surface.paramNames || [])
    if (SENSITIVE_PARAM.test(pn))
      add(
        'sensitive-param',
        pn,
        `Parameter "${pn}" looks sensitive — ensure it is not logged, cached, or carried in URLs.`,
      );
  for (const ap of surface.apiPaths || [])
    if (/graphql/i.test(ap))
      add('graphql', ap, 'GraphQL endpoint — verify introspection is disabled and query depth/complexity are limited.');
  return leads;
}

export async function reflectionLeads(surface = {}, { fetchText, maxTargets = 8 } = {}) {
  if (typeof fetchText !== 'function') return [];
  const leads = [];
  const seen = new Set();
  const getUrls = (surface.pages || [])
    .map((p) => p.url)
    .filter((u) => {
      try {
        return new URL(u).search.length > 1;
      } catch {
        return false;
      }
    })
    .slice(0, maxTargets);
  for (const base of getUrls) {
    let u;
    try {
      u = new URL(base);
    } catch {
      continue;
    }
    for (const k of [...u.searchParams.keys()]) {
      const key = `${k}|${u.pathname}`;
      if (seen.has(key)) continue;
      const test = new URL(base);
      test.searchParams.set(k, REFLECT_NONCE);
      let body = '';
      try {
        body = (await fetchText(test.toString())) || '';
      } catch {
        body = '';
      }
      if (body.includes(REFLECT_NONCE)) {
        seen.add(key);
        leads.push({
          kind: 'reflection',
          tier: 'potential',
          severity: 'info',
          target: test.toString(),
          note: `Parameter "${k}" reflects input verbatim — POTENTIAL reflected XSS / injection. NOT proven to execute; the confirmed XSS prober is what would prove or refute this.`,
        });
      }
    }
  }
  return leads;
}

// Aggregate both sources, dedupe, and DROP any lead on a path that already has a CONFIRMED finding
// (if it's proven it belongs in the confirmed tier, not here). Bounded.
export async function gatherLeads(surface = {}, { fetchText, confirmedTargets = [] } = {}) {
  const confirmed = new Set(confirmedTargets.map(pathname));
  const all = [...surfaceLeads(surface), ...(await reflectionLeads(surface, { fetchText }))];
  return all.filter((l) => !confirmed.has(pathname(l.target))).slice(0, 40);
}
