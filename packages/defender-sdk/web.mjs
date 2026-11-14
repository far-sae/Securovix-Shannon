// @securovix/defender/web — the same inspection for runtimes that speak the Web Fetch API instead
// of Express: Vercel Routing Middleware, Next.js middleware, Cloudflare Workers, Deno, Bun.
//
//   const defend = createWebDefender({ mode: 'enforce', honeypot: true, scanners: true });
//   const blocked = await defend(request, context);   // a Response to send, or null to continue
//
// Same rules as the Express middleware: detection is local, reporting is best-effort, and any fault
// in here lets the request through (fail-open). Nothing in this file touches a Node-only API.
//
// One difference to know about. Serverless and edge runtimes run many short-lived instances, so the
// repeat-offender ban kept here lives in one instance's memory: it slows a scanner down, it is not
// a shared blocklist. The Securovix dashboard's own ban is database-backed; this one is not.
import { HONEYPOT_PATHS, SCANNER_AGENTS, inspectRequest, listOption } from './signatures.mjs';

const DEFAULTS = {
  mode: 'monitor',
  endpoint: 'https://origin.securovix.com',
  maxBody: 256 * 1024, // inspect the first 256KB of a body; a larger one is not read at all
  skip: [],
  honeypot: false,
  scanners: false,
  // { threshold, windowMs, ttlMs } to refuse an address after repeated confirmed attacks. Off = null.
  ban: null,
};

// Bodies worth reading as text. Uploads and other binary types are never buffered.
const TEXT_BODY = /json|x-www-form-urlencoded|xml|text\/|graphql/i;

// The platform-set client address, most trustworthy first. On Vercel and Cloudflare the platform
// overwrites these, so a visitor cannot forge them; behind another proxy, pass your own `getIp`.
function clientIp(request) {
  const h = request.headers;
  return (
    h.get('x-vercel-forwarded-for')?.split(',')[0].trim() ||
    h.get('cf-connecting-ip') ||
    h.get('x-real-ip') ||
    h.get('x-forwarded-for')?.split(',')[0].trim() ||
    null
  );
}

const json = (status, error) =>
  new Response(JSON.stringify({ error }), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

/**
 * @param {object} opts
 * @param {'monitor'|'enforce'} [opts.mode]   'monitor' (default) observes and reports; 'enforce' blocks.
 * @param {string} [opts.apiKey]              Securovix key. Omit to run locally with no reporting.
 * @param {string} [opts.endpoint]            Base URL to report to.
 * @param {RegExp[]} [opts.skip]              Paths to leave uninspected.
 * @param {boolean|RegExp} [opts.honeypot]    Scanner-bait paths → 404. Off by default.
 * @param {boolean|RegExp} [opts.scanners]    Attack tools named in the User-Agent → 403. Off by default.
 * @param {object|null} [opts.ban]            { threshold = 5, windowMs = 60000, ttlMs = 900000 }.
 * @param {(request: Request) => string|null} [opts.getIp]  Client address, if the defaults are wrong for your host.
 * @param {(d: object) => void} [opts.onDetection]  Local hook, called for every detection.
 * @returns {(request: Request, context?: {waitUntil?: Function}) => Promise<Response|null>}
 */
export function createWebDefender(opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  let mode = cfg.mode === 'enforce' ? 'enforce' : 'monitor';
  const honeypot = listOption(cfg.honeypot, HONEYPOT_PATHS);
  const scanners = listOption(cfg.scanners, SCANNER_AGENTS);
  const policy = cfg.ban ? { threshold: 5, windowMs: 60_000, ttlMs: 15 * 60_000, ...cfg.ban } : null;
  const stats = { requests: 0, detections: 0, blocked: 0, banned: 0, reported: 0, dropped: 0 };
  const offences = new Map(); // ip -> number[] (ms)
  const banned = new Map(); // ip -> until (ms)

  const isBanned = (ip) => {
    const until = banned.get(ip);
    if (!until) return false;
    if (until <= Date.now()) {
      banned.delete(ip);
      return false;
    }
    return true;
  };

  const recordOffence = (ip, weight) => {
    if (!policy || !ip) return;
    const t = Date.now();
    const list = (offences.get(ip) || []).filter((x) => t - x <= policy.windowMs);
    for (let i = 0; i < weight; i++) list.push(t);
    if (list.length >= policy.threshold) {
      banned.set(ip, t + policy.ttlMs);
      offences.delete(ip);
    } else {
      offences.set(ip, list);
    }
    // Bound memory: an instance that sees many attackers keeps only the most recent ones.
    if (offences.size > 5000) offences.delete(offences.keys().next().value);
    if (banned.size > 5000) banned.delete(banned.keys().next().value);
  };

  const report = (detection, context) => {
    if (!cfg.apiKey) return;
    const sent = fetch(`${cfg.endpoint.replace(/\/$/, '')}/api/defender/report`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify({ detections: [detection] }),
    })
      .then((r) => {
        if (r.ok) stats.reported++;
        else stats.dropped++;
      })
      .catch(() => {
        stats.dropped++;
      });
    // Without waitUntil the platform may freeze the instance before the report leaves; with it the
    // response is still not delayed.
    try {
      context?.waitUntil?.(sent);
    } catch {}
  };

  async function readBody(request) {
    if (request.method === 'GET' || request.method === 'HEAD' || !request.body) return '';
    if (!TEXT_BODY.test(request.headers.get('content-type') || '')) return '';
    const declared = Number(request.headers.get('content-length') || 0);
    if (declared > cfg.maxBody) return '';
    // clone() so the application still receives the body untouched.
    const text = await request.clone().text();
    return text.length > cfg.maxBody ? text.slice(0, cfg.maxBody) : text;
  }

  async function defend(request, context) {
    try {
      const url = new URL(request.url);
      if (cfg.skip.some((r) => r.test(url.pathname))) return null;
      stats.requests++;

      const ip = (cfg.getIp || clientIp)(request);
      if (policy && mode === 'enforce' && ip && isBanned(ip)) {
        stats.banned++;
        return json(403, 'Blocked by Securovix Defender (repeat offender)');
      }

      const verdict = inspectRequest({
        url: url.pathname + url.search,
        path: url.pathname,
        body: await readBody(request),
        userAgent: request.headers.get('user-agent'),
        honeypot,
        scanners,
      });
      if (!verdict.attack) return null;

      stats.detections++;
      const enforced = verdict.enforce && mode === 'enforce';
      const instant = verdict.cls === 'honeypot' || verdict.cls === 'scanner-tool';
      if (verdict.enforce) recordOffence(ip, instant && policy ? policy.threshold : 1);

      const detection = {
        at: new Date().toISOString(),
        method: request.method,
        url: `${url.host}${url.pathname}${url.search}`.slice(0, 300),
        cls: verdict.cls,
        signal: verdict.signal,
        enforced,
        srcIp: ip,
      };
      report(detection, context);
      try {
        cfg.onDetection?.(detection);
      } catch {}

      if (!enforced) return null;
      stats.blocked++;
      // A honeypot hit gets a plain 404, so the scanner learns nothing.
      return verdict.cls === 'honeypot' ? json(404, 'Not found') : json(403, 'Blocked by Securovix Defender');
    } catch {
      // FAIL-OPEN. A fault in our inspection must never take the site down.
      return null;
    }
  }

  defend.stats = () => ({ ...stats, mode, activeBans: [...banned.keys()].filter(isBanned).length });
  defend.setMode = (m) => {
    mode = m === 'enforce' ? 'enforce' : 'monitor';
    return mode;
  };
  defend.getMode = () => mode;
  return defend;
}

/**
 * The response that tells Vercel Routing Middleware to continue to the page or function — what
 * `next()` from `@vercel/functions` returns, without needing that package installed.
 */
export const vercelNext = () => new Response(null, { headers: { 'x-middleware-next': '1' } });

export { inspect, inspectRequest, HONEYPOT_PATHS, SCANNER_AGENTS } from './signatures.mjs';
