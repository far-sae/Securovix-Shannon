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
  maxBody: 256 * 1024, // the first 256KB of a body is inspected; the rest passes uninspected
  skip: [],
  honeypot: false,
  scanners: false,
  // { threshold, windowMs, ttlMs } to refuse an address after repeated confirmed attacks. Off = null.
  ban: null,
  // { perMinute } to refuse an address that sends more requests than that in a minute. Off = null.
  rateLimit: null,
  // With an apiKey, the settings saved in the Securovix dashboard (watch-only or blocking, which
  // rules are on, pages never to inspect, ban, rate limit) replace the ones given here, and a change
  // there reaches this site within policyTtlMs — no redeploy. Set remotePolicy: false to keep the
  // settings in code.
  remotePolicy: true,
  policyTtlMs: 60_000,
};

// "/api/webhooks" covers that page and everything under it.
const under = (path, prefix) => path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);

// Bodies that are text by their declared type.
const TEXT_BODY = /json|x-www-form-urlencoded|xml|text\/|graphql/i;
// Bodies that are not: media and archives are never inspected. Anything else (no type, or
// application/octet-stream) is inspected when it reads as text, because a handler can parse it as
// JSON whatever the header said.
const BINARY_BODY =
  /^(?:image|video|audio|font)\/|application\/(?:pdf|zip|gzip|x-tar|x-7z-compressed|wasm|x-protobuf)|multipart\//i;
function readsAsText(sample) {
  let odd = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32) || c === 0xfffd) odd += 1;
  }
  return odd * 20 <= sample.length;
}

// The visitor's address, from the header the host platform itself writes. A header is only
// trustworthy on the platform that overwrites it: Vercel overwrites `x-vercel-forwarded-for` and
// `x-real-ip`, Cloudflare overwrites `cf-connecting-ip`. Anywhere else a visitor can send any of
// them, and a ban or rate limit keyed on a value the visitor chose is worthless (or a way to get
// someone else refused). So: name the platform, and only its header is read.
//   platform: 'vercel' | 'cloudflare' | 'none' (no address: bans and rate limits are off)
// Unset, Cloudflare Workers is recognised by itself; otherwise the headers are read in the order
// below, which is right on Vercel. Behind any other proxy, pass `platform: 'none'` or your own `getIp`.
const first = (value) => value?.split(',')[0].trim() || null;
const onCloudflare = () => {
  try {
    return globalThis.navigator?.userAgent === 'Cloudflare-Workers';
  } catch {
    return false;
  }
};
export function clientIp(request, platform) {
  const h = request.headers;
  const where = platform || (onCloudflare() ? 'cloudflare' : '');
  if (where === 'none') return null;
  if (where === 'cloudflare') return h.get('cf-connecting-ip') || null;
  if (where === 'vercel') return first(h.get('x-vercel-forwarded-for')) || h.get('x-real-ip') || null;
  return (
    first(h.get('x-vercel-forwarded-for')) ||
    h.get('cf-connecting-ip') ||
    h.get('x-real-ip') ||
    first(h.get('x-forwarded-for')) ||
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
 * @param {object|null} [opts.rateLimit]      { perMinute } requests one address may send. Off by default.
 * @param {boolean} [opts.remotePolicy]       Take the settings from the Securovix dashboard (default true, needs apiKey).
 * @param {'vercel'|'cloudflare'|'none'} [opts.platform]  Which host's client-address header to trust (see clientIp).
 * @param {(request: Request) => string|null} [opts.getIp]  Client address, if the defaults are wrong for your host.
 * @param {(d: object) => void} [opts.onDetection]  Local hook, called for every detection.
 * @returns {(request: Request, context?: {waitUntil?: Function}) => Promise<Response|null>}
 */
export function createWebDefender(opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  let mode = cfg.mode === 'enforce' ? 'enforce' : 'monitor';
  const honeypot = listOption(cfg.honeypot, HONEYPOT_PATHS);
  const scanners = listOption(cfg.scanners, SCANNER_AGENTS);
  const localBan = cfg.ban ? { threshold: 5, windowMs: 60_000, ttlMs: 15 * 60_000, ...cfg.ban } : null;
  // The ban settings in force for the request being handled (from the dashboard, or the local ones).
  let policy = localBan;
  const stats = { requests: 0, detections: 0, blocked: 0, banned: 0, limited: 0, reported: 0, dropped: 0 };

  // ── Settings from the dashboard ──────────────────────────────────────────────────────────────
  let remote = null; // the last settings received
  let loadedAt = 0; // when a load last finished, whether it worked or not
  let loading = null;
  const usesDashboard = () => !!cfg.apiKey && cfg.remotePolicy !== false;
  function loadSettings() {
    if (loading) return loading;
    let signal;
    try {
      signal = AbortSignal.timeout(3000);
    } catch {}
    loading = fetch(`${cfg.endpoint.replace(/\/$/, '')}/api/defender/sdk/policy`, {
      headers: { authorization: `Bearer ${cfg.apiKey}` },
      signal,
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data?.policy && typeof data.policy === 'object') remote = data.policy;
      })
      // The dashboard being away must not change how the site is protected: keep what we have.
      .catch(() => {})
      .finally(() => {
        loadedAt = Date.now();
        loading = null;
      });
    return loading;
  }
  async function settings(context) {
    if (!usesDashboard()) return null;
    if (!loadedAt) {
      // The first request of a new instance waits briefly, so blocking is on from the start
      // rather than after the first minute. Bounded: a slow dashboard never holds the site up.
      await Promise.race([loadSettings(), new Promise((resolve) => setTimeout(resolve, 1200))]);
    } else if (Date.now() - loadedAt > cfg.policyTtlMs) {
      const refresh = loadSettings();
      try {
        context?.waitUntil?.(refresh);
      } catch {}
    }
    return remote;
  }

  // ── Rate limit ───────────────────────────────────────────────────────────────────────────────
  // Counted in this instance's memory, like the ban: it stops a burst from one address, it is not
  // an exact global quota.
  const windows = new Map(); // ip -> { start, count, told }
  function overLimit(ip, perMinute) {
    if (!ip || !(perMinute > 0)) return null;
    const t = Date.now();
    let w = windows.get(ip);
    if (!w || t - w.start >= 60_000) {
      w = { start: t, count: 0, told: false };
      windows.set(ip, w);
      if (windows.size > 5000) windows.delete(windows.keys().next().value);
    }
    w.count += 1;
    if (w.count <= perMinute) return null;
    const first = !w.told;
    w.told = true;
    return { first, retryAfter: Math.max(1, Math.ceil((w.start + 60_000 - t) / 1000)) };
  }
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
    const type = request.headers.get('content-type') || '';
    if (BINARY_BODY.test(type)) return '';
    // clone() so the application still receives the body untouched. Only the first maxBody bytes
    // are read: a larger body is inspected up to there instead of not at all.
    const reader = request.clone().body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let bytes = 0;
    try {
      while (bytes < cfg.maxBody) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        text += decoder.decode(value, { stream: true });
      }
    } finally {
      reader.cancel().catch(() => {});
    }
    if (text.length > cfg.maxBody) text = text.slice(0, cfg.maxBody);
    return TEXT_BODY.test(type) || readsAsText(text.slice(0, 2048)) ? text : '';
  }

  async function defend(request, context) {
    try {
      const url = new URL(request.url);
      if (cfg.skip.some((r) => r.test(url.pathname))) return null;

      // What the owner set in the dashboard, when there is any; otherwise the options given in code.
      const site = await settings(context);
      if (site?.enabled === false) return null;
      if (Array.isArray(site?.skip) && site.skip.some((prefix) => under(url.pathname, String(prefix)))) return null;
      const activeMode = site ? (site.mode === 'enforce' ? 'enforce' : 'monitor') : mode;
      policy = site
        ? site.ban?.enabled
          ? {
              threshold: Number(site.ban.threshold) || 5,
              windowMs: 60_000,
              ttlMs: (Number(site.ban.minutes) || 15) * 60_000,
            }
          : null
        : localBan;
      const perMinute = site
        ? site.rateLimit?.enabled
          ? Number(site.rateLimit.perMinute)
          : 0
        : Number(cfg.rateLimit?.perMinute || 0);
      stats.requests++;

      const ip = cfg.getIp ? cfg.getIp(request) : clientIp(request, cfg.platform);
      if (policy && activeMode === 'enforce' && ip && isBanned(ip)) {
        stats.banned++;
        return json(403, 'Blocked by Securovix Defender (repeat offender)');
      }

      const flood = overLimit(ip, perMinute);
      if (flood) {
        stats.limited++;
        if (flood.first) {
          report(
            {
              at: new Date().toISOString(),
              method: request.method,
              url: `${url.host}${url.pathname}`.slice(0, 300),
              cls: 'rate-limit',
              signal: `more than ${perMinute} requests in a minute from one address`,
              enforced: activeMode === 'enforce',
              srcIp: ip,
            },
            context,
          );
        }
        if (activeMode === 'enforce') {
          return new Response(JSON.stringify({ error: 'Too many requests' }), {
            status: 429,
            headers: {
              'content-type': 'application/json',
              'cache-control': 'no-store',
              'retry-after': String(flood.retryAfter),
            },
          });
        }
      }

      const verdict = inspectRequest({
        url: url.pathname + url.search,
        path: url.pathname,
        body: await readBody(request),
        userAgent: request.headers.get('user-agent'),
        headers: request.headers,
        honeypot: site ? (site.honeypot ? HONEYPOT_PATHS : null) : honeypot,
        scanners: site ? (site.scanners ? SCANNER_AGENTS : null) : scanners,
        disabled: Array.isArray(site?.disabled) ? site.disabled : null,
      });
      if (!verdict.attack) return null;

      stats.detections++;
      const enforced = verdict.enforce && activeMode === 'enforce';
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
      // A request from the owner's own test carries a signed mark. It is passed on untouched for the
      // dashboard to check; here it changes nothing, so a marked attack is blocked like any other.
      const mark = request.headers.get('x-securovix-test');
      if (mark) detection.test = mark.slice(0, 200);
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

  defend.stats = () => ({
    ...stats,
    mode: remote ? (remote.mode === 'enforce' ? 'enforce' : 'monitor') : mode,
    settings: remote ? 'dashboard' : 'local',
    activeBans: [...banned.keys()].filter(isBanned).length,
  });
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
