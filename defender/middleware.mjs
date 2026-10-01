// defender/middleware.mjs — self-defense: run the Defender INSIDE the app it protects.
//
// The inline proxy (connectors.mjs) assumes Shannon sits in front of a separate app, reached over a
// port. That shape cannot work when the app to protect IS this dashboard: the proxy would listen on
// loopback inside the same container and no request could ever route to it. As Express middleware
// the defender sits on the real request path instead — no port, no DNS or TLS work, nothing to
// reconnect after a restart.
//
// It reuses the same tested pipeline as the proxy (classify → applyResponse → blackboard facts), so
// the zero-FP, monitor-only-by-default and fail-open guarantees are identical here.
//
// Two additions over the first version:
//   subscribe(fn)  — every detection (and every ban decision) is pushed to listeners as it happens,
//                    so the server can stream it live and fan it out to alert integrations.
//   repeat-offender ban — an IP that produces several CONFIRMED, ENFORCEABLE attacks inside a short
//                    window is refused outright for a while. Off by default; and even when enabled
//                    it starts in a would-have-banned mode that only reports, so an operator sees what
//                    it would do before it does it. Keyed strictly on the enforceable classes: the
//                    detect-only signatures fire on apostrophes and HTML tags and must never ban.
import { makeBlackboard } from '../packages/dashboard/agent-team.mjs';
import { defenderAgent } from './agent.mjs';
import { makeRateLimiter } from './respond.mjs';

// Paths where attack-shaped payloads are the PRODUCT, not an attack. Shannon's own tools post
// traversal strings, injection payloads and exploit bodies by design — the Repeater replays crafted
// requests, AI check and Sandbox carry generated probes, scans carry target payloads. Inspecting
// these would flag the dashboard's own features and, in enforce mode, break them outright.
export const SELF_SKIP = [
  /^\/api\/agent\//,
  /^\/api\/scans/,
  /^\/api\/defender\//,
  /^\/api\/code-scan\//,
  /^\/api\/personal-shield\//,
];

const MAX_RECENT = 50;

export const BAN_DEFAULTS = {
  enabled: false, // track repeat offenders at all
  enforce: false, // actually refuse banned IPs (false = report "would have banned" only)
  threshold: 5, // confirmed enforceable attacks …
  windowMs: 60_000, // … within this window …
  ttlMs: 15 * 60_000, // … earn a ban this long
};

export function createSelfDefense({
  mode = 'monitor',
  deps = {},
  skip = SELF_SKIP,
  maxRecent = MAX_RECENT,
  now = () => new Date().toISOString(),
  nowMs = () => Date.now(),
  ban = {},
  onDetection = null,
} = {}) {
  let current = mode === 'enforce' ? 'enforce' : 'monitor';
  const policy = { ...BAN_DEFAULTS, ...ban };
  const bb = makeBlackboard();
  const counters = { events: 0, defenses: 0, banned: 0 };
  const allow = makeRateLimiter();
  const recent = [];
  const listeners = new Set();
  if (typeof onDetection === 'function') listeners.add(onDetection);
  const handle = defenderAgent(bb, { getMode: () => current, deps, allow, counters });

  // Repeat-offender state. Timestamps per IP of confirmed enforceable attacks; active bans per IP.
  const offences = new Map(); // ip -> number[] (ms)
  const banned = new Map(); // ip -> until (ms)

  const emit = (payload) => {
    for (const fn of listeners) {
      try {
        fn(payload);
      } catch {
        // a broken listener must never affect request handling
      }
    }
  };

  const isBanned = (ip) => {
    const until = banned.get(ip);
    if (!until) return false;
    if (until <= nowMs()) {
      banned.delete(ip);
      return false;
    }
    return true;
  };

  const recordOffence = (ip) => {
    if (!policy.enabled || !ip) return;
    const t = nowMs();
    const list = (offences.get(ip) || []).filter((x) => t - x <= policy.windowMs);
    list.push(t);
    offences.set(ip, list);
    if (list.length >= policy.threshold && !isBanned(ip)) {
      const until = t + policy.ttlMs;
      banned.set(ip, until);
      offences.delete(ip);
      emit({ type: 'ban', at: now(), ip, until, count: list.length, enforce: policy.enforce });
    }
  };

  bb.subscribe('defense', (e) => {
    const { event, verdict, result } = e.data;
    const row = {
      type: 'detection',
      at: event.at,
      method: event.method,
      url: event.url,
      srcIp: event.srcIp || null,
      cls: verdict.cls,
      signal: verdict.signal,
      recommendedAction: verdict.recommendedAction,
      action: result.action,
      enforced: result.enforced,
    };
    recent.unshift(row);
    if (recent.length > maxRecent) recent.length = maxRecent;
    emit(row);
    // Only CONFIRMED ENFORCEABLE classes count toward a ban — regardless of monitor/enforce mode,
    // so monitor mode still shows what the policy would have done.
    if (verdict.recommendedAction === 'block-inline') recordOffence(row.srcIp);
  });

  function middleware(req, res, next) {
    try {
      const path = req.path || (req.url || '').split('?')[0];
      if (skip.some((r) => r.test(path))) return next();

      const ip = req.ip || req.socket?.remoteAddress || null;
      if (policy.enabled && policy.enforce && ip && isBanned(ip)) {
        counters.banned++;
        res.status(403).json({ error: 'Blocked by Shannon Defender (repeat offender)' });
        return;
      }

      // Mounted after express.json(), so a JSON body is already parsed; serialise it back for
      // signature matching. A body we cannot read is simply not inspected — never a reason to block.
      let body = '';
      if (typeof req.body === 'string') body = req.body;
      else if (req.body && typeof req.body === 'object') {
        try {
          body = JSON.stringify(req.body);
        } catch {
          body = '';
        }
      }

      const event = {
        at: now(),
        // The classifier keys HTTP signature matching off this source; a request arriving through
        // middleware is the same surface as one arriving through the proxy.
        source: 'http-proxy',
        srcIp: ip,
        method: req.method,
        url: req.originalUrl || req.url || '',
        headers: null,
        body,
        connId: null,
        raw: `${req.method} ${req.originalUrl || req.url || ''}`,
      };

      if (handle(event).block) {
        res.status(403).json({ error: 'Blocked by Shannon Defender' });
        return;
      }
    } catch {
      // FAIL-OPEN: a fault in our own defence must never take the app down with it.
    }
    return next();
  }

  return {
    middleware,
    blackboard: bb,
    stats: () => ({ ...counters, activeBans: [...banned.keys()].filter(isBanned).length }),
    recent: () => recent.slice(),
    getMode: () => current,
    setMode: (m) => {
      current = m === 'enforce' ? 'enforce' : 'monitor';
      emit({ type: 'mode', at: now(), mode: current });
      return current;
    },
    subscribe: (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    banPolicy: () => ({ ...policy }),
    bans: () => [...banned.entries()].filter(([ip]) => isBanned(ip)).map(([ip, until]) => ({ ip, until })),
    unban: (ip) => {
      const had = banned.delete(ip);
      offences.delete(ip);
      if (had) emit({ type: 'unban', at: now(), ip });
      return had;
    },
  };
}
