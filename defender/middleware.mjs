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
import { makeBlackboard } from '../packages/dashboard/agent-team.mjs';
import { defenderAgent } from './agent.mjs';
import { makeRateLimiter } from './respond.mjs';

// Paths where attack-shaped payloads are the PRODUCT, not an attack. Shannon's own tools post
// traversal strings, injection payloads and exploit bodies by design — the Repeater replays crafted
// requests, AI check and Sandbox carry generated probes, scans carry target payloads. Inspecting
// these would flag the dashboard's own features and, in enforce mode, break them outright.
export const SELF_SKIP = [/^\/api\/agent\//, /^\/api\/scans/, /^\/api\/defender\//, /^\/api\/code-scan\//];

const MAX_RECENT = 50;

export function createSelfDefense({
  mode = 'monitor',
  deps = {},
  skip = SELF_SKIP,
  maxRecent = MAX_RECENT,
  now = () => new Date().toISOString(),
} = {}) {
  let current = mode === 'enforce' ? 'enforce' : 'monitor';
  const bb = makeBlackboard();
  const counters = { events: 0, defenses: 0 };
  const allow = makeRateLimiter();
  const recent = [];
  const handle = defenderAgent(bb, { getMode: () => current, deps, allow, counters });

  bb.subscribe('defense', (e) => {
    const { event, verdict, result } = e.data;
    recent.unshift({
      at: event.at,
      method: event.method,
      url: event.url,
      cls: verdict.cls,
      signal: verdict.signal,
      action: result.action,
      enforced: result.enforced,
    });
    if (recent.length > maxRecent) recent.length = maxRecent;
  });

  function middleware(req, res, next) {
    try {
      const path = req.path || (req.url || '').split('?')[0];
      if (skip.some((r) => r.test(path))) return next();

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
        srcIp: req.ip || req.socket?.remoteAddress || null,
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
    stats: () => ({ ...counters }),
    recent: () => recent.slice(),
    getMode: () => current,
    setMode: (m) => {
      current = m === 'enforce' ? 'enforce' : 'monitor';
      return current;
    },
  };
}
