// @securovix/defender — drop-in request inspection for the app you want to protect.
//
// Runs INSIDE the customer's app rather than in front of it. That is a deliberate trade:
//
//   * no DNS change, no TLS to terminate, no port to expose, nothing to reconnect after a deploy
//   * and — the part that matters most — Securovix is NOT in the customer's uptime path. If our
//     reporting endpoint is down or slow, their site keeps serving. An edge proxy cannot promise
//     that: when the proxy is down, the site behind it is down.
//
// Detection is local and synchronous (regex over URL + body, no network call on the hot path).
// Reporting is fire-and-forget: queued, flushed on a timer, dropped on failure. A request is never
// delayed, and never fails, because of us.
import { inspect } from './signatures.mjs';

const DEFAULTS = {
  mode: 'monitor',
  endpoint: 'https://securovix.com',
  flushMs: 10_000,
  maxQueue: 200,
  maxBody: 1024 * 1024, // inspect the first 1MB; past that, forward unexamined
  skip: [],
};

/**
 * Express/Connect middleware.
 *
 * @param {object} opts
 * @param {string} [opts.apiKey]   Securovix key (sk_...). Omit to run purely locally with no reporting.
 * @param {'monitor'|'enforce'} [opts.mode]  'monitor' observes and reports; 'enforce' returns 403 on
 *                                           a confirmed attack. Defaults to monitor — a new install
 *                                           must never start dropping a customer's traffic.
 * @param {string} [opts.endpoint] Base URL to report to.
 * @param {RegExp[]} [opts.skip]   Paths to leave uninspected (internal tooling that carries payloads).
 * @param {(d:object)=>void} [opts.onDetection] Local hook, called for every detection.
 */
export function shannonDefender(opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  let mode = cfg.mode === 'enforce' ? 'enforce' : 'monitor';
  const queue = [];
  const stats = { requests: 0, detections: 0, blocked: 0, reported: 0, dropped: 0 };

  const flush = async () => {
    if (!queue.length || !cfg.apiKey) return;
    const batch = queue.splice(0, queue.length);
    try {
      const r = await fetch(`${cfg.endpoint.replace(/\/$/, '')}/api/defender/report`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` },
        body: JSON.stringify({ detections: batch }),
      });
      if (r.ok) stats.reported += batch.length;
      else stats.dropped += batch.length;
    } catch {
      // Reporting is best-effort. Losing telemetry is acceptable; breaking the customer's app is not.
      stats.dropped += batch.length;
    }
  };

  const timer = setInterval(flush, cfg.flushMs);
  if (typeof timer.unref === 'function') timer.unref(); // never hold the host process open

  function middleware(req, res, next) {
    try {
      const path = req.path || String(req.url || '').split('?')[0];
      if (cfg.skip.some((r) => r.test(path))) return next();

      stats.requests++;

      let body = '';
      if (typeof req.body === 'string') body = req.body;
      else if (req.body && typeof req.body === 'object') {
        try {
          body = JSON.stringify(req.body);
        } catch {
          body = '';
        }
      }
      if (body.length > cfg.maxBody) body = body.slice(0, cfg.maxBody);

      const url = req.originalUrl || req.url || '';
      const verdict = inspect(url, body);

      if (verdict.attack) {
        stats.detections++;
        const enforced = verdict.enforce && mode === 'enforce';
        if (enforced) stats.blocked++;

        const detection = {
          at: new Date().toISOString(),
          method: req.method,
          url,
          cls: verdict.cls,
          signal: verdict.signal,
          enforced,
          srcIp: req.ip || req.socket?.remoteAddress || null,
        };

        if (queue.length < cfg.maxQueue) queue.push(detection);
        else stats.dropped++;

        try {
          cfg.onDetection?.(detection);
        } catch {}

        if (enforced) {
          res.status(403).json({ error: 'Blocked by Shannon Defender' });
          return;
        }
      }
    } catch {
      // FAIL-OPEN. A fault in our inspection must never take the customer's app down.
    }
    return next();
  }

  middleware.stats = () => ({ ...stats, queued: queue.length, mode });
  middleware.setMode = (m) => {
    mode = m === 'enforce' ? 'enforce' : 'monitor';
    return mode;
  };
  middleware.getMode = () => mode;
  middleware.flush = flush;
  middleware.stop = () => clearInterval(timer);
  return middleware;
}

export { inspect, ENFORCE_CLASSES, DETECT_SIGNATURES, ENFORCE_SIGNATURES } from './signatures.mjs';
