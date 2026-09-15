// defender/respond.mjs — graduated, safe-by-default response.
//
// SAFETY: enforcement (block/isolate) happens ONLY in mode 'enforce'. In 'monitor' the defender
// still alerts, so a newly connected system is never broken by a bad read. Responder failures are
// swallowed — a broken enforcer must never take the defender down with it.
const ENFORCING = new Set(['block-inline', 'block-ip', 'isolate']);

// Invoke a responder without ever letting its failure reach the defender: a synchronous throw is
// caught, and a rejected promise from an async responder gets a rejection handler attached (never
// awaited) so it cannot become an unhandled rejection and kill the process.
function safeCall(fn, ...args) {
  if (typeof fn !== 'function') return;
  try {
    const r = fn(...args);
    if (r && typeof r.then === 'function') r.then(undefined, () => {});
  } catch {}
}

export function makeRateLimiter({ max = 20, windowMs = 60_000, now = () => Date.now() } = {}) {
  const hits = [];
  return () => {
    const t = now();
    while (hits.length && t - hits[0] > windowMs) hits.shift();
    if (hits.length >= max) return false;
    hits.push(t);
    return true;
  };
}

export function applyResponse(verdict, ctx = {}, opts = {}) {
  const { mode = 'monitor', deps = {}, allow = () => true } = opts;
  const wanted = verdict?.recommendedAction || 'observe';

  if (wanted === 'observe') return { action: 'observe', enforced: false, wanted, reason: 'no action required' };
  if (!allow()) return { action: 'observe', enforced: false, wanted, reason: 'rate limited' };

  safeCall(deps.alert, verdict, ctx);

  if (!ENFORCING.has(wanted)) return { action: 'alert', enforced: false, wanted, reason: 'alert only' };
  if (mode !== 'enforce')
    return { action: 'alert', enforced: false, wanted, reason: 'monitor mode — enforcement withheld' };

  safeCall(deps.enforce, wanted, verdict, ctx);
  return { action: wanted, enforced: true, wanted, reason: 'enforced' };
}
