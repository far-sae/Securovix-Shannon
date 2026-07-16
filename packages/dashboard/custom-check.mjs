// AI CUSTOM CHECK — the SAFE form of a "custom exploit sandbox". Instead of executing arbitrary
// LLM-written code on the host (a server-side RCE risk — that belongs in the hardened Docker broker),
// the LLM AUTHORS a bounded HTTP check (method + path + a success matcher) and Shannon runs it
// DETERMINISTICALLY through the engine's SSRF-guarded fetcher. A match is reported as a labeled
// POTENTIAL lead (it is not a benign-proof by construction), never as a confirmed finding. Pure core.

export function evaluateMatcher(resp = {}, matcher = {}) {
  const status = Number(resp.status) || 0;
  const body = String(resp.body || '');
  const checks = [];
  if (matcher.status !== undefined) checks.push(status === Number(matcher.status));
  if (matcher.contains) checks.push(body.includes(String(matcher.contains)));
  if (matcher.regex) {
    try {
      checks.push(new RegExp(matcher.regex, 'i').test(body));
    } catch {
      checks.push(false);
    }
  }
  if (!checks.length) return false; // no assertion → never "matched" (never invents)
  return matcher.condition === 'or' ? checks.some(Boolean) : checks.every(Boolean);
}

// Sanitize an LLM-proposed (or user) check into a bounded, safe shape. Method allowlisted; path forced
// relative (so it can only hit the already-authorized target origin); matcher fields clamped.
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
export function sanitizeCheck(raw = {}) {
  const method = METHODS.has(String(raw.method || 'GET').toUpperCase()) ? String(raw.method).toUpperCase() : 'GET';
  let path = String(raw.path || '/');
  try {
    // If a full URL sneaks in, keep only its path+query so we can't be pointed off the target origin.
    path = new URL(path, 'http://x').pathname + (new URL(path, 'http://x').search || '');
  } catch {
    if (!path.startsWith('/')) path = `/${path}`;
  }
  const m = raw.matcher || {};
  const matcher = {};
  if (m.status !== undefined && Number.isFinite(Number(m.status))) matcher.status = Number(m.status);
  if (m.contains) matcher.contains = String(m.contains).slice(0, 200);
  if (m.regex) matcher.regex = String(m.regex).slice(0, 200);
  if (m.condition === 'or') matcher.condition = 'or';
  return {
    method,
    path,
    body: raw.body ? String(raw.body).slice(0, 10_000) : undefined,
    matcher,
    why: raw.why ? String(raw.why).slice(0, 300) : '',
  };
}
