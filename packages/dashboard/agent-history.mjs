// Stable identity + diff for agent runs, so scans can be compared over time (regression tracking).
// A finding's key is its class + a NORMALIZED target (volatile query values / numeric ids / scan
// nonces stripped) so the same issue on the same endpoint matches across runs even when a specific
// value changes. Pure — no storage/deps. The diff never invents: a finding is "new", "fixed", or
// "still present" purely by key membership.

const normTarget = (raw) => {
  let t = String(raw || '');
  try {
    const u = new URL(t);
    t = u.origin + u.pathname + u.search;
  } catch {}
  return t
    .replace(/([?&])(sx[a-z0-9]+|_|nonce|ts|t)=[^&#]*/gi, '$1') // drop scan nonces / cache-busters
    .replace(/=[0-9a-f]{8,}/gi, '=H') // long hex/uuid values → H
    .replace(/=\d+/g, '=N') // numeric query values → N
    .replace(/\/\d+(?=\/|$)/g, '/N') // numeric path ids → N
    .replace(/[?&]+$/, '');
};

export function findingKey(f = {}) {
  const cls = String(f.cls || f.tool || '');
  return `${cls}|${normTarget(f.target)}`;
}

// diffRuns(prev, curr) → what changed between two runs (each is { findings: [...] }).
export function diffRuns(prev = {}, curr = {}) {
  const prevMap = new Map((prev.findings || []).map((f) => [findingKey(f), f]));
  const currMap = new Map((curr.findings || []).map((f) => [findingKey(f), f]));
  const added = [];
  const removed = [];
  const unchanged = [];
  for (const [k, f] of currMap) (prevMap.has(k) ? unchanged : added).push(f);
  for (const [k, f] of prevMap) if (!currMap.has(k)) removed.push(f);
  return { added, removed, unchanged, summary: { new: added.length, fixed: removed.length, still: unchanged.length } };
}
