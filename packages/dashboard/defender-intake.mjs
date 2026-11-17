// What the dashboard accepts from a protected site, and how much of it.
//
// A site key sits on a customer's web server, and a real attack can be a flood. Neither may fill an
// organization's history in seconds, or send its owner one message per request. Reports are also
// text written by a stranger (the attacker chose the URL), so each field is checked for type and
// shape before it is stored.
import { isIP } from 'node:net';

const text = (value, max) => (typeof value === 'string' ? value.slice(0, max) : '');

// One reported detection, reduced to the fields that are stored, each of a known type and length.
export function cleanDetection(raw) {
  const method = text(raw?.method, 10).toUpperCase();
  const cls = text(raw?.cls, 60).toLowerCase();
  const address = text(raw?.srcIp, 64).trim();
  return {
    method: /^[A-Z]+$/.test(method) ? method : '',
    url: text(raw?.url, 300),
    cls: /^[a-z0-9][a-z0-9-]*$/.test(cls) ? cls : 'unknown',
    enforced: raw?.enforced === true,
    srcIp: isIP(address) ? address : null,
    at:
      typeof raw?.at === 'string' && Number.isFinite(Date.parse(raw.at))
        ? new Date(raw.at).toISOString()
        : new Date().toISOString(),
  };
}

/**
 * Per-minute allowances, counted in memory per dashboard instance.
 * - admit(orgId, source): 'store' while the organization is under its per-minute allowance for that
 *   source, 'overflow' for the first report over it (the caller stores one notice), then 'drop'.
 * - alertOnce(orgId, key): true for the first alert with that key in the window, false after.
 */
export function createIntakeGate({
  perMinute = 300,
  windowMs = 60_000,
  now = () => Date.now(),
  maxKeys = 10_000,
} = {}) {
  const windows = new Map(); // key -> { start, used, dropped }
  const alerts = new Map(); // key -> last sent (ms)
  const trim = (map, expired) => {
    if (map.size < maxKeys) return;
    for (const [key, value] of map) if (expired(value)) map.delete(key);
    while (map.size >= maxKeys) map.delete(map.keys().next().value);
  };
  return {
    admit(orgId, source) {
      const key = `${orgId}|${source}`;
      const t = now();
      let w = windows.get(key);
      if (!w || t - w.start >= windowMs) {
        trim(windows, (value) => t - value.start >= windowMs);
        w = { start: t, used: 0, dropped: 0 };
        windows.set(key, w);
      }
      if (w.used < perMinute) {
        w.used += 1;
        return 'store';
      }
      w.dropped += 1;
      return w.dropped === 1 ? 'overflow' : 'drop';
    },
    alertOnce(orgId, key) {
      const id = `${orgId}|${key}`;
      const t = now();
      const last = alerts.get(id);
      if (last !== undefined && t - last < windowMs) return false;
      trim(alerts, (value) => t - value >= windowMs);
      alerts.set(id, t);
      return true;
    },
    perMinute,
    size: () => windows.size + alerts.size,
  };
}
