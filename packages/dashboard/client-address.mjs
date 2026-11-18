// Whose address is a request from?
//
// Express answers from X-Forwarded-For (`trust proxy`), which is right behind one ordinary proxy.
// Behind Railway's edge it is wrong: the last address in that header is the edge server itself, a
// different one on each request, so every visitor looks like one of a handful of edge servers. Rate
// limits are then shared by strangers, a ban lands on an edge server instead of an attacker, and
// "is this the same machine as before?" can never be answered. Railway puts the visitor's address
// in X-Real-IP, which its edge sets on every request.
//
// So: on Railway (recognised by the variables Railway itself provides) the address is read from
// X-Real-IP. SHANNON_CLIENT_IP_HEADER names a different header for another host, and "none" keeps
// Express's own answer.
import { isIP } from 'node:net';

export function clientIpHeader(env = process.env) {
  const chosen = String(env.SHANNON_CLIENT_IP_HEADER || '')
    .trim()
    .toLowerCase();
  if (chosen === 'none') return '';
  if (chosen) return chosen;
  return env.RAILWAY_ENVIRONMENT_ID || env.RAILWAY_SERVICE_ID || env.RAILWAY_PROJECT_ID ? 'x-real-ip' : '';
}

// The address a header carries, or null when the header is missing or is not an address.
export function headerAddress(headers, name) {
  if (!name) return null;
  const raw = headers?.[name];
  const value = String((Array.isArray(raw) ? raw[0] : raw) || '')
    .split(',')[0]
    .trim()
    .replace(/^\[|\]$/g, '');
  return isIP(value) ? value : null;
}

// Express middleware: makes req.ip the visitor's address. Mount it before anything that reads req.ip.
export function clientAddress(header = clientIpHeader()) {
  return (req, _res, next) => {
    const address = headerAddress(req.headers, header);
    if (address) Object.defineProperty(req, 'ip', { value: address, configurable: true, enumerable: true });
    next();
  };
}
