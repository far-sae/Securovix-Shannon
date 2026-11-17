// defender-edge — a PUBLIC, multi-tenant filtering reverse proxy.
//
// The dashboard's inline proxy binds loopback and hands out a random port, which is fine for a
// dashboard running on your own machine and useless as a hosted service: nothing on the internet can
// reach 127.0.0.1, and the port changes on every restart. This service is the hosted shape.
//
//   visitor → edge.securovix.com → (Host: app.customer.com) → that customer's real origin
//
// One public listener serves every customer, routed by the Host header rather than a port each.
// A customer points DNS at the edge:  app.customer.com  CNAME  edge.securovix.com
//
// THE TRADE, STATED PLAINLY: this puts Securovix in the customer's uptime path. If this service is
// down, their site is down. That is why it fails open in every direction it can — unknown host,
// inspection error, oversized body — and why the SDK (@securovix/defender) exists as the option that
// carries no such risk.
import http from 'node:http';
import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { BlockList, isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from '../defender-sdk/signatures.mjs';

const PORT = process.env.PORT || 8080;
const HOST = process.env.SHANNON_EDGE_BIND || '0.0.0.0';
const DASHBOARD = (process.env.SHANNON_DASHBOARD_URL || '').replace(/\/$/, '');
const API_KEY = process.env.SHANNON_EDGE_API_KEY || '';
const PLATFORM_TOKEN = process.env.SHANNON_EDGE_PLATFORM_TOKEN || '';
const EDGE_TOKEN = PLATFORM_TOKEN || API_KEY;
const ROUTES_PATH = PLATFORM_TOKEN ? '/api/platform/defender/edge/routes' : '/api/defender/edge/routes';
const REPORT_PATH = PLATFORM_TOKEN ? '/api/platform/defender/edge/report' : '/api/defender/report';
const INSTANCE = process.env.RAILWAY_REPLICA_ID || process.env.RAILWAY_DEPLOYMENT_ID || 'edge';
const ROUTES_REFRESH_MS = Number(process.env.SHANNON_EDGE_REFRESH_MS || 60_000);
const MAX_CLASSIFIED_BODY = 1024 * 1024;

// Hop-by-hop headers are per-connection (RFC 9110 §7.6.1). We re-frame the request, so forwarding
// the client's framing headers verbatim would let a crafted content-length + transfer-encoding pair
// desync us from the origin (CL.TE request smuggling) — unacceptable in a device that sits inline.
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

// hostname → { origin, mode }. Exported so tests can drive routing without a live dashboard.
export const routes = new Map();
const stats = { requests: 0, detections: 0, blocked: 0, unknownHost: 0 };
const pending = [];

// Addresses that are not on the public internet. A block list (not string prefixes) so that every
// way of writing an address is covered, including an IPv4 address wrapped in IPv6
// (::ffff:169.254.169.254) and the NAT64 range, which reach the same private hosts.
const PRIVATE_ADDRESSES = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3],
]) PRIVATE_ADDRESSES.addSubnet(network, prefix, 'ipv4');
for (const [network, prefix] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]])
  PRIVATE_ADDRESSES.addSubnet(network, prefix, 'ipv6');
export function isPrivateAddress(address) {
  const value = String(address || '').toLowerCase().replace(/^\[|\]$/g, '');
  const family = isIP(value);
  return family ? PRIVATE_ADDRESSES.check(value, family === 6 ? 'ipv6' : 'ipv4') : false;
}

function publicLookup(hostname, options, callback) {
  dnsLookup(hostname, options, (error, address, family) => {
    if (error) return callback(error);
    const addresses = Array.isArray(address) ? address : [{ address, family }];
    if (!addresses.length || addresses.some((x) => isPrivateAddress(x.address))) {
      return callback(new Error('private or reserved upstream address rejected'));
    }
    if (options?.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

function loadRoutesFromEnv() {
  try {
    for (const r of JSON.parse(process.env.SHANNON_EDGE_ROUTES || '[]')) {
      if (r?.host && r?.origin) {
        routes.set(String(r.host).toLowerCase(), {
          origin: r.origin,
          mode: r.mode === 'enforce' ? 'enforce' : 'monitor',
        });
      }
    }
  } catch {
    console.error('[edge] SHANNON_EDGE_ROUTES is not valid JSON — ignoring it');
  }
}

async function refreshRoutes() {
  if (!DASHBOARD || !EDGE_TOKEN) return;
  try {
    const r = await fetch(`${DASHBOARD}${ROUTES_PATH}`, {
      headers: { authorization: `Bearer ${EDGE_TOKEN}`, 'x-shannon-edge-instance': INSTANCE },
    });
    if (!r.ok) return;
    const { routes: list } = await r.json();
    if (!Array.isArray(list)) return;
    // A successful response is authoritative, including an empty list. This makes route deletion
    // and emergency revocation effective; transport/dashboard failures retain the last valid set.
    routes.clear();
    loadRoutesFromEnv(); // env entries are the floor; the dashboard adds to them
    for (const x of list) {
      if (x?.host && x?.origin) {
        routes.set(String(x.host).toLowerCase(), {
          origin: x.origin,
          mode: x.mode === 'enforce' ? 'enforce' : 'monitor',
        });
      }
    }
  } catch {
    // Keep serving the routes we already have. A dashboard outage must not break proxied traffic.
  }
}

async function flushDetections() {
  if (!pending.length || !DASHBOARD || !EDGE_TOKEN) return;
  const batch = pending.splice(0, pending.length);
  try {
    await fetch(`${DASHBOARD}${REPORT_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${EDGE_TOKEN}` },
      body: JSON.stringify({ detections: batch }),
    });
  } catch {
    // Telemetry is best-effort; never retried into a backlog that could grow without bound.
  }
}

export function createEdgeServer({ allowPrivateOrigins = false } = {}) {
  return http.createServer((req, res) => {
    res.on('error', () => {});
    req.on('error', () => {});

    const host = String(req.headers.host || '')
      .toLowerCase()
      .split(':')[0];

    if (req.url === '/__edge/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, routes: routes.size, stats }));
      return;
    }

    const route = routes.get(host);
    if (!route) {
      // Fail CLOSED only here, and only because there is nowhere to send the request: we have no
      // origin for this hostname. Anything else would be proxying to an arbitrary destination.
      stats.unknownHost++;
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('No origin configured for this host');
      return;
    }

    const o = new URL(route.origin);
    if (!allowPrivateOrigins && (isPrivateAddress(o.hostname) || o.hostname === 'localhost' || o.hostname.endsWith('.local'))) {
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('Unsafe upstream rejected');
      return;
    }
    const agent = o.protocol === 'https:' ? https : http;

    const upstreamHeaders = (bodyBuf) => {
      const out = {};
      for (const [k, v] of Object.entries(req.headers || {})) {
        const lk = k.toLowerCase();
        if (HOP_BY_HOP.has(lk) || lk === 'host' || lk === 'content-length') continue;
        out[k] = v;
      }
      out.host = o.host;
      const prior = req.headers['x-forwarded-for'];
      const ip = req.socket?.remoteAddress || '';
      out['x-forwarded-for'] = prior ? `${prior}, ${ip}` : ip;
      out['x-forwarded-proto'] = 'https';
      out['x-forwarded-host'] = host;
      if (bodyBuf === null) {
        const cl = req.headers['content-length'];
        if (cl !== undefined) out['content-length'] = cl;
      } else if (bodyBuf.length) {
        out['content-length'] = String(bodyBuf.length);
      }
      return out;
    };

    const openUpstream = (headers) => {
      const fwd = agent.request(
        {
          hostname: o.hostname,
          port: o.port || (o.protocol === 'https:' ? 443 : 80),
          path: req.url,
          method: req.method,
          headers,
          timeout: 15_000,
          lookup: allowPrivateOrigins ? undefined : publicLookup,
        },
        (up) => {
          up.on('error', () => res.destroy());
          try {
            // The origin's per-connection headers describe its connection to us, not ours to the visitor.
            const named = String(up.headers.connection || '').toLowerCase().split(',').map((x) => x.trim()).filter(Boolean);
            const headers = Object.fromEntries(Object.entries(up.headers).filter(([k]) => !HOP_BY_HOP.has(k.toLowerCase()) && !named.includes(k.toLowerCase())));
            res.writeHead(up.statusCode || 502, headers);
            up.pipe(res);
          } catch {
            up.destroy();
            res.destroy();
          }
        },
      );
      fwd.on('timeout', () => fwd.destroy());
      fwd.on('error', () => {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        try {
          res.writeHead(502);
          res.end('upstream error');
        } catch {
          res.destroy();
        }
      });
      return fwd;
    };

    let chunks = [];
    let size = 0;
    let oversize = false;

    // Whether to refuse the request, judged on the URL, the headers and this much of the body.
    const refuse = (bodyBuf) => {
      stats.requests++;
      let blocked = false;
      try {
        // latin1 keeps one char per byte, so ASCII signatures match and the ORIGINAL bytes are still
        // what gets forwarded — decoding as UTF-8 would silently corrupt uploads, gzip and protobuf.
        const verdict = inspect(req.url || '', bodyBuf.toString('latin1'), req.headers);
        if (verdict.attack) {
          stats.detections++;
          blocked = verdict.enforce && route.mode === 'enforce';
          if (blocked) stats.blocked++;
          if (pending.length < 500) {
            pending.push({
              at: new Date().toISOString(),
              host,
              method: req.method,
              url: `${host}${req.url}`,
              cls: verdict.cls,
              enforced: blocked,
              srcIp: req.socket?.remoteAddress || null,
              // The owner's own test carries a signed mark; the dashboard checks it. It changes nothing here.
              test: typeof req.headers['x-securovix-test'] === 'string' ? req.headers['x-securovix-test'].slice(0, 200) : undefined,
            });
          }
        }
      } catch {
        blocked = false; // FAIL-OPEN: our own fault must never break the customer's site
      }
      if (blocked) {
        res.writeHead(403, { 'content-type': 'text/plain', connection: 'close' });
        res.end('Blocked by Securovix Defender');
      }
      return blocked;
    };

    req.on('data', (d) => {
      if (oversize) return;
      size += d.length;
      if (size > MAX_CLASSIFIED_BODY) {
        // Past the inspection cap the rest is streamed through rather than buffered. What has
        // arrived so far — the URL, the headers and the first part of the body — is still judged.
        oversize = true;
        const prefix = Buffer.concat([...chunks, d]);
        chunks = [];
        if (refuse(prefix)) {
          req.resume();
          return;
        }
        const fwd = openUpstream(upstreamHeaders(null));
        fwd.write(prefix);
        req.pipe(fwd);
        return;
      }
      chunks.push(d);
    });

    req.on('end', () => {
      if (oversize) return;
      const bodyBuf = Buffer.concat(chunks);
      chunks = [];
      if (refuse(bodyBuf)) return;

      const fwd = openUpstream(upstreamHeaders(bodyBuf));
      if (bodyBuf.length) fwd.write(bodyBuf);
      fwd.end();
    });
  });
}

// Start only when this exact file is the process entry point. Checking only the
// basename is unsafe because the dashboard entry point is also named server.mjs.
export function isDirectExecution(entry = process.argv[1]) {
  return !!entry && resolve(entry) === fileURLToPath(import.meta.url);
}

if (isDirectExecution()) {
  loadRoutesFromEnv();
  refreshRoutes();
  const t1 = setInterval(refreshRoutes, ROUTES_REFRESH_MS);
  const t2 = setInterval(flushDetections, 10_000);
  t1.unref?.();
  t2.unref?.();
  createEdgeServer().listen(PORT, HOST, () => {
    console.log(`[edge] Securovix Defender edge listening on ${HOST}:${PORT} — ${routes.size} route(s)`);
    if (!DASHBOARD || !EDGE_TOKEN) {
      console.warn(
        '[edge] SHANNON_DASHBOARD_URL / SHANNON_EDGE_PLATFORM_TOKEN unset — routes come from SHANNON_EDGE_ROUTES only, and detections are not reported',
      );
    } else if (!PLATFORM_TOKEN) {
      console.warn('[edge] SHANNON_EDGE_API_KEY is legacy single-organization mode; set SHANNON_EDGE_PLATFORM_TOKEN for shared multi-tenant routing');
    }
  });
}
