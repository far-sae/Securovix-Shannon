#!/usr/bin/env node
/**
 * Exposed services — fourth non-web module. Detects UNAUTHENTICATED data services and anonymous FTP
 * on the host that serves the client's verified domain.
 *
 * SAFETY / AUTHORIZATION (important): this is OPT-IN and deliberately narrow. It does NOT port-scan a
 * range — it connects to a handful of KNOWN service ports on the SAME host the client already
 * verified for web scanning, and only reports a finding when the service answers WITHOUT
 * authentication (a real, provable misconfiguration). If the host is behind a CDN/shared host those
 * ports simply don't answer → nothing is reported. Zero-FP: every finding is a live unauth response.
 */

import net from 'node:net';

// Minimal TCP probe: connect, optionally send a line, resolve true when `matchRe` is seen.
function tcpProbe(host, port, send, matchRe, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let data = '';
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (ok) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {}
      resolve({ ok, banner: data.slice(0, 200) });
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.on('connect', () => {
      if (send) socket.write(send);
    });
    socket.on('data', (d) => {
      data += d.toString('latin1');
      if (matchRe.test(data)) finish(true);
      else if (data.length > 8192) finish(false);
    });
    socket.on('error', () => finish(false));
    socket.on('close', () => finish(matchRe.test(data)));
  });
}

const F = (severity, target, detail) => ({
  tool: 'exposed-service',
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool: 'exposed-service', detail }),
});

// Redis: PING → +PONG only when NO auth is required (a password-protected Redis answers -NOAUTH).
export async function checkRedis(host, port = 6379) {
  const r = await tcpProbe(host, port, 'PING\r\n', /\+PONG/);
  return r.ok
    ? F(
        'critical',
        `${host}:${port}`,
        'Unauthenticated Redis exposed (PING → +PONG without AUTH) — full read/write to the datastore',
      )
    : null;
}

// Memcached: stats → STAT lines when unauthenticated.
export async function checkMemcached(host, port = 11211) {
  const r = await tcpProbe(host, port, 'stats\r\n', /STAT (?:pid|version|uptime)/);
  return r.ok ? F('high', `${host}:${port}`, 'Unauthenticated Memcached exposed (stats returned without auth)') : null;
}

// Elasticsearch: the HTTP banner (cluster_name + tagline / lucene_version) when open to the world.
export async function checkElasticsearch(host, port = 9200) {
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 6000);
    const r = await fetch(`http://${host}:${port}/`, { signal: c.signal });
    const body = await r.text().catch(() => '');
    clearTimeout(t);
    if (/"cluster_name"/.test(body) && /"lucene_version"|You Know, for Search/i.test(body))
      return F(
        'critical',
        `${host}:${port}`,
        'Unauthenticated Elasticsearch exposed (cluster banner served without auth) — indices are readable',
      );
  } catch {}
  return null;
}

// Anonymous FTP: a 230 (login successful) after USER anonymous / PASS.
export function checkFtpAnon(host, port = 21, timeoutMs = 6000) {
  return new Promise((resolve) => {
    let stage = 0;
    let buf = '';
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (ok) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {}
      resolve(ok ? F('medium', `${host}:${port}`, 'Anonymous FTP login allowed (USER anonymous → 230)') : null);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.on('error', () => finish(false));
    socket.on('data', (d) => {
      buf += d.toString('latin1');
      if (stage === 0 && /(^|\n)220/.test(buf)) {
        stage = 1;
        buf = '';
        socket.write('USER anonymous\r\n');
      } else if (stage === 1 && /(^|\n)33[01]/.test(buf)) {
        stage = 2;
        buf = '';
        socket.write('PASS anonymous@example.com\r\n');
      } else if (stage >= 1 && /(^|\n)230/.test(buf)) {
        finish(true);
      } else if (/(^|\n)530/.test(buf)) {
        finish(false);
      }
    });
    socket.on('close', () => finish(false));
  });
}

// Run all service checks against ONE host (the verified web host). services override lets tests point
// at mock servers on custom ports.
export async function runNetworkScan(host, { services } = {}) {
  const checks = services || [
    () => checkRedis(host),
    () => checkMemcached(host),
    () => checkElasticsearch(host),
    () => checkFtpAnon(host),
  ];
  const results = await Promise.all(checks.map((c) => c().catch(() => null)));
  return { findings: results.filter(Boolean) };
}
