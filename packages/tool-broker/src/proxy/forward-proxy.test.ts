import { type Server, createServer, request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScopeEnforcer } from '../scope/enforcer.js';
import type { ScopeConfig } from '../types.js';
import { createForwardProxy } from './forward-proxy.js';

function scope(ips: string[]): ScopeConfig {
  return {
    targetHost: 'target.test',
    targetIps: ips,
    allowlistCidrs: [],
    allowPrivateCidrs: [],
    focusPaths: [],
    avoidPaths: [],
  };
}

// GET through the proxy: the absolute URL goes in the request path (HTTP proxy convention).
function viaProxy(proxyPort: number, absoluteUrl: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: absoluteUrl }, (res) => {
      let body = '';
      res.on('data', (c) => {
        body += c;
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    r.on('error', reject);
    r.end();
  });
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as AddressInfo).port;
}

describe('createForwardProxy', () => {
  let upstream: Server;
  let upstreamPort: number;

  beforeAll(async () => {
    upstream = createServer((_req, res) => {
      res.writeHead(200);
      res.end('upstream-ok');
    });
    upstreamPort = await listen(upstream);
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  it('forwards an allowed request to the resolved IP (forwarding mechanics)', async () => {
    // The upstream is on loopback, which the real enforcer hard-denies; use an
    // allow-stub to isolate the FORWARDING path. Block decisions are covered below.
    const allowAll = { evaluate: () => ({ allowed: true, reason: 'in-scope' as const }) } as unknown as ScopeEnforcer;
    const proxy = createForwardProxy({ enforcer: allowAll, resolve: async () => '127.0.0.1' });
    const port = await listen(proxy);
    try {
      const r = await viaProxy(port, `http://target.test:${upstreamPort}/x`);
      expect(r.status).toBe(200);
      expect(r.body).toBe('upstream-ok');
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });

  it('blocks a request that resolves to an out-of-scope IP (403)', async () => {
    const proxy = createForwardProxy({
      enforcer: new ScopeEnforcer(scope(['93.184.216.34'])),
      resolve: async () => '8.8.8.8',
    });
    const port = await listen(proxy);
    try {
      const r = await viaProxy(port, 'http://target.test/x');
      expect(r.status).toBe(403);
      expect(r.body).toContain('out-of-scope-host');
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });

  it('hard-blocks a request that resolves to cloud metadata (403), defeating rebinding', async () => {
    const proxy = createForwardProxy({
      enforcer: new ScopeEnforcer(scope(['93.184.216.34'])),
      resolve: async () => '169.254.169.254',
    });
    const port = await listen(proxy);
    try {
      const r = await viaProxy(port, 'http://target.test/latest/meta-data/');
      expect(r.status).toBe(403);
      expect(r.body).toContain('denied-metadata');
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });
});
