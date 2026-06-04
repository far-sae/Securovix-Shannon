import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildServer } from './server-main.js';
import type { ScopeConfig } from './types.js';

const scope: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};

describe('buildServer (broker bootstrap)', () => {
  // No Docker needed: /health does not invoke the sandbox executor.
  const server = buildServer({
    scope,
    scopeKey: 'k',
    recordKey: 'r',
    scanNet: 'bridge',
    imageForTool: (t) => `shannon-tool-${t}:local`,
  });
  let base = '';

  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('builds from explicit config and serves /health', async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });
});
