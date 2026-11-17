import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildServer, buildServerFromEnv } from './server-main.js';
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

describe('buildServerFromEnv (keys)', () => {
  const names = ['SHANNON_BROKER_SCOPE', 'SHANNON_BROKER_SCOPE_KEY', 'SHANNON_BROKER_RECORD_KEY'] as const;
  const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  afterAll(() => {
    for (const name of names) {
      if (saved[name] === undefined) Reflect.deleteProperty(process.env, name);
      else process.env[name] = saved[name];
    }
  });

  it('does not start with a missing or short signing key', () => {
    process.env.SHANNON_BROKER_SCOPE = JSON.stringify(scope);
    Reflect.deleteProperty(process.env, 'SHANNON_BROKER_SCOPE_KEY');
    Reflect.deleteProperty(process.env, 'SHANNON_BROKER_RECORD_KEY');
    expect(() => buildServerFromEnv()).toThrow(/SHANNON_BROKER_SCOPE_KEY is required/);
    process.env.SHANNON_BROKER_SCOPE_KEY = 'k'.repeat(32);
    process.env.SHANNON_BROKER_RECORD_KEY = 'short';
    expect(() => buildServerFromEnv()).toThrow(/SHANNON_BROKER_RECORD_KEY is required/);
    process.env.SHANNON_BROKER_RECORD_KEY = 'r'.repeat(32);
    expect(() => buildServerFromEnv()).not.toThrow();
  });
});
