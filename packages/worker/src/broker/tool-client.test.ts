import { mkdtempSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BudgetLedger,
  DESCRIPTORS,
  type ScopeConfig,
  ScopeEnforcer,
  ToolRegistry,
  type ToolRequest,
  createBrokerHandler,
  createBrokerServer,
  signScopeToken,
} from '@shannon/tool-broker';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ToolClient } from './tool-client.js';

const SCOPE_KEY = 'scope-key';
const RECORD_KEY = 'record-key';
const scope: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};

function makeServer(recordKey: string): Server {
  const handler = createBrokerHandler({
    authorize: {
      scopeConfig: scope,
      scopeKey: SCOPE_KEY,
      enforcer: new ScopeEnforcer(scope),
      registry: new ToolRegistry(DESCRIPTORS),
      ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'tc-')), 'b.json'), { toolInvocations: 100 }),
    },
    recordKey,
    resolveTarget: () => ({ ip: '93.184.216.34', path: '/p' }),
    execute: async () => ({ stdout: '', stderr: '', exitCode: 0, durationMs: 1, timedOut: false }),
    now: () => '2026-06-04T00:00:00.000Z',
  });
  return createBrokerServer(handler);
}

function req(): ToolRequest {
  return {
    tool: 'sqlmap',
    params: { url: 'https://app.example.com/p?id=1' },
    scanId: 's1',
    scopeToken: signScopeToken(scope, SCOPE_KEY),
  };
}

describe('ToolClient', () => {
  const server = makeServer(RECORD_KEY);
  let base = '';

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('invokes the broker and returns a record-verified response', async () => {
    const client = new ToolClient({ brokerUrl: base, recordKey: RECORD_KEY });
    const res = await client.invoke(req());
    expect(res.result.status).toBe('success');
    expect(res.result.tool).toBe('sqlmap');
  });

  it('rejects a response whose signed record does not verify under our key', async () => {
    const client = new ToolClient({ brokerUrl: base, recordKey: 'WRONG-KEY' });
    await expect(client.invoke(req())).rejects.toThrow(/HMAC/i);
  });
});
