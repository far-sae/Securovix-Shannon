import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { BudgetLedger } from '../budget/ledger.js';
import type { SandboxResult } from '../exec/sandbox.js';
import { verifyInvocationRecord } from '../forensic/invocation-record.js';
import { DESCRIPTORS } from '../registry/descriptors.js';
import { ToolRegistry } from '../registry/registry.js';
import { ScopeEnforcer } from '../scope/enforcer.js';
import { signScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolRequest } from '../types.js';
import { type BrokerHandlerDeps, createBrokerHandler } from './handler.js';

const KEY = 'scan-key';
const RECORD_KEY = 'record-key';
const TS = '2026-06-04T00:00:00.000Z';
const scope: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};

function sandbox(over: Partial<SandboxResult> = {}): SandboxResult {
  return { stdout: '', stderr: '', exitCode: 0, durationMs: 5, timedOut: false, ...over };
}

function makeDeps(execute: BrokerHandlerDeps['execute'], limit = 10): BrokerHandlerDeps {
  return {
    authorize: {
      scopeConfig: scope,
      scopeKey: KEY,
      enforcer: new ScopeEnforcer(scope),
      registry: new ToolRegistry(DESCRIPTORS),
      ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'h-')), 'b.json'), { toolInvocations: limit }),
    },
    recordKey: RECORD_KEY,
    resolveTarget: () => ({ ip: '93.184.216.34', path: '/p' }),
    execute,
    now: () => TS,
  };
}

function req(over: Partial<ToolRequest> = {}): ToolRequest {
  return {
    tool: 'sqlmap',
    params: { url: 'https://app.example.com/p?id=1' },
    scanId: 's1',
    scopeToken: signScopeToken(scope, KEY),
    ...over,
  };
}

describe('createBrokerHandler', () => {
  it('executes an authorized request, normalizes output, and signs a verifiable record', async () => {
    const csv = 'Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://app/p?id=1,GET,id,B,\n';
    const execute = vi.fn(async () => sandbox({ stdout: csv }));
    const handle = createBrokerHandler(makeDeps(execute));
    const res = await handle(req());

    expect(res.result.status).toBe('success');
    expect(res.result.argv).toEqual(['sqlmap', '-u', 'https://app.example.com/p?id=1']);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].tool).toBe('sqlmap');
    expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
    expect(execute).toHaveBeenCalledOnce();
  });

  it('denies a forged scope token without executing, and still signs a record', async () => {
    const execute = vi.fn(async () => sandbox());
    const handle = createBrokerHandler(makeDeps(execute));
    const res = await handle(req({ scopeToken: 'forged' }));

    expect(res.result.status).toBe('scope');
    expect(res.findings).toEqual([]);
    expect(execute).not.toHaveBeenCalled();
    expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
  });

  it('returns blocked for invalid args without executing', async () => {
    const execute = vi.fn(async () => sandbox());
    const handle = createBrokerHandler(makeDeps(execute));
    const res = await handle(req({ params: { url: 'https://app.example.com/p', level: '9' } }));

    expect(res.result.status).toBe('blocked');
    expect(execute).not.toHaveBeenCalled();
  });

  it('returns budget when the ledger is exhausted', async () => {
    const execute = vi.fn(async () => sandbox());
    const deps = makeDeps(execute, 1);
    const handle = createBrokerHandler(deps);
    await handle(req()); // consumes the single unit
    const res = await handle(req());
    expect(res.result.status).toBe('budget');
  });

  it('maps a sandbox timeout to a timeout result with no findings', async () => {
    const execute = vi.fn(async () => sandbox({ timedOut: true, exitCode: null }));
    const handle = createBrokerHandler(makeDeps(execute));
    const res = await handle(req());
    expect(res.result.status).toBe('timeout');
    expect(res.findings).toEqual([]);
  });

  it('maps a non-zero exit to an error result', async () => {
    const execute = vi.fn(async () => sandbox({ exitCode: 1, stderr: 'boom' }));
    const handle = createBrokerHandler(makeDeps(execute));
    const res = await handle(req());
    expect(res.result.status).toBe('error');
    expect(res.result.exitCode).toBe(1);
  });
});
