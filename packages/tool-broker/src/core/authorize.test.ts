import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BudgetLedger } from '../budget/ledger.js';
import { DESCRIPTORS } from '../registry/descriptors.js';
import { ToolRegistry } from '../registry/registry.js';
import { ScopeEnforcer } from '../scope/enforcer.js';
import { signScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolRequest } from '../types.js';
import { authorizeRequest } from './authorize.js';

const KEY = 'scan-key';
const scope: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};
function deps(limit = 10) {
  return {
    scopeConfig: scope,
    scopeKey: KEY,
    enforcer: new ScopeEnforcer(scope),
    registry: new ToolRegistry(DESCRIPTORS),
    ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'auth-')), 'b.json'), { toolInvocations: limit }),
  };
}
function req(overrides: Partial<ToolRequest> = {}): ToolRequest {
  return {
    tool: 'sqlmap',
    params: { url: 'https://app.example.com/p?id=1' },
    scanId: 's1',
    scopeToken: signScopeToken(scope, KEY),
    ...overrides,
  };
}

describe('authorizeRequest', () => {
  it('authorizes an in-scope, valid, budgeted request and returns argv', () => {
    const r = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, deps());
    expect(r.authorized).toBe(true);
    if (r.authorized) expect(r.argv).toEqual(['sqlmap', '-u', 'https://app.example.com/p?id=1']);
  });

  it('rejects a forged scope token (scope status, no budget spent)', () => {
    const d = deps();
    const r = authorizeRequest(req({ scopeToken: 'forged' }), { ip: '93.184.216.34', path: '/p' }, d);
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
    const r2 = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, { ...d });
    expect(r2.authorized).toBe(true);
  });

  it('rejects an out-of-scope target IP', () => {
    const r = authorizeRequest(req(), { ip: '8.8.8.8', path: '/p' }, deps());
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
  });

  it('rejects metadata IP even with a valid token', () => {
    const r = authorizeRequest(req(), { ip: '169.254.169.254', path: '/' }, deps());
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
  });

  it('rejects a request whose args fail the registry (blocked status)', () => {
    const r = authorizeRequest(
      req({ params: { url: 'https://app.example.com/p', level: '9' } }),
      { ip: '93.184.216.34', path: '/p' },
      deps(),
    );
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('blocked');
  });

  it('rejects once the budget is exhausted', () => {
    const d = deps(1);
    expect(authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, d).authorized).toBe(true);
    const r = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, d);
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('budget');
  });
});
