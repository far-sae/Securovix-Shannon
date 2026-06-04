import { describe, expect, it } from 'vitest';
import type { ScopeConfig } from '../types.js';
import { signScopeToken, verifyScopeToken } from './lock.js';

const KEY = 'test-scan-secret-key';
const cfg: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};

describe('scope-lock', () => {
  it('verifies a token signed over the same config', () => {
    const token = signScopeToken(cfg, KEY);
    expect(verifyScopeToken(token, cfg, KEY)).toBe(true);
  });
  it('rejects when the scope config was tampered with', () => {
    const token = signScopeToken(cfg, KEY);
    const widened = { ...cfg, allowlistCidrs: ['0.0.0.0/0'] };
    expect(verifyScopeToken(token, widened, KEY)).toBe(false);
  });
  it('rejects a token signed with a different key', () => {
    const token = signScopeToken(cfg, KEY);
    expect(verifyScopeToken(token, cfg, 'other-key')).toBe(false);
  });
  it('rejects a garbage token without throwing', () => {
    expect(verifyScopeToken('not-a-token', cfg, KEY)).toBe(false);
  });
});
