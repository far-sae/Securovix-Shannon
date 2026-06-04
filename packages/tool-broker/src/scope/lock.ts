import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ScopeConfig } from '../types.js';

function canonical(cfg: ScopeConfig): string {
  return JSON.stringify({
    targetHost: cfg.targetHost,
    targetIps: [...cfg.targetIps].sort(),
    allowlistCidrs: [...cfg.allowlistCidrs].sort(),
    allowPrivateCidrs: [...cfg.allowPrivateCidrs].sort(),
    focusPaths: [...cfg.focusPaths].sort(),
    avoidPaths: [...cfg.avoidPaths].sort(),
  });
}

export function signScopeToken(cfg: ScopeConfig, key: string): string {
  return createHmac('sha256', key).update(canonical(cfg)).digest('hex');
}

export function verifyScopeToken(token: string, cfg: ScopeConfig, key: string): boolean {
  const expected = signScopeToken(cfg, key);
  const a = Buffer.from(token, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
