import type { ScopeConfig, ScopeDecision } from '../types.js';
import { ipInCidr, isPrivateOrSpecial } from './ip.js';
import { matchesPath } from './path-match.js';

export class ScopeEnforcer {
  constructor(private readonly cfg: ScopeConfig) {}

  evaluate(ip: string, path: string): ScopeDecision {
    const special = isPrivateOrSpecial(ip);
    if (special === 'metadata') return deny('denied-metadata', ip);
    if (special === 'loopback') return deny('denied-loopback', ip);
    if (special === 'link-local') return deny('denied-link-local', ip);
    if (special === 'private') {
      const reAllowed = this.cfg.allowPrivateCidrs.some((c) => ipInCidr(ip, c));
      if (!reAllowed) return deny('denied-private', ip);
    }

    const inScopeIp =
      this.cfg.targetIps.includes(ip) ||
      this.cfg.allowlistCidrs.some((c) => ipInCidr(ip, c)) ||
      this.cfg.allowPrivateCidrs.some((c) => ipInCidr(ip, c));
    if (!inScopeIp) return deny('out-of-scope-host', ip);

    if (this.cfg.avoidPaths.some((r) => matchesPath(r, path))) return deny('path-avoided', path);
    if (this.cfg.focusPaths.length > 0 && !this.cfg.focusPaths.some((r) => matchesPath(r, path))) {
      return deny('path-not-allowed', path);
    }

    return { allowed: true, reason: 'in-scope' };
  }
}

function deny(reason: ScopeDecision['reason'], detail: string): ScopeDecision {
  return { allowed: false, reason, detail };
}
