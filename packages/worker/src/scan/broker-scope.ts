import { signScopeToken, type ScopeConfig } from '@shannon/tool-broker';
import { CLASS_CONFIGS } from '../agents/class-configs.js';
import type { ShannonConfig } from '../config/schema.js';

// The vuln classes Track-B can actually exploit through the broker — the keys of
// CLASS_CONFIGS are the single source of truth (each has a system prompt + tool def).
export function brokerCapableCategories(): string[] {
  return Object.keys(CLASS_CONFIGS);
}

// Which broker classes this scan should run: the user's `broker.categories` allowlist
// intersected with what's actually capable, or ALL capable classes when unset/empty.
export function brokerCategoriesFor(config: ShannonConfig): string[] {
  const capable = brokerCapableCategories();
  const requested = config.broker?.categories;
  if (!requested || requested.length === 0) return capable;
  const allow = new Set(requested);
  return capable.filter((c) => allow.has(c));
}

// Derive the canonical broker ScopeConfig from the user's ShannonConfig + the resolved
// target IPs. Both worker (signer) and broker (verifier) must build this identically for
// the HMAC scope-lock to match — keep it deterministic and free of volatile inputs.
export function deriveScopeConfig(config: ShannonConfig, targetIps: string[]): ScopeConfig {
  const host = new URL(config.target.url).hostname;
  const scope = config.broker?.scope;
  return {
    targetHost: host,
    targetIps: [...targetIps].sort(),
    allowlistCidrs: [...(scope?.allowlistCidrs ?? [])].sort(),
    allowPrivateCidrs: [...(scope?.allowPrivateCidrs ?? [])].sort(),
    focusPaths: [...(config.target.urls?.focus ?? [])].sort(),
    avoidPaths: [...(config.target.urls?.avoid ?? [])].sort(),
  };
}

export interface BrokerScanFields {
  brokerCategories?: string[];
  scopeToken?: string;
}

// Assemble the opt-in Track-B fields for ScanInput. Fail-safe: if the broker block is
// absent, no signing key is provided, or no capable classes are selected, return {} so
// the workflow skips the broker phase entirely (a missing token is a hard "off").
export function buildBrokerScanFields(
  config: ShannonConfig,
  opts: { scopeKey?: string; targetIps: string[] },
): BrokerScanFields {
  if (!config.broker || !opts.scopeKey) return {};
  const brokerCategories = brokerCategoriesFor(config);
  if (brokerCategories.length === 0) return {};
  const scope = deriveScopeConfig(config, opts.targetIps);
  const scopeToken = signScopeToken(scope, opts.scopeKey);
  return { brokerCategories, scopeToken };
}
