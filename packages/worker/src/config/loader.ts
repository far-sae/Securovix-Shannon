import { existsSync, readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { brokerCapableCategories } from '../scan/broker-scope.js';
import { type Result, err, ok } from '../result.js';
import type { ShannonConfig } from './schema.js';
import { isValidCidr } from './scope-rules.js';

export function validateConfig(config: ShannonConfig): Result<ShannonConfig> {
  if (!config.target?.url) {
    return err(new Error('Config must specify target.url'));
  }

  if (config.pipeline?.maxConcurrentPipelines !== undefined) {
    const max = config.pipeline.maxConcurrentPipelines;
    if (max < 1 || max > 5) {
      return err(new Error('maxConcurrentPipelines must be between 1 and 5'));
    }
  }

  const broker = config.broker;
  if (broker) {
    for (const cidr of broker.scope?.allowlistCidrs ?? []) {
      if (!isValidCidr(cidr)) return err(new Error(`Invalid CIDR in broker.scope.allowlistCidrs: ${cidr}`));
    }
    for (const cidr of broker.scope?.allowPrivateCidrs ?? []) {
      if (!isValidCidr(cidr)) return err(new Error(`Invalid CIDR in broker.scope.allowPrivateCidrs: ${cidr}`));
    }
    const budgets = broker.budgets;
    if (budgets) {
      for (const [key, val] of Object.entries(budgets)) {
        if (val !== undefined && (typeof val !== 'number' || val <= 0)) {
          return err(new Error(`broker.budgets.${key} must be a positive number`));
        }
      }
    }
    const mode = broker.oob?.mode;
    if (mode !== undefined && mode !== 'reflected-only' && mode !== 'self-hosted') {
      return err(new Error(`broker.oob.mode must be 'reflected-only' or 'self-hosted', got: ${mode}`));
    }
    if (broker.categories !== undefined) {
      const capable = new Set(brokerCapableCategories());
      for (const cat of broker.categories) {
        if (!capable.has(cat)) {
          return err(new Error(`Unknown broker.categories entry '${cat}'. Valid: ${[...capable].sort().join(', ')}`));
        }
      }
    }
  }

  return ok(config);
}

export class ConfigLoader {
  load(path: string): Result<ShannonConfig> {
    if (!existsSync(path)) {
      return err(new Error(`Config file not found: ${path}`));
    }
    try {
      const raw = readFileSync(path, 'utf-8');
      const config = parseYaml(raw) as ShannonConfig;
      return validateConfig(config);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }
}
