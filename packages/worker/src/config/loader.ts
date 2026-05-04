import { readFileSync, existsSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import Ajv from 'ajv';
import type { ShannonConfig } from './schema.js';
import { type Result, ok, err } from '../result.js';

const ajv = new Ajv({ allErrors: true });

export class ConfigLoader {
  load(path: string): Result<ShannonConfig> {
    if (!existsSync(path)) {
      return err(new Error(`Config file not found: ${path}`));
    }

    try {
      const raw = readFileSync(path, 'utf-8');
      const config = parseYaml(raw) as ShannonConfig;
      return this.validate(config);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private validate(config: ShannonConfig): Result<ShannonConfig> {
    if (!config.target?.url) {
      return err(new Error('Config must specify target.url'));
    }

    if (config.pipeline?.maxConcurrentPipelines !== undefined) {
      const max = config.pipeline.maxConcurrentPipelines;
      if (max < 1 || max > 5) {
        return err(new Error('maxConcurrentPipelines must be between 1 and 5'));
      }
    }

    return ok(config);
  }
}
