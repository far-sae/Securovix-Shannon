import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { parse as parseToml } from 'toml';
import { homedir } from 'node:os';
import Ajv from 'ajv';
import type { ScanConfig } from '../docker/orchestrator.js';

const ajv = new Ajv({ allErrors: true });

export async function loadConfig(configPath: string): Promise<ScanConfig> {
  if (!existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  const raw = readFileSync(configPath, 'utf-8');
  const config = parseYaml(raw);

  // Load and validate against JSON Schema
  const schemaPath = join(import.meta.dirname ?? __dirname, '..', '..', 'config', 'shannon.schema.json');
  if (existsSync(schemaPath)) {
    const schema = JSON.parse(readFileSync(schemaPath, 'utf-8'));
    const validate = ajv.compile(schema);
    if (!validate(config)) {
      const errors = validate.errors?.map((e) => `${e.instancePath} ${e.message}`).join(', ');
      throw new Error(`Config validation failed: ${errors}`);
    }
  }

  return config as ScanConfig;
}

export function loadNpxCredentials(): Record<string, string> {
  const configPath = join(homedir(), '.shannon', 'config.toml');
  if (!existsSync(configPath)) {
    return {};
  }

  const raw = readFileSync(configPath, 'utf-8');
  return parseToml(raw) as Record<string, string>;
}
