import { lookup } from 'node:dns/promises';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client, Connection } from '@temporalio/client';
import { validateConfig } from '../config/loader.js';
import type { ShannonConfig } from '../config/schema.js';
import type { ScanInput } from '../workflows/scan.js';
import { buildBrokerScanFields } from './broker-scope.js';

export interface StartScanOptions {
  temporalAddress: string;
  taskQueue: string;
  workspaceDir: string;
  // Raw config JSON (as forwarded by the CLI via SHANNON_CONFIG) or an already-parsed object.
  config: ShannonConfig;
  resume: boolean;
  // HMAC key for the scope-lock token; when absent the broker phase stays off.
  scopeKey?: string;
}

// Resolve the target host to its IPv4/IPv6 addresses so the signed scope-lock pins the
// exact IPs the broker will be allowed to reach. Best-effort: an unresolvable host yields
// an empty list (the token still signs; the broker will simply deny out-of-scope IPs).
async function resolveTargetIps(url: string): Promise<string[]> {
  try {
    const host = new URL(url).hostname;
    const records = await lookup(host, { all: true });
    return records.map((r) => r.address);
  } catch {
    return [];
  }
}

// Persist the CLI-forwarded config to the workspace so the workflow's activities (which
// take a configPath, not the raw object) can load it deterministically.
function writeConfigFile(workspaceDir: string, config: ShannonConfig): string {
  mkdirSync(workspaceDir, { recursive: true });
  const configPath = join(workspaceDir, 'shannon.config.json');
  writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
  return configPath;
}

// Build the full ScanInput, including the opt-in Track-B broker fields.
export async function buildScanInput(opts: StartScanOptions): Promise<ScanInput> {
  const configPath = writeConfigFile(opts.workspaceDir, opts.config);
  const targetIps = await resolveTargetIps(opts.config.target.url);
  const broker = buildBrokerScanFields(opts.config, { scopeKey: opts.scopeKey, targetIps });
  return {
    configPath,
    workspaceDir: opts.workspaceDir,
    resume: opts.resume,
    ...broker,
  };
}

// Connect a Temporal client and start scanWorkflow, returning the workflow's result.
export async function startScan(opts: StartScanOptions): Promise<string> {
  const validated = validateConfig(opts.config);
  if (!validated.ok) throw validated.error;

  const input = await buildScanInput(opts);

  const connection = await Connection.connect({ address: opts.temporalAddress });
  try {
    const client = new Client({ connection });
    const handle = await client.workflow.start('scanWorkflow', {
      taskQueue: opts.taskQueue,
      workflowId: `scan-${opts.taskQueue}`,
      args: [input],
    });
    return await handle.result();
  } finally {
    await connection.close();
  }
}
