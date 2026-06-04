import type { Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBrokerHandler } from './api/handler.js';
import { createBrokerServer } from './api/server.js';
import { BudgetLedger } from './budget/ledger.js';
import { runInSandbox } from './exec/sandbox.js';
import { normalizeFfufJson, normalizeNucleiJsonl, normalizeSqlmapCsv } from './normalize/normalizer.js';
import { DESCRIPTORS } from './registry/descriptors.js';
import { ToolRegistry } from './registry/registry.js';
import { ScopeEnforcer } from './scope/enforcer.js';
import type { ScopeConfig, ToolDescriptor } from './types.js';

// Production bootstrap for the tool-broker sidecar. Builds the broker HTTP server from
// environment config and listens. Designed to run as a container that talks to the host
// Docker engine (mounted socket) so the Sandbox can launch per-tool containers.
//
// Env:
//   BROKER_PORT            (default 8443)
//   SHANNON_BROKER_SCOPE   JSON ScopeConfig (targetHost, targetIps, allowlistCidrs, …)
//   SHANNON_BROKER_SCOPE_KEY   HMAC key the CLI signed the scope token with
//   SHANNON_BROKER_RECORD_KEY  HMAC key for signing InvocationRecords
//   SHANNON_SCAN_NET       docker network the sandbox + targets share (default 'bridge')
//   SHANNON_TOOL_IMAGES    JSON map of tool id → container image (defaults to shannon-tool-<id>:local)

function normalizeFor(tool: string, stdout: string) {
  if (tool === 'sqlmap') return normalizeSqlmapCsv(stdout);
  if (tool === 'ffuf') return normalizeFfufJson(stdout);
  return normalizeNucleiJsonl(stdout); // nuclei + in-house probers emit nuclei-style JSONL
}

export interface BuildOptions {
  scope: ScopeConfig;
  scopeKey: string;
  recordKey: string;
  scanNet: string;
  imageForTool: (tool: string) => string;
  extraDescriptors?: ToolDescriptor[];
}

export function buildServer(opts: BuildOptions): Server {
  const enforcer = new ScopeEnforcer(opts.scope);
  const registry = new ToolRegistry([...DESCRIPTORS, ...(opts.extraDescriptors ?? [])]);
  const ledger = new BudgetLedger(join(tmpdir(), `broker-budget-${Date.now()}.json`), {});

  const handler = createBrokerHandler({
    authorize: { scopeConfig: opts.scope, scopeKey: opts.scopeKey, enforcer, registry, ledger },
    recordKey: opts.recordKey,
    // Connect-time resolution: resolve the request's target host to an IP for the scope
    // check. (The ForwardProxy enforces pinning at the socket layer in full deployments.)
    resolveTarget: () => ({ ip: opts.scope.targetIps[0] ?? '0.0.0.0', path: '/' }),
    execute: (argv, tool) => runInSandbox(argv, { image: opts.imageForTool(tool), network: opts.scanNet }),
    now: () => new Date().toISOString(),
    normalize: normalizeFor,
  });
  return createBrokerServer(handler);
}

export function buildServerFromEnv(): Server {
  const scopeRaw = process.env.SHANNON_BROKER_SCOPE;
  if (!scopeRaw) throw new Error('SHANNON_BROKER_SCOPE (JSON ScopeConfig) is required');
  const scope = JSON.parse(scopeRaw) as ScopeConfig;
  const imageMap = process.env.SHANNON_TOOL_IMAGES
    ? (JSON.parse(process.env.SHANNON_TOOL_IMAGES) as Record<string, string>)
    : {};
  return buildServer({
    scope,
    scopeKey: process.env.SHANNON_BROKER_SCOPE_KEY ?? '',
    recordKey: process.env.SHANNON_BROKER_RECORD_KEY ?? '',
    scanNet: process.env.SHANNON_SCAN_NET ?? 'bridge',
    imageForTool: (tool) => imageMap[tool] ?? `shannon-tool-${tool}:local`,
  });
}

// Entry point (only when run directly, not when imported by tests).
function main(): void {
  const port = Number(process.env.BROKER_PORT ?? 8443);
  const server = buildServerFromEnv();
  server.listen(port, () => {
    process.stdout.write(`tool-broker listening on :${port}\n`);
  });
}

if (process.argv[1]?.endsWith('server-main.js') || process.argv[1]?.endsWith('server-main.ts')) {
  try {
    main();
  } catch (e) {
    process.stderr.write(`tool-broker failed to start: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
}
