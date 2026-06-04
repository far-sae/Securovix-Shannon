import { type AuthorizeDeps, authorizeRequest } from '../core/authorize.js';
import type { SandboxResult } from '../exec/sandbox.js';
import { buildInvocationRecord } from '../forensic/invocation-record.js';
import {
  type NormalizedToolFinding,
  normalizeFfufJson,
  normalizeNucleiJsonl,
  normalizeSqlmapCsv,
} from '../normalize/normalizer.js';
import type { InvocationRecord, ToolRequest, ToolResult } from '../types.js';

// What the handler needs injected. `execute` and `resolveTarget` are injected so the
// handler is testable without Docker or DNS; the server bootstrap wires the real
// sandbox executor + DNS-pinning resolver.
export interface BrokerHandlerDeps {
  authorize: AuthorizeDeps;
  recordKey: string; // HMAC key for the signed InvocationRecord
  resolveTarget: (req: ToolRequest) => { ip: string; path: string };
  execute: (argv: string[], tool: string) => Promise<SandboxResult>;
  now: () => string; // ISO timestamp (injected so records are deterministic in tests)
  normalize?: (tool: string, stdout: string) => NormalizedToolFinding[];
}

export interface BrokerResponse {
  result: ToolResult;
  findings: NormalizedToolFinding[];
  record: InvocationRecord;
}

function defaultNormalize(tool: string, stdout: string): NormalizedToolFinding[] {
  switch (tool) {
    case 'sqlmap':
      return normalizeSqlmapCsv(stdout);
    case 'nuclei':
      return normalizeNucleiJsonl(stdout);
    case 'ffuf':
      return normalizeFfufJson(stdout);
    default:
      return [];
  }
}

// The broker's request lifecycle: authorize → (execute → normalize) → sign a record.
// EVERY outcome (allow or deny) produces a signed InvocationRecord that the worker
// HMAC-verifies before appending to the forensic chain.
export function createBrokerHandler(deps: BrokerHandlerDeps): (req: ToolRequest) => Promise<BrokerResponse> {
  const normalize = deps.normalize ?? defaultNormalize;

  return async function handle(req: ToolRequest): Promise<BrokerResponse> {
    const target = deps.resolveTarget(req);
    const auth = authorizeRequest(req, target, deps.authorize);

    if (!auth.authorized) {
      const record = buildInvocationRecord(
        { scanId: req.scanId, tool: req.tool, argv: [], status: auth.result.status, timestamp: deps.now() },
        deps.recordKey,
      );
      return { result: auth.result, findings: [], record };
    }

    const sb = await deps.execute(auth.argv, req.tool);
    const status: ToolResult['status'] = sb.timedOut ? 'timeout' : sb.exitCode === 0 ? 'success' : 'error';
    const result: ToolResult = {
      tool: req.tool,
      status,
      argv: auth.argv,
      stdout: sb.stdout,
      stderr: sb.stderr,
      exitCode: sb.exitCode ?? undefined,
      durationMs: sb.durationMs,
    };
    const findings = status === 'success' ? normalize(req.tool, sb.stdout) : [];
    const record = buildInvocationRecord(
      {
        scanId: req.scanId,
        tool: req.tool,
        argv: auth.argv,
        status,
        exitCode: sb.exitCode ?? undefined,
        durationMs: sb.durationMs,
        timestamp: deps.now(),
      },
      deps.recordKey,
    );
    return { result, findings, record };
  };
}
