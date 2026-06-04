import type { ToolRequest } from '@shannon/tool-broker';
import { type BrokerInvokeDeps, brokerInvoke } from '../broker/broker-invoke.js';

export interface BrokerDispatchCtx {
  scanId: string;
  scopeToken: string; // signed at scan start; the broker verifies it on every call
}

// Anthropic tool definitions the SSTI agent may call. The tool NAME equals the broker
// descriptor id so dispatch routes directly; the inputs mirror the broker's allowlisted
// params (the broker still validates — this is only what the model sees).
export const SSTI_TOOL_DEFS = [
  {
    name: 'sstimap',
    description:
      'Detect/exploit server-side template injection (SSTI) at a URL. Optionally run a benign proof command via osCmd.',
    input_schema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Target URL including the injectable parameter' },
        osCmd: { type: 'string', enum: ['id', 'whoami', 'hostname'], description: 'Benign proof command' },
      },
      required: ['url'],
    },
  },
] as const;

// Builds the dispatch passed to executeAgentWithTools: maps an LLM tool_use to a broker
// ToolRequest, invokes it through the circuit breaker, and returns a compact JSON string
// for the tool_result. Circuit-open is surfaced so the model can fall back to manual
// reasoning instead of hanging.
export function makeBrokerDispatch(deps: BrokerInvokeDeps, ctx: BrokerDispatchCtx) {
  return async function dispatch(name: string, input: unknown, _id: string): Promise<string> {
    const params = (input ?? {}) as Record<string, string | number>;
    const request: ToolRequest = { tool: name, params, scanId: ctx.scanId, scopeToken: ctx.scopeToken };
    const outcome = await brokerInvoke(deps, request);
    if (outcome.degraded) {
      return JSON.stringify({ status: 'broker-unavailable', note: 'broker circuit open — degrade to manual analysis' });
    }
    const { result, findings } = outcome.response;
    return JSON.stringify({
      status: result.status,
      findings,
      stdout: result.stdout?.slice(0, 4000),
      exitCode: result.exitCode,
    });
  };
}
