import type { NormalizedToolFinding } from '@shannon/tool-broker';
import type { BrokerInvokeDeps } from '../broker/broker-invoke.js';
import { makeBrokerDispatch } from './broker-tools.js';
import { type LlmClient, executeAgentWithTools } from './tool-loop.js';

// Class-agnostic broker-backed agent. Drives the ReAct loop with a class-specific system
// prompt + tool set; tool calls route through the circuit-breaker + broker (real
// execution), and tool-confirmed findings are collected. runSstiAgent and the future
// JWT/GraphQL/IDOR agents are all thin wrappers over this.
export interface BrokerAgentDeps {
  client: LlmClient;
  model: string;
  brokerDeps: BrokerInvokeDeps;
  scanId: string;
  scopeToken: string;
  system: string; // class-specific system prompt
  tools: unknown[]; // Anthropic tool defs the model may call
  userMessage: string; // task framing (usually includes the target)
  maxTurns?: number;
}

export interface BrokerAgentResult {
  finalText: string;
  findings: NormalizedToolFinding[];
  turns: number;
  toolCalls: number;
}

export async function runBrokerAgent(deps: BrokerAgentDeps): Promise<BrokerAgentResult> {
  const findings: NormalizedToolFinding[] = [];
  const dispatch = makeBrokerDispatch(deps.brokerDeps, { scanId: deps.scanId, scopeToken: deps.scopeToken }, (f) =>
    findings.push(...f),
  );
  const result = await executeAgentWithTools(deps.userMessage, {
    client: deps.client,
    model: deps.model,
    system: deps.system,
    tools: deps.tools,
    dispatch,
    maxTurns: deps.maxTurns ?? 6,
  });
  return { finalText: result.finalText, findings, turns: result.turns, toolCalls: result.toolCalls };
}
