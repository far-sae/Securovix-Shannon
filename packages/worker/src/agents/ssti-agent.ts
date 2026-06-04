import type { NormalizedToolFinding } from '@shannon/tool-broker';
import type { BrokerInvokeDeps } from '../broker/broker-invoke.js';
import { makeBrokerDispatch } from './broker-tools.js';
import { type LlmClient, executeAgentWithTools } from './tool-loop.js';

export interface SstiAgentDeps {
  client: LlmClient;
  model: string;
  brokerDeps: BrokerInvokeDeps; // toolClient + circuit breaker
  scanId: string;
  scopeToken: string; // signed at scan start
  tools: unknown[]; // Anthropic tool defs (sstimap in prod; the in-house probe in the lab)
  targetUrl: string; // URL to test (use an INJECT marker where the payload goes)
  maxTurns?: number;
}

export interface SstiAgentResult {
  finalText: string;
  findings: NormalizedToolFinding[];
  turns: number;
  toolCalls: number;
}

const SYSTEM = [
  'You are an autonomous SSTI (server-side template injection) testing agent.',
  'Use the provided tool to test the target for SSTI: put the injection payload where the',
  'URL contains the INJECT marker. After running the tool, report concisely whether SSTI was',
  'CONFIRMED and cite the evidence. Do not claim a vulnerability the tool did not confirm.',
].join(' ');

// Drives the broker-backed ReAct loop for SSTI: the model calls the SSTI tool (routed
// through the circuit-breaker + broker), tool-confirmed findings are collected, and the
// model's final summary is returned. Findings come from the broker (tool-verified), so
// the "zero false positives" property holds — the agent reports what the tool proved.
export async function runSstiAgent(deps: SstiAgentDeps): Promise<SstiAgentResult> {
  const findings: NormalizedToolFinding[] = [];
  const dispatch = makeBrokerDispatch(deps.brokerDeps, { scanId: deps.scanId, scopeToken: deps.scopeToken }, (f) =>
    findings.push(...f),
  );
  const result = await executeAgentWithTools(
    `Target: ${deps.targetUrl}\nTest this target for SSTI using the available tool, then summarize the findings.`,
    {
      client: deps.client,
      model: deps.model,
      system: SYSTEM,
      tools: deps.tools,
      dispatch,
      maxTurns: deps.maxTurns ?? 6,
    },
  );
  return { finalText: result.finalText, findings, turns: result.turns, toolCalls: result.toolCalls };
}
