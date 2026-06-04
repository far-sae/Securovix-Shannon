import type { BrokerInvokeDeps } from '../broker/broker-invoke.js';
import { type BrokerAgentResult, runBrokerAgent } from './broker-agent.js';
import { CLASS_CONFIGS } from './class-configs.js';
import type { LlmClient } from './tool-loop.js';

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

export type SstiAgentResult = BrokerAgentResult;

const SSTI_SYSTEM =
  CLASS_CONFIGS['rce-ssti']?.system ?? 'You are an autonomous SSTI testing agent. Report only tool-CONFIRMED findings.';

// Thin wrapper over runBrokerAgent with the SSTI class config. Kept for callers/tests
// that pass a specific tool set + target URL (e.g. the live e2e using the in-house probe).
export async function runSstiAgent(deps: SstiAgentDeps): Promise<SstiAgentResult> {
  return runBrokerAgent({
    client: deps.client,
    model: deps.model,
    brokerDeps: deps.brokerDeps,
    scanId: deps.scanId,
    scopeToken: deps.scopeToken,
    system: SSTI_SYSTEM,
    tools: deps.tools,
    userMessage: `Target: ${deps.targetUrl}\nTest this target for SSTI using the available tool, then summarize the findings.`,
    maxTurns: deps.maxTurns,
  });
}
