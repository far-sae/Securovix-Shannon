import type { BrokerResponse, ToolRequest } from '@shannon/tool-broker';
import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../broker/circuit-breaker.js';
import type { ToolClient } from '../broker/tool-client.js';
import { runSstiAgent } from './ssti-agent.js';
import type { LlmClient, LlmResponse } from './tool-loop.js';

// Scripted LLM: turn 1 calls the SSTI tool, turn 2 reports the confirmed finding.
function scriptedClient(responses: LlmResponse[]): LlmClient {
  let i = 0;
  return {
    messages: {
      create: async () => responses[Math.min(i++, responses.length - 1)],
    },
  };
}

function brokerResponseWithFinding(): BrokerResponse {
  return {
    result: { tool: 'ssti-probe', status: 'success', stdout: '{"ssti":true}', exitCode: 0 },
    findings: [
      {
        tool: 'ssti-probe',
        severity: 'critical',
        target: 'http://lab/?name=INJECT',
        detail: 'SSTI confirmed: 221',
        raw: '',
      },
    ],
    record: { scanId: 's1', tool: 'ssti-probe', argvHash: 'h', status: 'success', timestamp: 'ts', signature: 'sig' },
  };
}

function fakeToolClient(invoke: (req: ToolRequest) => Promise<BrokerResponse>): ToolClient {
  return { invoke } as unknown as ToolClient;
}

const SSTI_PROBE_TOOL = {
  name: 'ssti-probe',
  description: 'Probe a URL (with INJECT marker) for SSTI.',
  input_schema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
};

describe('runSstiAgent (mock LLM)', () => {
  it('calls the SSTI tool via the broker and collects the tool-confirmed finding', async () => {
    let captured: ToolRequest | undefined;
    const client = scriptedClient([
      {
        content: [{ type: 'tool_use', id: 'c1', name: 'ssti-probe', input: { url: 'http://lab/?name=INJECT' } }],
        stop_reason: 'tool_use',
      },
      { content: [{ type: 'text', text: 'SSTI CONFIRMED via arithmetic oracle (221).' }], stop_reason: 'end_turn' },
    ]);
    const brokerDeps = {
      toolClient: fakeToolClient(async (req) => {
        captured = req;
        return brokerResponseWithFinding();
      }),
      breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => 0 }),
    };

    const res = await runSstiAgent({
      client,
      model: 'test-model',
      brokerDeps,
      scanId: 's1',
      scopeToken: 'tok',
      tools: [SSTI_PROBE_TOOL],
      targetUrl: 'http://lab/?name=INJECT',
    });

    expect(captured?.tool).toBe('ssti-probe');
    expect(captured?.scopeToken).toBe('tok');
    expect(res.toolCalls).toBe(1);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].detail).toContain('SSTI confirmed');
    expect(res.finalText).toContain('CONFIRMED');
  });

  it('collects no findings when the model never calls a tool', async () => {
    const client = scriptedClient([
      { content: [{ type: 'text', text: 'No injectable parameter found.' }], stop_reason: 'end_turn' },
    ]);
    const brokerDeps = {
      toolClient: fakeToolClient(async () => brokerResponseWithFinding()),
      breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => 0 }),
    };
    const res = await runSstiAgent({
      client,
      model: 'test-model',
      brokerDeps,
      scanId: 's1',
      scopeToken: 'tok',
      tools: [SSTI_PROBE_TOOL],
      targetUrl: 'http://lab/',
    });
    expect(res.toolCalls).toBe(0);
    expect(res.findings).toEqual([]);
  });
});
