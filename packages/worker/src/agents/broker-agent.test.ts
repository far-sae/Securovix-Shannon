import type { BrokerResponse, ToolRequest } from '@shannon/tool-broker';
import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../broker/circuit-breaker.js';
import type { ToolClient } from '../broker/tool-client.js';
import { runBrokerAgent } from './broker-agent.js';
import { CLASS_CONFIGS } from './class-configs.js';
import type { LlmClient, LlmResponse } from './tool-loop.js';

function scriptedClient(responses: LlmResponse[]): LlmClient {
  let i = 0;
  return { messages: { create: async () => responses[Math.min(i++, responses.length - 1)] } };
}
function brokerResponseWithFinding(tool: string): BrokerResponse {
  return {
    result: { tool, status: 'success', stdout: 'ok', exitCode: 0 },
    findings: [{ tool, severity: 'high', target: 'http://t', detail: `${tool} confirmed`, raw: '' }],
    record: { scanId: 's1', tool, argvHash: 'h', status: 'success', timestamp: 'ts', signature: 'sig' },
  };
}
function fakeToolClient(invoke: (req: ToolRequest) => Promise<BrokerResponse>): ToolClient {
  return { invoke } as unknown as ToolClient;
}

describe('runBrokerAgent (class-agnostic)', () => {
  it('drives the loop with a class config, routes the tool to the broker, collects findings', async () => {
    const config = CLASS_CONFIGS['token-forgery'];
    if (!config) throw new Error('token-forgery config missing');
    const toolName = config.tools[0].name;
    let captured: ToolRequest | undefined;
    const client = scriptedClient([
      {
        content: [{ type: 'tool_use', id: 'c1', name: toolName, input: { url: 'http://t/auth' } }],
        stop_reason: 'tool_use',
      },
      { content: [{ type: 'text', text: 'forged token accepted — CONFIRMED' }], stop_reason: 'end_turn' },
    ]);

    const res = await runBrokerAgent({
      client,
      model: 'm',
      brokerDeps: {
        toolClient: fakeToolClient(async (req) => {
          captured = req;
          return brokerResponseWithFinding(toolName);
        }),
        breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => 0 }),
      },
      scanId: 's1',
      scopeToken: 'tok',
      system: config.system,
      tools: [...config.tools],
      userMessage: 'test http://t/auth',
    });

    expect(captured?.tool).toBe(toolName);
    expect(res.toolCalls).toBe(1);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].detail).toContain('confirmed');
  });
});

describe('CLASS_CONFIGS', () => {
  it('provides SSTI, JWT/OAuth, GraphQL, and IDOR agent configs with tools', () => {
    for (const cat of ['rce-ssti', 'token-forgery', 'graphql-idor', 'authz-bypass'] as const) {
      const c = CLASS_CONFIGS[cat];
      expect(c, `config for ${cat}`).toBeDefined();
      expect(c?.system.length).toBeGreaterThan(20);
      expect(c?.tools.length).toBeGreaterThanOrEqual(1);
      expect(c?.tools[0].name.length).toBeGreaterThan(0);
    }
  });
});
