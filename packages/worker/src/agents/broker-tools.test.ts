import type { BrokerResponse, ToolRequest } from '@shannon/tool-broker';
import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../broker/circuit-breaker.js';
import type { ToolClient } from '../broker/tool-client.js';
import { SSTI_TOOL_DEFS, makeBrokerDispatch } from './broker-tools.js';

function resp(): BrokerResponse {
  return {
    result: { tool: 'sstimap', status: 'success', stdout: 'Engine: Jinja2', exitCode: 0 },
    findings: [{ tool: 'sstimap', target: 'http://x', detail: 'SSTI confirmed', raw: '' }],
    record: { scanId: 's1', tool: 'sstimap', argvHash: 'h', status: 'success', timestamp: 'ts', signature: 'sig' },
  };
}
function client(invoke: (req: ToolRequest) => Promise<BrokerResponse>): ToolClient {
  return { invoke } as unknown as ToolClient;
}

describe('SSTI_TOOL_DEFS', () => {
  it('exposes the sstimap tool requiring a url', () => {
    expect(SSTI_TOOL_DEFS[0].name).toBe('sstimap');
    expect(SSTI_TOOL_DEFS[0].input_schema.required).toContain('url');
  });
});

describe('makeBrokerDispatch', () => {
  it('routes a tool_use to a broker ToolRequest and returns findings JSON', async () => {
    let captured: ToolRequest | undefined;
    const breaker = new CircuitBreaker({ failureThreshold: 2, cooldownMs: 1000, now: () => 0 });
    const toolClient = client(async (req) => {
      captured = req;
      return resp();
    });
    const dispatch = makeBrokerDispatch({ toolClient, breaker }, { scanId: 's1', scopeToken: 'tok' });
    const out = await dispatch('sstimap', { url: 'http://x?n=1' }, 'tid');

    expect(captured?.tool).toBe('sstimap');
    expect(captured?.scopeToken).toBe('tok');
    expect(captured?.params.url).toBe('http://x?n=1');
    const parsed = JSON.parse(out);
    expect(parsed.status).toBe('success');
    expect(parsed.findings).toHaveLength(1);
  });

  it('surfaces broker-unavailable when the circuit is open', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 10_000, now: () => 0 });
    breaker.recordFailure(); // open
    const toolClient = client(async () => resp());
    const dispatch = makeBrokerDispatch({ toolClient, breaker }, { scanId: 's1', scopeToken: 'tok' });
    const out = await dispatch('sstimap', { url: 'http://x' }, 'tid');
    expect(JSON.parse(out).status).toBe('broker-unavailable');
  });
});
