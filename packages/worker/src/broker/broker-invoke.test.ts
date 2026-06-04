import type { BrokerResponse, ToolRequest } from '@shannon/tool-broker';
import { describe, expect, it, vi } from 'vitest';
import { brokerInvoke } from './broker-invoke.js';
import { CircuitBreaker } from './circuit-breaker.js';
import type { ToolClient } from './tool-client.js';

const req: ToolRequest = { tool: 'sqlmap', params: { url: 'https://x/y' }, scanId: 's1', scopeToken: 't' };

function fakeResponse(): BrokerResponse {
  return {
    result: { tool: 'sqlmap', status: 'success' },
    findings: [],
    record: { scanId: 's1', tool: 'sqlmap', argvHash: 'h', status: 'success', timestamp: 'ts', signature: 'sig' },
  };
}

function client(invoke: () => Promise<BrokerResponse>): ToolClient {
  return { invoke } as unknown as ToolClient;
}

describe('brokerInvoke', () => {
  it('returns the response and records success when the broker is reachable', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 2, cooldownMs: 1000, now: () => 0 });
    const invoke = vi.fn(async () => fakeResponse());
    const out = await brokerInvoke({ toolClient: client(invoke), breaker }, req);
    expect(out.degraded).toBe(false);
    if (!out.degraded) expect(out.response.result.status).toBe('success');
    expect(breaker.getState()).toBe('closed');
  });

  it('degrades (without calling the broker) when the circuit is open', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 10_000, now: () => 0 });
    breaker.recordFailure(); // open
    const invoke = vi.fn(async () => fakeResponse());
    const out = await brokerInvoke({ toolClient: client(invoke), breaker }, req);
    expect(out.degraded).toBe(true);
    expect(invoke).not.toHaveBeenCalled();
  });

  it('trips the breaker and rethrows when the broker call throws', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1000, now: () => 0 });
    const invoke = vi.fn(async () => {
      throw new Error('tool-broker unavailable: connection refused');
    });
    await expect(brokerInvoke({ toolClient: client(invoke), breaker }, req)).rejects.toThrow(/unavailable/);
    expect(breaker.getState()).toBe('open');
  });
});
