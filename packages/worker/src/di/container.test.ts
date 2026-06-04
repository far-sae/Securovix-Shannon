import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createContainer } from './container.js';

// createContainer() constructs LLMClientFactory, which requires exactly one LLM
// provider env var. Pin a single dummy provider for this test (no network calls
// happen at construction) and restore the prior environment afterward.
const PROVIDER_VARS = [
  'ANTHROPIC_API_KEY',
  'AWS_BEDROCK_REGION',
  'VERTEX_PROJECT_ID',
  'SHANNON_LLM_BASE_URL',
  'BROKER_URL',
];

describe('createContainer', () => {
  const saved: Record<string, string | undefined> = {};

  beforeAll(() => {
    for (const v of PROVIDER_VARS) {
      saved[v] = process.env[v];
      delete process.env[v];
    }
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-dummy';
  });

  afterAll(() => {
    for (const v of PROVIDER_VARS) {
      if (saved[v] === undefined) delete process.env[v];
      else process.env[v] = saved[v];
    }
  });

  it('builds without a workspace and exposes no standalone evidenceHasher', () => {
    const c = createContainer();
    expect('evidenceHasher' in c).toBe(false);
    expect(c.evidenceStore).toBeUndefined(); // no workspace → no store
    expect(c.configLoader).toBeDefined();
  });

  it('always provides a broker circuit breaker, but no toolClient without BROKER_URL', () => {
    const c = createContainer();
    expect(c.brokerBreaker).toBeDefined();
    expect(c.brokerBreaker.getState()).toBe('closed');
    expect(c.toolClient).toBeUndefined();
  });
});
