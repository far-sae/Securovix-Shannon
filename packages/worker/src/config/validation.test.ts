import { describe, expect, it } from 'vitest';
import { classifyError } from './validation.js';

describe('classifyError — broker/scope/budget', () => {
  it('classifies out-of-scope as non-retryable SCOPE_DENIED', () => {
    const e = classifyError(new Error('Request blocked: out of scope host evil.com'));
    expect(e.code).toBe('SCOPE_DENIED');
    expect(e.retryable).toBe(false);
  });

  it('classifies budget exhaustion as non-retryable BUDGET_EXHAUSTED', () => {
    const e = classifyError(new Error('budget exceeded: max tool invocations reached'));
    expect(e.code).toBe('BUDGET_EXHAUSTED');
    expect(e.retryable).toBe(false);
  });

  it('classifies broker unavailability as retryable BROKER_UNAVAILABLE', () => {
    const e = classifyError(new Error('tool-broker unavailable: connection refused'));
    expect(e.code).toBe('BROKER_UNAVAILABLE');
    expect(e.retryable).toBe(true);
  });

  it('still falls back to retryable UNKNOWN for unrecognized errors', () => {
    const e = classifyError(new Error('something weird happened'));
    expect(e.code).toBe('UNKNOWN');
    expect(e.retryable).toBe(true);
  });
});
