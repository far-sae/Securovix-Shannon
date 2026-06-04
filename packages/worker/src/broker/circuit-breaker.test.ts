import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from './circuit-breaker.js';

describe('CircuitBreaker', () => {
  it('stays closed and proceeds until the failure threshold', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => 0 });
    expect(cb.canProceed()).toBe(true);
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('closed');
    expect(cb.canProceed()).toBe(true);
  });

  it('opens after threshold consecutive failures and blocks while open', () => {
    const t = 0;
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => t });
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('open');
    expect(cb.canProceed()).toBe(false);
  });

  it('half-opens after the cooldown and closes on a successful trial', () => {
    let t = 0;
    const cb = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1000, now: () => t });
    cb.recordFailure(); // open at t=0
    expect(cb.canProceed()).toBe(false);
    t = 1000; // cooldown elapsed
    expect(cb.canProceed()).toBe(true); // half-open trial allowed
    expect(cb.getState()).toBe('half-open');
    cb.recordSuccess();
    expect(cb.getState()).toBe('closed');
  });

  it('re-opens if the half-open trial fails', () => {
    let t = 0;
    const cb = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1000, now: () => t });
    cb.recordFailure(); // open
    t = 1000;
    expect(cb.canProceed()).toBe(true); // half-open
    cb.recordFailure(); // trial failed
    expect(cb.getState()).toBe('open');
    expect(cb.canProceed()).toBe(false);
  });

  it('resets the failure count on success', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => 0 });
    cb.recordFailure();
    cb.recordFailure();
    cb.recordSuccess();
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.getState()).toBe('closed'); // only 2 since the reset
  });
});
