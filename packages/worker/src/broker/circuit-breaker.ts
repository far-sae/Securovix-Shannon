export type BreakerState = 'closed' | 'open' | 'half-open';

export interface CircuitBreakerOptions {
  failureThreshold: number; // consecutive failures that trip the breaker
  cooldownMs: number; // how long to stay open before allowing a trial request
  now?: () => number; // injectable clock for deterministic tests
}

// Trips after N consecutive failures (e.g. BROKER_UNAVAILABLE). While open, callers
// should skip the broker and degrade to the LLM+Playwright path. After the cooldown it
// half-opens to allow one trial; success closes it, failure re-opens it.
export class CircuitBreaker {
  private failures = 0;
  private state: BreakerState = 'closed';
  private openedAt = 0;

  constructor(private readonly opts: CircuitBreakerOptions) {}

  private clock(): number {
    return (this.opts.now ?? Date.now)();
  }

  canProceed(): boolean {
    if (this.state === 'open') {
      if (this.clock() - this.openedAt >= this.opts.cooldownMs) {
        this.state = 'half-open';
        return true; // allow a single trial request
      }
      return false;
    }
    return true; // closed or half-open
  }

  recordSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  recordFailure(): void {
    this.failures++;
    if (this.state === 'half-open' || this.failures >= this.opts.failureThreshold) {
      this.state = 'open';
      this.openedAt = this.clock();
    }
  }

  getState(): BreakerState {
    return this.state;
  }
}
