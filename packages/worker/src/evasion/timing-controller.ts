export class TimingController {
  private baseDelayMs: number;
  private currentDelayMs: number;
  private jitterRange: number;
  private consecutiveSuccesses: number = 0;
  private readonly minDelayMs = 100;
  private readonly maxDelayMs = 30_000;

  constructor(baseDelayMs: number = 500) {
    this.baseDelayMs = baseDelayMs;
    this.currentDelayMs = baseDelayMs;
    this.jitterRange = baseDelayMs * 0.3;
  }

  async wait(): Promise<void> {
    const jitter = (Math.random() - 0.5) * 2 * this.jitterRange;
    const delay = Math.max(this.minDelayMs, this.currentDelayMs + jitter);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  onDetection(): void {
    // Exponential backoff on detection
    this.currentDelayMs = Math.min(this.currentDelayMs * 2, this.maxDelayMs);
    this.jitterRange = this.currentDelayMs * 0.5;
    this.consecutiveSuccesses = 0;
  }

  onSuccess(): void {
    this.consecutiveSuccesses++;
    // Gradually reduce delay after sustained success
    if (this.consecutiveSuccesses > 10) {
      this.currentDelayMs = Math.max(this.baseDelayMs, this.currentDelayMs * 0.9);
      this.jitterRange = this.currentDelayMs * 0.3;
    }
  }

  getCurrentDelay(): number {
    return this.currentDelayMs;
  }

  setBaseDelay(delayMs: number): void {
    this.baseDelayMs = delayMs;
    this.currentDelayMs = delayMs;
    this.jitterRange = delayMs * 0.3;
  }
}
