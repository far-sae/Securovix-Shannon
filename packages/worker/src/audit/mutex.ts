export class AuditMutex {
  private static instance: AuditMutex;
  private locked = false;
  private queue: Array<() => void> = [];

  static getInstance(): AuditMutex {
    if (!AuditMutex.instance) {
      AuditMutex.instance = new AuditMutex();
    }
    return AuditMutex.instance;
  }

  acquire(fn: () => void): void {
    if (!this.locked) {
      this.locked = true;
      try {
        fn();
      } finally {
        this.locked = false;
        this.processQueue();
      }
    } else {
      this.queue.push(fn);
    }
  }

  private processQueue(): void {
    if (this.queue.length > 0 && !this.locked) {
      const next = this.queue.shift()!;
      this.acquire(next);
    }
  }
}
