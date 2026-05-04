import { chromium, type Browser, type BrowserContext } from 'playwright';

export interface BrowserSession {
  label: string;
  context: BrowserContext;
}

export class BrowserPool {
  private browser: Browser | null = null;
  private sessions = new Map<string, BrowserSession>();
  private maxSessions: number;

  constructor(maxSessions: number = 5) {
    this.maxSessions = maxSessions;
  }

  async acquire(label: string): Promise<BrowserSession> {
    if (this.sessions.has(label)) {
      return this.sessions.get(label)!;
    }

    if (this.sessions.size >= this.maxSessions) {
      throw new Error(`Browser pool exhausted (max ${this.maxSessions} sessions)`);
    }

    if (!this.browser) {
      this.browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });
    }

    const context = await this.browser.newContext({
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true,
    });

    const session: BrowserSession = { label, context };
    this.sessions.set(label, session);
    return session;
  }

  async release(label: string): Promise<void> {
    const session = this.sessions.get(label);
    if (session) {
      await session.context.close();
      this.sessions.delete(label);
    }
  }

  async releaseAll(): Promise<void> {
    for (const [label] of this.sessions) {
      await this.release(label);
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}
