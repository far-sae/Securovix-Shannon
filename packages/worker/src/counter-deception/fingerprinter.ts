import type { BrowserContext } from 'playwright';
import type { DeceptionSignal, HoneypotFingerprint } from './types.js';

// Known canary token patterns
const CANARY_PATTERNS = [
  // AWS canary keys
  /AKIA[0-9A-Z]{16}/g,
  // Thinkst canary tokens
  /canarytokens\.com/gi,
  /[a-z0-9]{32}\.canarytokens\.org/gi,
  // Common canary credential patterns
  /admin:admin/g,
  /test:test123/g,
  // Canary DNS tokens
  /[a-f0-9]{32}\.[a-z]+\.canary\./gi,
  // Canary URLs with tracking
  /\/canary[_-]?[a-f0-9]+/gi,
];

const EXPECTED_HEADERS = ['content-type', 'date', 'server', 'content-length'];

export class DeceptionFingerprinter {
  async checkResponseTiming(context: BrowserContext, url: string, samples: number = 10): Promise<DeceptionSignal[]> {
    const signals: DeceptionSignal[] = [];
    const times: number[] = [];

    for (let i = 0; i < samples; i++) {
      const page = await context.newPage();
      const start = Date.now();
      try {
        await page.goto(url, { timeout: 10_000, waitUntil: 'networkidle' });
        times.push(Date.now() - start);
      } catch {
        times.push(-1);
      } finally {
        await page.close();
      }
    }

    const validTimes = times.filter((t) => t > 0);
    if (validTimes.length < 3) return signals;

    const mean = validTimes.reduce((a, b) => a + b, 0) / validTimes.length;
    const variance = validTimes.reduce((a, b) => a + (b - mean) ** 2, 0) / validTimes.length;
    const stdDev = Math.sqrt(variance);
    const cv = stdDev / mean; // Coefficient of variation

    // Suspiciously low variance suggests synthetic responses (honeypot)
    if (cv < 0.02 && mean < 50) {
      signals.push({
        type: 'honeypot',
        indicator: `Near-zero response time variance (CV: ${cv.toFixed(4)}, mean: ${mean.toFixed(1)}ms)`,
        confidence: 0.7,
        source: 'behavioral',
        details: `Response times are unnaturally consistent, suggesting synthetic/honeypot responses`,
      });
    }

    // Increasing response times suggest tarpit
    const isIncreasing = validTimes.every((t, i) => i === 0 || t >= validTimes[i - 1] * 0.9);
    if (isIncreasing && validTimes[validTimes.length - 1] > validTimes[0] * 3) {
      signals.push({
        type: 'tarpit',
        indicator: `Response time increasing: ${validTimes[0]}ms -> ${validTimes[validTimes.length - 1]}ms`,
        confidence: 0.8,
        source: 'behavioral',
        details: 'Linear response time increase detected, characteristic of tarpits',
      });
    }

    return signals;
  }

  async checkHeaderAnomalies(context: BrowserContext, url: string): Promise<DeceptionSignal[]> {
    const signals: DeceptionSignal[] = [];
    const page = await context.newPage();

    try {
      const response = await page.goto(url, { timeout: 10_000 });
      if (!response) return signals;

      const headers = response.headers();

      // Check for missing expected headers
      const missing = EXPECTED_HEADERS.filter((h) => !headers[h]);
      if (missing.length >= 2) {
        signals.push({
          type: 'honeypot',
          indicator: `Missing common headers: ${missing.join(', ')}`,
          confidence: 0.5,
          source: 'heuristic',
          details: 'Real web servers typically include standard headers',
        });
      }

      // Check server banner mismatch
      const server = headers['server'] ?? '';
      const poweredBy = headers['x-powered-by'] ?? '';
      if (server.toLowerCase().includes('apache') && poweredBy.toLowerCase().includes('express')) {
        signals.push({
          type: 'honeypot',
          indicator: `Server banner mismatch: Server=${server}, X-Powered-By=${poweredBy}`,
          confidence: 0.8,
          source: 'heuristic',
          details: 'Server header contradicts X-Powered-By, suggesting deception',
        });
      }

      // Check for honeypot-specific headers
      const suspiciousHeaders = Object.keys(headers).filter(
        (h) => h.includes('honey') || h.includes('canary') || h.includes('trap'),
      );
      if (suspiciousHeaders.length > 0) {
        signals.push({
          type: 'honeypot',
          indicator: `Suspicious headers found: ${suspiciousHeaders.join(', ')}`,
          confidence: 0.9,
          source: 'heuristic',
          details: 'Headers contain honeypot/canary indicators',
        });
      }
    } finally {
      await page.close();
    }

    return signals;
  }

  async checkOverpermissiveAuth(context: BrowserContext, url: string): Promise<DeceptionSignal[]> {
    const signals: DeceptionSignal[] = [];
    const testCreds = [
      { user: `test_${Math.random().toString(36).slice(2, 8)}`, pass: 'random123' },
      { user: `admin_${Math.random().toString(36).slice(2, 8)}`, pass: 'password' },
      { user: `fake_${Math.random().toString(36).slice(2, 8)}`, pass: 'fake' },
    ];

    let successCount = 0;

    for (const cred of testCreds) {
      const page = await context.newPage();
      try {
        await page.goto(url, { timeout: 10_000 });

        // Try to find and fill login form
        const usernameField = await page.$('input[type="text"], input[type="email"], input[name*="user"], input[name*="login"]');
        const passwordField = await page.$('input[type="password"]');
        const submitBtn = await page.$('button[type="submit"], input[type="submit"]');

        if (usernameField && passwordField && submitBtn) {
          await usernameField.fill(cred.user);
          await passwordField.fill(cred.pass);
          await submitBtn.click();
          await page.waitForTimeout(2000);

          // Check if login succeeded (redirected away from login, or no error)
          const currentUrl = page.url();
          if (!currentUrl.includes('login') && !currentUrl.includes('error')) {
            successCount++;
          }
        }
      } catch {
        // Ignore failures
      } finally {
        await page.close();
      }
    }

    if (successCount >= 2) {
      signals.push({
        type: 'honeypot',
        indicator: `${successCount}/3 random credentials accepted`,
        confidence: 0.9,
        source: 'behavioral',
        details: 'Overpermissive authentication - accepts random credentials, characteristic of honeypots',
      });
    }

    return signals;
  }

  detectCanaryTokens(responseBody: string): DeceptionSignal[] {
    const signals: DeceptionSignal[] = [];

    for (const pattern of CANARY_PATTERNS) {
      const matches = responseBody.match(pattern);
      if (matches) {
        signals.push({
          type: 'canary-token',
          indicator: `Canary token pattern found: ${matches[0]}`,
          confidence: 0.85,
          source: 'heuristic',
          details: `Response contains known canary token pattern. Interacting with this may alert defenders.`,
        });
      }
    }

    return signals;
  }

  async detectTarpit(context: BrowserContext, url: string): Promise<DeceptionSignal[]> {
    const signals: DeceptionSignal[] = [];
    const times: number[] = [];

    // Make 5 sequential requests to the same endpoint
    for (let i = 0; i < 5; i++) {
      const page = await context.newPage();
      const start = Date.now();
      try {
        await page.goto(url, { timeout: 30_000 });
        times.push(Date.now() - start);
      } catch {
        times.push(-1);
      } finally {
        await page.close();
      }
    }

    const validTimes = times.filter((t) => t > 0);
    if (validTimes.length < 3) return signals;

    // Check if response time increases linearly
    let increasing = true;
    for (let i = 1; i < validTimes.length; i++) {
      if (validTimes[i] < validTimes[i - 1]) {
        increasing = false;
        break;
      }
    }

    if (increasing && validTimes[validTimes.length - 1] > validTimes[0] * 2) {
      signals.push({
        type: 'tarpit',
        indicator: `Response time increasing: ${validTimes.map((t) => `${t}ms`).join(' -> ')}`,
        confidence: 0.85,
        source: 'behavioral',
        details: 'Deliberate slowdown detected. This endpoint appears to be a tarpit designed to waste attacker time.',
      });
    }

    return signals;
  }

  async fingerprint(context: BrowserContext, url: string): Promise<HoneypotFingerprint> {
    const timingSignals = await this.checkResponseTiming(context, url, 5);
    const headerSignals = await this.checkHeaderAnomalies(context, url);

    return {
      responseTimeMs: 0,
      responseTimeDeviation: 0,
      unusualHeaders: headerSignals.filter((s) => s.indicator.includes('header')).map((s) => s.indicator),
      missingExpectedHeaders: [],
      serverBannerMismatch: headerSignals.some((s) => s.indicator.includes('mismatch')),
      overpermissiveAuth: false,
      fakeDataPatterns: false,
      canaryTokensFound: [],
      acceptsAllInput: false,
      identicalErrorResponses: false,
      tarpitDetected: timingSignals.some((s) => s.type === 'tarpit'),
    };
  }
}
