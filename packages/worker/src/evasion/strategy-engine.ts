import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { DetectionSignal, EvasionProfile, EvasionStrategy, EvasionTechnique } from './types.js';
import { PayloadEncoder } from './payload-encoder.js';
import { TimingController } from './timing-controller.js';

const DEFAULT_STRATEGIES: EvasionStrategy[] = [
  {
    techniques: ['timing-jitter', 'header-rotation'],
    priority: 1,
    effectiveness: 0.5,
    lastUsed: '',
    successCount: 0,
    failureCount: 0,
  },
  {
    techniques: ['timing-slowdown', 'payload-case-variation', 'header-rotation'],
    priority: 2,
    effectiveness: 0.5,
    lastUsed: '',
    successCount: 0,
    failureCount: 0,
  },
  {
    techniques: ['payload-double-encode', 'timing-slowdown', 'path-normalization'],
    priority: 3,
    effectiveness: 0.5,
    lastUsed: '',
    successCount: 0,
    failureCount: 0,
  },
  {
    techniques: ['payload-comment-inject', 'payload-unicode', 'timing-jitter', 'session-rotation'],
    priority: 4,
    effectiveness: 0.5,
    lastUsed: '',
    successCount: 0,
    failureCount: 0,
  },
  {
    techniques: ['payload-chunked', 'method-override', 'parameter-pollution', 'timing-slowdown'],
    priority: 5,
    effectiveness: 0.5,
    lastUsed: '',
    successCount: 0,
    failureCount: 0,
  },
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
];

export class EvasionStrategyEngine {
  private profile: EvasionProfile;
  private encoder: PayloadEncoder;
  private timing: TimingController;
  private currentStrategyIndex: number = 0;

  constructor(targetHost: string) {
    this.profile = {
      targetHost,
      detectedWAF: null,
      detectionHistory: [],
      activeStrategies: [...DEFAULT_STRATEGIES],
      failedStrategies: [],
      currentTimingMs: 500,
      requestsSinceLastDetection: 0,
    };
    this.encoder = new PayloadEncoder();
    this.timing = new TimingController();
  }

  onDetection(signal: DetectionSignal): EvasionStrategy {
    this.profile.detectionHistory.push(signal);
    this.profile.requestsSinceLastDetection = 0;
    this.timing.onDetection();

    // Mark current strategy as less effective
    const current = this.profile.activeStrategies[this.currentStrategyIndex];
    if (current) {
      current.failureCount++;
      current.effectiveness = current.successCount / (current.successCount + current.failureCount);
    }

    // Move to next strategy
    this.currentStrategyIndex = (this.currentStrategyIndex + 1) % this.profile.activeStrategies.length;

    // Sort by effectiveness (learned over time)
    this.profile.activeStrategies.sort((a, b) => b.effectiveness - a.effectiveness);

    const nextStrategy = this.profile.activeStrategies[this.currentStrategyIndex];
    nextStrategy.lastUsed = new Date().toISOString();
    return nextStrategy;
  }

  onSuccess(): void {
    this.profile.requestsSinceLastDetection++;
    this.timing.onSuccess();

    const current = this.profile.activeStrategies[this.currentStrategyIndex];
    if (current) {
      current.successCount++;
      current.effectiveness = current.successCount / (current.successCount + current.failureCount);
    }
  }

  getRecommendedDelay(): number {
    return this.timing.getCurrentDelay();
  }

  async waitBeforeRequest(): Promise<void> {
    await this.timing.wait();
  }

  transformPayload(payload: string): string {
    const strategy = this.profile.activeStrategies[this.currentStrategyIndex];
    if (!strategy) return payload;

    let result = payload;
    for (const technique of strategy.techniques) {
      if (technique.startsWith('payload-')) {
        result = this.encoder.encode(result, technique);
      }
    }
    return result;
  }

  transformHeaders(headers: Record<string, string>): Record<string, string> {
    const strategy = this.profile.activeStrategies[this.currentStrategyIndex];
    if (!strategy) return headers;

    const transformed = { ...headers };

    if (strategy.techniques.includes('header-rotation')) {
      transformed['User-Agent'] = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
      transformed['Accept-Language'] = ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9'][
        Math.floor(Math.random() * 3)
      ];
    }

    if (strategy.techniques.includes('method-override') && transformed['X-HTTP-Method-Override'] === undefined) {
      // Only set if not already present; caller decides actual method
    }

    return transformed;
  }

  transformUrl(url: string): string {
    const strategy = this.profile.activeStrategies[this.currentStrategyIndex];
    if (!strategy) return url;

    if (strategy.techniques.includes('path-normalization')) {
      // Insert ../ traversals that resolve to the same path
      const urlObj = new URL(url);
      const segments = urlObj.pathname.split('/').filter(Boolean);
      if (segments.length > 0) {
        const randomIndex = Math.floor(Math.random() * segments.length);
        segments.splice(randomIndex, 0, '.', '.');
        urlObj.pathname = '/' + segments.join('/');
      }
      return urlObj.toString();
    }

    if (strategy.techniques.includes('parameter-pollution')) {
      const urlObj = new URL(url);
      const params = [...urlObj.searchParams.entries()];
      if (params.length > 0) {
        const [key, value] = params[Math.floor(Math.random() * params.length)];
        urlObj.searchParams.append(key, value);
      }
      return urlObj.toString();
    }

    return url;
  }

  setDetectedWAF(waf: string): void {
    this.profile.detectedWAF = waf;
  }

  getProfile(): EvasionProfile {
    return { ...this.profile };
  }

  serializeProfile(): string {
    return JSON.stringify(this.profile, null, 2);
  }

  loadProfile(serialized: string): void {
    this.profile = JSON.parse(serialized);
    this.timing.setBaseDelay(this.profile.currentTimingMs);
  }

  persistProfile(workspaceDir: string): void {
    writeFileSync(join(workspaceDir, 'evasion-profile.json'), this.serializeProfile());
  }

  restoreProfile(workspaceDir: string): boolean {
    const profilePath = join(workspaceDir, 'evasion-profile.json');
    if (existsSync(profilePath)) {
      this.loadProfile(readFileSync(profilePath, 'utf-8'));
      return true;
    }
    return false;
  }
}
