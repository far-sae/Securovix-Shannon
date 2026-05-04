import type { BrowserContext, Route } from 'playwright';
import { DetectionDetector } from './detector.js';
import { EvasionStrategyEngine } from './strategy-engine.js';
import type { EvidenceStore } from '../forensic/evidence-store.js';

export class EvasionMiddleware {
  private detector: DetectionDetector;
  private engine: EvasionStrategyEngine;
  private evidenceStore?: EvidenceStore;

  constructor(
    engine: EvasionStrategyEngine,
    detector: DetectionDetector,
    evidenceStore?: EvidenceStore,
  ) {
    this.engine = engine;
    this.detector = detector;
    this.evidenceStore = evidenceStore;
  }

  async wrapContext(context: BrowserContext): Promise<void> {
    await context.route('**/*', async (route: Route) => {
      const request = route.request();

      // Apply evasion timing
      await this.engine.waitBeforeRequest();

      // Transform URL if needed
      const originalUrl = request.url();

      try {
        const response = await route.fetch();
        const headers = response.headers();
        const status = response.status();
        const body = await response.text().catch(() => '');

        // Check for WAF identification (first request)
        if (!this.engine.getProfile().detectedWAF) {
          const waf = this.detector.identifyWAF(headers);
          if (waf) {
            this.engine.setDetectedWAF(waf);
          }
        }

        // Check for detection
        const detection = this.detector.analyzeResponse(status, headers, body);

        if (detection) {
          detection.requestThatTriggered = `${request.method()} ${originalUrl}`;
          const newStrategy = this.engine.onDetection(detection);

          // Retry with evasion applied
          await this.engine.waitBeforeRequest();

          const retryResponse = await route.fetch({
            headers: this.engine.transformHeaders(Object.fromEntries(
              Object.entries(await request.allHeaders()),
            )),
          });

          await route.fulfill({
            status: retryResponse.status(),
            headers: retryResponse.headers(),
            body: await retryResponse.body(),
          });
        } else {
          this.engine.onSuccess();

          await route.fulfill({
            status: response.status(),
            headers: response.headers(),
            body: await response.body(),
          });
        }
      } catch {
        await route.continue();
      }
    });
  }

  getEngine(): EvasionStrategyEngine {
    return this.engine;
  }
}
