import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { DeceptionScanInput } from './index.js';
import { unwrap } from '../../result.js';
import { BrowserPool } from '../../browser/pool.js';
import { DeceptionFingerprinter } from '../../counter-deception/fingerprinter.js';
import { DeceptionClassifier } from '../../counter-deception/deception-classifier.js';
import type { DeceptionVerdict } from '../../counter-deception/types.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

export async function deceptionScanActivity(container: Container, input: DeceptionScanInput): Promise<void> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const outputDir = join(input.workspaceDir, 'recon');
  mkdirSync(outputDir, { recursive: true });

  const browserPool = new BrowserPool(1);

  try {
    heartbeat('Starting counter-deception scan');
    const session = await browserPool.acquire('deception-scan');
    const fingerprinter = new DeceptionFingerprinter();
    const classifier = new DeceptionClassifier();

    // Load discovered endpoints from recon phase
    const apiMapPath = join(outputDir, 'api-map.json');
    let endpoints: string[] = [config.target.url];

    if (existsSync(apiMapPath)) {
      const apiMap = JSON.parse(readFileSync(apiMapPath, 'utf-8'));
      if (apiMap.endpoints) {
        endpoints = apiMap.endpoints.map((e: { url?: string; path?: string }) =>
          e.url ?? `${config.target.url}${e.path ?? ''}`,
        );
      }
    }

    const verdicts: DeceptionVerdict[] = [];

    for (const endpoint of endpoints.slice(0, 20)) {
      heartbeat(`Scanning ${endpoint} for deception`);

      const signals = [
        ...await fingerprinter.checkHeaderAnomalies(session.context, endpoint),
        ...fingerprinter.detectCanaryTokens(await fetchBody(session.context, endpoint)),
      ];

      // Only run expensive checks if initial signals are suspicious
      if (signals.length > 0) {
        signals.push(...await fingerprinter.checkResponseTiming(session.context, endpoint, 5));
      }

      const verdict = classifier.classify(endpoint, signals);
      verdicts.push(verdict);
    }

    // Save verdicts
    writeFileSync(
      join(outputDir, 'deception-verdicts.json'),
      truncateForSerialization(JSON.stringify(verdicts, null, 2)),
    );

    const decoyCount = verdicts.filter((v) => v.isDecoy).length;
    heartbeat(`Deception scan complete: ${decoyCount} decoys found out of ${verdicts.length} endpoints`);
  } catch (error) {
    throw toTemporalError(error);
  } finally {
    await browserPool.releaseAll();
  }
}

async function fetchBody(context: import('playwright').BrowserContext, url: string): Promise<string> {
  const page = await context.newPage();
  try {
    const response = await page.goto(url, { timeout: 10_000 });
    return await response?.text() ?? '';
  } catch {
    return '';
  } finally {
    await page.close();
  }
}
