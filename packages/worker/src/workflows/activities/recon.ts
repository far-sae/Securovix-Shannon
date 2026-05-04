import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { ReconInput } from './index.js';
import { unwrap } from '../../result.js';
import { loadPrompt } from '../../prompts/loader.js';
import { BrowserPool } from '../../browser/pool.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

export async function reconActivity(container: Container, input: ReconInput): Promise<void> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const outputDir = join(input.workspaceDir, 'recon');
  mkdirSync(outputDir, { recursive: true });

  const browserPool = new BrowserPool(1);

  try {
    heartbeat('Launching browser for recon');
    const session = await browserPool.acquire('recon');

    const prompt = unwrap(loadPrompt('recon', {
      targetUrl: config.target.url,
      repoPath: config.target.repoPath,
      configContext: JSON.stringify(config.target.urls ?? {}),
      loginInstructions: config.loginInstructions,
    }));

    const model = container.llmClientFactory.resolveModelForAgent('recon');
    const client = container.llmClientFactory.createClient();

    heartbeat('Running browser exploration via LLM');
    const response = await client.messages.create({
      model,
      max_tokens: 8192,
      messages: [{ role: 'user', content: prompt }],
    });

    const analysis = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    writeFileSync(join(outputDir, 'exploration.md'), truncateForSerialization(analysis));
    writeFileSync(join(outputDir, 'api-map.json'), truncateForSerialization(JSON.stringify({ endpoints: [] }, null, 2)));

    heartbeat('Recon complete');
  } catch (error) {
    throw toTemporalError(error);
  } finally {
    await browserPool.releaseAll();
  }
}
