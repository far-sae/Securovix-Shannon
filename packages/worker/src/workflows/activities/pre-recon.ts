import { execSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { PreReconInput } from './index.js';
import { unwrap } from '../../result.js';
import { loadPrompt } from '../../prompts/loader.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

export async function preReconActivity(container: Container, input: PreReconInput): Promise<void> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const outputDir = join(input.workspaceDir, 'pre-recon');
  mkdirSync(outputDir, { recursive: true });

  try {
    heartbeat('Starting nmap scan');
    const nmapResult = runTool('nmap', ['-sV', '-sC', '-oN', join(outputDir, 'nmap.txt'), new URL(config.target.url).hostname]);
    writeFileSync(join(outputDir, 'nmap-raw.txt'), truncateForSerialization(nmapResult));

    heartbeat('Running subfinder');
    const subfinderResult = runTool('subfinder', ['-d', new URL(config.target.url).hostname, '-silent']);
    writeFileSync(join(outputDir, 'subdomains.txt'), truncateForSerialization(subfinderResult));

    heartbeat('Running whatweb');
    const whatwebResult = runTool('whatweb', [config.target.url, '--color=never']);
    writeFileSync(join(outputDir, 'whatweb.txt'), truncateForSerialization(whatwebResult));

    heartbeat('Running source code analysis');
    if (config.target.repoPath && existsSync(config.target.repoPath)) {
      const prompt = unwrap(loadPrompt('pre-recon', {
        targetUrl: config.target.url,
        repoPath: config.target.repoPath,
        loginInstructions: config.loginInstructions,
      }));

      const model = container.llmClientFactory.resolveModelForAgent('pre-recon');
      const client = container.llmClientFactory.createClient();

      const response = await client.messages.create({
        model,
        max_tokens: 8192,
        messages: [{ role: 'user', content: prompt }],
      });

      const analysis = response.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');

      writeFileSync(join(outputDir, 'source-analysis.md'), truncateForSerialization(analysis));
    }

    heartbeat('Pre-recon complete');
  } catch (error) {
    throw toTemporalError(error);
  }
}

function runTool(name: string, args: string[]): string {
  try {
    return execSync(`${name} ${args.join(' ')}`, {
      encoding: 'utf-8',
      timeout: 300_000,
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (e) {
    return `[${name} error: ${e instanceof Error ? e.message.slice(0, 500) : 'unknown'}]`;
  }
}
