import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { VulnAgentInput, VulnAgentOutput } from './index.js';
import { unwrap } from '../../result.js';
import { loadPrompt } from '../../prompts/loader.js';
import { BrowserPool } from '../../browser/pool.js';
import { AuditSession } from '../../audit/session.js';
import { GitCheckpoint } from '../../workspace/git-checkpoint.js';
import { SessionManager } from '../../workspace/session.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';
import { ACTIVE_VULN_CATEGORIES } from '../categories.js';

export function categoryAgentIndex(category: string): number {
  const idx = ACTIVE_VULN_CATEGORIES.indexOf(category as (typeof ACTIVE_VULN_CATEGORIES)[number]);
  if (idx < 0) {
    throw new Error(`Unknown vuln category: ${category}. Add it to workflows/categories.ts.`);
  }
  return idx + 1;
}

export async function vulnAgentActivity(container: Container, input: VulnAgentInput): Promise<VulnAgentOutput> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const agentName = `vuln-${input.category}`;
  const outputDir = join(input.workspaceDir, 'vuln', input.category);
  mkdirSync(outputDir, { recursive: true });

  const sessionMgr = new SessionManager(input.workspaceDir);
  const gitCheckpoint = new GitCheckpoint(input.workspaceDir);
  const audit = new AuditSession(agentName, input.workspaceDir);

  // Check resume - skip if already completed
  if (input.resume && sessionMgr.isAgentCompleted(agentName)) {
    const queuePath = join(outputDir, 'exploitation-queue.json');
    const analysisPath = join(outputDir, 'analysis.md');
    return { hasFindings: true, queuePath, analysisPath };
  }

  const agentIndex = categoryAgentIndex(input.category);
  const browserPool = new BrowserPool(1);

  try {
    // Git checkpoint before agent
    await gitCheckpoint.createCheckpoint(`pre-${agentName}`);

    heartbeat(`Starting ${agentName} agent`);
    const session = await browserPool.acquire(`agent${agentIndex}`);

    const prompt = unwrap(loadPrompt(`vuln/${input.category}`, {
      targetUrl: config.target.url,
      repoPath: config.target.repoPath,
      configContext: JSON.stringify(config.target.urls ?? {}),
      loginInstructions: config.loginInstructions,
    }));

    audit.logPromptSnapshot(prompt);

    const model = container.llmClientFactory.resolveModelForAgent(agentName);
    const client = container.llmClientFactory.createClient();
    const startTime = Date.now();

    const response = await client.messages.create({
      model,
      max_tokens: 8192,
      messages: [{ role: 'user', content: prompt }],
    });

    const analysis = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    // Write deliverables
    const analysisPath = join(outputDir, 'analysis.md');
    writeFileSync(analysisPath, truncateForSerialization(analysis));

    // Generate exploitation queue from analysis
    const exploitQueue = extractExploitQueue(analysis);
    const queuePath = join(outputDir, 'exploitation-queue.json');
    writeFileSync(queuePath, truncateForSerialization(JSON.stringify(exploitQueue, null, 2)));

    // Track metrics
    const duration = Date.now() - startTime;
    audit.trackMetrics({
      cost: response.usage.input_tokens * 0.000003 + response.usage.output_tokens * 0.000015,
      turns: 1,
      duration,
    });

    // Git checkpoint after agent
    await gitCheckpoint.createCheckpoint(`post-${agentName}`);
    sessionMgr.markAgentCompleted(agentName);

    heartbeat(`${agentName} complete`);

    return {
      hasFindings: exploitQueue.findings.length > 0,
      queuePath,
      analysisPath,
    };
  } catch (error) {
    await gitCheckpoint.rollback(`pre-${agentName}`);
    throw toTemporalError(error);
  } finally {
    await browserPool.releaseAll();
    audit.close();
  }
}

interface ExploitQueue {
  category: string;
  findings: Array<{
    id: string;
    type: string;
    endpoint: string;
    description: string;
    severity: string;
    evidence: string;
  }>;
}

function extractExploitQueue(analysis: string): ExploitQueue {
  // Parse structured findings from analysis markdown
  const findings: ExploitQueue['findings'] = [];
  const findingRegex = /##\s+Finding\s+(\d+)[:\s]+(.*?)(?=##\s+Finding|\Z)/gs;

  let match: RegExpExecArray | null;
  while ((match = findingRegex.exec(analysis)) !== null) {
    findings.push({
      id: `finding-${match[1]}`,
      type: 'potential',
      endpoint: '',
      description: match[2]?.trim().slice(0, 500) ?? '',
      severity: 'medium',
      evidence: '',
    });
  }

  return { category: '', findings };
}
