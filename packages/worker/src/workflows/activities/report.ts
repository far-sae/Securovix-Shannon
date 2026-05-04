import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { ReportInput } from './index.js';
import { unwrap } from '../../result.js';
import { loadPrompt } from '../../prompts/loader.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

export async function reportActivity(container: Container, input: ReportInput): Promise<string> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const reportPath = join(input.workspaceDir, 'report.md');

  try {
    heartbeat('Gathering exploitation evidence');

    const evidence = gatherEvidence(input.workspaceDir);
    if (input.purpleTeamReportPath && existsSync(input.purpleTeamReportPath)) {
      evidence.purpleTeam = safeRead(input.purpleTeamReportPath);
    }

    const prompt = unwrap(loadPrompt('report', {
      targetUrl: config.target.url,
      repoPath: config.target.repoPath,
      configContext: JSON.stringify(evidence, null, 2),
    }));

    const model = container.llmClientFactory.resolveModelForAgent('report');
    const client = container.llmClientFactory.createClient();

    heartbeat('Generating final report');
    const response = await client.messages.create({
      model,
      max_tokens: 8192,
      messages: [{ role: 'user', content: prompt }],
    });

    const report = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    writeFileSync(reportPath, truncateForSerialization(report));

    // Emit through plugin
    await container.reportPlugin.emit('scan', { format: 'markdown', content: report });

    heartbeat('Report complete');
    return reportPath;
  } catch (error) {
    throw toTemporalError(error);
  }
}

interface Evidence {
  preRecon: string;
  recon: string;
  vulnFindings: Record<string, string>;
  exploitResults: Record<string, string>;
  purpleTeam?: string;
}

function gatherEvidence(workspaceDir: string): Evidence {
  const evidence: Evidence = {
    preRecon: safeRead(join(workspaceDir, 'pre-recon', 'source-analysis.md')),
    recon: safeRead(join(workspaceDir, 'recon', 'exploration.md')),
    vulnFindings: {},
    exploitResults: {},
  };

  const categories = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf'];

  for (const cat of categories) {
    const vulnPath = join(workspaceDir, 'vuln', cat, 'analysis.md');
    if (existsSync(vulnPath)) {
      evidence.vulnFindings[cat] = safeRead(vulnPath);
    }

    const exploitPath = join(workspaceDir, 'exploit', cat, 'exploit-report.md');
    if (existsSync(exploitPath)) {
      evidence.exploitResults[cat] = safeRead(exploitPath);
    }
  }

  return evidence;
}

function safeRead(path: string): string {
  try {
    return existsSync(path) ? readFileSync(path, 'utf-8') : '';
  } catch {
    return '';
  }
}
