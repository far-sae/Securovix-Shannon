import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { WarRoomInput, WarRoomOutput } from './index.js';
import { unwrap } from '../../result.js';
import { WarRoomModerator } from '../../war-room/moderator.js';
import type { FindingInput } from '../../war-room/types.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

const CATEGORIES = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic'] as const;

export async function warRoomActivity(container: Container, input: WarRoomInput): Promise<WarRoomOutput> {
  const outputDir = join(input.workspaceDir, 'war-room');
  mkdirSync(outputDir, { recursive: true });

  try {
    heartbeat('Gathering findings for war room review');

    // Collect all findings from vuln and exploit phases
    const findings: FindingInput[] = [];
    let findingCounter = 0;

    for (const category of CATEGORIES) {
      const queuePath = join(input.workspaceDir, 'vuln', category, 'exploitation-queue.json');
      if (!existsSync(queuePath)) continue;

      const queue = JSON.parse(readFileSync(queuePath, 'utf-8'));
      if (!queue.findings) continue;

      // Check for exploit evidence
      const exploitPath = join(input.workspaceDir, 'exploit', category, 'exploit-report.md');
      const exploitEvidence = existsSync(exploitPath) ? readFileSync(exploitPath, 'utf-8') : undefined;

      for (const finding of queue.findings) {
        findings.push({
          id: `finding-${++findingCounter}`,
          category,
          endpoint: finding.endpoint ?? '',
          severity: finding.severity ?? 'medium',
          description: finding.description ?? '',
          evidence: finding.evidence ?? '',
          exploitPoc: exploitEvidence?.slice(0, 2000),
        });
      }
    }

    if (findings.length === 0) {
      const verdictsPath = join(outputDir, 'verdicts.json');
      writeFileSync(verdictsPath, JSON.stringify({ findings: [], eliminatedCount: 0 }, null, 2));
      return { verdictsPath };
    }

    heartbeat(`War room reviewing ${findings.length} findings`);

    const moderator = new WarRoomModerator(container.llmClientFactory);
    const result = await moderator.conductReview(findings);

    // Save verdicts
    const verdictsPath = join(outputDir, 'verdicts.json');
    writeFileSync(verdictsPath, truncateForSerialization(JSON.stringify(result, null, 2)));

    // Save transcript for audit
    writeFileSync(
      join(outputDir, 'transcript.md'),
      truncateForSerialization(
        result.transcript
          .map((m) => `### [Round ${m.round}] ${m.from} -> ${m.to} (${m.type})\n\n${m.content}`)
          .join('\n\n---\n\n'),
      ),
    );

    // Save summary
    const summaryLines = [
      '# War Room Summary',
      '',
      `**Findings Reviewed**: ${findings.length}`,
      `**False Positives Eliminated**: ${result.eliminatedCount}`,
      `**Severity Escalations**: ${result.escalatedCount}`,
      `**Total Debate Rounds**: ${result.totalDebateRounds}`,
      '',
      '## Verdicts',
      '',
    ];

    for (const verdict of result.findings) {
      const status = verdict.confirmedFalsePositive ? 'FALSE POSITIVE' : 'CONFIRMED';
      summaryLines.push(
        `- **${verdict.findingId}**: ${status} | ${verdict.originalSeverity} -> ${verdict.adjustedSeverity} | Rounds: ${verdict.debateRounds}`,
      );
    }

    writeFileSync(join(outputDir, 'summary.md'), truncateForSerialization(summaryLines.join('\n')));

    heartbeat(`War room complete: ${result.eliminatedCount} false positives eliminated`);

    return { verdictsPath };
  } catch (error) {
    throw toTemporalError(error);
  }
}
