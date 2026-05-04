import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { PurpleTeamInput, PurpleTeamOutput } from './index.js';
import { PurpleTeamModerator } from '../../purple-team/moderator.js';
import type { PurpleFinding, PurpleTeamResult } from '../../purple-team/types.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

const CATEGORIES = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic'] as const;

export async function purpleTeamActivity(
  container: Container,
  input: PurpleTeamInput,
): Promise<PurpleTeamOutput> {
  const outputDir = join(input.workspaceDir, 'purple-team');
  mkdirSync(outputDir, { recursive: true });

  try {
    heartbeat('Selecting findings for purple team review');

    const findings = collectFindings(input.workspaceDir, input.warRoomVerdictsPath);

    if (findings.length === 0) {
      const conclusionsPath = join(outputDir, 'conclusions.json');
      writeFileSync(
        conclusionsPath,
        JSON.stringify({ conclusions: [], totalRounds: 0, agreementRate: 0, transcript: [] }, null, 2),
      );
      return { conclusionsPath, reportPath: '' };
    }

    heartbeat(`Purple team running on ${findings.length} findings`);

    const moderator = new PurpleTeamModerator(container.llmClientFactory);
    const result = await moderator.run(findings);

    const conclusionsPath = join(outputDir, 'conclusions.json');
    writeFileSync(conclusionsPath, truncateForSerialization(JSON.stringify(result, null, 2)));

    writeFileSync(
      join(outputDir, 'transcript.md'),
      truncateForSerialization(renderTranscript(result)),
    );

    const reportPath = join(outputDir, 'purple-report.md');
    writeFileSync(reportPath, truncateForSerialization(renderReport(result, findings)));

    heartbeat(
      `Purple team complete: agreement ${(result.agreementRate * 100).toFixed(0)}% across ${findings.length} findings`,
    );

    return { conclusionsPath, reportPath };
  } catch (error) {
    throw toTemporalError(error);
  }
}

function collectFindings(workspaceDir: string, warRoomVerdictsPath?: string): PurpleFinding[] {
  // Prefer war-room verdicts (skip false positives) when available; fall back to vuln queues.
  if (warRoomVerdictsPath && existsSync(warRoomVerdictsPath)) {
    try {
      const verdicts = JSON.parse(readFileSync(warRoomVerdictsPath, 'utf-8')) as {
        findings?: Array<{
          findingId: string;
          confirmedFalsePositive?: boolean;
          adjustedSeverity?: string;
          finalAssessment?: string;
          redTeamNotes?: string;
        }>;
      };
      if (Array.isArray(verdicts.findings) && verdicts.findings.length > 0) {
        const queueIndex = buildVulnIndex(workspaceDir);
        const out: PurpleFinding[] = [];
        for (const v of verdicts.findings) {
          if (v.confirmedFalsePositive) continue;
          const raw = queueIndex.get(v.findingId);
          if (!raw) continue;
          out.push({
            id: v.findingId,
            category: raw.category,
            endpoint: raw.endpoint,
            severity: v.adjustedSeverity ?? raw.severity,
            description: raw.description,
            evidence: raw.evidence,
            exploitPoc: raw.exploitPoc,
          });
        }
        if (out.length > 0) return out;
      }
    } catch {
      // fall through to direct queue scan
    }
  }

  return [...buildVulnIndex(workspaceDir).values()];
}

interface RawFinding {
  category: string;
  endpoint: string;
  severity: string;
  description: string;
  evidence: string;
  exploitPoc?: string;
}

function buildVulnIndex(workspaceDir: string): Map<string, RawFinding & { id: string }> {
  const index = new Map<string, RawFinding & { id: string }>();
  let counter = 0;

  for (const category of CATEGORIES) {
    const queuePath = join(workspaceDir, 'vuln', category, 'exploitation-queue.json');
    if (!existsSync(queuePath)) continue;

    let queue: { findings?: Array<Record<string, unknown>> };
    try {
      queue = JSON.parse(readFileSync(queuePath, 'utf-8'));
    } catch {
      continue;
    }
    if (!queue.findings) continue;

    const exploitPath = join(workspaceDir, 'exploit', category, 'exploit-report.md');
    const exploitEvidence = existsSync(exploitPath)
      ? readFileSync(exploitPath, 'utf-8').slice(0, 2000)
      : undefined;

    for (const f of queue.findings) {
      const id = `finding-${++counter}`;
      index.set(id, {
        id,
        category,
        endpoint: typeof f.endpoint === 'string' ? f.endpoint : '',
        severity: typeof f.severity === 'string' ? f.severity : 'medium',
        description: typeof f.description === 'string' ? f.description : '',
        evidence: typeof f.evidence === 'string' ? f.evidence : '',
        exploitPoc: exploitEvidence,
      });
    }
  }

  return index;
}

function renderTranscript(result: PurpleTeamResult): string {
  const lines: string[] = ['# Purple Team Transcript', ''];
  for (const m of result.transcript) {
    lines.push(
      `### [Round ${m.round} | ${m.channel} | ${m.from} -> ${m.to} | ${m.type}] (${m.findingRef})`,
      '',
      m.content,
      '',
      '---',
      '',
    );
  }
  return lines.join('\n');
}

function renderReport(result: PurpleTeamResult, findings: PurpleFinding[]): string {
  const findingMap = new Map(findings.map((f) => [f.id, f]));
  const lines: string[] = [
    '# Purple Team Report',
    '',
    `**Findings reviewed:** ${result.conclusions.length}`,
    `**Agreement rate:** ${(result.agreementRate * 100).toFixed(0)}%`,
    `**Total debate rounds:** ${result.totalRounds}`,
    '',
  ];

  for (const c of result.conclusions) {
    const f = findingMap.get(c.findingId);
    lines.push(
      `## ${c.findingId}${f ? ` — ${f.category} @ ${f.endpoint}` : ''}`,
      '',
      `**Exploitable:** ${c.exploitable ? 'YES' : 'NO'}  `,
      `**Residual risk:** ${c.residualRisk}  `,
      `**Red/Blue agreement:** ${c.agreement ? 'yes' : 'no'}  `,
      `**Rounds:** ${c.rounds}`,
      '',
      '### Attack chain',
      c.attackChainSummary || '_(none)_',
      '',
      '### Mitigations',
    );
    if (c.mitigations.length === 0) {
      lines.push('_(none proposed)_');
    } else {
      for (const m of c.mitigations) {
        lines.push(`- **[${m.layer} | ${m.effort}]** ${m.control} — ${m.rationale}`);
      }
    }
    lines.push('', '### Detections');
    if (c.detections.length === 0) {
      lines.push('_(none proposed)_');
    } else {
      for (const d of c.detections) {
        lines.push(
          `- **${d.name}** (source: ${d.source}) — ${d.signal}`,
          d.query ? `  - Query: \`${d.query}\`` : '',
          `  - ${d.rationale}`,
        );
      }
    }
    lines.push(
      '',
      '### Final positions',
      '**Red:**',
      c.redFinalPosition,
      '',
      '**Blue:**',
      c.blueFinalPosition,
      '',
      '---',
      '',
    );
  }

  return lines.filter((l) => l !== undefined).join('\n');
}
