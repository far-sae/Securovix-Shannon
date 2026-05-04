import type { LLMClientFactory } from '../llm/client.js';
import type { FindingInput, FindingVerdict, WarRoomResult, MitreMapping } from './types.js';
import { DebateProtocol } from './protocol.js';
import { RedTeamLead } from './red-team-lead.js';
import { AdversarySimAgent } from './adversary-sim.js';
import { SkepticAgent } from './skeptic.js';

const MAX_ROUNDS_PER_FINDING = 5;

export class WarRoomModerator {
  private llmFactory: LLMClientFactory;
  private maxRoundsPerFinding: number;

  constructor(llmFactory: LLMClientFactory, maxRoundsPerFinding?: number) {
    this.llmFactory = llmFactory;
    this.maxRoundsPerFinding = maxRoundsPerFinding ?? MAX_ROUNDS_PER_FINDING;
  }

  async conductReview(findings: FindingInput[]): Promise<WarRoomResult> {
    const protocol = new DebateProtocol();
    const verdicts: FindingVerdict[] = [];

    const leadClient = this.llmFactory.createClient();
    const adversaryClient = this.llmFactory.createClient();
    const skepticClient = this.llmFactory.createClient();

    const lead = new RedTeamLead(leadClient, this.llmFactory.resolveModelForAgent('war-room-lead'));
    const adversary = new AdversarySimAgent(adversaryClient, this.llmFactory.resolveModelForAgent('war-room-adversary'));
    const skeptic = new SkepticAgent(skepticClient, this.llmFactory.resolveModelForAgent('war-room-skeptic'));

    for (const finding of findings) {
      const verdict = await this.debateFinding(finding, lead, adversary, skeptic, protocol);
      verdicts.push(verdict);
    }

    const eliminatedCount = verdicts.filter((v) => v.confirmedFalsePositive).length;
    const escalatedCount = verdicts.filter(
      (v) => !v.confirmedFalsePositive && this.severityRank(v.adjustedSeverity) > this.severityRank(v.originalSeverity),
    ).length;

    return {
      findings: verdicts,
      eliminatedCount,
      escalatedCount,
      totalDebateRounds: protocol.getCurrentRound(),
      transcript: protocol.getTranscript(),
    };
  }

  private async debateFinding(
    finding: FindingInput,
    lead: RedTeamLead,
    adversary: AdversarySimAgent,
    skeptic: SkepticAgent,
    protocol: DebateProtocol,
  ): Promise<FindingVerdict> {
    let mitreMappings: MitreMapping[] = [];
    let lastSkepticResponse = '';
    let consensusReached = false;
    let debateRounds = 0;

    for (let round = 1; round <= this.maxRoundsPerFinding; round++) {
      debateRounds = round;
      const history = protocol.buildContextForAgent('moderator', finding.id);

      // Round step 1: Red Team Lead assesses
      const leadAssessment = await lead.assess(finding, history);
      protocol.createMessage('red-team-lead', 'all', 'assertion', finding.id, leadAssessment);

      // Round step 2: Adversary Sim maps to MITRE ATT&CK
      const adversaryResult = await adversary.analyze(finding, protocol.buildContextForAgent('adversary-sim', finding.id));
      protocol.createMessage('adversary-sim', 'all', 'evidence', finding.id, adversaryResult.assessment, {
        mitreMappings: adversaryResult.mappings,
      });
      mitreMappings = adversaryResult.mappings;

      // Round step 3: Skeptic challenges
      const skepticChallenge = await skeptic.challenge(
        finding,
        protocol.buildContextForAgent('skeptic', finding.id),
      );
      lastSkepticResponse = skepticChallenge;

      const challengeType = skepticChallenge.includes('CONCEDE') ? 'concession' : 'challenge';
      protocol.createMessage('skeptic', 'all', challengeType, finding.id, skepticChallenge);

      // Check for consensus
      if (this.assessConsensus(skepticChallenge)) {
        consensusReached = true;
        break;
      }

      protocol.advanceRound();
    }

    // Determine verdict
    const isFalsePositive = this.isFalsePositive(lastSkepticResponse, debateRounds);
    const adjustedSeverity = this.adjustSeverity(finding.severity, lastSkepticResponse, consensusReached);

    return {
      findingId: finding.id,
      originalSeverity: finding.severity,
      adjustedSeverity,
      confirmedFalsePositive: isFalsePositive,
      mitreMappings,
      debateRounds,
      consensusReached,
      redTeamNotes: protocol.getLastMessageFrom('red-team-lead', finding.id)?.content ?? '',
      skepticChallenges: protocol
        .getMessagesForFinding(finding.id)
        .filter((m) => m.from === 'skeptic')
        .map((m) => m.content),
      finalAssessment: consensusReached
        ? 'Finding confirmed through adversarial review'
        : `Finding debated for ${debateRounds} rounds without full consensus`,
    };
  }

  private assessConsensus(skepticResponse: string): boolean {
    return skepticResponse.includes('CONCEDE');
  }

  private isFalsePositive(skepticResponse: string, rounds: number): boolean {
    // If skeptic never conceded after max rounds, and keeps challenging, likely false positive
    if (rounds >= this.maxRoundsPerFinding && !skepticResponse.includes('CONCEDE')) {
      // Check for strong challenge language
      if (skepticResponse.includes('false positive') || skepticResponse.includes('not exploitable')) {
        return true;
      }
    }
    return false;
  }

  private adjustSeverity(original: string, skepticResponse: string, consensusReached: boolean): string {
    if (!consensusReached) return original;

    // Check if skeptic suggested severity adjustment
    const severities = ['critical', 'high', 'medium', 'low'];
    for (const sev of severities) {
      if (skepticResponse.toLowerCase().includes(`severity.*${sev}`) || skepticResponse.toLowerCase().includes(`should be ${sev}`)) {
        return sev;
      }
    }

    return original;
  }

  private severityRank(severity: string): number {
    const ranks: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    return ranks[severity] ?? 0;
  }
}
