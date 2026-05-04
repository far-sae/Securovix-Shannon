import type Anthropic from '@anthropic-ai/sdk';
import type { LLMClientFactory } from '../llm/client.js';
import { PurpleProtocol } from './protocol.js';
import { RedStrategist } from './red-strategist.js';
import { RedAttacker } from './red-attacker.js';
import { BlueDefender } from './blue-defender.js';
import { BlueIR } from './blue-ir.js';
import type {
  DetectionProposal,
  FindingConclusion,
  MitigationProposal,
  PurpleFinding,
  PurpleTeamResult,
} from './types.js';

const DEFAULT_ROUNDS = 3;

export class PurpleTeamModerator {
  private llmFactory: LLMClientFactory;
  private maxRounds: number;

  constructor(llmFactory: LLMClientFactory, maxRounds?: number) {
    this.llmFactory = llmFactory;
    this.maxRounds = maxRounds ?? DEFAULT_ROUNDS;
  }

  async run(findings: PurpleFinding[]): Promise<PurpleTeamResult> {
    const protocol = new PurpleProtocol();

    const redStrategist = new RedStrategist(
      this.llmFactory.createClient(),
      this.llmFactory.resolveModelForAgent('purple-red-strategist'),
    );
    const redAttacker = new RedAttacker(
      this.llmFactory.createClient(),
      this.llmFactory.resolveModelForAgent('purple-red-attacker'),
    );
    const blueDefender = new BlueDefender(
      this.llmFactory.createClient(),
      this.llmFactory.resolveModelForAgent('purple-blue-defender'),
    );
    const blueIR = new BlueIR(
      this.llmFactory.createClient(),
      this.llmFactory.resolveModelForAgent('purple-blue-ir'),
    );

    const moderatorClient = this.llmFactory.createClient();
    const moderatorModel = this.llmFactory.resolveModelForAgent('purple-moderator');

    const conclusions: FindingConclusion[] = [];
    for (const finding of findings) {
      const conclusion = await this.processFinding(
        finding,
        protocol,
        redStrategist,
        redAttacker,
        blueDefender,
        blueIR,
        moderatorClient,
        moderatorModel,
      );
      conclusions.push(conclusion);
    }

    const agreementRate =
      conclusions.length === 0
        ? 0
        : conclusions.filter((c) => c.agreement).length / conclusions.length;

    return {
      conclusions,
      transcript: protocol.transcript(),
      totalRounds: protocol.currentRound(),
      agreementRate,
    };
  }

  private async processFinding(
    finding: PurpleFinding,
    protocol: PurpleProtocol,
    redStrategist: RedStrategist,
    redAttacker: RedAttacker,
    blueDefender: BlueDefender,
    blueIR: BlueIR,
    moderatorClient: Anthropic,
    moderatorModel: string,
  ): Promise<FindingConclusion> {
    let rounds = 0;
    let lastRedFinal = '';
    let lastBlueFinal = '';

    for (let round = 1; round <= this.maxRounds; round++) {
      rounds = round;

      // 1. Red internal huddle
      const lastAttackerNote = protocol
        .visibleTo('red-strategist', finding.id)
        .filter((m) => m.from === 'red-attacker')
        .at(-1)?.content ?? '';

      const stratPlan = await redStrategist.plan(
        finding,
        protocol.renderHistory('red-strategist', finding.id),
        lastAttackerNote,
      );
      protocol.send({
        channel: 'red-internal',
        team: 'red',
        from: 'red-strategist',
        to: 'red-attacker',
        type: 'plan',
        findingRef: finding.id,
        content: stratPlan,
      });

      const execution = await redAttacker.execute(
        finding,
        protocol.renderHistory('red-attacker', finding.id),
        stratPlan,
      );
      protocol.send({
        channel: 'red-internal',
        team: 'red',
        from: 'red-attacker',
        to: 'red-strategist',
        type: 'exploit-step',
        findingRef: finding.id,
        content: execution,
      });

      // 2. Blue internal huddle
      const lastIRNote = protocol
        .visibleTo('blue-defender', finding.id)
        .filter((m) => m.from === 'blue-ir')
        .at(-1)?.content ?? '';

      const mitigation = await blueDefender.propose(
        finding,
        protocol.renderHistory('blue-defender', finding.id),
        lastIRNote,
      );
      protocol.send({
        channel: 'blue-internal',
        team: 'blue',
        from: 'blue-defender',
        to: 'blue-ir',
        type: 'mitigation',
        findingRef: finding.id,
        content: mitigation,
      });

      const detection = await blueIR.propose(
        finding,
        protocol.renderHistory('blue-ir', finding.id),
        mitigation,
      );
      protocol.send({
        channel: 'blue-internal',
        team: 'blue',
        from: 'blue-ir',
        to: 'blue-defender',
        type: 'detection',
        findingRef: finding.id,
        content: detection,
      });

      // 3. Cross-team exchange. Red strategist <-> Blue defender, Red attacker <-> Blue IR.
      const stratXTalk = await redStrategist.crossTeamReply(
        finding,
        protocol.renderHistory('red-strategist', finding.id),
        mitigation,
      );
      protocol.send({
        channel: 'cross-team',
        team: 'cross',
        from: 'red-strategist',
        to: 'blue-team',
        type: 'rebuttal',
        findingRef: finding.id,
        content: stratXTalk,
      });

      const defenderXTalk = await blueDefender.crossTeamReply(
        finding,
        protocol.renderHistory('blue-defender', finding.id),
        stratXTalk,
      );
      protocol.send({
        channel: 'cross-team',
        team: 'cross',
        from: 'blue-defender',
        to: 'red-team',
        type: 'rebuttal',
        findingRef: finding.id,
        content: defenderXTalk,
      });

      const attackerXTalk = await redAttacker.crossTeamReply(
        finding,
        protocol.renderHistory('red-attacker', finding.id),
        detection,
      );
      protocol.send({
        channel: 'cross-team',
        team: 'cross',
        from: 'red-attacker',
        to: 'blue-team',
        type: 'rebuttal',
        findingRef: finding.id,
        content: attackerXTalk,
      });

      const irXTalk = await blueIR.crossTeamReply(
        finding,
        protocol.renderHistory('blue-ir', finding.id),
        attackerXTalk,
      );
      protocol.send({
        channel: 'cross-team',
        team: 'cross',
        from: 'blue-ir',
        to: 'red-team',
        type: 'rebuttal',
        findingRef: finding.id,
        content: irXTalk,
      });

      // Convergence: stop if both red messages contain CONCEDE
      if (stratXTalk.includes('CONCEDE') && attackerXTalk.includes('CONCEDE')) {
        break;
      }

      protocol.advanceRound();
    }

    // Final positions
    lastRedFinal = await redStrategist.finalPosition(
      finding,
      protocol.renderHistory('red-strategist', finding.id),
    );
    protocol.send({
      channel: 'cross-team',
      team: 'cross',
      from: 'red-strategist',
      to: 'all',
      type: 'final-position',
      findingRef: finding.id,
      content: lastRedFinal,
    });

    lastBlueFinal = await blueDefender.finalPosition(
      finding,
      protocol.renderHistory('blue-defender', finding.id),
    );
    protocol.send({
      channel: 'cross-team',
      team: 'cross',
      from: 'blue-defender',
      to: 'all',
      type: 'final-position',
      findingRef: finding.id,
      content: lastBlueFinal,
    });

    // Moderator synthesis
    const synthesis = await this.synthesize(
      finding,
      protocol.renderHistory('moderator', finding.id),
      moderatorClient,
      moderatorModel,
    );

    return {
      findingId: finding.id,
      exploitable: synthesis.exploitable,
      attackChainSummary: synthesis.attackChain,
      mitigations: synthesis.mitigations,
      detections: synthesis.detections,
      residualRisk: synthesis.residualRisk,
      redFinalPosition: lastRedFinal,
      blueFinalPosition: lastBlueFinal,
      agreement: synthesis.agreement,
      rounds,
    };
  }

  private async synthesize(
    finding: PurpleFinding,
    fullHistory: string,
    client: Anthropic,
    model: string,
  ): Promise<{
    exploitable: boolean;
    attackChain: string;
    mitigations: MitigationProposal[];
    detections: DetectionProposal[];
    residualRisk: 'low' | 'medium' | 'high' | 'critical';
    agreement: boolean;
  }> {
    const prompt = [
      'You are the PURPLE TEAM MODERATOR. Read the full red-vs-blue transcript for one finding and return a strict JSON conclusion.',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      '',
      `## Transcript\n${fullHistory}`,
      '',
      '## Output',
      'Return ONLY a JSON object with this exact shape:',
      '{',
      '  "exploitable": boolean,',
      '  "attackChain": string (one paragraph summarizing how the attack actually works),',
      '  "mitigations": [ { "control": string, "layer": "code"|"config"|"network"|"process"|"monitoring", "effort": "low"|"medium"|"high", "rationale": string } ],',
      '  "detections": [ { "name": string, "signal": string, "source": string, "query": string, "rationale": string } ],',
      '  "residualRisk": "low"|"medium"|"high"|"critical",',
      '  "agreement": boolean (true if red and blue final positions are compatible)',
      '}',
      'No prose, no markdown fences, no commentary outside the JSON.',
    ].join('\n');

    const response = await client.messages.create({
      model,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });

    const raw = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n')
      .trim();

    return parseSynthesis(raw);
  }
}

function parseSynthesis(raw: string): {
  exploitable: boolean;
  attackChain: string;
  mitigations: MitigationProposal[];
  detections: DetectionProposal[];
  residualRisk: 'low' | 'medium' | 'high' | 'critical';
  agreement: boolean;
} {
  const fallback = {
    exploitable: true,
    attackChain: 'Moderator output unparseable; see transcript.',
    mitigations: [] as MitigationProposal[],
    detections: [] as DetectionProposal[],
    residualRisk: 'medium' as const,
    agreement: false,
  };

  const jsonStart = raw.indexOf('{');
  const jsonEnd = raw.lastIndexOf('}');
  if (jsonStart === -1 || jsonEnd === -1 || jsonEnd <= jsonStart) return fallback;

  try {
    const parsed = JSON.parse(raw.slice(jsonStart, jsonEnd + 1)) as Record<string, unknown>;
    return {
      exploitable: Boolean(parsed.exploitable),
      attackChain: typeof parsed.attackChain === 'string' ? parsed.attackChain : '',
      mitigations: Array.isArray(parsed.mitigations)
        ? (parsed.mitigations as MitigationProposal[])
        : [],
      detections: Array.isArray(parsed.detections)
        ? (parsed.detections as DetectionProposal[])
        : [],
      residualRisk: normalizeRisk(parsed.residualRisk),
      agreement: Boolean(parsed.agreement),
    };
  } catch {
    return fallback;
  }
}

function normalizeRisk(value: unknown): 'low' | 'medium' | 'high' | 'critical' {
  if (value === 'low' || value === 'medium' || value === 'high' || value === 'critical') {
    return value;
  }
  return 'medium';
}
