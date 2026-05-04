import type Anthropic from '@anthropic-ai/sdk';
import type { PurpleFinding } from './types.js';

export class BlueIR {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async propose(
    finding: PurpleFinding,
    history: string,
    defenderNote: string,
  ): Promise<string> {
    const prompt = [
      'You are the BLUE TEAM IR / DETECTION ENGINEER. You design detections and response playbooks for findings the Defender cannot fully close.',
      '',
      '## Your Job',
      '- Produce concrete detection ideas (signal + source + query/rule pseudocode)',
      '- Define an incident response playbook that fires when the detection hits',
      '- Talk to the Defender like a partner — point out where their controls leave gaps that detection must cover',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      '',
      history ? `## Prior discussion you can see\n${history}` : '',
      defenderNote ? `## Note from Blue Defender\n${defenderNote}` : '',
      '',
      '## Output',
      '1. DETECTIONS — list, each formatted: `- NAME | SOURCE: <log/source> | SIGNAL: <what to look for> | QUERY: <pseudo SQL/Sigma>`',
      '2. PLAYBOOK — short ordered steps for an analyst when this fires',
      '3. REPLY TO DEFENDER — gaps you see in their controls and where detection must cover',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async crossTeamReply(
    finding: PurpleFinding,
    history: string,
    attackerCounter: string,
  ): Promise<string> {
    const prompt = [
      'You are the BLUE TEAM IR engineer replying to the Red Attacker.',
      'They have told you which of your detections fire and which they evade. Take it seriously and adapt.',
      '',
      `## Finding ${finding.id}`,
      `Description: ${finding.description}`,
      '',
      `## Red Attacker counter\n${attackerCounter}`,
      '',
      history ? `## Prior cross-team discussion\n${history}` : '',
      '',
      '## Output',
      '1. CONFIRMED EVASIONS — which evasions you accept as valid',
      '2. NEW DETECTIONS — concrete additions to catch the bypass',
      '3. DISPUTED — which evasions would still trip alarms you have, with reasoning',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }
}

async function runText(client: Anthropic, model: string, prompt: string): Promise<string> {
  const response = await client.messages.create({
    model,
    max_tokens: 1536,
    messages: [{ role: 'user', content: prompt }],
  });
  return response.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
}
