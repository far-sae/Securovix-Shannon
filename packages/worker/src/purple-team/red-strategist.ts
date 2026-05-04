import type Anthropic from '@anthropic-ai/sdk';
import type { PurpleFinding } from './types.js';

export class RedStrategist {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async plan(finding: PurpleFinding, history: string, peerNote: string): Promise<string> {
    const prompt = [
      'You are the RED TEAM STRATEGIST. You partner with the Red Attacker to plan how to exploit a finding.',
      '',
      '## Your Job',
      '- Decide attack objectives and the order of operations',
      '- Identify which findings to chain together for maximum impact',
      '- Brief the Red Attacker on what to actually try, in plain operator terms',
      '- When the Blue team proposes defenses, find ways around them or concede when they hold',
      '',
      '## Style',
      '- Talk to your teammate (Red Attacker) like a partner, not a report.',
      '- When addressing the Blue team in cross-team rounds, be precise and adversarial but professional.',
      '- Cite the finding and any prior round outputs explicitly.',
      '',
      '## Finding',
      `ID: ${finding.id}`,
      `Category: ${finding.category}`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      finding.exploitPoc ? `POC: ${finding.exploitPoc}` : '',
      '',
      history ? `## Prior discussion you can see\n${history}` : '',
      peerNote ? `## Note from your teammate (Red Attacker)\n${peerNote}` : '',
      '',
      '## Output',
      'Produce 4 short sections:',
      '1. OBJECTIVE — what success looks like for this finding',
      '2. PLAN — ordered steps the Red Attacker should run',
      '3. CHAINING — other findings to combine, if any',
      '4. ASK FOR ATTACKER — concrete questions or refinements you need from them',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async crossTeamReply(
    finding: PurpleFinding,
    history: string,
    blueProposal: string,
  ): Promise<string> {
    const prompt = [
      'You are the RED TEAM STRATEGIST speaking to the Blue Team.',
      'They have proposed mitigations and detections. Your job is to honestly assess whether they break your attack.',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Description: ${finding.description}`,
      '',
      `## Blue team proposal\n${blueProposal}`,
      '',
      history ? `## Prior cross-team discussion\n${history}` : '',
      '',
      '## Output',
      'Respond in 3 sections:',
      '1. WHAT THE DEFENSE BREAKS — be specific about which steps stop working',
      '2. BYPASS IDEAS — concrete ways your Attacker could route around it',
      '3. CONCESSION — if a control truly closes the issue, say "CONCEDE: <which control>". Otherwise omit.',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async finalPosition(finding: PurpleFinding, history: string): Promise<string> {
    const prompt = [
      'You are the RED TEAM STRATEGIST giving your final position before the moderator concludes the case.',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      '',
      history ? `## Full visible discussion\n${history}` : '',
      '',
      '## Output (concise)',
      '1. EXPLOITABLE: yes/no, with one-line reason',
      '2. RESIDUAL RISK after blue proposals: critical/high/medium/low',
      '3. WHAT BLUE GOT RIGHT',
      '4. WHAT BLUE STILL MISSES',
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
