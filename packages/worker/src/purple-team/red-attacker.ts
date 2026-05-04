import type Anthropic from '@anthropic-ai/sdk';
import type { PurpleFinding } from './types.js';

export class RedAttacker {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async execute(
    finding: PurpleFinding,
    history: string,
    strategistPlan: string,
  ): Promise<string> {
    const prompt = [
      'You are the RED TEAM ATTACKER (operator). You take the strategist plan and translate it into concrete exploit steps.',
      '',
      '## Your Job',
      '- Refine the plan into payloads, requests, and a real attack chain',
      '- Surface obstacles only the operator would notice (rate limits, WAF, encoding gotchas)',
      '- Push back on the strategist when their plan is unrealistic on the wire',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      finding.exploitPoc ? `POC: ${finding.exploitPoc}` : '',
      '',
      `## Strategist plan\n${strategistPlan}`,
      '',
      history ? `## Prior discussion you can see\n${history}` : '',
      '',
      '## Output',
      '1. EXECUTION — concrete steps with payloads / requests',
      '2. OBSERVED OBSTACLES — what the network/app actually does back',
      '3. REPLY TO STRATEGIST — what you need them to adjust',
      '4. PROOF OF IMPACT — what evidence proves this works',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async crossTeamReply(
    finding: PurpleFinding,
    history: string,
    blueDetection: string,
  ): Promise<string> {
    const prompt = [
      'You are the RED TEAM ATTACKER speaking directly to the Blue IR analyst.',
      'They have proposed detections. Tell them honestly which would have caught your steps and which would not.',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Description: ${finding.description}`,
      '',
      `## Blue IR detection proposal\n${blueDetection}`,
      '',
      history ? `## Prior cross-team discussion\n${history}` : '',
      '',
      '## Output',
      '1. CAUGHT — which detections would fire on your real steps',
      '2. MISSED — which steps slip through, and how',
      '3. EVASION — small tweaks that defeat the proposed detection',
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
