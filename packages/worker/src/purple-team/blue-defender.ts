import type Anthropic from '@anthropic-ai/sdk';
import type { PurpleFinding } from './types.js';

export class BlueDefender {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async propose(
    finding: PurpleFinding,
    history: string,
    irNote: string,
  ): Promise<string> {
    const prompt = [
      'You are the BLUE TEAM DEFENDER (security engineer). You design controls that make the finding non-exploitable.',
      '',
      '## Your Job',
      '- Propose specific mitigations across code, config, network, and process',
      '- Coordinate with Blue IR so detections cover the gaps your controls do not close',
      '- Be honest about cost, and label controls that fail-open vs fail-closed',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      '',
      history ? `## Prior discussion you can see\n${history}` : '',
      irNote ? `## Note from Blue IR\n${irNote}` : '',
      '',
      '## Output',
      'Produce a structured proposal:',
      '1. ROOT CAUSE — one paragraph',
      '2. MITIGATIONS — list, each in the form: `- LAYER (code|config|network|process|monitoring) | EFFORT (low|medium|high) | CONTROL: <what> | WHY: <reason>`',
      '3. RESIDUAL RISK after these controls',
      '4. ASK FOR IR — what you need them to monitor',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async crossTeamReply(
    finding: PurpleFinding,
    history: string,
    redCounter: string,
  ): Promise<string> {
    const prompt = [
      'You are the BLUE TEAM DEFENDER replying to the Red Strategist.',
      'They claim your controls can be bypassed. Engage seriously: agree where they are right, push back where they are wrong.',
      '',
      `## Finding ${finding.id}`,
      `Description: ${finding.description}`,
      '',
      `## Red Strategist counter\n${redCounter}`,
      '',
      history ? `## Prior cross-team discussion\n${history}` : '',
      '',
      '## Output',
      '1. ACKNOWLEDGED BYPASSES — which red claims are valid',
      '2. ADDITIONAL CONTROLS — concrete additions to close those',
      '3. DISPUTED — which red claims do not actually bypass your controls, with reasoning',
    ].join('\n');

    return runText(this.client, this.model, prompt);
  }

  async finalPosition(finding: PurpleFinding, history: string): Promise<string> {
    const prompt = [
      'You are the BLUE TEAM DEFENDER giving your final position.',
      '',
      `## Finding ${finding.id} (${finding.category})`,
      `Description: ${finding.description}`,
      '',
      history ? `## Full visible discussion\n${history}` : '',
      '',
      '## Output (concise)',
      '1. FINAL MITIGATIONS — bulleted, each with LAYER and EFFORT',
      '2. RESIDUAL RISK after final controls: critical/high/medium/low',
      '3. AGREEMENT WITH RED: yes/no with one-line reason',
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
