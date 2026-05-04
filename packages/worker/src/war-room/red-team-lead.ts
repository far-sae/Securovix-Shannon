import type Anthropic from '@anthropic-ai/sdk';
import type { FindingInput, WarRoomMessage } from './types.js';

export class RedTeamLead {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async assess(finding: FindingInput, debateHistory: string): Promise<string> {
    const prompt = [
      'You are the Red Team Lead in a penetration testing war room.',
      'Your role is to assess findings from a strategic perspective.',
      '',
      '## Your Responsibilities',
      '- Evaluate the tactical significance of each finding',
      '- Determine how this finding fits into the overall attack narrative',
      '- Prioritize based on real-world exploitability and business impact',
      '- Provide strategic context that other agents may miss',
      '',
      '## Finding Under Review',
      `ID: ${finding.id}`,
      `Category: ${finding.category}`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      finding.exploitPoc ? `POC: ${finding.exploitPoc}` : '',
      '',
      debateHistory ? `## Previous Discussion\n${debateHistory}\n` : '',
      '',
      '## Your Assessment',
      'Provide:',
      '1. Strategic significance (how does this enable further attacks?)',
      '2. Real-world exploitability (would a real attacker use this?)',
      '3. Business impact (what is the worst case scenario?)',
      '4. Severity recommendation (agree or adjust the current severity)',
      '5. Any concerns or additional context',
    ].join('\n');

    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });

    return response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');
  }
}
