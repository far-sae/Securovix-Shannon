import type Anthropic from '@anthropic-ai/sdk';
import type { StateMachine, LogicFlaw } from './types.js';
import { type Result, ok, err } from '../result.js';

export class LogicAnalyzer {
  async analyzeStateMachine(
    machine: StateMachine,
    client: Anthropic,
    model: string,
    targetUrl: string,
  ): Promise<Result<LogicFlaw[]>> {
    try {
      const prompt = this.buildAnalysisPrompt(machine, targetUrl);

      const response = await client.messages.create({
        model,
        max_tokens: 8192,
        messages: [{ role: 'user', content: prompt }],
      });

      const text = response.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');

      const flaws = this.parseFlaws(text, machine.name);
      return ok(flaws);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private buildAnalysisPrompt(machine: StateMachine, targetUrl: string): string {
    return [
      `You are a business logic vulnerability specialist analyzing the "${machine.name}" workflow.`,
      `Target: ${targetUrl}`,
      '',
      '## State Machine',
      `Initial State: ${machine.initialState}`,
      `Terminal States: ${machine.terminalStates.join(', ')}`,
      '',
      '### States',
      ...machine.states.map((s) => `- **${s.id}** (${s.name}): ${s.endpoint} [role: ${s.requiredRole ?? 'any'}]`),
      '',
      '### Transitions',
      ...machine.transitions.map(
        (t) =>
          `- ${t.from} -> ${t.to}: ${t.trigger}\n  Guards: ${t.guards.join(', ') || 'none'}\n  Side Effects: ${t.sideEffects.join(', ') || 'none'}`,
      ),
      '',
      '## Analysis Tasks',
      'Find business logic vulnerabilities in this workflow:',
      '',
      '1. **State Skip**: Can any state be bypassed by directly calling a later endpoint?',
      '2. **Price Manipulation**: Are monetary values validated server-side or only client-side?',
      '3. **Race Condition**: Can parallel requests exploit TOCTOU gaps in transitions?',
      '4. **Token Reuse**: Are one-time tokens (reset, verify) actually invalidated after use?',
      '5. **Privilege Escalation**: Can role parameters be tampered to gain higher access?',
      '6. **Workflow Bypass**: Can the terminal state be reached without completing required steps?',
      '7. **Parameter Tampering**: Can IDs, quantities, or amounts be modified in requests?',
      '',
      'For each flaw found, provide:',
      '```json',
      '{',
      '  "id": "flaw-1",',
      '  "type": "state-skip",',
      '  "workflow": "Checkout Flow",',
      '  "description": "User can skip payment by directly POSTing to /api/confirm-order",',
      '  "affectedTransition": {"from": "payment", "to": "confirmed", "trigger": "POST /api/confirm-order", "guards": [], "sideEffects": []},',
      '  "attackVector": "curl -X POST target/api/confirm-order -d \'{\\"orderId\\": \\"123\\"}\'",',
      '  "severity": "critical",',
      '  "businessImpact": "Attacker receives goods without paying"',
      '}',
      '```',
    ].join('\n');
  }

  private parseFlaws(text: string, workflowName: string): LogicFlaw[] {
    const flaws: LogicFlaw[] = [];
    const jsonBlocks = text.match(/```json\s*([\s\S]*?)```/g);

    if (!jsonBlocks) return flaws;

    for (const block of jsonBlocks) {
      try {
        const json = block.replace(/```json\s*/, '').replace(/```/, '');
        const parsed = JSON.parse(json);
        if (Array.isArray(parsed)) {
          flaws.push(...parsed);
        } else if (parsed.id) {
          flaws.push(parsed);
        }
      } catch {
        // Skip unparseable blocks
      }
    }

    return flaws;
  }
}
