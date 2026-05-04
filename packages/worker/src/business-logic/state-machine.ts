import type Anthropic from '@anthropic-ai/sdk';
import type { DomainEntity, WorkflowState, StateMachine, WorkflowTransition } from './types.js';
import { type Result, ok, err } from '../result.js';

export class StateMachineBuilder {
  async inferStateMachines(
    entities: DomainEntity[],
    routes: WorkflowState[],
    client: Anthropic,
    model: string,
  ): Promise<Result<StateMachine[]>> {
    try {
      const prompt = this.buildInferencePrompt(entities, routes);

      const response = await client.messages.create({
        model,
        max_tokens: 8192,
        messages: [{ role: 'user', content: prompt }],
      });

      const text = response.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');

      const machines = this.parseStateMachines(text);
      return ok(machines);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private buildInferencePrompt(entities: DomainEntity[], routes: WorkflowState[]): string {
    return [
      'Analyze the following application structure and identify business workflow state machines.',
      '',
      '## Domain Entities',
      ...entities.map((e) => `- ${e.name}: ${e.fields.map((f) => f.name).join(', ')}`),
      '',
      '## API Routes',
      ...routes.map((r) => `- ${r.name} (${r.endpoint}) [preconditions: ${r.expectedPreconditions.join(', ') || 'none'}]`),
      '',
      '## Instructions',
      'Identify all business workflows (e.g., checkout flow, registration, password reset, order processing).',
      'For each workflow, specify:',
      '1. States (with corresponding API endpoints)',
      '2. Transitions (what triggers moving from one state to another)',
      '3. Guards (server-side validations that should prevent invalid transitions)',
      '4. Side effects (what happens during each transition)',
      '',
      'Output as JSON array of state machines:',
      '```json',
      '[{',
      '  "name": "Checkout Flow",',
      '  "states": [{"id": "cart", "name": "Shopping Cart", "endpoint": "/api/cart"}],',
      '  "transitions": [{"from": "cart", "to": "checkout", "trigger": "POST /api/checkout", "guards": ["cart not empty", "valid items"], "sideEffects": ["calculate totals"]}],',
      '  "initialState": "cart",',
      '  "terminalStates": ["order-confirmed"]',
      '}]',
      '```',
    ].join('\n');
  }

  private parseStateMachines(text: string): StateMachine[] {
    // Extract JSON blocks from LLM response
    const jsonMatch = text.match(/```json\s*([\s\S]*?)```/);
    if (!jsonMatch) {
      // Try parsing the entire response as JSON
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        return [];
      }
      return [];
    }

    try {
      const parsed = JSON.parse(jsonMatch[1]);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      return [];
    }
  }
}
