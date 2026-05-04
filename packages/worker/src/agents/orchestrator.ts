import type { LLMClientFactory } from '../llm/client.js';

export class AgentOrchestrator {
  constructor(private llmFactory: LLMClientFactory) {}

  async executeAgent(agentName: string, prompt: string): Promise<string> {
    const model = this.llmFactory.resolveModelForAgent(agentName);
    const client = this.llmFactory.createClient();

    const response = await client.messages.create({
      model,
      max_tokens: 8192,
      messages: [{ role: 'user', content: prompt }],
    });

    return response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');
  }
}
