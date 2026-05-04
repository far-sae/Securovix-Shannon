import Anthropic from '@anthropic-ai/sdk';
import { resolveProvider, type LLMProvider } from './provider.js';
import { resolveModel, type ModelTier, AGENT_TIERS } from './tiers.js';
import { unwrap } from '../result.js';
import type { ModelOverrides } from '../config/schema.js';

const MAX_TURNS = 10_000;

export class LLMClientFactory {
  private provider: LLMProvider;
  private modelOverrides?: ModelOverrides;

  constructor(overrides?: ModelOverrides) {
    this.provider = unwrap(resolveProvider());
    this.modelOverrides = overrides;
  }

  createClient(): Anthropic {
    switch (this.provider.type) {
      case 'anthropic':
        return new Anthropic({ apiKey: this.provider.apiKey });
      case 'bedrock':
        return new Anthropic({
          apiKey: '',
          baseURL: `https://bedrock-runtime.${this.provider.region}.amazonaws.com`,
        });
      case 'vertex':
        return new Anthropic({
          apiKey: '',
          baseURL: `https://${this.provider.region}-aiplatform.googleapis.com`,
        });
      case 'proxy':
        return new Anthropic({
          apiKey: this.provider.apiKey ?? '',
          baseURL: this.provider.baseUrl,
        });
    }
  }

  resolveModelForAgent(agentName: string): string {
    const tier = AGENT_TIERS[agentName] ?? 'medium';
    return resolveModel(tier, this.modelOverrides as Partial<Record<ModelTier, string>>);
  }

  getMaxTurns(): number {
    return MAX_TURNS;
  }
}
