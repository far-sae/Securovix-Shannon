import { type Result, ok, err } from '../result.js';

export type ProviderType = 'anthropic' | 'bedrock' | 'vertex' | 'proxy';

export interface AnthropicProvider {
  type: 'anthropic';
  apiKey: string;
}

export interface BedrockProvider {
  type: 'bedrock';
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
}

export interface VertexProvider {
  type: 'vertex';
  projectId: string;
  region: string;
}

export interface ProxyProvider {
  type: 'proxy';
  baseUrl: string;
  apiKey?: string;
}

export type LLMProvider = AnthropicProvider | BedrockProvider | VertexProvider | ProxyProvider;

export function resolveProvider(): Result<LLMProvider> {
  const providers: LLMProvider[] = [];

  if (process.env.ANTHROPIC_API_KEY) {
    providers.push({ type: 'anthropic', apiKey: process.env.ANTHROPIC_API_KEY });
  }

  if (process.env.AWS_BEDROCK_REGION) {
    providers.push({
      type: 'bedrock',
      region: process.env.AWS_BEDROCK_REGION,
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    });
  }

  if (process.env.VERTEX_PROJECT_ID) {
    providers.push({
      type: 'vertex',
      projectId: process.env.VERTEX_PROJECT_ID,
      region: process.env.VERTEX_REGION ?? 'us-central1',
    });
  }

  if (process.env.SHANNON_LLM_BASE_URL) {
    providers.push({
      type: 'proxy',
      baseUrl: process.env.SHANNON_LLM_BASE_URL,
      apiKey: process.env.SHANNON_LLM_API_KEY,
    });
  }

  if (providers.length === 0) {
    return err(new Error('No LLM provider configured. Set ANTHROPIC_API_KEY, AWS_BEDROCK_REGION, VERTEX_PROJECT_ID, or SHANNON_LLM_BASE_URL.'));
  }

  if (providers.length > 1) {
    return err(new Error(`Exactly one LLM provider must be configured. Found: ${providers.map((p) => p.type).join(', ')}`));
  }

  return ok(providers[0]);
}
