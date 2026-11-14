// Claude calls for the security assistant and research reports. The organization's own Anthropic
// key is used (BYO), so every call is billed to the org that asked. The client factory is
// injectable so tests never reach the network.
import Anthropic from '@anthropic-ai/sdk';

export const DEFAULT_ASSISTANT_MODEL = 'claude-opus-5-5';

let clientFactory = (apiKey) => new Anthropic({ apiKey, timeout: 10 * 60 * 1000, maxRetries: 2 });
export function setAssistantClientFactory(factory) {
  clientFactory = factory;
}

export function assistantModel(env = process.env) {
  return String(env.SHANNON_ASSISTANT_MODEL || DEFAULT_ASSISTANT_MODEL).trim();
}

// Adaptive thinking + effort exist on Claude 4.6+ and the 5.x family.
const MODERN = /^claude-(?:(?:opus|sonnet)-4-[6-9]|(?:opus|sonnet|haiku|fable|mythos)-5(?:-\d+)?)$/;
// Server-side refusal fallbacks ("default" routing).
const FALLBACK = new Set(['claude-opus-5-5', 'claude-opus-5', 'claude-fable-5-1', 'claude-sonnet-5-5']);

function requestFor(model, effort, base) {
  const params = { model, ...base };
  if (MODERN.test(model)) {
    params.thinking = { type: 'adaptive' };
    params.output_config = { effort };
  }
  if (FALLBACK.has(model)) {
    params.betas = ['server-side-fallback-2026-07-01'];
    params.fallbacks = 'default';
  }
  return params;
}

function interpret(response) {
  const text = (response.content || [])
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join('\n')
    .trim();
  const servedByFallback = (response.usage?.iterations || []).some((entry) => entry.type === 'fallback_message');
  if (response.stop_reason === 'refusal') {
    return {
      ok: false,
      refusal: true,
      category: response.stop_details?.category || null,
      text: '',
      model: response.model,
      servedByFallback,
    };
  }
  return {
    ok: true,
    text,
    model: response.model,
    stopReason: response.stop_reason,
    truncated: response.stop_reason === 'max_tokens',
    servedByFallback,
    usage: { input: response.usage?.input_tokens ?? null, output: response.usage?.output_tokens ?? null },
  };
}

// Maps SDK errors to an HTTP status + message the dashboard can show.
export function describeAiError(error) {
  if (error instanceof Anthropic.AuthenticationError)
    return { status: 400, message: "Your organization's Anthropic key was rejected. Update it in Settings." };
  if (error instanceof Anthropic.PermissionDeniedError)
    return { status: 400, message: 'This Anthropic key cannot use the configured model.' };
  if (error instanceof Anthropic.NotFoundError)
    return { status: 400, message: 'The configured assistant model was not found for this key.' };
  if (error instanceof Anthropic.RateLimitError)
    return { status: 429, message: 'The AI provider is rate limiting this key. Try again shortly.' };
  if (error instanceof Anthropic.BadRequestError)
    return { status: 400, message: `The AI provider rejected the request: ${error.message}` };
  if (error instanceof Anthropic.APIConnectionError)
    return { status: 502, message: 'Could not reach the AI provider.' };
  if (error instanceof Anthropic.APIError)
    return { status: 502, message: `AI provider error (${error.status ?? 'unknown'}).` };
  return { status: 500, message: error?.message || 'Assistant failed.' };
}

export async function runChat({ apiKey, system, messages, model = assistantModel() }) {
  const client = clientFactory(apiKey);
  const params = requestFor(model, 'medium', { max_tokens: 16000, system, messages });
  const response = params.betas ? await client.beta.messages.create(params) : await client.messages.create(params);
  return interpret(response);
}

// Long output: stream and collect the final message so the HTTP request never times out.
export async function runResearch({ apiKey, system, prompt, model = assistantModel() }) {
  const client = clientFactory(apiKey);
  const params = requestFor(model, 'high', {
    max_tokens: 64000,
    system,
    messages: [{ role: 'user', content: prompt }],
  });
  const stream = params.betas ? client.beta.messages.stream(params) : client.messages.stream(params);
  return interpret(await stream.finalMessage());
}
