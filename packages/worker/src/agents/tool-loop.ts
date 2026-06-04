// Minimal Anthropic-Messages-shaped types so the loop is testable without the SDK.
// The real @anthropic-ai/sdk client is structurally compatible with LlmClient.
export interface TextBlock {
  type: 'text';
  text: string;
}
export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: unknown;
}
export type ContentBlock = TextBlock | ToolUseBlock;

export interface LlmResponse {
  content: ContentBlock[];
  stop_reason: string | null;
}

export interface LlmCreateParams {
  model: string;
  max_tokens: number;
  system?: string;
  tools?: unknown[];
  messages: Array<{ role: 'user' | 'assistant'; content: unknown }>;
}

export interface LlmClient {
  messages: { create(params: LlmCreateParams): Promise<LlmResponse> };
}

export interface ToolLoopOptions {
  client: LlmClient;
  model: string;
  system: string;
  tools: unknown[]; // Anthropic tool definitions exposed to the model
  // Dispatches one tool_use to its implementation (the real wiring routes this to the
  // broker ToolClient) and returns the tool_result content string.
  dispatch: (name: string, input: unknown, id: string) => Promise<string>;
  maxTurns: number; // hard cap — a runaway agent throws rather than looping forever
  onTurn?: (turn: number, response: LlmResponse) => void; // e.g. per-turn forensic snapshot
}

export interface ToolLoopResult {
  finalText: string;
  turns: number;
  toolCalls: number;
}

// ReAct tool-use loop: call the model with tools, dispatch any tool_use blocks, feed
// the tool_results back, and repeat until the model stops requesting tools — or the
// hard turn cap trips (defense-in-depth on top of the broker's BudgetLedger).
export async function executeAgentWithTools(userMessage: string, opts: ToolLoopOptions): Promise<ToolLoopResult> {
  const messages: Array<{ role: 'user' | 'assistant'; content: unknown }> = [{ role: 'user', content: userMessage }];
  let toolCalls = 0;

  for (let turn = 1; turn <= opts.maxTurns; turn++) {
    const response = await opts.client.messages.create({
      model: opts.model,
      max_tokens: 4096,
      system: opts.system,
      tools: opts.tools,
      messages,
    });
    opts.onTurn?.(turn, response);
    messages.push({ role: 'assistant', content: response.content });

    const toolUses = response.content.filter((b): b is ToolUseBlock => b.type === 'tool_use');
    if (response.stop_reason !== 'tool_use' || toolUses.length === 0) {
      const finalText = response.content
        .filter((b): b is TextBlock => b.type === 'text')
        .map((b) => b.text)
        .join('\n');
      return { finalText, turns: turn, toolCalls };
    }

    const toolResults = [];
    for (const tu of toolUses) {
      toolCalls++;
      const content = await opts.dispatch(tu.name, tu.input, tu.id);
      toolResults.push({ type: 'tool_result', tool_use_id: tu.id, content });
    }
    messages.push({ role: 'user', content: toolResults });
  }

  throw new Error(`executeAgentWithTools: exceeded maxTurns=${opts.maxTurns} (possible runaway agent)`);
}
