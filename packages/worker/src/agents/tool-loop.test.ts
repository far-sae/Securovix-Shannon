import { describe, expect, it, vi } from 'vitest';
import { type LlmClient, type LlmResponse, executeAgentWithTools } from './tool-loop.js';

// A fake client that returns a scripted sequence of responses, one per turn.
function scriptedClient(responses: LlmResponse[]): { client: LlmClient; calls: () => number } {
  let i = 0;
  return {
    client: {
      messages: {
        create: async () => {
          const r = responses[i] ?? responses[responses.length - 1];
          i++;
          return r;
        },
      },
    },
    calls: () => i,
  };
}

const baseOpts = {
  model: 'test-model',
  system: 'you are a tester',
  tools: [{ name: 'probe' }],
  maxTurns: 5,
};

describe('executeAgentWithTools', () => {
  it('returns immediately when the model ends without tool use', async () => {
    const { client } = scriptedClient([{ content: [{ type: 'text', text: 'all done' }], stop_reason: 'end_turn' }]);
    const dispatch = vi.fn();
    const res = await executeAgentWithTools('go', { ...baseOpts, client, dispatch });
    expect(res.finalText).toBe('all done');
    expect(res.turns).toBe(1);
    expect(res.toolCalls).toBe(0);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('dispatches a tool_use then completes on the next turn', async () => {
    const { client } = scriptedClient([
      { content: [{ type: 'tool_use', id: 't1', name: 'probe', input: { url: 'x' } }], stop_reason: 'tool_use' },
      { content: [{ type: 'text', text: 'found it' }], stop_reason: 'end_turn' },
    ]);
    const dispatch = vi.fn(async () => 'tool output');
    const res = await executeAgentWithTools('go', { ...baseOpts, client, dispatch });
    expect(dispatch).toHaveBeenCalledWith('probe', { url: 'x' }, 't1');
    expect(res.finalText).toBe('found it');
    expect(res.turns).toBe(2);
    expect(res.toolCalls).toBe(1);
  });

  it('throws when the model keeps requesting tools past maxTurns (runaway guard)', async () => {
    const { client } = scriptedClient([
      { content: [{ type: 'tool_use', id: 't', name: 'probe', input: {} }], stop_reason: 'tool_use' },
    ]);
    const dispatch = vi.fn(async () => 'again');
    await expect(executeAgentWithTools('go', { ...baseOpts, client, dispatch, maxTurns: 3 })).rejects.toThrow(
      /maxTurns=3/,
    );
    expect(dispatch).toHaveBeenCalledTimes(3);
  });

  it('invokes onTurn for every turn', async () => {
    const { client } = scriptedClient([
      { content: [{ type: 'tool_use', id: 't1', name: 'probe', input: {} }], stop_reason: 'tool_use' },
      { content: [{ type: 'text', text: 'done' }], stop_reason: 'end_turn' },
    ]);
    const onTurn = vi.fn();
    await executeAgentWithTools('go', { ...baseOpts, client, dispatch: async () => 'r', onTurn });
    expect(onTurn).toHaveBeenCalledTimes(2);
    expect(onTurn.mock.calls[0][0]).toBe(1);
    expect(onTurn.mock.calls[1][0]).toBe(2);
  });
});
