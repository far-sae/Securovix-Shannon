// defender/agent.mjs — the agentic defender: detect → decide → respond, on the shared blackboard.
//
// Mirrors the multi-agent security team's contract (agent-team.mjs): an agent is a plain function
// whose capabilities are injected, and which coordinates only by posting typed facts. Facts:
//   'attack-event' (every observed request)  →  'defense' (a verdict + the action taken)
import { makeBlackboard } from '../packages/dashboard/agent-team.mjs';
import { classify } from './classify.mjs';
import { applyResponse, makeRateLimiter } from './respond.mjs';

export function defenderAgent(bb, { getMode = () => 'monitor', deps = {}, allow } = {}) {
  return function handle(event) {
    bb.post('attack-event', event, 'connector');
    const verdict = classify(event);
    const result = applyResponse(verdict, { event }, { mode: getMode(), deps, allow });
    if (verdict.attack || result.action !== 'observe') {
      bb.post('defense', { event, verdict, result }, 'defender');
    }
    return { block: result.enforced && result.action === 'block-inline' };
  };
}

export async function runDefender({ connect, mode = 'monitor', deps = {}, onUpdate } = {}) {
  let current = mode;
  const bb = makeBlackboard();
  const allow = makeRateLimiter();
  const timeline = [];
  const graph = {
    nodes: [
      { id: 'connector', label: 'Connector', role: 'source' },
      { id: 'defender', label: 'Defender', role: 'agent' },
      { id: 'responder', label: 'Responder', role: 'action' },
    ],
    edges: [
      { from: 'connector', to: 'defender' },
      { from: 'defender', to: 'responder' },
    ],
  };

  bb.subscribe('defense', (e) => {
    const { event, verdict, result } = e.data;
    timeline.push({ at: event.at, phase: 'defend', detail: `${verdict.signal} → ${result.action}` });
    try {
      onUpdate?.(e.data);
    } catch {}
  });

  const handle = defenderAgent(bb, { getMode: () => current, deps, allow });
  const conn = await connect({ onEvent: handle });

  return {
    blackboard: bb,
    graph,
    timeline,
    meta: conn.meta,
    stop: conn.stop,
    setMode: (m) => {
      current = m === 'enforce' ? 'enforce' : 'monitor';
      return current;
    },
    getMode: () => current,
    stats: () => ({ events: bb.all('attack-event').length, defenses: bb.all('defense').length }),
  };
}
