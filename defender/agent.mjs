// defender/agent.mjs — the agentic defender: detect → decide → respond, on the shared blackboard.
//
// Mirrors the multi-agent security team's contract (agent-team.mjs): an agent is a plain function
// whose capabilities are injected, and which coordinates only by posting typed facts. Facts:
//   'attack-event' (a non-benign request)  →  'defense' (a verdict + the action taken)
//
// RETENTION: the blackboard is append-only and holds the full request (headers + body), so posting
// every observed request would retain ~360k events/hour at 100 rps until the process dies of it —
// taking the inline proxy, and therefore the protected app, down with it. That is precisely what
// fail-open exists to prevent, so benign traffic only moves an O(1) counter and is never a fact.
import { makeBlackboard } from '../packages/dashboard/agent-team.mjs';
import { classify } from './classify.mjs';
import { applyResponse, makeRateLimiter } from './respond.mjs';

// Non-benign traffic must not grow without bound either. Restricting inline blocking to an
// allowlist deliberately widened "non-benign" to every DETECTED class — and xss matches any HTML
// tag while sqli matches a bare apostrophe — so on a real app with a search box or a CMS, a large
// share of ordinary requests are alert-only detections. The blackboard is append-only and shared
// with the offensive team, so the bound has to live here: retain a trimmed event, and only up to
// MAX_FACTS of them. The counters stay exact regardless, so stats never lie.
const MAX_FACTS = 1000;
const MAX_FACT_BODY = 512;

const trimEvent = (event) => ({
  at: event.at,
  source: event.source,
  srcIp: event.srcIp,
  method: event.method,
  url: event.url,
  // Headers dropped, body truncated: the operator needs the request line and enough payload to
  // recognise the attack — not a full retained copy of every request that ever matched.
  body: typeof event.body === 'string' ? event.body.slice(0, MAX_FACT_BODY) : event.body,
  connId: event.connId,
  raw: event.raw,
});

export function defenderAgent(bb, { getMode = () => 'monitor', deps = {}, allow, counters } = {}) {
  const count = counters || { events: 0, defenses: 0 };
  function handle(event) {
    count.events++;
    const verdict = classify(event);
    const result = applyResponse(verdict, { event }, { mode: getMode(), deps, allow });
    if (verdict.attack || result.action !== 'observe') {
      count.defenses++;
      // Only a non-benign request becomes a durable fact, trimmed and capped.
      if (count.defenses <= MAX_FACTS) {
        const trimmed = trimEvent(event);
        bb.post('attack-event', trimmed, 'connector');
        bb.post('defense', { event: trimmed, verdict, result }, 'defender');
      }
    }
    return { block: result.enforced && result.action === 'block-inline' };
  }
  handle.counters = count;
  return handle;
}

// Keep the narrated timeline bounded: it is a UI convenience, not the system of record.
const TIMELINE_MAX = 500;

export async function runDefender({ connect, mode = 'monitor', deps = {}, onUpdate } = {}) {
  let current = mode;
  const bb = makeBlackboard();
  const allow = makeRateLimiter();
  const timeline = [];
  const counters = { events: 0, defenses: 0 }; // O(1) stats — never a full scan of the board
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
    if (timeline.length > TIMELINE_MAX) timeline.splice(0, timeline.length - TIMELINE_MAX);
    try {
      onUpdate?.(e.data);
    } catch {}
  });

  const handle = defenderAgent(bb, { getMode: () => current, deps, allow, counters });
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
    stats: () => ({ events: counters.events, defenses: counters.defenses }),
  };
}
