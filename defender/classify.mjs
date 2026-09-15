// defender/classify.mjs — deterministic attack classification for the live Defender.
//
// ZERO-FP CONTRACT: only a deterministic signature match may produce confidence:'confirmed',
// and only a 'confirmed' verdict may ever lead to a block. The LLM layer (applyLlmJudgment)
// can raise a benign event to 'suspected' (→ alert) but can NEVER create a confirmation.
import { buildCompositeFilter } from '../purple-engine.mjs';

const matchClass = buildCompositeFilter();

// Classes whose signatures are specific enough to enforce against live production traffic.
// Everything else is still detected and surfaced to the operator, but only as an alert:
// the engine's other filters exist to re-test a replayed exploit, and match ordinary traffic
// (a bare apostrophe, any HTML tag, a newline in a textarea, an OAuth redirect) far too readily.
export const DEFENSE_CLASSES = ['path-traversal', 'nosql', 'llm-prompt-injection'];

const benign = (signal = 'no deterministic signature matched') => ({
  attack: false,
  cls: null,
  confidence: 'benign',
  signal,
  recommendedAction: 'observe',
});

export function classify(event, { match = matchClass } = {}) {
  if (!event || event.source !== 'http-proxy') return benign('source carries no HTTP signature surface');
  let cls = null;
  try {
    cls = match(event.url || '', event.body || '');
  } catch (err) {
    return benign(`classifier error — failing open: ${err?.message || err}`);
  }
  if (!cls) return benign();
  // Detection is never narrowed — the operator sees every confirmed match. Only the *inline*
  // block is restricted to DEFENSE_CLASSES; anything else is alert-only so ordinary production
  // traffic is never 403'd by a signature that was written to re-test a replayed exploit.
  const enforceable = DEFENSE_CLASSES.includes(cls);
  return {
    attack: true,
    cls,
    confidence: 'confirmed',
    signal: `signature match: ${cls}${enforceable ? '' : ' (detect-only class — not enforced inline)'}`,
    recommendedAction: enforceable ? 'block-inline' : 'alert',
  };
}

// The LLM may only escalate an unconfirmed event to an alert, or annotate. It is never authority.
export function applyLlmJudgment(verdict, llmOpinion) {
  if (!llmOpinion) return verdict;
  if (verdict.confidence === 'confirmed') return verdict; // deterministic authority stands
  if (llmOpinion.suspicious) {
    return {
      ...verdict,
      confidence: 'suspected',
      signal: `LLM suspicion: ${llmOpinion.reason || 'unspecified'}`,
      recommendedAction: 'alert',
    };
  }
  return verdict;
}
