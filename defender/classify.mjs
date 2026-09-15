// defender/classify.mjs — deterministic attack classification for the live Defender.
//
// ZERO-FP CONTRACT: only a deterministic signature match may produce confidence:'confirmed',
// and only a 'confirmed' verdict may ever lead to a block. The LLM layer (applyLlmJudgment)
// can raise a benign event to 'suspected' (→ alert) but can NEVER create a confirmation.
import { buildCompositeFilter } from '../purple-engine.mjs';

const matchClass = buildCompositeFilter();

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
  return {
    attack: true,
    cls,
    confidence: 'confirmed',
    signal: `signature match: ${cls}`,
    recommendedAction: 'block-inline',
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
