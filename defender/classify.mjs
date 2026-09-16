// defender/classify.mjs — deterministic attack classification for the live Defender.
//
// ZERO-FP CONTRACT: only a deterministic signature match may produce confidence:'confirmed',
// and only a 'confirmed' verdict may ever lead to a block. The LLM layer (applyLlmJudgment)
// can raise a benign event to 'suspected' (→ alert) but can NEVER create a confirmation.
import { ENFORCE_CLASSES, matchEnforceable } from '../packages/defender-sdk/signatures.mjs';
import { buildCompositeFilter } from '../purple-engine.mjs';

const matchClass = buildCompositeFilter();

// Enforcement predicates come from the SDK's standalone signature module — the single definition of
// "safe to block on live traffic", shared by this dashboard, the edge proxy and the customer SDK, so
// the three can never drift apart. Detection still uses the full engine below, which is far broader
// but far too eager to gate real traffic with.
//
// Enforcement is evaluated INDEPENDENTLY of detection on purpose: buildCompositeFilter reports the
// first matching class in PROBERS order, and sqli/xss/rce-ssti all precede the enforceable classes —
// so `?path=../../etc/passwd&name=O'Brien` would report sqli and, if enforcement followed detection,
// appending one character would turn a 403 into a 200.
export const DEFENSE_CLASSES = ENFORCE_CLASSES;

const benign = (signal = 'no deterministic signature matched') => ({
  attack: false,
  cls: null,
  confidence: 'benign',
  signal,
  recommendedAction: 'observe',
});

export function classify(event, { match = matchClass } = {}) {
  if (!event || event.source !== 'http-proxy') return benign('source carries no HTTP signature surface');
  const url = event.url || '';
  const body = event.body || '';
  let cls = null;
  let enforcing = null;
  try {
    cls = match(url, body);
    // Independent of `cls` so a shadowing class cannot suppress enforcement.
    enforcing = matchEnforceable(url, body);
  } catch (err) {
    return benign(`classifier error — failing open: ${err?.message || err}`);
  }
  if (!cls && !enforcing) return benign();
  // Detection is never narrowed — the operator sees every confirmed match. Only the *inline* block
  // is restricted to DEFENSE_CLASSES; anything else is alert-only, so ordinary production traffic is
  // never 403'd by a signature that was written to re-test a replayed exploit.
  const reported = enforcing || cls;
  return {
    attack: true,
    cls: reported,
    confidence: 'confirmed',
    signal: enforcing
      ? `signature match: ${enforcing}${cls && cls !== enforcing ? ` (also matched ${cls})` : ''}`
      : `signature match: ${cls} (detect-only class — not enforced inline)`,
    recommendedAction: enforcing ? 'block-inline' : 'alert',
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
