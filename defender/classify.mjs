// defender/classify.mjs — deterministic attack classification for the live Defender.
//
// ZERO-FP CONTRACT: only a deterministic signature match may produce confidence:'confirmed',
// and only a 'confirmed' verdict may ever lead to a block. The LLM layer (applyLlmJudgment)
// can raise a benign event to 'suspected' (→ alert) but can NEVER create a confirmation.
import { PROBERS, buildCompositeFilter } from '../purple-engine.mjs';

const matchClass = buildCompositeFilter();

const dec = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

// A tightened, DEFENDER-OWNED prompt-injection signature. The engine's own filter also matches
// ordinary prose ("please ignore my previous instructions about the invoice", "the reveal was
// prompt and dramatic") — acceptable when it only ever re-tested a payload the engine had just
// sent itself, unacceptable as a gate on live traffic. To enforce, the request must target the
// MODEL's own configuration (its system/developer prompt, its instructions) rather than merely
// contain the words. The first two alternatives are the engine's computed-marker oracles, which
// never occur in ordinary text.
const PROMPT_INJECTION = new RegExp(
  [
    'reversed:\\s*sxpi',
    'result of \\d{3,}\\s*[*+]\\s*\\d{3,}',
    '(?:ignore|disregard|forget|override)\\b[^.]{0,40}\\byour\\s+(?:previous\\s+|prior\\s+|above\\s+|earlier\\s+|initial\\s+|original\\s+|system\\s+)*(?:instructions|prompt|rules)',
    '(?:ignore|disregard|forget|override)\\b[^.]{0,40}\\b(?:system|developer)\\s+(?:prompt|instructions|message)',
    '(?:reveal|print|show|output|repeat|dump|echo|display)\\b[^.]{0,20}\\byour\\s+(?:system\\s+|initial\\s+|original\\s+|full\\s+)*(?:prompt|instructions)',
    'you\\s+are\\s+now\\b[^.]{0,40}\\b(?:ignore|instead|no longer|disregard)',
  ].join('|'),
  'i',
);

// Per-class ENFORCEMENT predicates, owned by the defender. A class blocks inline only when its own
// predicate matches the request — never merely because the composite filter reported it. That
// independence matters: buildCompositeFilter returns the FIRST matching class in PROBERS order, and
// sqli/xss/rce-ssti all precede these, so without it, appending `&name=O'Brien` to a path-traversal
// attack reclassifies it as sqli (alert-only) and sails straight through.
const ENFORCE = {
  'path-traversal': (u, b) => PROBERS['path-traversal'].filter(u, b),
  nosql: (u, b) => PROBERS.nosql.filter(u, b),
  'llm-prompt-injection': (u, b) => PROMPT_INJECTION.test(`${dec(u)} ${dec(b || '')}`),
};

// Classes specific enough to enforce against live production traffic. Everything else is still
// detected and surfaced to the operator, but only as an alert.
export const DEFENSE_CLASSES = Object.keys(ENFORCE);

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
    // Evaluated independently of `cls` so a shadowing class cannot suppress enforcement.
    for (const name of DEFENSE_CLASSES) {
      if (ENFORCE[name](url, body)) {
        enforcing = name;
        break;
      }
    }
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
