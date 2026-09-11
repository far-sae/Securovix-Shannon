// llm-inject.mjs — direct and indirect (2nd-order) prompt-injection probers.
//
// Direct: run the oracle battery across candidate params, each against its own control baseline.
// Indirect: plant a benign instruction into a stored sink via one flow, then trigger a DIFFERENT
// LLM feature that consumes stored content; confirm the computed marker in the rendered output even
// though it never appeared in the render request. Both confirm only on a deterministic marker.
import { buildOracles, candidateParams, genNonce, reqFor } from './llm-surface.mjs';

const F = (tool, severity, target, detail) => ({
  tool,
  severity,
  target: typeof target === 'string' ? target : target.url,
  detail,
  raw: JSON.stringify({ tool, detail }),
});

// Run every oracle on one param against a control. Returns the confirming { oracle, nonce } or null.
export async function runOraclesOnParam({ target, param, fetchT, nonce }) {
  const n = nonce || genNonce();
  const oracles = buildOracles(n);
  const ctlReq = reqFor(target, param, `sxctl${n}`);
  const ctl = (await fetchT(ctlReq.url, ctlReq.opts)).body || '';
  for (const o of oracles) {
    const req = reqFor(target, param, o.payload);
    const r = await fetchT(req.url, req.opts);
    if (o.confirm(r.body || '', ctl)) return { oracle: o, nonce: n, param };
  }
  return null;
}

// DIRECT prompt injection. `params` optional (defaults to discovered candidates).
export async function probeDirect({ target, params, fetchT }) {
  const cand = params && params.length ? params : candidateParams(target);
  for (const p of cand) {
    const hit = await runOraclesOnParam({ target, param: p, fetchT });
    if (hit)
      return [
        F(
          'llm-inject-probe',
          'high',
          target,
          `Prompt injection: the model obeyed an injected instruction via '${p}' ` +
            `(${hit.oracle.name} oracle → emitted the computed marker ${hit.oracle.marker}, ` +
            `which was absent from the control baseline). Deterministic proof, no LLM-judge.`,
        ),
      ];
  }
  return [];
}

// INDIRECT / second-order injection. `plant(instruction)` stores content via one flow; `render()`
// returns the output of the consuming LLM feature. The render request carries NO attacker input, so
// any appearance of the computed marker proves the stored instruction was executed by the model.
export async function probeIndirect({ plant, render, nonce }) {
  const n = nonce || genNonce();
  const oracle = buildOracles(n)[0]; // arithmetic-product
  await plant(oracle.payload);
  const body = (await render()) || '';
  // Zero-FP: the product is a computed value never sent in the render request; its presence in the
  // rendered output means the model consumed and obeyed the stored instruction (2nd-order).
  if (body.includes(oracle.marker))
    return [
      F(
        'llm-indirect-probe',
        'critical',
        'stored-content',
        `Indirect (2nd-order) prompt injection: a benign instruction stored via one flow was ` +
          `executed by the LLM in a separate render flow (emitted the computed marker ` +
          `${oracle.marker}, never present in the render request). Deterministic proof.`,
      ),
    ];
  return [];
}

export { F as llmFinding };
