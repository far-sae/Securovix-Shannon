#!/usr/bin/env node
/**
 * AI reasoning layer — the LLM PROPOSES, the engine VERIFIES. Confirmed findings still come only
 * from deterministic proof; the LLM's job is to add app-specific IDEAS the fixed rules miss:
 *   1. extra privileged field names for a mass-assignment check (e.g. account_tier, org_role,
 *      is_premium) — each is then run through Shannon's DETERMINISTIC mass-assignment verifier, so a
 *      proposal becomes a CONFIRMED finding only if it actually binds. No hallucinated findings.
 *   2. free-text business-logic hypotheses — recorded as clearly-labeled LEADS (analysis, not proof;
 *      manual verification recommended), never mixed into the confirmed bucket.
 *
 * `propose` (the LLM call) is injectable so the gate is testable without API credits. With no key,
 * makeLlmProposer returns null and the whole layer is skipped.
 */

const F = (tool, severity, target, detail) => ({
  tool,
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool, detail }),
});

// Build the LLM proposer (Anthropic). Returns null without a key. Output: { fields:[str], leads:[{endpoint,idea,category}] }.
export function makeLlmProposer(apiKey, model = process.env.SHANNON_MODEL || 'claude-opus-4-7') {
  if (!apiKey) return null;
  return async (context) => {
    try {
      const { default: Anthropic } = await import('@anthropic-ai/sdk');
      const client = new Anthropic({ apiKey, maxRetries: 2, timeout: 60_000 });
      const prompt = `You are a senior pentester reviewing an automated scan. Confirmed classes: ${(context.confirmedClasses || []).join(', ') || 'none'}. Endpoints/forms:\n${(context.endpoints || []).slice(0, 40).join('\n')}\n\nPropose ONLY: (a) app-specific PRIVILEGED field names an update/create endpoint might over-bind (mass assignment) — short snake/camel case tokens; (b) concrete business-logic test IDEAS tied to a specific endpoint. Do NOT claim anything is vulnerable. Respond as strict JSON: {"fields":["..."],"leads":[{"endpoint":"/x","category":"business-logic","idea":"..."}]}`;
      const r = await client.messages.create({ model, max_tokens: 700, messages: [{ role: 'user', content: prompt }] });
      const text = r.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('');
      const cost = (r.usage?.input_tokens || 0) * 0.000003 + (r.usage?.output_tokens || 0) * 0.000015;
      const m = text.match(/\{[\s\S]*\}/);
      const parsed = m ? JSON.parse(m[0]) : { fields: [], leads: [] };
      return { fields: parsed.fields || [], leads: parsed.leads || [], cost };
    } catch {
      return { fields: [], leads: [], cost: 0 };
    }
  };
}

// Deterministic mass-assignment verifier for ONE field (mirrors the mass-assignment prober): the
// field must be reflected/bound AND a random control field must NOT be — so echo-all apps can't FP.
async function verifyMassAssign(target, field, fetchT) {
  if (typeof target === 'string' || !Array.isArray(target.params)) return null;
  if ((target.method || 'get').toLowerCase() !== 'post') return null;
  const rnd = Math.random().toString(36).slice(2, 10);
  const base = {};
  for (const p of target.params) base[p] = `sx${p}`;
  const post = (extra) =>
    fetchT(target.url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...base, ...extra }).toString(),
      redirect: 'manual',
    });
  const resp0 = (await post({})).body || '';
  const ctrl = `sxctrl${rnd}`;
  const respC = (await post({ [`sxjunk${rnd}`]: ctrl })).body || '';
  if (respC.includes(ctrl)) return null; // echoes arbitrary input → can't distinguish binding
  const nonce = `sxai${rnd}`;
  const respT = (await post({ [field]: nonce })).body || '';
  if (respT.includes(nonce) && !resp0.includes(nonce))
    return F(
      'ai-verified',
      'high',
      target.url,
      `Mass assignment (AI-proposed field "${field}"): the endpoint bound an unexpected privileged field — VERIFIED deterministically (not an AI guess)`,
    );
  return null;
}

// deps: propose (LLM), fetchT (engine), formTargets (POST forms), surface (endpoint strings).
export async function runAiReason({ report, surface = [], formTargets = [], propose, fetchT }) {
  if (!propose) return { findings: [], leads: [], cost: 0 };
  const context = {
    target: report.target,
    confirmedClasses: (report.exploits || []).filter((e) => e.confirmed > 0).map((e) => e.cls),
    endpoints: surface,
  };
  let out;
  try {
    out = await propose(context);
  } catch {
    return { findings: [], leads: [], cost: 0 };
  }
  const findings = [];
  const seenField = new Set();
  for (const field of (out.fields || []).slice(0, 12)) {
    const f = String(field || '')
      .replace(/[^\w.-]/g, '')
      .slice(0, 40);
    if (!f || seenField.has(f)) continue;
    seenField.add(f);
    for (const t of formTargets.slice(0, 8)) {
      const hit = await verifyMassAssign(t, f, fetchT).catch(() => null);
      if (hit) {
        findings.push(hit);
        break;
      }
    }
  }
  const leads = (out.leads || [])
    .slice(0, 15)
    .map((l) =>
      F(
        'ai-lead',
        'info',
        l.endpoint || report.target,
        `AI-suggested test (${l.category || 'business-logic'}) — NOT verified, manual review recommended: ${String(l.idea || '').slice(0, 200)}`,
      ),
    );
  return { findings, leads, cost: out.cost || 0 };
}

export { verifyMassAssign };
