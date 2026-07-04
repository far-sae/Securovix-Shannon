#!/usr/bin/env node
/**
 * Broken Access Control (OWASP A01) — the #1 real-world category — proven with TWO authenticated
 * identities and a DETERMINISTIC differential. Two sub-classes:
 *
 *   Horizontal (BOLA/IDOR): identity A reads identity B's private object.
 *   Vertical  (BFLA):       a low-privilege identity invokes an admin-only function.
 *
 * ZERO HALLUCINATION BY CONSTRUCTION. A finding is emitted ONLY when the math proves cross-identity
 * exposure:
 *   - victimSelf (B viewing B's object)  → 200 with B's PRIVATE tokens (tokens absent from the
 *     unauthenticated view — so the resource is genuinely access-controlled, not public).
 *   - victimByAttacker (A viewing B's object) → 200 that CONTAINS most of B's private tokens
 *     (A literally received B's private data) AND differs from the unauth view.
 *   If any leg fails, nothing is reported.
 *
 * THE LLM IS A JUDGE, NOT AN ORACLE. An optional LLM reviews each deterministically-proven candidate
 * and may only REFUTE it (e.g. "that leaked content is a shared/public template, not private data").
 * It can never promote a non-proven candidate — so it can reduce false positives but cannot invent a
 * finding. With no API key (or on any judge error) the deterministic finding stands.
 */

import http from 'node:http';
import https from 'node:https';

// Only ever touch the authorized scan origin — same-origin enforcement doubles as the SSRF guard.
export function guardedFetch(url, { origin, headers = {}, method = 'GET', body, timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return resolve({ status: 0, body: '', headers: {} });
    }
    if (origin && u.origin !== origin) return resolve({ status: 0, body: '', headers: {} });
    const agent = u.protocol === 'https:' ? https : http;
    const req = agent.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method,
        headers,
        timeout: timeoutMs,
      },
      (res) => {
        let b = '';
        res.on('data', (d) => (b += d));
        res.on('end', () => resolve({ status: res.statusCode || 0, body: b, headers: res.headers || {} }));
      },
    );
    req.on('error', () => resolve({ status: 0, body: '', headers: {} }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0, body: '', headers: {} });
    });
    if (body) req.write(body);
    req.end();
  });
}

// Distinctive data tokens in a body (words/ids/emails long enough to be meaningful, not markup).
const tokenSet = (body) => new Set((body || '').toLowerCase().match(/[a-z0-9_@.-]{6,}/g) || []);
// Victim's PRIVATE tokens = present when the victim views their own object, absent from the public view.
const privateTokens = (self, unauth) => {
  const pub = tokenSet(unauth);
  return [...tokenSet(self)].filter((t) => !pub.has(t));
};
// Fraction of the victim's private tokens that appear in the attacker's response.
const leakRatio = (attackerBody, priv) => {
  if (!priv.length) return 0;
  const a = tokenSet(attackerBody);
  return priv.filter((t) => a.has(t)).length / priv.length;
};

const F = (severity, target, detail, extra = {}) => ({
  tool: 'access-control',
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool: 'access-control', detail, ...extra }),
});

const MIN_PRIVATE_TOKENS = 4; // the object must carry real private content, not a near-empty page
const MIN_LEAK_RATIO = 0.6; // the attacker must have received MOST of the victim's private data

// Build an LLM judge that can only REFUTE a deterministically-proven candidate. Returns null if no key.
export function makeLlmJudge(apiKey, model = process.env.SHANNON_MODEL || 'claude-opus-4-7') {
  if (!apiKey) return null;
  return async (candidate) => {
    try {
      const { default: Anthropic } = await import('@anthropic-ai/sdk');
      const client = new Anthropic({ apiKey, maxRetries: 2, timeout: 60_000 });
      const prompt = `You are a senior penetration tester acting as a STRICT reviewer of an automated Broken Access Control finding. The scanner already has DETERMINISTIC proof, so your ONLY job is to catch FALSE POSITIVES — do NOT invent issues.

Type: ${candidate.type}
Attacker identity: "${candidate.attacker}"  Victim/privileged identity: "${candidate.victim}"
Resource: ${candidate.url}
Victim's private tokens that leaked to the attacker (${candidate.leakedTokens.length}): ${candidate.leakedTokens.slice(0, 20).join(', ')}
Leak ratio: ${(candidate.ratio * 100).toFixed(0)}%

Victim's own view (should be private):
${candidate.snippets.self}

Attacker's view of the victim's resource (the alleged leak):
${candidate.snippets.byAttacker}

Unauthenticated view (public baseline):
${candidate.snippets.unauth}

Refute ONLY if the "leaked" content is actually public/shared/non-sensitive (e.g. a common template, nav bar, or generic error) rather than the victim's private data. Otherwise confirm.
Respond with ONLY strict JSON: {"verdict":"confirmed"|"refuted","reason":"<one sentence>"}`;
      const r = await client.messages.create({
        model,
        max_tokens: 200,
        messages: [{ role: 'user', content: prompt }],
      });
      const text = r.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('');
      const cost = (r.usage?.input_tokens || 0) * 0.000003 + (r.usage?.output_tokens || 0) * 0.000015;
      const m = text.match(/\{[\s\S]*\}/);
      const parsed = m ? JSON.parse(m[0]) : null;
      // Refute ONLY on an explicit, parseable "refuted" — any error keeps the proven finding.
      return { verdict: parsed?.verdict === 'refuted' ? 'refuted' : 'confirmed', reason: parsed?.reason || '', cost };
    } catch {
      return { verdict: 'confirmed', reason: 'judge unavailable — deterministic proof stands', cost: 0 };
    }
  };
}

// identities: [{ label, headers, resources: [url,...], role? }].  adminEndpoints: [url].  judge: optional.
export async function runAccessControl({ origin, identities = [], adminEndpoints = [], judge = null, log = () => {} }) {
  const findings = [];
  let cost = 0;
  const get = (url, headers) => guardedFetch(url, { origin, headers: headers || {} });

  const gate = async (candidate, make) => {
    if (!judge) return findings.push(make());
    let v;
    try {
      v = await judge(candidate);
    } catch {
      v = { verdict: 'confirmed' }; // a judge error must never drop a deterministically-proven finding
    }
    cost += v.cost || 0;
    if (v.verdict === 'refuted') {
      log(`  access-control: candidate refuted by judge (${candidate.url}) — ${v.reason}`);
      return;
    }
    findings.push(make());
  };

  // ── Horizontal (BOLA/IDOR): PEER-to-peer only, over the victim's own resources. An admin reading
  // another identity's data is expected elevated access, NOT horizontal privesc — so skip any pair
  // involving an admin (that avoids a whole class of false positives). ──
  for (const attacker of identities) {
    for (const victim of identities) {
      if (attacker === victim) continue;
      if (attacker.role === 'admin' || victim.role === 'admin') continue;
      for (const url of victim.resources || []) {
        const victimSelf = await get(url, victim.headers);
        if (victimSelf.status !== 200) continue; // victim must actually own/see it
        const unauth = await get(url, {});
        const priv = privateTokens(victimSelf.body, unauth.body);
        if (priv.length < MIN_PRIVATE_TOKENS) continue; // resource isn't genuinely private → skip
        const byAttacker = await get(url, attacker.headers);
        if (byAttacker.status !== 200) continue; // attacker was denied → secure
        const ratio = leakRatio(byAttacker.body, priv);
        if (ratio < MIN_LEAK_RATIO) continue; // attacker didn't get the victim's private data
        if (leakRatio(unauth.body, priv) >= MIN_LEAK_RATIO) continue; // content is actually public → not a leak
        await gate(
          {
            type: 'horizontal (BOLA/IDOR)',
            attacker: attacker.label,
            victim: victim.label,
            url,
            leakedTokens: priv.filter((t) => tokenSet(byAttacker.body).has(t)),
            ratio,
            snippets: {
              self: victimSelf.body.slice(0, 700),
              byAttacker: byAttacker.body.slice(0, 700),
              unauth: unauth.body.slice(0, 300),
            },
          },
          () =>
            F(
              'high',
              url,
              `Broken object-level authorization (BOLA/IDOR): identity "${attacker.label}" read identity "${victim.label}"'s private resource (${(ratio * 100).toFixed(0)}% of ${priv.length} private tokens leaked)`,
              { attacker: attacker.label, victim: victim.label },
            ),
        );
      }
    }
  }

  // ── Vertical (BFLA): a non-admin identity reaching admin-only functions ──
  const admin = identities.find((i) => i.role === 'admin');
  const lows = identities.filter((i) => i.role !== 'admin');
  if (admin && adminEndpoints.length) {
    for (const url of adminEndpoints) {
      const adminView = await get(url, admin.headers);
      if (adminView.status !== 200) continue; // endpoint isn't a working admin function
      const unauth = await get(url, {});
      const priv = privateTokens(adminView.body, unauth.body);
      if (priv.length < MIN_PRIVATE_TOKENS) continue; // not genuinely privileged content
      for (const low of lows) {
        const lowView = await get(url, low.headers);
        if (lowView.status !== 200) continue; // low-priv denied → secure
        const ratio = leakRatio(lowView.body, priv);
        if (ratio < MIN_LEAK_RATIO) continue;
        await gate(
          {
            type: 'vertical (BFLA)',
            attacker: low.label,
            victim: admin.label,
            url,
            leakedTokens: priv.filter((t) => tokenSet(lowView.body).has(t)),
            ratio,
            snippets: {
              self: adminView.body.slice(0, 700),
              byAttacker: lowView.body.slice(0, 700),
              unauth: unauth.body.slice(0, 300),
            },
          },
          () =>
            F(
              'critical',
              url,
              `Broken function-level authorization (BFLA): low-privilege identity "${low.label}" invoked admin-only function (${(ratio * 100).toFixed(0)}% of ${priv.length} admin-only tokens exposed)`,
              { attacker: low.label, admin: admin.label },
            ),
        );
      }
    }
  }

  return { findings, cost };
}
