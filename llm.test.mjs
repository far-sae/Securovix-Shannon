// Integration tests for the LLM Attack Surface module — zero-FP, proof-based prompt-injection
// detection for deployed web apps. Each test stands up an in-process mock (no network, no API key):
// a fake LLM that OBEYS injected instructions (arithmetic/reverse oracles), a plain reflector that
// does NOT, a stored+render pair (indirect / 2nd-order), and a system-prompt leaker. The engine's
// zero-FP discipline requires: confirm on the obeying model, ABSTAIN on the reflector.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, test } from 'node:test';
import { LLM_COMPLIANCE, mapLlmFinding } from './llm-compliance.mjs';
import { proveSystemPromptLeak } from './llm-impact.mjs';
import { probeDirect, probeIndirect } from './llm-inject.mjs';
import { buildOracles, candidateParams, detectBoundary, genNonce } from './llm-surface.mjs';
import { fetchT, setScanOrigin } from './purple-engine.mjs';

const servers = [];
after(() => servers.forEach((s) => s.close()));
const send = (res, body, ct = 'text/plain') => (res.writeHead(200, { 'content-type': ct }), res.end(body));
function mkHttp(handler) {
  const s = http.createServer(handler);
  servers.push(s);
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));
}
const found = (fs) => fs.length > 0;

// A minimal fake LLM: it OBEYS a small directive language so the same deterministic markers a real
// model would emit are emitted here — no API key needed. It computes products/sums and reverses a
// token, exactly what an instruction-following model does when injected.
function fakeLlmReply(instruction) {
  const s = String(instruction);
  const rev = s.match(/reversed:\s*([A-Za-z0-9]+)/i);
  if (rev) return `Sure: ${rev[1].split('').reverse().join('')}`;
  const mul = s.match(/(\d{3,})\s*\*\s*(\d{3,})/);
  if (mul) return `The result is ${Number(mul[1]) * Number(mul[2])}.`;
  const sum = s.match(/(\d{3,})\s*\+\s*(\d{3,})/);
  if (sum) return `The sum is ${Number(sum[1]) + Number(sum[2])}.`;
  return "I'm a helpful assistant. How can I help?";
}

test('oracles: each marker is a computed value absent from its own payload (echo-immune)', () => {
  const n = genNonce();
  const oracles = buildOracles(n);
  assert.ok(oracles.length >= 3, 'at least three independent oracles');
  for (const o of oracles) {
    assert.ok(o.marker && o.marker.length >= 3, `${o.name} has a marker`);
    if (o.name !== 'reverse-nonce') assert.ok(!o.payload.includes(o.marker), `${o.name} marker not in payload`);
    // confirm fires only when the marker is present AND absent from the control baseline
    assert.ok(o.confirm(`prefix ${o.marker} suffix`, 'clean control'), `${o.name} confirms on marker`);
    assert.ok(!o.confirm('no marker here', 'clean control'), `${o.name} abstains without marker`);
    assert.ok(!o.confirm(`${o.marker}`, `${o.marker}`), `${o.name} abstains when marker is already in control`);
  }
});

test('direct injection: confirms against an obeying LLM, ABSTAINS against a plain reflector', async () => {
  const llm = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    return send(res, fakeLlmReply(q)); // obeys injected instructions
  });
  const reflector = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    return send(res, `<p>You searched for: ${q}</p>`); // reflects but never obeys
  });
  setScanOrigin(llm);
  assert.ok(found(await probeDirect({ target: `${llm}/chat?q=hi`, fetchT })), 'confirms on obeying LLM');
  setScanOrigin(reflector);
  assert.ok(
    !found(await probeDirect({ target: `${reflector}/search?q=hi`, fetchT })),
    'abstains on reflector (zero-FP)',
  );
});

test('boundary discovery: finds the param that routes to an LLM, rejects a static one', async () => {
  const app = await mkHttp((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/ask') return send(res, fakeLlmReply(u.searchParams.get('prompt') || ''));
    return send(res, `<p>static page ${u.searchParams.get('id') || ''}</p>`);
  });
  setScanOrigin(app);
  const hit = await detectBoundary({ target: `${app}/ask?prompt=x`, params: ['prompt'], fetchT });
  assert.ok(hit && hit.param === 'prompt', 'LLM boundary detected on the prompt param');
  const miss = await detectBoundary({ target: `${app}/page?id=1`, params: ['id'], fetchT });
  assert.equal(miss, null, 'no boundary on a static param');
});

test('indirect (2nd-order) injection: stored instruction executed by a different render flow', async () => {
  let stored = '';
  const app = await mkHttp(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST' && u.pathname === '/note') {
      let b = '';
      for await (const c of req) b += c;
      stored = new URLSearchParams(b).get('content') || '';
      return send(res, 'saved');
    }
    if (u.pathname === '/summarize') return send(res, `Summary: ${fakeLlmReply(stored)}`); // consumes stored content
    return send(res, 'ok');
  });
  setScanOrigin(app);
  const plant = async (instruction) =>
    fetchT(`${app}/note`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ content: instruction }).toString(),
    });
  const render = async () => (await fetchT(`${app}/summarize`)).body;
  assert.ok(found(await probeIndirect({ plant, render })), 'confirms 2nd-order injection');

  // Control: render with nothing planted must NOT confirm.
  stored = '';
  const renderEmpty = async () => (await fetchT(`${app}/summarize`)).body;
  assert.ok(!found(await probeIndirect({ plant: async () => {}, render: renderEmpty })), 'abstains without a plant');
});

test('impact: system-prompt leak confirmed only when a stable non-supplied context returns twice', async () => {
  const leaker = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    const m = q.match(/between the markers (\S+?)\[ and \](\S+)/);
    if (m) return send(res, `${m[1]}[You are ACME-SUPPORT-BOT. Secret ops code OMEGA-7731.]${m[2]}`);
    return send(res, 'ok');
  });
  setScanOrigin(leaker);
  assert.ok(found(await proveSystemPromptLeak({ target: `${leaker}/chat?q=x`, param: 'q', fetchT })), 'confirms leak');

  const echoer = await mkHttp((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    return send(res, `<p>${q}</p>`); // only echoes the request, no fixed context
  });
  setScanOrigin(echoer);
  assert.ok(!found(await proveSystemPromptLeak({ target: `${echoer}/chat?q=x`, param: 'q', fetchT })), 'abstains');
});

test('compliance: new classes map to OWASP LLM Top 10 (2025)', () => {
  assert.match(mapLlmFinding('llm-prompt-injection').owasp, /LLM01/);
  assert.match(mapLlmFinding('llm-indirect-injection').owasp, /LLM01/);
  assert.match(mapLlmFinding('llm-system-prompt-leak').owasp, /LLM07/);
  assert.ok(LLM_COMPLIANCE['llm-prompt-injection'].cwe, 'has a CWE');
  assert.equal(mapLlmFinding('not-a-class'), null);
});

test('candidateParams: prefers existing query params, falls back to LLM hints', () => {
  const c = candidateParams('http://x/ask?prompt=hi&id=3');
  assert.ok(c.includes('prompt'), 'includes an existing param');
  const d = candidateParams('http://x/chat');
  assert.ok(d.includes('q') || d.includes('prompt') || d.includes('message'), 'falls back to hint params');
});
