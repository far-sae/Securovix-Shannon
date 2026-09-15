import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyLlmJudgment, classify } from './defender/classify.mjs';
import { buildCompositeFilter } from './purple-engine.mjs';

// ---------- composite signature matcher ----------
test('composite filter: flags an SSTI payload with its class', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/?q={{7*7}}', ''), 'rce-ssti');
});
test('composite filter: flags an XSS payload', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/search?q=<script>alert(1)</script>', ''), 'xss');
});
test('composite filter: matches on the request BODY too', () => {
  const match = buildCompositeFilter();
  assert.ok(match('/login', 'user=admin&note={{7*7}}'));
});
test('composite filter: abstains on benign traffic (zero-FP)', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/products?page=2&sort=price', ''), null);
  assert.equal(match('/api/users/42', '{"name":"Ada Lovelace"}'), null);
});
test('composite filter: a throwing prober filter never breaks matching', () => {
  const match = buildCompositeFilter();
  assert.doesNotThrow(() => match('/%E0%A4%A', ''));
});

const httpEvent = (url, body = '') => ({
  at: '2026-09-15T00:00:00.000Z',
  source: 'http-proxy',
  srcIp: '10.0.0.9',
  method: 'GET',
  url,
  headers: {},
  body,
  connId: null,
  raw: `GET ${url}`,
});

// ---------- classifier ----------
test('classify: confirms a signature-matching request and recommends an inline block', () => {
  const v = classify(httpEvent('/?q={{7*7}}'));
  assert.equal(v.attack, true);
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.cls, 'rce-ssti');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('classify: abstains on benign traffic (zero-FP)', () => {
  const v = classify(httpEvent('/products?page=2&sort=price'));
  assert.equal(v.attack, false);
  assert.equal(v.confidence, 'benign');
  assert.equal(v.recommendedAction, 'observe');
});
test('classify: non-http sources get no HTTP signature verdict', () => {
  const v = classify({ ...httpEvent('/?q={{7*7}}'), source: 'log-stream' });
  assert.equal(v.confidence, 'benign');
});
test('LLM judgment: suspicion escalates a benign verdict to ALERT only — never a block', () => {
  const base = classify(httpEvent('/products?page=2'));
  const v = applyLlmJudgment(base, { suspicious: true, reason: 'odd user agent' });
  assert.equal(v.confidence, 'suspected');
  assert.equal(v.recommendedAction, 'alert');
  assert.notEqual(v.confidence, 'confirmed', 'LLM must never produce a confirmed verdict');
});
test('LLM judgment: cannot weaken a deterministic confirmation', () => {
  const base = classify(httpEvent('/?q={{7*7}}'));
  const v = applyLlmJudgment(base, { suspicious: false, reason: 'looks fine to me' });
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('LLM judgment: absent opinion is a no-op', () => {
  const base = classify(httpEvent('/products'));
  assert.deepEqual(applyLlmJudgment(base, null), base);
});
test('classify: FAILS OPEN — a throwing matcher can never block traffic', () => {
  const v = classify(httpEvent('/?q={{7*7}}'), {
    match: () => {
      throw new Error('boom');
    },
  });
  assert.equal(v.attack, false);
  assert.equal(v.confidence, 'benign');
  assert.equal(v.recommendedAction, 'observe');
  assert.match(v.signal, /boom/);
});
