import assert from 'node:assert/strict';
import { test } from 'node:test';
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
