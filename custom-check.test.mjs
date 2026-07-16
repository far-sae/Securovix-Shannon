// Tests for the AI custom-check core — deterministic matcher + safe sanitization.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { evaluateMatcher, sanitizeCheck } from './packages/dashboard/custom-check.mjs';

test('evaluateMatcher: status / contains / regex with AND (default) and OR', () => {
  const resp = { status: 200, body: 'welcome admin panel' };
  assert.equal(evaluateMatcher(resp, { status: 200, contains: 'admin' }), true, 'AND both true');
  assert.equal(evaluateMatcher(resp, { status: 200, contains: 'nope' }), false, 'AND one false');
  assert.equal(evaluateMatcher(resp, { status: 500, contains: 'admin', condition: 'or' }), true, 'OR one true');
  assert.equal(evaluateMatcher(resp, { regex: 'ADMIN\\s+PANEL' }), true, 'regex case-insensitive');
  assert.equal(evaluateMatcher(resp, {}), false, 'no assertion → never matches (never invents)');
  assert.equal(evaluateMatcher(resp, { regex: '(' }), false, 'a bad regex is false, not a crash');
});

test('sanitizeCheck: allowlists method, forces a relative path (can never leave the target origin)', () => {
  const c = sanitizeCheck({ method: 'delete', path: 'https://evil.example/steal?x=1', matcher: { contains: 'ok' } });
  assert.equal(c.method, 'DELETE');
  assert.equal(c.path, '/steal?x=1', 'absolute URL reduced to path+query — stays on the authorized origin');
  const bad = sanitizeCheck({ method: 'TRACE', path: 'admin' });
  assert.equal(bad.method, 'GET', 'unknown method → GET');
  assert.equal(bad.path, '/admin', 'relative path gets a leading slash');
});

test('sanitizeCheck: clamps matcher fields and body size', () => {
  const c = sanitizeCheck({
    path: '/x',
    body: 'a'.repeat(50000),
    matcher: { contains: 'b'.repeat(500), condition: 'or' },
  });
  assert.ok(c.body.length <= 10000);
  assert.ok(c.matcher.contains.length <= 200);
  assert.equal(c.matcher.condition, 'or');
});
