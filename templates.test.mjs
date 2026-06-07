import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadTemplates, runTemplates } from './templates.mjs';

const TPLS = [
  {
    id: 'a',
    name: 'A',
    severity: 'high',
    requests: [{ path: '/x' }],
    'matchers-condition': 'and',
    matchers: [
      { part: 'status', status: 200 },
      { part: 'body', words: ['NEEDLE'], condition: 'and' },
    ],
  },
];

test('runTemplates matches on status 200 + word', async () => {
  const f = async (url) =>
    url.endsWith('/x')
      ? { status: 200, body: 'has NEEDLE here', headers: new Headers() }
      : { status: 404, body: '', headers: new Headers() };
  const hits = await runTemplates('http://h', TPLS, f);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].id, 'a');
  assert.equal(hits[0].severity, 'high');
});

test('runTemplates no match when the word is absent (and-condition holds)', async () => {
  const f = async () => ({ status: 200, body: 'nothing special', headers: new Headers() });
  assert.equal((await runTemplates('http://h', TPLS, f)).length, 0);
});

test('runTemplates no match on wrong status even if word present', async () => {
  const f = async () => ({ status: 404, body: 'has NEEDLE', headers: new Headers() });
  assert.equal((await runTemplates('http://h', TPLS, f)).length, 0);
});

test('runTemplates regex matcher', async () => {
  const t = [{ id: 'r', requests: [{ path: '/h' }], matchers: [{ part: 'body', regex: '^ref:\\s+refs/' }] }];
  const f = async () => ({ status: 200, body: 'ref: refs/heads/main', headers: new Headers() });
  assert.equal((await runTemplates('http://h', t, f)).length, 1);
});

test('wordpress-debug-log template: no FP on prose, hits a real log line', async () => {
  const wp = loadTemplates(join(import.meta.dirname, 'templates')).filter((t) => t.id === 'wordpress-debug-log');
  assert.equal(wp.length, 1);
  const prose = async () => ({
    status: 200,
    body: '<h1>How to fix a PHP Warning in WordPress</h1>',
    headers: new Headers(),
  });
  assert.equal((await runTemplates('http://h', wp, prose)).length, 0, 'must NOT match prose mentioning "PHP Warning"');
  const real = async () => ({
    status: 200,
    body: '[07-Jun-2026 12:00:00 UTC] PHP Notice:  Undefined variable $x',
    headers: new Headers(),
  });
  assert.equal((await runTemplates('http://h', wp, real)).length, 1, 'must match a real debug.log line');
});
