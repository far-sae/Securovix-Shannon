// Tests for run-to-run diffing (regression tracking) — stable keys + new/fixed/still-present.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diffRuns, findingKey } from './packages/dashboard/agent-history.mjs';

test('findingKey: same issue on the same endpoint matches despite a changed query value', () => {
  const a = findingKey({ cls: 'sqli', target: 'https://x/search?q=1' });
  const b = findingKey({ cls: 'sqli', target: 'https://x/search?q=999' });
  assert.equal(a, b, 'numeric query values are normalized');
  // different class or different path → different key
  assert.notEqual(a, findingKey({ cls: 'xss', target: 'https://x/search?q=1' }));
  assert.notEqual(a, findingKey({ cls: 'sqli', target: 'https://x/other?q=1' }));
});

test('findingKey: numeric path ids and scan nonces are normalized away', () => {
  assert.equal(
    findingKey({ cls: 'idor', target: 'https://x/orders/1001' }),
    findingKey({ cls: 'idor', target: 'https://x/orders/2002' }),
  );
  assert.equal(
    findingKey({ cls: 'sqli', target: 'https://x/s?q=1&sxABC123=nonce' }),
    findingKey({ cls: 'sqli', target: 'https://x/s?q=2&sxZZZ999=other' }),
  );
});

test('diffRuns: classifies new / fixed / still-present correctly', () => {
  const prev = {
    findings: [
      { cls: 'sqli', target: 'https://x/s?q=1' },
      { cls: 'xss', target: 'https://x/p?a=1' },
    ],
  };
  const curr = {
    findings: [
      { cls: 'xss', target: 'https://x/p?a=9' },
      { cls: 'ssrf', target: 'https://x/f?url=1' },
    ],
  };
  const d = diffRuns(prev, curr);
  assert.deepEqual(d.summary, { new: 1, fixed: 1, still: 1 });
  assert.equal(d.added[0].cls, 'ssrf', 'ssrf is new');
  assert.equal(d.removed[0].cls, 'sqli', 'sqli was fixed');
  assert.equal(d.unchanged[0].cls, 'xss', 'xss still present (value changed, key stable)');
});

test('diffRuns: identical runs → all still-present, nothing new/fixed', () => {
  const run = { findings: [{ cls: 'sqli', target: 'https://x/s?q=1' }] };
  const d = diffRuns(run, { findings: [{ cls: 'sqli', target: 'https://x/s?q=42' }] });
  assert.deepEqual(d.summary, { new: 0, fixed: 0, still: 1 });
});

test('diffRuns: empty previous → everything is new (first scan)', () => {
  const d = diffRuns({}, { findings: [{ cls: 'sqli', target: 'https://x/s?q=1' }] });
  assert.deepEqual(d.summary, { new: 1, fixed: 0, still: 0 });
});
