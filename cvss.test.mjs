import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cvss31, cvssForClass, severityFromScore } from './cvss.mjs';

// Official CVSS 3.1 base-score examples (FIRST/NVD) — proves the formula is correct.
const CASES = [
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'critical'], // full RCE
  ['AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'medium'], // reflected XSS (spec example)
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'high'], // info disclosure
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5, 'medium'], // IDOR (auth'd)
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N', 8.6, 'high'], // scope-changed high
  ['AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1, 'low'], // weak headers
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'none'], // no impact
];

for (const [vector, score, sev] of CASES) {
  test(`cvss31 ${vector} = ${score} (${sev})`, () => {
    const r = cvss31(vector);
    assert.equal(r.score, score);
    assert.equal(r.severity, sev);
    assert.ok(r.vector.startsWith('CVSS:3.1/'));
  });
}

test('severityFromScore bands', () => {
  assert.equal(severityFromScore(0), 'none');
  assert.equal(severityFromScore(3.9), 'low');
  assert.equal(severityFromScore(6.9), 'medium');
  assert.equal(severityFromScore(8.9), 'high');
  assert.equal(severityFromScore(9.8), 'critical');
});

test('cvssForClass resolves a class vector and a severity fallback', () => {
  assert.equal(cvssForClass('rce-ssti').score, 9.8);
  assert.equal(cvssForClass('unknown-class', 'low').severity, 'low');
});
