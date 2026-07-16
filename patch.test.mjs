// Tests for the patch generator — confident rewrite for the clean SQLi case, targeted notes otherwise.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyLineFix, generatePatch } from './packages/dashboard/patch.mjs';

test('generatePatch: SQLi string-concat → parameterized query (confident rewrite)', () => {
  const p = generatePatch({
    finding: { cls: 'sqli' },
    snippet: "const rows = db.query('SELECT * FROM products WHERE name = ' + req.query.q);",
  });
  assert.equal(p.applicable, true);
  assert.equal(p.confidence, 'high');
  assert.ok(/\?['"`]\s*,\s*\[req\.query\.q\]\)/.test(p.after), `after was: ${p.after}`);
  assert.ok(!/\+/.test(p.after), 'no concatenation remains');
  assert.ok(/review before applying/i.test(p.disclaimer));
});

test('generatePatch: impact-tagged SQLi maps back and still rewrites', () => {
  const p = generatePatch({
    finding: { cls: 'impact-sqli-extract' },
    snippet: "cursor.execute('SELECT x FROM t WHERE id=' + id)",
  });
  assert.equal(p.applicable, true);
  assert.ok(p.after.includes('?') && p.after.includes('[id]'));
});

test('generatePatch: a non-trivial SQLi line (multi-concat) falls back to guidance, not a bad rewrite', () => {
  const p = generatePatch({
    finding: { cls: 'sqli' },
    snippet: "db.query('SELECT ' + cols + ' FROM t WHERE a=' + a)",
  });
  assert.equal(p.applicable, false, 'does not fabricate a rewrite it cannot do safely');
  assert.ok(/parameterized|params array|placeholder/i.test(p.note) || p.note.length > 0);
});

test('generatePatch: command injection → targeted note (no blind rewrite)', () => {
  const p = generatePatch({ finding: { cls: 'cmd-injection' }, snippet: "exec('ping -c 1 ' + req.query.host)" });
  assert.equal(p.applicable, false);
  assert.ok(/execFile/.test(p.note), 'note tells them to use execFile with argv');
});

test('generatePatch: uses server-supplied guidance when the class has no line-note', () => {
  const p = generatePatch({
    finding: { cls: 'token-forgery' },
    snippet: 'jwt.verify(t)',
    guidance: 'Pin the algorithm; reject alg=none.',
  });
  assert.equal(p.applicable, false);
  assert.ok(/alg=none/.test(p.note));
});

test('generatePatch: empty snippet → null', () => {
  assert.equal(generatePatch({ finding: { cls: 'sqli' }, snippet: '   ' }), null);
});

test('applyLineFix: replaces the target line, preserves indentation, leaves others intact', () => {
  const code = [
    "app.get('/s', (req, res) => {",
    "  const r = db.query('SELECT * FROM t WHERE q=' + req.query.q);",
    '  res.json(r);',
    '});',
  ].join('\n');
  const fixed = applyLineFix(code, 2, "const r = db.query('SELECT * FROM t WHERE q=?', [req.query.q]);");
  const lines = fixed.split('\n');
  assert.ok(lines[1].startsWith('  '), 'indentation preserved');
  assert.ok(/\?', \[req\.query\.q\]/.test(lines[1]) && !/\+/.test(lines[1]));
  assert.equal(lines[0], "app.get('/s', (req, res) => {");
  assert.equal(lines[2], '  res.json(r);');
});

test('applyLineFix: out-of-range line or bad input → null (never guesses)', () => {
  assert.equal(applyLineFix('a\nb', 9, 'x'), null);
  assert.equal(applyLineFix('a\nb', 0, 'x'), null);
  assert.equal(applyLineFix(null, 1, 'x'), null);
});
