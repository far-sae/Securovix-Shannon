// Tests for the code locator — maps a proven finding to the likely vulnerable line in pasted source.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { locateFinding } from './packages/dashboard/code-locate.mjs';

test('locateFinding: points at the SQL sink line that uses the flagged param on the flagged route', () => {
  const code = [
    "const express = require('express');",
    'const app = express();',
    "app.get('/search', (req, res) => {",
    "  const rows = db.query('SELECT * FROM products WHERE name = ' + req.query.q);", // line 4 — the bug
    '  res.json(rows);',
    '});',
  ].join('\n');
  const locs = locateFinding({
    finding: { cls: 'sqli', target: 'https://shop.example/search?q=x' },
    files: [{ path: 'routes.js', content: code }],
  });
  assert.ok(locs.length >= 1);
  assert.equal(locs[0].line, 4, 'top candidate is the vulnerable query line');
  assert.ok(/uses the flagged parameter/.test(locs[0].why) && /sink/.test(locs[0].why));
  assert.ok(/SELECT \* FROM products/.test(locs[0].snippet));
});

test('locateFinding: command-injection sink located from the finding', () => {
  const code = [
    "app.get('/ping', (req, res) => {",
    "  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));", // line 2
    '});',
  ].join('\n');
  const locs = locateFinding({
    finding: { cls: 'cmd-injection', target: 'https://x.example/ping?host=1' },
    files: [{ path: 'app.js', content: code }],
  });
  assert.equal(locs[0].line, 2);
});

test('locateFinding: an impact-tagged class maps back to its base sink', () => {
  const code = "row = cursor.execute('SELECT * FROM t WHERE id=' + request.GET['id'])";
  const locs = locateFinding({
    finding: { cls: 'impact-sqli-extract', target: 'https://x/item?id=1' },
    files: [{ path: 'v.py', content: code }],
  });
  assert.ok(locs.length >= 1 && locs[0].line === 1);
});

test('locateFinding: benign source yields no candidates (no over-claiming)', () => {
  const code = "app.get('/health', (req, res) => res.send('ok'));\nconst x = 1 + 1;";
  assert.equal(
    locateFinding({ finding: { cls: 'sqli', target: 'https://x/health' }, files: [{ path: 'h.js', content: code }] })
      .length,
    0,
  );
});

test('locateFinding: multi-language sinks — PHP, Java, Python, Go, C#, Ruby', () => {
  const cases = [
    // [class, target, code(one line), lang]
    [
      'sqli',
      'https://x/user?id=1',
      '$res = mysqli_query($db, "SELECT * FROM users WHERE id=" . $_GET[\'id\']);',
      'PHP',
    ],
    [
      'sqli',
      'https://x/user?id=1',
      'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + request.getParameter("id"));',
      'Java',
    ],
    ['cmd-injection', 'https://x/ping?host=1', 'os.system("ping " + request.args.get("host"))', 'Python'],
    [
      'cmd-injection',
      'https://x/run?cmd=1',
      'out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Output()',
      'Go',
    ],
    ['ssrf', 'https://x/fetch?url=1', 'var resp = await httpClient.GetAsync(Request.Query["url"]);', 'C#'],
    ['path-traversal', 'https://x/file?name=1', 'contents = File.read(params[:name])', 'Ruby'],
    ['xss', 'https://x/p?q=1', 'echo $_GET["q"];', 'PHP'],
  ];
  for (const [cls, target, line, lang] of cases) {
    const locs = locateFinding({ finding: { cls, target }, files: [{ path: `f.${lang}`, content: line }] });
    assert.ok(locs.length >= 1 && locs[0].line === 1, `${lang} ${cls} should be located; got ${JSON.stringify(locs)}`);
  }
});

test('locateFinding: unknown class → empty (never guesses)', () => {
  assert.deepEqual(
    locateFinding({
      finding: { cls: 'totally-unknown', target: 'https://x/a?b=1' },
      files: [{ path: 'a.js', content: 'db.query(req.query.b)' }],
    }),
    [],
  );
});
