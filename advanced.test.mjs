import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildAttackChains } from './attack-chains.mjs';
import { extractBuckets } from './cloud-exposure.mjs';
import { ipInCidr, ipToInt, ipVerifyToken, parseCidr } from './ip-ownership.mjs';
import { diffReports, reportFindingIds, sendMonitorAlert } from './monitor.mjs';
import { buildSarif } from './sarif.mjs';

const rep = (ex, extra = {}) => ({ target: 'https://demo.example', exploits: ex, ...extra });
const cf = (cls, detail, severity = 'high', target = 'https://demo.example') => ({
  cls,
  confirmed: 1,
  findings: [{ severity, target, detail, raw: '{}' }],
});

// ---------- attack-chains ----------
test('attack-chains: secrets + exposed datastore → datastore compromise (multi-finding)', () => {
  const { chains } = buildAttackChains(rep([cf('secrets-exposure', '/.env'), cf('exposed-service', 'Unauthenticated Redis exposed')]));
  const c = chains.find((x) => /datastore compromise/i.test(x.detail));
  assert.ok(c, 'datastore-compromise chain present');
  assert.ok(/secrets-exposure/.test(c.raw) && /exposed-service/.test(c.raw), 'combines both findings');
});
test('attack-chains: SSRF → cloud account takeover (single finding, high impact)', () => {
  const { chains } = buildAttackChains(rep([cf('ssrf', 'OOB callback received')]));
  assert.ok(chains.some((x) => /cloud account takeover/i.test(x.detail)));
});
test('attack-chains: no confirmed findings → no chains', () => {
  assert.equal(buildAttackChains(rep([{ cls: 'sqli', confirmed: 0, findings: [] }])).chains.length, 0);
});
test('attack-chains: a lone RCE finding is not restated as a chain', () => {
  assert.equal(buildAttackChains(rep([cf('cmd-injection', 'OS command injection')])).chains.length, 0);
});

// ---------- monitor ----------
test('monitor: stable finding id ignores nonces/counts', () => {
  const a = reportFindingIds(rep([cf('xss', 'reflected marker abc123def executed 5 times')]));
  const b = reportFindingIds(rep([cf('xss', 'reflected marker 99ff88aa executed 9 times')]));
  assert.deepEqual([...a.keys()], [...b.keys()], 'same identity across nonce/number changes');
});
test('monitor: diff surfaces NEW and RESOLVED', () => {
  const base = Object.fromEntries(reportFindingIds(rep([cf('sqli', 'SQLi', 'critical', 'https://demo.example/a'), cf('xss', 'XSS', 'high', 'https://demo.example/b')])));
  const d = diffReports(base, rep([cf('sqli', 'SQLi', 'critical', 'https://demo.example/a'), cf('ssrf', 'SSRF', 'high', 'https://demo.example/c')]));
  assert.equal(d.new.length, 1);
  assert.equal(d.new[0].cls, 'ssrf');
  assert.equal(d.resolved.length, 1);
  assert.equal(d.resolved[0].cls, 'xss');
});
test('monitor: alert fires only on a re-scan with new findings', async () => {
  let posted = 0;
  const fake = async () => (posted++, { ok: true });
  await sendMonitorAlert('x', { firstRun: true, new: [{ cls: 'a' }] }, 'https://hook', fake); // baseline
  await sendMonitorAlert('x', { firstRun: false, new: [] }, 'https://hook', fake); // no change
  await sendMonitorAlert('x', { firstRun: false, new: [{ cls: 'a', severity: 'high', target: 't' }] }, '', fake); // no webhook
  assert.equal(posted, 0, 'silent on baseline / no-change / no-webhook');
  const sent = await sendMonitorAlert('x', { firstRun: false, new: [{ cls: 'a', severity: 'high', target: 't' }] }, 'https://hook', fake);
  assert.equal(posted, 1);
  assert.equal(sent, true);
});

// ---------- ip-ownership ----------
test('ip-ownership: CIDR membership across mask sizes', () => {
  assert.ok(ipInCidr('203.0.113.42', '203.0.113.0/24'));
  assert.ok(!ipInCidr('203.0.114.1', '203.0.113.0/24'));
  assert.ok(ipInCidr('10.9.8.7', '10.0.0.0/8'));
  assert.ok(ipInCidr('1.2.3.4', '1.2.3.4/32'));
  assert.ok(!ipInCidr('1.2.3.5', '1.2.3.4/32'));
  assert.equal(ipToInt('256.0.0.1'), null);
  assert.equal(parseCidr('1.2.3.4/33'), null);
});
test('ip-ownership: verify token is deterministic + per-range', () => {
  assert.equal(ipVerifyToken('S', 'u', '203.0.113.0/24'), ipVerifyToken('S', 'u', '203.0.113.0/24'));
  assert.notEqual(ipVerifyToken('S', 'u', '203.0.113.0/24'), ipVerifyToken('S', 'u', '198.51.100.0/24'));
});

// ---------- sarif ----------
test('sarif: valid 2.1.0 envelope with severity-mapped results', () => {
  const s = buildSarif(rep([cf('sqli', 'SQLi', 'critical', 'https://demo.example/x'), cf('security-headers', 'Missing CSP', 'low')]), {
    sqli: { owasp: 'A03', cwe: 'CWE-89', mitre: [] },
    'security-headers': { owasp: 'A05', cwe: 'CWE-693', mitre: [] },
  });
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].tool.driver.name, 'Securovix Shannon');
  assert.equal(s.runs[0].results.length, 2);
  assert.equal(s.runs[0].results.find((r) => r.ruleId === 'sqli').level, 'error');
  assert.equal(s.runs[0].results.find((r) => r.ruleId === 'security-headers').level, 'note');
  assert.ok(s.runs[0].tool.driver.rules.every((r) => r.properties['security-severity'] !== undefined));
});

// ---------- cloud-exposure ----------
test('cloud-exposure: extract S3/GCS/Azure buckets, ignore non-cloud CDN', () => {
  const body = `<img src="https://acme-assets.s3.amazonaws.com/l.png">
    <link href="https://storage.googleapis.com/acme-pub/s.css">
    <script src="https://acct1.blob.core.windows.net/media/a.js"></script>
    <img src="https://cdn.jsdelivr.net/x.png">`;
  const got = extractBuckets(body).map((b) => b.provider).sort();
  assert.deepEqual(got, ['AWS S3', 'Azure Blob', 'Google Cloud Storage']);
});
