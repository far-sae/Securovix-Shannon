// Committed unit tests for the TLS/SSL verdict logic. classifyTlsFindings is the pure fact→findings
// core of runTlsScan; testing it here regression-gates the zero-FP classification without needing a
// live handshake — essential for the weak-key branch, which a real server can't exercise (Node
// refuses to load an RSA key < 2048 bits as a server key).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyTlsFindings } from './tls-scan.mjs';

const NOW = new Date('2026-07-15T00:00:00Z').getTime();
const days = (n) => new Date(NOW + n * 86_400_000).toUTCString();
const clf = (o) => classifyTlsFindings({ host: 'x.test', cert: {}, now: NOW, ...o });
const sev = (fs, s) => fs.filter((f) => f.severity === s).length;
const has = (fs, re) => fs.some((f) => re.test(f.detail));

test('tls: expired cert → single high (not double-counted by the expiry-window branch)', () => {
  const fs = clf({ authError: 'CERT_HAS_EXPIRED', cert: { valid_to: days(-30) } });
  assert.equal(sev(fs, 'high'), 1);
  assert.ok(has(fs, /EXPIRED/));
});

test('tls: self-signed and not-yet-valid and hostname-mismatch each classified', () => {
  assert.ok(has(clf({ authError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }), /self-signed/i));
  assert.ok(has(clf({ authError: 'SELF_SIGNED_CERT_IN_CHAIN' }), /self-signed/i));
  assert.ok(has(clf({ authError: 'CERT_NOT_YET_VALID' }), /not yet valid/i));
  assert.ok(
    has(
      classifyTlsFindings({ host: 'wrong.test', cert: {}, now: NOW, authError: 'ERR_TLS_CERT_ALTNAME_INVALID' }),
      /wrong\.test/,
    ),
  );
});

test('tls: weak RSA key flagged; strong RSA and small EC key ignored', () => {
  assert.ok(has(clf({ cert: { bits: 1024 } }), /weak 1024-bit/));
  assert.equal(clf({ cert: { bits: 2048 } }).length, 0);
  assert.equal(clf({ cert: { bits: 256, nistCurve: 'P-256' } }).length, 0, 'EC 256-bit is strong');
});

test('tls: near-expiry → low; comfortably valid → none', () => {
  assert.ok(has(clf({ cert: { valid_to: days(5) } }), /expires in \d+ day/));
  assert.equal(sev(clf({ cert: { valid_to: days(5) } }), 'low'), 1);
  assert.equal(clf({ cert: { valid_to: days(90) } }).length, 0);
});

test('tls: deprecated protocols flagged individually; modern-only silent', () => {
  const fs = clf({ legacyProtocols: ['TLSv1', 'TLSv1.1'] });
  assert.ok(has(fs, /TLS 1\.0/) && has(fs, /TLS 1\.1/));
  assert.equal(fs.length, 2);
  assert.equal(clf({ legacyProtocols: [] }).length, 0);
});

test('tls: weak cipher flagged; strong cipher ignored', () => {
  assert.ok(has(clf({ weakCipher: 'DES-CBC3-SHA' }), /Weak TLS cipher/));
  assert.ok(has(clf({ weakCipher: 'RC4-MD5' }), /Weak TLS cipher/));
  assert.equal(clf({ weakCipher: 'ECDHE-RSA-AES256-GCM-SHA384' }).length, 0);
});

test('tls: fully modern config → zero findings (no false positives)', () => {
  assert.equal(
    clf({ authError: null, cert: { bits: 2048, valid_to: days(200) }, legacyProtocols: [], weakCipher: null }).length,
    0,
  );
});
