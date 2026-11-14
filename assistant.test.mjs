import assert from 'node:assert/strict';
import { test } from 'node:test';

const a = await import('./packages/dashboard/assistant.mjs');

test('org context is wrapped as data, most severe open findings first, capped', () => {
  const findings = [
    { id: 'f1', title: 'Low thing', severity: 'low', status: 'new', details: {} },
    {
      id: 'f2',
      title: 'Critical SQLi',
      severity: 'critical',
      status: 'triaged',
      details: { target: 'https://app.example.com/login' },
    },
    { id: 'f3', title: 'Fixed', severity: 'critical', status: 'resolved', details: {} },
    ...Array.from({ length: 60 }, (_, i) => ({
      id: `x${i}`,
      title: `Medium ${i}`,
      severity: 'medium',
      status: 'new',
      details: {},
    })),
  ];
  const ctx = a.buildOrgContext({
    orgName: 'Acme',
    memory: [{ text: 'We use Express 5' }],
    findings,
    scans: [{ id: 's1', target: 'https://app.example.com', status: 'completed', hasReport: true }],
  });
  assert.match(ctx, /^<org_context>/);
  assert.match(ctx, /<\/org_context>$/);
  assert.ok(ctx.indexOf('Critical SQLi') < ctx.indexOf('Medium 0'));
  assert.doesNotMatch(ctx, /Fixed/);
  assert.match(ctx, /40 of 62 shown/);
  assert.match(ctx, /We use Express 5/);
  assert.match(ctx, /target https:\/\/app.example.com\/login/);
});

test('history is trimmed to recent turns and always starts with the user', () => {
  const stored = [
    { role: 'assistant', content: 'orphan' },
    { role: 'user', content: 'q1' },
    { role: 'assistant', content: 'a1' },
    { role: 'user', content: '   ' },
    { role: 'user', content: 'q2' },
  ];
  assert.deepEqual(a.toApiMessages(stored), [
    { role: 'user', content: 'q1' },
    { role: 'assistant', content: 'a1' },
    { role: 'user', content: 'q2' },
  ]);
  assert.equal(a.toApiMessages(stored, 2)[0].role, 'user');
});

test('remember command and memory validation', () => {
  assert.equal(a.parseRememberCommand('/remember we deploy on Railway'), 'we deploy on Railway');
  assert.equal(a.parseRememberCommand('please remember this'), null);
  assert.equal(a.normalizeMemoryText('hi').ok, false);
  assert.equal(a.normalizeMemoryText('x'.repeat(501)).ok, false);
  assert.equal(a.normalizeMemoryText('  spaced   out  ').text, 'spaced out');
});

test('API keys: format, hashing, constant-time check, scopes and route table', () => {
  const key = a.newApiKey();
  assert.match(key.token, /^svx_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(a.parseApiKey(key.token), { id: key.id, secret: key.secret });
  assert.equal(a.parseApiKey('svx_bad'), null);
  assert.ok(a.secretMatches(key.secret, key.secretHash));
  assert.ok(!a.secretMatches(`${key.secret.slice(0, -1)}x`, key.secretHash));
  assert.ok(!key.hint.includes(key.secret));
  assert.deepEqual(a.normalizeScopes(['scans:write', 'admin:all', 'scans:write']), ['scans:write']);
  assert.deepEqual(a.normalizeScopes([]), ['scans:read', 'findings:read']);
  assert.deepEqual(a.v1RouteScope('POST', '/v1/scans'), { known: true, scope: 'scans:write' });
  assert.deepEqual(a.v1RouteScope('GET', '/v1/scans/abc123/report'), { known: true, scope: 'scans:read' });
  assert.equal(a.v1RouteScope('DELETE', '/v1/scans/abc').known, false);
  assert.equal(a.v1RouteScope('GET', '/v1/team/members').known, false);
});

test('share tokens, expiry clamping and domain matching', () => {
  const t = a.newShareToken();
  assert.deepEqual(a.parseShareToken(t.token), { id: t.id, secret: t.secret });
  assert.equal(a.parseShareToken('../etc/passwd'), null);
  const now = 1_000_000;
  assert.equal(a.shareExpiry(90, now), now + 30 * 86_400_000);
  assert.equal(a.shareExpiry(0, now), now + 86_400_000);
  assert.equal(a.shareExpiry('nope', now), now + 7 * 86_400_000);
  assert.equal(a.shareUsable({ expiresAt: now + 1, revokedAt: null }, now), true);
  assert.equal(a.shareUsable({ expiresAt: now + 1, revokedAt: 5 }, now), false);
  assert.ok(a.domainMatches('https://api.example.com/x', 'example.com'));
  assert.ok(a.domainMatches('example.com', 'example.com'));
  assert.ok(!a.domainMatches('https://notexample.com', 'example.com'));
  assert.ok(!a.domainMatches('https://example.com.evil.test', 'example.com'));
});

test('research material marks truncation instead of silently cutting', () => {
  const text = a.researchMaterial({
    domain: 'example.com',
    reports: [{ scanId: 's1', target: 'https://example.com', status: 'completed', text: 'x'.repeat(30_000) }],
  });
  assert.match(text, /report truncated at 24000 characters/);
  assert.match(text, /^<evidence>/);
});
