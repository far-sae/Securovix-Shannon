import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BAN_DEFAULTS, createSelfDefense } from './defender/middleware.mjs';

const mkReq = (method, url, { ip = '10.0.0.5', body } = {}) => ({
  method,
  url,
  originalUrl: url,
  path: url.split('?')[0],
  body,
  ip,
  socket: {},
});
const mkRes = () => {
  const r = { code: null, payload: null };
  r.status = (c) => {
    r.code = c;
    return r;
  };
  r.json = (p) => {
    r.payload = p;
    return r;
  };
  return r;
};
const run = (mw, req) => {
  const res = mkRes();
  let nexted = false;
  mw(req, res, () => {
    nexted = true;
  });
  return { res, nexted };
};
const ATTACK = '/files?path=../../etc/passwd'; // path-traversal: confirmed AND enforceable

// ---------- live subscription ----------
test('self-defense: subscribers receive each detection as it happens, with the source IP', () => {
  const d = createSelfDefense({ mode: 'monitor' });
  const seen = [];
  const off = d.subscribe((e) => seen.push(e));
  run(d.middleware, mkReq('GET', ATTACK, { ip: '203.0.113.9' }));
  run(d.middleware, mkReq('GET', '/pricing'));
  assert.equal(seen.length, 1, 'benign traffic is not a detection');
  assert.equal(seen[0].type, 'detection');
  assert.equal(seen[0].cls, 'path-traversal');
  assert.equal(seen[0].srcIp, '203.0.113.9');
  assert.equal(seen[0].enforced, false, 'monitor mode records without enforcing');
  off();
  run(d.middleware, mkReq('GET', ATTACK));
  assert.equal(seen.length, 1, 'unsubscribed listeners stop receiving');
});
test('self-defense: a throwing subscriber never affects request handling', () => {
  const d = createSelfDefense({ mode: 'enforce' });
  d.subscribe(() => {
    throw new Error('listener bug');
  });
  const { res } = run(d.middleware, mkReq('GET', ATTACK));
  assert.equal(res.code, 403, 'the request is still handled correctly');
});
test('self-defense: mode changes are announced to subscribers', () => {
  const d = createSelfDefense({ mode: 'monitor' });
  const seen = [];
  d.subscribe((e) => seen.push(e));
  d.setMode('enforce');
  assert.deepEqual(
    seen.map((e) => [e.type, e.mode]),
    [['mode', 'enforce']],
  );
});

// ---------- repeat-offender ban ----------
test('ban: OFF by default — nothing is tracked, nothing is banned', () => {
  assert.equal(BAN_DEFAULTS.enabled, false);
  assert.equal(BAN_DEFAULTS.enforce, false);
  const d = createSelfDefense({ mode: 'enforce' });
  for (let i = 0; i < 20; i++) run(d.middleware, mkReq('GET', `${ATTACK}&i=${i}`, { ip: '198.51.100.1' }));
  assert.deepEqual(d.bans(), []);
  const { res } = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.1' }));
  assert.equal(res.code, null, 'benign request from that IP still passes');
});
test('ban: enabled but not enforcing reports "would have banned" and never blocks a benign request', () => {
  const t = 1_000_000;
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => t,
    ban: { enabled: true, threshold: 3, windowMs: 60_000, ttlMs: 600_000 },
  });
  const bans = [];
  d.subscribe((e) => {
    if (e.type === 'ban') bans.push(e);
  });
  for (let i = 0; i < 3; i++) run(d.middleware, mkReq('GET', `${ATTACK}&i=${i}`, { ip: '198.51.100.2' }));
  assert.equal(bans.length, 1, 'the policy fired once');
  assert.equal(bans[0].enforce, false, 'and says it is report-only');
  assert.equal(d.bans().length, 1, 'the ban is recorded so the operator can see it');
  const { res, nexted } = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.2' }));
  assert.equal(res.code, null, 'report-only mode must not refuse the request');
  assert.equal(nexted, true);
});
test('ban: enforcing refuses every request from a repeat offender, other IPs are untouched', () => {
  const t = 1_000_000;
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => t,
    ban: { enabled: true, enforce: true, threshold: 3, windowMs: 60_000, ttlMs: 600_000 },
  });
  for (let i = 0; i < 3; i++) run(d.middleware, mkReq('GET', `${ATTACK}&i=${i}`, { ip: '198.51.100.3' }));
  const bad = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.3' }));
  assert.equal(bad.res.code, 403, 'banned IP is refused even for a benign path');
  assert.equal(bad.nexted, false);
  assert.match(bad.res.payload.error, /repeat offender/);
  const good = run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.4' }));
  assert.equal(good.res.code, null, 'a different IP is unaffected');
  assert.equal(d.stats().activeBans, 1);
  assert.equal(d.stats().banned, 1, 'refusals are counted separately from detections');
});
test('ban: expires after its TTL', () => {
  let t = 1_000_000;
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => t,
    ban: { enabled: true, enforce: true, threshold: 2, windowMs: 60_000, ttlMs: 1_000 },
  });
  run(d.middleware, mkReq('GET', ATTACK, { ip: '198.51.100.5' }));
  run(d.middleware, mkReq('GET', `${ATTACK}&x=1`, { ip: '198.51.100.5' }));
  assert.equal(run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.5' })).res.code, 403);
  t += 1_001;
  assert.equal(
    run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.5' })).res.code,
    null,
    'ban lifted after TTL',
  );
  assert.deepEqual(d.bans(), []);
});
test('ban: attacks outside the window do not accumulate', () => {
  let t = 1_000_000;
  const d = createSelfDefense({
    mode: 'enforce',
    nowMs: () => t,
    ban: { enabled: true, enforce: true, threshold: 3, windowMs: 10_000, ttlMs: 600_000 },
  });
  run(d.middleware, mkReq('GET', ATTACK, { ip: '198.51.100.6' }));
  t += 11_000; // first offence ages out
  run(d.middleware, mkReq('GET', `${ATTACK}&a=1`, { ip: '198.51.100.6' }));
  run(d.middleware, mkReq('GET', `${ATTACK}&a=2`, { ip: '198.51.100.6' }));
  assert.deepEqual(d.bans(), [], 'only 2 offences inside the window — under threshold');
});
test('ban: detect-only classes NEVER count — an apostrophe storm cannot earn a ban', () => {
  const d = createSelfDefense({
    mode: 'enforce',
    ban: { enabled: true, enforce: true, threshold: 2, windowMs: 60_000, ttlMs: 600_000 },
  });
  for (let i = 0; i < 10; i++)
    run(d.middleware, mkReq('POST', '/signup', { ip: '198.51.100.7', body: { name: `O'Brien ${i}` } }));
  assert.deepEqual(d.bans(), [], "sqli's apostrophe signature is detect-only and must not ban");
  assert.equal(run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.7' })).res.code, null);
});
test("ban: Shannon's own tool endpoints never count toward a ban", () => {
  const d = createSelfDefense({
    mode: 'enforce',
    ban: { enabled: true, enforce: true, threshold: 2, windowMs: 60_000, ttlMs: 600_000 },
  });
  for (let i = 0; i < 5; i++)
    run(d.middleware, mkReq('POST', '/api/agent/understand', { ip: '198.51.100.8', body: { target: ATTACK } }));
  assert.deepEqual(d.bans(), []);
});
test('ban: an operator can lift a ban, and subscribers hear about it', () => {
  const d = createSelfDefense({
    mode: 'enforce',
    ban: { enabled: true, enforce: true, threshold: 2, windowMs: 60_000, ttlMs: 600_000 },
  });
  const seen = [];
  d.subscribe((e) => seen.push(e.type));
  run(d.middleware, mkReq('GET', ATTACK, { ip: '198.51.100.9' }));
  run(d.middleware, mkReq('GET', `${ATTACK}&z=1`, { ip: '198.51.100.9' }));
  assert.equal(d.bans().length, 1);
  assert.equal(d.unban('198.51.100.9'), true);
  assert.deepEqual(d.bans(), []);
  assert.equal(run(d.middleware, mkReq('GET', '/pricing', { ip: '198.51.100.9' })).res.code, null);
  assert.ok(seen.includes('ban') && seen.includes('unban'));
  assert.equal(d.unban('198.51.100.9'), false, 'lifting a non-existent ban reports false');
});
test('ban: the policy in effect is reported back for the UI', () => {
  const d = createSelfDefense({ ban: { enabled: true, threshold: 7 } });
  const p = d.banPolicy();
  assert.equal(p.enabled, true);
  assert.equal(p.enforce, false, 'unspecified fields keep their safe defaults');
  assert.equal(p.threshold, 7);
});
