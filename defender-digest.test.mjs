// Weekly attack summary: the pure builder, then the routes and the scheduled send.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const { buildDefenseDigest, classLabel, lastCompleteWeek, DAY } = await import(
  './packages/dashboard/defender-digest.mjs'
);

const MONDAY = Date.UTC(2026, 10, 9); // Monday 9 Nov 2026 00:00 UTC

test('lastCompleteWeek: Monday to Monday in UTC, whatever day it is asked', () => {
  const expected = { from: MONDAY - 7 * DAY, to: MONDAY, key: '2026-11-02' };
  assert.deepEqual(lastCompleteWeek(MONDAY), expected, 'Monday 00:00 itself');
  assert.deepEqual(lastCompleteWeek(MONDAY + 3 * DAY + 5 * 3_600_000), expected, 'Thursday');
  assert.deepEqual(lastCompleteWeek(MONDAY + 7 * DAY - 1), expected, 'Sunday 23:59:59');
  assert.equal(lastCompleteWeek(MONDAY + 7 * DAY).key, '2026-11-09', 'the next Monday moves on');
});

const event = (
  cls,
  { enforced = true, srcIp = '203.0.113.5', source = 'self', at = MONDAY - 3 * DAY, method = 'GET' } = {},
) => ({
  cls,
  enforced,
  srcIp,
  source,
  method,
  createdAt: at,
});

test('digest: nothing to report gives null', () => {
  assert.equal(buildDefenseDigest([], { from: MONDAY - 7 * DAY, to: MONDAY }), null);
  assert.equal(buildDefenseDigest(null, { from: MONDAY - 7 * DAY, to: MONDAY }), null);
});

test('digest: counts, ranking, bans and trend', () => {
  const events = [
    event('sqli'),
    event('sqli', { srcIp: '203.0.113.6' }),
    event('sqli', { at: MONDAY - 2 * DAY }),
    event('xss', { enforced: false, source: 'sdk' }),
    event('honeypot', { srcIp: '198.51.100.9' }),
    event('repeat-offender', { method: 'BAN', srcIp: '198.51.100.9' }),
  ];
  const d = buildDefenseDigest(events, {
    orgName: 'Acme Ltd',
    from: MONDAY - 7 * DAY,
    to: MONDAY,
    previousTotal: 10,
    dashboardUrl: 'https://app.example.test',
  });
  assert.deepEqual(d.totals, { attacks: 5, blocked: 4, detectedOnly: 1, bans: 1, sources: 3 });
  assert.equal(d.subject, 'Securovix Defender weekly summary: 5 attacks, 4 blocked (2 Nov – 8 Nov)');
  assert.deepEqual(d.byClass[0], ['sqli', 3]);
  assert.deepEqual(d.byAddress[0], ['203.0.113.5', 3]);
  assert.match(d.text, /5 attacks detected, 4 blocked, 1 recorded without blocking\./);
  assert.match(d.text, /50% fewer than the week before \(10\)\./);
  assert.match(d.text, /1 address banned for repeated attacks\./);
  assert.match(d.text, /SQL injection: 3/);
  assert.match(d.text, /Scanner probing bait paths: 1/);
  assert.match(d.text, /Your apps \(SDK\): 1/);
  assert.match(d.text, /Acme Ltd, 2 Nov – 8 Nov/);
  assert.match(d.text, /https:\/\/app\.example\.test\/#defender/);
  assert.doesNotMatch(d.text, /\n\n\n/, 'no doubled blank lines');
});

test('digest: singular wording, a capped store, and escaped HTML', () => {
  const d = buildDefenseDigest([event('xss', { srcIp: '<img src=x onerror=alert(1)>' })], {
    orgName: '<b>Evil & Co</b>',
    from: MONDAY - 7 * DAY,
    to: MONDAY,
    capped: true,
  });
  assert.match(d.subject, /: 1 attack\+, 1 blocked/);
  assert.match(d.text, /Counts are a minimum/);
  assert.doesNotMatch(d.html, /<img|<b>Evil/, 'attacker-controlled text is escaped');
  assert.match(d.html, /&lt;b&gt;Evil &amp; Co&lt;\/b&gt;/);
  assert.equal(classLabel('cmd-injection'), 'Command injection');
  assert.equal(classLabel('something-new'), 'something-new');
});

// ---------- routes and the scheduled send ----------

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-digest-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'digest-test-secret-that-is-long-enough-01234',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_PUBLIC_URL: 'https://app.example.test/',
  NODE_ENV: 'test',
});
Reflect.deleteProperty(process.env, 'SHANNON_DEFENSE_DIGEST');
const { startDashboard, runDefenseDigests } = await import('./packages/dashboard/server.mjs');
const db = await import('./packages/dashboard/db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, json: await response.json().catch(() => ({})) };
}
async function signup(email) {
  const response = await fetch(`${base}/api/auth/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email.split('@')[0],
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    }),
  });
  const json = await response.json();
  assert.equal(response.status, 200, JSON.stringify(json));
  return {
    cookie: response.headers.get('set-cookie').split(';')[0],
    orgId: json.organizations[0].id,
    userId: json.user.id,
    email,
  };
}

// Emails go to the console in test mode; collect them instead.
async function captureEmails(fn) {
  const realLog = console.log;
  const emails = [];
  console.log = (...args) => {
    const line = args.join(' ');
    const match = /^\[email:development\] to=(\S+) subject=(.*)\n([\s\S]*)$/.exec(line);
    if (match) emails.push({ to: match[1], subject: match[2], text: match[3] });
    else realLog(...args);
  };
  try {
    return { result: await fn(), emails };
  } finally {
    console.log = realLog;
  }
}

let seq = 0;
function seed(orgId, cls, at, extra = {}) {
  db.appendDefenseEvent({
    id: `evt_${++seq}`,
    orgId,
    userId: null,
    at: new Date(at).toISOString(),
    method: 'GET',
    url: '/x',
    cls,
    enforced: true,
    srcIp: '203.0.113.5',
    severity: 'high',
    source: 'self',
    status: 'contained',
    metadata: {},
    createdAt: at,
    ...extra,
  });
}

const owner = await signup('digest-owner@example.test');
const quiet = await signup('digest-quiet@example.test');

test('routes: the card shows the last 7 days and each person can switch the email off', async () => {
  assert.equal((await request('/api/defender/digest')).status, 401);

  const empty = await request('/api/defender/digest', { cookie: quiet.cookie });
  assert.equal(empty.status, 200);
  assert.deepEqual(
    { enabled: empty.json.enabled, eligible: empty.json.eligible, digest: empty.json.digest },
    { enabled: true, eligible: true, digest: null },
  );
  assert.equal((await request('/api/defender/digest/send', { method: 'POST', cookie: quiet.cookie })).status, 409);

  const now = Date.now();
  seed(owner.orgId, 'sqli', now - 60_000);
  seed(owner.orgId, 'xss', now - 120_000, { enforced: false });
  const card = await request('/api/defender/digest', { cookie: owner.cookie });
  assert.deepEqual(card.json.digest.totals, { attacks: 2, blocked: 1, detectedOnly: 1, bans: 0, sources: 1 });
  assert.match(card.json.digest.text, /https:\/\/app\.example\.test\/#defender/);
  assert.equal(
    (await request('/api/defender/digest', { cookie: quiet.cookie })).json.digest,
    null,
    'another organization sees none of it',
  );

  const sent = await captureEmails(() =>
    request('/api/defender/digest/send', { method: 'POST', cookie: owner.cookie }),
  );
  assert.equal(sent.result.status, 200);
  assert.equal(sent.result.json.to, owner.email);
  assert.equal(sent.emails.length, 1);
  assert.equal(sent.emails[0].to, owner.email);
  assert.match(sent.emails[0].subject, /weekly summary: 2 attacks, 1 blocked/);

  const off = await request('/api/defender/digest', { method: 'POST', cookie: owner.cookie, body: { enabled: false } });
  assert.deepEqual(off.json, { ok: true, enabled: false });
  assert.equal((await request('/api/defender/digest', { cookie: owner.cookie })).json.enabled, false);
  await request('/api/defender/digest', { method: 'POST', cookie: owner.cookie, body: { enabled: true } });
});

test('schedule: one email per owner per week, only on time, only when there is something to say', async () => {
  const week = lastCompleteWeek(Date.now());
  const sendTime = week.to + 9 * 3_600_000; // Monday 09:00 UTC
  seed(owner.orgId, 'path-traversal', week.from + DAY);
  seed(owner.orgId, 'honeypot', week.from + 2 * DAY);

  const early = await captureEmails(() => runDefenseDigests(week.to + 3_600_000));
  assert.equal(early.result.sent, 0, 'not before Monday 08:00 UTC');
  const late = await captureEmails(() => runDefenseDigests(week.to + 4 * DAY));
  assert.equal(late.result.sent, 0, 'not more than three days late');

  const first = await captureEmails(() => runDefenseDigests(sendTime));
  assert.equal(first.result.sent, 1);
  assert.equal(first.result.week, week.key);
  assert.deepEqual(
    first.emails.map((e) => e.to),
    [owner.email],
    'the organization with no attacks that week gets nothing',
  );
  assert.match(first.emails[0].subject, /weekly summary: 2 attacks, 2 blocked/);
  assert.match(first.emails[0].text, /Path traversal: 1/);

  const again = await captureEmails(() => runDefenseDigests(sendTime + 3_600_000));
  assert.equal(again.result.sent, 0, 'the same week is never sent twice');
  assert.equal(again.emails.length, 0);
});

test('schedule: respects the per-person switch and the global kill switch', async () => {
  const week = lastCompleteWeek(Date.now());
  const sendTime = week.to + 9 * 3_600_000;
  seed(quiet.orgId, 'ssrf', week.from + DAY);

  await request('/api/defender/digest', { method: 'POST', cookie: quiet.cookie, body: { enabled: false } });
  assert.equal(
    (await captureEmails(() => runDefenseDigests(sendTime))).result.sent,
    0,
    'switched off by the recipient',
  );

  await request('/api/defender/digest', { method: 'POST', cookie: quiet.cookie, body: { enabled: true } });
  process.env.SHANNON_DEFENSE_DIGEST = '0';
  assert.deepEqual((await captureEmails(() => runDefenseDigests(sendTime))).result, { sent: 0, skipped: 'disabled' });
  Reflect.deleteProperty(process.env, 'SHANNON_DEFENSE_DIGEST');

  const sent = await captureEmails(() => runDefenseDigests(sendTime));
  assert.equal(sent.result.sent, 1);
  assert.equal(sent.emails[0].to, quiet.email);
});
