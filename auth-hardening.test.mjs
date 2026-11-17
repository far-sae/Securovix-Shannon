// Who gets a session, and what a member can read. Each test is a way into someone else's account
// (or a secret) that must stay closed, run through the real routes.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-auth-hardening-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'auth-hardening-test-secret-that-is-long-enough',
  SHANNON_ENCRYPTION_KEY: 'auth-hardening-test-encryption-key',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  // No special trust for requests from this machine: every caller here is an ordinary user.
  SHANNON_OWNER_BYPASS: '0',
  NODE_ENV: 'test',
});
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);

const { totpCode } = await import('./packages/dashboard/enterprise-security.mjs');
const { startDashboard, publicJob, devTokensAllowed } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

const PASSWORD = 'correct-horse-battery-staple';
let nextIp = 1;
// Every call comes from a new address, so the per-address limits never decide a test.
async function request(path, { method = 'GET', cookie, body, headers = {} } = {}) {
  const send = { 'x-forwarded-for': `198.51.100.${nextIp++ % 250}`, ...headers };
  if (cookie) send.cookie = cookie;
  if (body !== undefined) send['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers: send,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const setCookie = response.headers.get('set-cookie') || '';
  return {
    status: response.status,
    json: await response.json().catch(() => ({})),
    cookie:
      /shannon_session=[^;]+/.test(setCookie) && !/shannon_session=;/.test(setCookie) ? setCookie.split(';')[0] : null,
  };
}
async function account(email) {
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: { email, name: email.split('@')[0], password: PASSWORD, acceptedTerms: true },
  });
  assert.equal(out.status, 200);
  return { email, cookie: out.cookie, id: out.json.user.id, orgId: out.json.organizations[0].id };
}
const whoami = async (cookie) => (await request('/api/auth/me', { cookie })).json.user?.email || null;
async function invite(owner, email, role = 'viewer') {
  const out = await request(`/api/team/${owner.orgId}/invitations`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { email, role },
  });
  assert.equal(out.status, 201);
  assert.ok(out.json.developmentToken, 'test mode hands back the invitation token');
  return out.json.developmentToken;
}
async function turnOnTwoStep(person) {
  const setup = await request('/api/auth/mfa/setup', {
    method: 'POST',
    cookie: person.cookie,
    body: { password: PASSWORD },
  });
  assert.equal(setup.status, 200);
  const enabled = await request('/api/auth/mfa/enable', {
    method: 'POST',
    cookie: person.cookie,
    body: { code: totpCode(setup.json.secret) },
  });
  assert.equal(enabled.status, 200);
  return { secret: setup.json.secret, cookie: enabled.cookie };
}

test('an invitation never signs anyone in to an account that already exists', async () => {
  const victim = await account('victim@example.test');
  const inviter = await account('inviter@example.test');
  const token = await invite(inviter, victim.email, 'admin');

  // Whoever holds the link, with no session at all.
  const anonymous = await request('/api/auth/invitations/accept', { method: 'POST', body: { token } });
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.json.signInRequired, true);
  assert.equal(anonymous.cookie, null, 'no session is handed out');
  assert.equal(anonymous.json.user, undefined);

  // The inviter, signed in as themselves, using the link they caused to be sent.
  const asInviter = await request('/api/auth/invitations/accept', {
    method: 'POST',
    cookie: inviter.cookie,
    body: { token },
  });
  assert.equal(asInviter.status, 401);
  assert.equal(asInviter.cookie, null);
  assert.equal(await whoami(inviter.cookie), inviter.email, 'the inviter is still only themselves');

  // A refused attempt does not use the invitation up: the invited person, signed in, accepts it.
  const accepted = await request('/api/auth/invitations/accept', {
    method: 'POST',
    cookie: victim.cookie,
    body: { token },
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.json.organization.id, inviter.orgId);
  const members = await request(`/api/team/${inviter.orgId}/members`, { cookie: inviter.cookie });
  assert.ok(
    members.json.members.some(
      (member) =>
        member.userId === victim.id ||
        member.user?.id === victim.id ||
        member.id === victim.id ||
        member.email === victim.email,
    ),
  );

  // And it works once.
  const again = await request('/api/auth/invitations/accept', {
    method: 'POST',
    cookie: victim.cookie,
    body: { token },
  });
  assert.equal(again.status, 400);
});

test('an invitation to a new address still creates the account and signs it in', async () => {
  const inviter = await account('inviter-two@example.test');
  const token = await invite(inviter, 'newcomer@example.test');
  const short = await request('/api/auth/invitations/accept', {
    method: 'POST',
    body: { token, password: 'short', acceptedTerms: true },
  });
  assert.equal(short.status, 400);
  const accepted = await request('/api/auth/invitations/accept', {
    method: 'POST',
    body: { token, password: PASSWORD, name: 'New', acceptedTerms: true },
  });
  assert.equal(accepted.status, 200);
  assert.ok(accepted.cookie);
  assert.equal(await whoami(accepted.cookie), 'newcomer@example.test');
});

test('a password reset does not skip two-step sign-in', async () => {
  const person = await account('two-step@example.test');
  const twoStep = await turnOnTwoStep(person);
  const asked = await request('/api/auth/password/request', { method: 'POST', body: { email: person.email } });
  assert.ok(asked.json.developmentToken);
  const reset = await request('/api/auth/password/reset', {
    method: 'POST',
    body: { token: asked.json.developmentToken, password: 'a-brand-new-password-1' },
  });
  assert.equal(reset.status, 200);
  assert.equal(reset.json.mfaRequired, true);
  assert.equal(reset.cookie, null, 'the mailbox alone does not open the account');
  assert.equal(reset.json.user, undefined);
  assert.equal(await whoami(twoStep.cookie), null, 'sessions from before the reset are over');

  const wrong = await request('/api/auth/mfa/login', {
    method: 'POST',
    body: { challenge: reset.json.challenge, code: '000000' },
  });
  assert.equal(wrong.status, 401);
  const right = await request('/api/auth/mfa/login', {
    method: 'POST',
    body: { challenge: reset.json.challenge, code: totpCode(twoStep.secret) },
  });
  assert.equal(right.status, 200);
  assert.equal(await whoami(right.cookie), person.email);

  // Without two-step sign-in a reset signs in directly, as before.
  const plain = await account('one-step@example.test');
  const asked2 = await request('/api/auth/password/request', { method: 'POST', body: { email: plain.email } });
  const reset2 = await request('/api/auth/password/reset', {
    method: 'POST',
    body: { token: asked2.json.developmentToken, password: 'a-brand-new-password-2' },
  });
  assert.equal(await whoami(reset2.cookie), plain.email);
});

test('signing out ends the session on the server, not only in the browser', async () => {
  const person = await account('leaver@example.test');
  assert.equal(await whoami(person.cookie), person.email);
  const out = await request('/api/auth/logout', { method: 'POST', cookie: person.cookie });
  assert.equal(out.status, 200);
  assert.equal(await whoami(person.cookie), null, 'a copy of the old cookie no longer works');
  // Wait a moment so the new session is not issued in the same millisecond as the sign-out.
  await new Promise((resolve) => setTimeout(resolve, 5));
  const back = await request('/api/auth/login', { method: 'POST', body: { email: person.email, password: PASSWORD } });
  assert.equal(await whoami(back.cookie), person.email);
});

test('reset links for one address are capped, and the answer stays the same', async () => {
  const person = await account('flooded@example.test');
  const answers = [];
  for (let i = 0; i < 5; i++)
    answers.push(await request('/api/auth/password/request', { method: 'POST', body: { email: person.email } }));
  assert.ok(answers.every((answer) => answer.status === 200 && /If an account exists/.test(answer.json.message)));
  assert.equal(
    answers.filter((answer) => answer.json.developmentToken).length,
    3,
    'three links an hour, however many addresses ask',
  );
});

test('a queued email is listed without its text, so a link inside it stays with its recipient', () => {
  const job = {
    id: 'j1',
    type: 'email',
    status: 'succeeded',
    secretEnc: 'x',
    payload: {
      to: 'someone@example.test',
      subject: 'You were invited',
      text: 'Join here\n\nhttps://app.example.test/?invite=SECRET-TOKEN',
    },
  };
  const shown = publicJob(job);
  assert.equal(JSON.stringify(shown).includes('SECRET-TOKEN'), false);
  assert.deepEqual(shown.payload, { to: 'someone@example.test', subject: 'You were invited' });
  assert.equal(shown.secretEnc, undefined);
  // Other kinds of work keep the details the page needs.
  assert.deepEqual(
    publicJob({ id: 'j2', type: 'scan', payload: { scanId: 's1', targetUrl: 'https://example.test' } }).payload,
    { scanId: 's1', targetUrl: 'https://example.test' },
  );
});

test('sign-in tokens are handed back in an answer only when asked for outside production', () => {
  assert.equal(devTokensAllowed({ NODE_ENV: 'test' }), true);
  assert.equal(devTokensAllowed({ SHANNON_DEV_TOKENS: '1' }), true);
  assert.equal(devTokensAllowed({}), false, 'a deployment that forgot NODE_ENV does not leak reset links');
  assert.equal(devTokensAllowed({ NODE_ENV: 'development' }), false);
  assert.equal(devTokensAllowed({ NODE_ENV: 'production', SHANNON_DEV_TOKENS: '1' }), false);
});

test('another website cannot start an AI Agent run in a signed-in visitor’s name', async () => {
  const person = await account('visitor@example.test');
  for (const path of [
    '/api/agent/run/stream?target=http%3A%2F%2F127.0.0.1%3A9',
    '/api/agent/team/stream?target=http%3A%2F%2F127.0.0.1%3A9',
  ]) {
    const crossSite = await request(path, { cookie: person.cookie, headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(crossSite.status, 403, path);
  }
});

test('API answers are never stored by browsers or proxies', async () => {
  const person = await account('cache@example.test');
  const me = await fetch(`${base}/api/auth/me`, { headers: { cookie: person.cookie } });
  assert.equal(me.headers.get('cache-control'), 'no-store');
});

// ---------- what each role may do ----------
async function viewerOf(owner, email) {
  const token = await invite(owner, email, 'viewer');
  const accepted = await request('/api/auth/invitations/accept', {
    method: 'POST',
    body: { token, password: PASSWORD, name: 'Viewer', acceptedTerms: true },
  });
  assert.equal(accepted.status, 200);
  const cookie = accepted.cookie;
  await request('/api/team/active', { method: 'POST', cookie, body: { orgId: owner.orgId } });
  return { cookie, headers: { 'x-shannon-org': owner.orgId } };
}

test('a viewer can read a finding and cannot change one', async () => {
  const owner = await account('findings-owner@example.test');
  const viewer = await viewerOf(owner, 'findings-viewer@example.test');
  const made = await request(`/api/team/${owner.orgId}/findings`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { title: 'Outdated library', severity: 'low' },
  });
  assert.equal(made.status, 201);
  const id = made.json.finding.id;
  const list = await request(`/api/team/${owner.orgId}/findings`, { cookie: viewer.cookie });
  assert.equal(list.status, 200);
  const touched = await request(`/api/team/${owner.orgId}/findings/${id}`, {
    method: 'PATCH',
    cookie: viewer.cookie,
    body: {},
  });
  assert.equal(touched.status, 403, 'even a change that changes nothing is refused, so it leaves no trail of events');
  const triaged = await request(`/api/team/${owner.orgId}/findings/${id}`, {
    method: 'PATCH',
    cookie: owner.cookie,
    body: { status: 'triaged' },
  });
  assert.equal(triaged.status, 200);
});

test('asking the AI for a fix needs a role that may fix things', async () => {
  const owner = await account('patch-owner@example.test');
  const viewer = await viewerOf(owner, 'patch-viewer@example.test');
  const body = { finding: { cls: 'xss' }, snippet: 'res.send(req.query.q)' };
  assert.equal((await request('/api/agent/patch', { method: 'POST', body })).status, 401);
  assert.equal(
    (await request('/api/agent/patch', { method: 'POST', cookie: viewer.cookie, headers: viewer.headers, body }))
      .status,
    403,
  );
});

test('how the platform is set up is shown to its operator only', async () => {
  const owner = await account('readiness-owner@example.test');
  const seen = await request('/api/system/readiness', { cookie: owner.cookie });
  assert.equal(seen.status, 200);
  assert.ok(seen.json.checks.length > 5);
  for (const check of seen.json.checks) assert.deepEqual(Object.keys(check).sort(), ['key', 'label', 'status']);
  assert.equal(JSON.stringify(seen.json).includes('SHANNON_'), false, 'no variable names or addresses of the platform');
});

test('a monitor’s alert address must be a public one', async () => {
  const owner = await account('monitor-owner@example.test');
  const internal = await request('/api/agent/monitors', {
    method: 'POST',
    cookie: owner.cookie,
    body: { target: 'http://127.0.0.1:9', webhookUrl: 'http://127.0.0.1:9/hook' },
  });
  assert.equal(internal.status, 400);
  assert.match(internal.json.error, /public/);
  const metadata = await request('/api/agent/monitors', {
    method: 'POST',
    cookie: owner.cookie,
    body: { target: 'http://127.0.0.1:9', webhookUrl: 'http://[::ffff:169.254.169.254]/latest' },
  });
  assert.equal(metadata.status, 400);
  const none = await request('/api/agent/monitors', {
    method: 'POST',
    cookie: owner.cookie,
    body: { target: 'http://127.0.0.1:9' },
  });
  assert.equal(none.status, 200);
});

test('on the hosted service a target on "this machine" is not exempt from proof of ownership', async () => {
  const { localTargetsAllowed } = await import('./packages/dashboard/server.mjs');
  assert.equal(localTargetsAllowed({ NODE_ENV: 'production' }), false);
  assert.equal(localTargetsAllowed({ NODE_ENV: 'production', SHANNON_ALLOW_LOCAL_TARGETS: '1' }), true);
  assert.equal(localTargetsAllowed({}), true, 'a copy on someone’s own computer can test local sites');
});

test('on the hosted service a target that points at a private network is refused, however it is written', async () => {
  const { privateTarget } = await import('./packages/dashboard/server.mjs');
  const hosted = false; // "local targets allowed" is off, as in production
  for (const target of [
    '127.0.0.1',
    'http://127.0.0.1:9/',
    'localhost',
    '10.0.0.5',
    '169.254.169.254',
    'https://[::1]/',
    'https://[::ffff:169.254.169.254]/',
    'no-such-host.invalid',
  ])
    assert.equal(await privateTarget(target, hosted), true, target);
  assert.equal(await privateTarget('8.8.8.8', hosted), false, 'a public address passes');
  assert.equal(await privateTarget('127.0.0.1', true), false, 'a copy on someone’s own computer may test local sites');
});

test('saving the AI settings keeps the account’s other choices, and refuses an address that is not http(s)', async () => {
  const owner = await account('settings-owner@example.test');
  const off = await request('/api/defender/digest', { method: 'POST', cookie: owner.cookie, body: { enabled: false } });
  assert.equal(off.status, 200, JSON.stringify(off.json));
  const saved = await request('/api/settings', {
    method: 'POST',
    cookie: owner.cookie,
    body: { provider: 'claude', model: 'claude-opus-5-5', baseUrl: '', role: 'owner', orgId: 'someone-else' },
  });
  assert.equal(saved.status, 200);
  const digest = await request('/api/defender/digest', { cookie: owner.cookie });
  assert.equal(digest.json.enabled, false, 'the weekly summary stays switched off');
  const odd = await request('/api/settings', {
    method: 'POST',
    cookie: owner.cookie,
    body: { baseUrl: 'file:///etc/passwd' },
  });
  assert.equal(odd.status, 400);
  assert.equal((await request('/api/settings', { method: 'POST', body: { baseUrl: '' } })).status, 401);
});
