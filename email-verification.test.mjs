// A new account proves its email address before it can use the product.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-email-verify-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'email-verify-test-secret-that-is-long-enough',
  SHANNON_ENCRYPTION_KEY: 'email-verify-test-encryption-key',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_REQUIRE_EMAIL_VERIFICATION: '1',
  NODE_ENV: 'test',
});
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);

const { startDashboard, emailVerificationRequired } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

const PASSWORD = 'correct-horse-battery-staple';
let nextIp = 1;
async function request(path, { method = 'GET', cookie, body } = {}) {
  const headers = { 'x-forwarded-for': `198.51.100.${nextIp++ % 250}` };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
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
const signup = (email) =>
  request('/api/auth/signup', {
    method: 'POST',
    body: { email, name: 'New', password: PASSWORD, acceptedTerms: true },
  });

test('when it is asked for: on by default where email can be sent, and it can be switched either way', () => {
  assert.equal(emailVerificationRequired({ NODE_ENV: 'production', RESEND_API_KEY: 'k' }), true);
  assert.equal(
    emailVerificationRequired({ NODE_ENV: 'production', SHANNON_EMAIL_WEBHOOK_URL: 'https://mail.example.test' }),
    true,
  );
  assert.equal(
    emailVerificationRequired({ NODE_ENV: 'production' }),
    false,
    'a service that cannot send email cannot ask for it',
  );
  assert.equal(
    emailVerificationRequired({ NODE_ENV: 'production', RESEND_API_KEY: 'k', SHANNON_REQUIRE_EMAIL_VERIFICATION: '0' }),
    false,
  );
  assert.equal(emailVerificationRequired({ SHANNON_REQUIRE_EMAIL_VERIFICATION: '1' }), true);
  assert.equal(
    emailVerificationRequired({ RESEND_API_KEY: 'k' }),
    false,
    'a copy on someone’s own computer does not ask',
  );
});

test('a new account gets no session until its email address is verified', async () => {
  const made = await signup('new-person@example.test');
  assert.equal(made.status, 202);
  assert.equal(made.json.verificationRequired, true);
  assert.equal(made.cookie, null, 'signing up does not sign in');
  const early = await request('/api/auth/login', {
    method: 'POST',
    body: { email: 'new-person@example.test', password: PASSWORD },
  });
  assert.equal(early.status, 403);
  assert.equal(early.json.emailVerificationRequired, true);
  assert.equal(early.cookie, null);

  const verified = await request('/api/auth/email/verify', {
    method: 'POST',
    body: { token: made.json.developmentToken },
  });
  assert.equal(verified.status, 200);
  assert.ok(verified.cookie, 'opening the link signs in');
  assert.equal((await request('/api/team/context', { cookie: verified.cookie })).status, 200);
  const again = await request('/api/auth/email/verify', {
    method: 'POST',
    body: { token: made.json.developmentToken },
  });
  assert.equal(again.status, 400, 'the link works once');
  const later = await request('/api/auth/login', {
    method: 'POST',
    body: { email: 'new-person@example.test', password: PASSWORD },
  });
  assert.equal(later.status, 200);
});

test('a session that belongs to an unverified account can ask for the link and sign out, and nothing else', async () => {
  // An account from before verification was asked for (or one signed in another way) holds a session.
  process.env.SHANNON_REQUIRE_EMAIL_VERIFICATION = '0';
  const old = await signup('older-account@example.test');
  process.env.SHANNON_REQUIRE_EMAIL_VERIFICATION = '1';
  assert.ok(old.cookie);
  const orgId = old.json.organizations[0].id;

  assert.equal(
    (await request('/api/auth/me', { cookie: old.cookie })).status,
    200,
    'the page can still tell who is signed in',
  );
  for (const [method, path, body] of [
    ['GET', '/api/team/context'],
    ['GET', '/api/defender/overview'],
    ['POST', `/api/team/${orgId}/invitations`, { email: 'stranger@example.test', role: 'viewer' }],
    ['POST', '/api/agent/run', { target: 'http://127.0.0.1:9' }],
    ['GET', '/api/settings'],
  ]) {
    const out = await request(path, { method, cookie: old.cookie, body });
    assert.equal(out.status, 403, `${method} ${path}`);
    assert.equal(out.json.code, 'EMAIL_NOT_VERIFIED');
  }

  const resent = await request('/api/auth/email/resend', {
    method: 'POST',
    body: { email: 'older-account@example.test' },
  });
  assert.equal(resent.status, 200);
  assert.ok(resent.json.developmentToken);
  const verified = await request('/api/auth/email/verify', {
    method: 'POST',
    body: { token: resent.json.developmentToken },
  });
  assert.equal(verified.status, 200);
  assert.equal(
    (await request('/api/team/context', { cookie: old.cookie })).status,
    200,
    'the same session works once the address is verified',
  );
  assert.equal((await request('/api/auth/logout', { method: 'POST', cookie: old.cookie })).status, 200);
});
