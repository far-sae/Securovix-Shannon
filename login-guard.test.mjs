// Per-account lockout: the unit, then the real sign-in routes with an attacker that changes address
// on every attempt (which the per-address limit alone cannot stop).
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const { createLoginGuard } = await import('./packages/dashboard/login-guard.mjs');

test('guard: locks after the limit, for the lock period, and forgets on success', () => {
  let t = 1_000_000;
  const guard = createLoginGuard({ limit: 3, windowMs: 60_000, lockMs: 120_000, now: () => t });
  assert.deepEqual(guard.check('password', 'a@example.test'), { locked: false });
  assert.equal(guard.fail('password', 'a@example.test').locked, false);
  assert.equal(guard.fail('password', 'A@Example.test ').remaining, 1, 'case and spacing do not make a new account');
  const tripped = guard.fail('password', 'a@example.test');
  assert.deepEqual(tripped, { locked: true, retryAfter: 120, justLocked: true });
  assert.equal(guard.check('password', 'a@example.test').locked, true);
  assert.equal(guard.check('password', 'b@example.test').locked, false, 'other accounts are unaffected');
  assert.equal(guard.check('mfa', 'a@example.test').locked, false, 'scopes are separate');

  // Attempts during the lock do not extend it.
  t += 60_000;
  assert.equal(guard.fail('password', 'a@example.test').justLocked, false);
  assert.equal(guard.check('password', 'a@example.test').retryAfter, 60);
  t += 60_001;
  assert.equal(guard.check('password', 'a@example.test').locked, false, 'the lock ends on schedule');

  guard.fail('password', 'a@example.test');
  guard.fail('password', 'a@example.test');
  guard.succeed('password', 'a@example.test');
  assert.equal(guard.fail('password', 'a@example.test').remaining, 2, 'a success clears the count');
});

test('guard: old failures fall out of the window, and memory is bounded', () => {
  let t = 0;
  const guard = createLoginGuard({ limit: 3, windowMs: 1000, lockMs: 1000, maxKeys: 5, now: () => t });
  guard.fail('password', 'slow@example.test');
  guard.fail('password', 'slow@example.test');
  t = 1500;
  assert.equal(guard.fail('password', 'slow@example.test').locked, false, 'two stale failures no longer count');
  for (let i = 0; i < 50; i++) guard.fail('password', `user${i}@example.test`);
  assert.equal(guard.size(), 5);
});

// ---------- the real routes ----------

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-lockout-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'lockout-test-secret-that-is-long-enough-0123',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_LOGIN_LOCK_THRESHOLD: '4',
  NODE_ENV: 'test',
});
const { startDashboard } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

let nextIp = 1;
// Every call comes from a new address, so the per-address limit never triggers.
async function post(path, body) {
  const response = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `198.51.100.${nextIp++ % 250}` },
    body: JSON.stringify(body),
  });
  return { status: response.status, json: await response.json().catch(() => ({})), response };
}
const PASSWORD = 'correct-horse-battery-staple';
const signup = (email) => post('/api/auth/signup', { email, name: 'Test', password: PASSWORD, acceptedTerms: true });

test('sign-in: an account locks after repeated wrong passwords from rotating addresses', async () => {
  const email = 'victim@example.test';
  assert.equal((await signup(email)).status, 200);
  assert.equal((await post('/api/auth/login', { email, password: PASSWORD })).status, 200);

  for (let i = 0; i < 4; i++) {
    assert.equal((await post('/api/auth/login', { email, password: `wrong-${i}` })).status, 401);
  }
  const locked = await post('/api/auth/login', { email, password: PASSWORD });
  assert.equal(locked.status, 429, 'even the right password is refused while locked');
  assert.equal(locked.json.code, 'ACCOUNT_LOCKED');
  assert.match(locked.json.error, /reset your password/);
  assert.ok(Number(locked.response.headers.get('retry-after')) > 0);

  // Another account is untouched.
  const other = 'bystander@example.test';
  assert.equal((await signup(other)).status, 200);
  assert.equal((await post('/api/auth/login', { email: other, password: PASSWORD })).status, 200);
});

test('sign-in: an unknown email locks the same way, so the response reveals nothing', async () => {
  const email = 'nobody@example.test';
  for (let i = 0; i < 4; i++) {
    assert.equal((await post('/api/auth/login', { email, password: 'x' })).status, 401);
  }
  const locked = await post('/api/auth/login', { email, password: 'x' });
  assert.equal(locked.status, 429);
  assert.equal(locked.json.code, 'ACCOUNT_LOCKED');
});

test('sign-in: a successful sign-in resets the count, and a password reset lifts a lock', async () => {
  const email = 'careful@example.test';
  assert.equal((await signup(email)).status, 200);
  for (let i = 0; i < 3; i++) await post('/api/auth/login', { email, password: 'typo' });
  assert.equal((await post('/api/auth/login', { email, password: PASSWORD })).status, 200);
  for (let i = 0; i < 3; i++) {
    assert.equal((await post('/api/auth/login', { email, password: 'typo' })).status, 401, 'the count started again');
  }
  assert.equal((await post('/api/auth/login', { email, password: 'typo' })).status, 401);
  assert.equal((await post('/api/auth/login', { email, password: PASSWORD })).status, 429, 'now locked');

  const requested = await post('/api/auth/password/request', { email });
  assert.ok(requested.json.developmentToken, 'test mode returns the reset token');
  const fresh = 'a-brand-new-passphrase-2026';
  assert.equal(
    (await post('/api/auth/password/reset', { token: requested.json.developmentToken, password: fresh })).status,
    200,
  );
  assert.equal(
    (await post('/api/auth/login', { email, password: fresh })).status,
    200,
    'the owner is back in straight away',
  );
});
