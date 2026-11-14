// End-to-end: the real dashboard with self-defense in enforce mode and the ban enforcing,
// exactly as configured on the live site. Separate file because the settings are read at import.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-defender-live-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'defender-live-test-secret-long-enough-0123',
  NODE_ENV: 'test',
  SHANNON_DEFEND_SELF: '1',
  SHANNON_DEFEND_SELF_MODE: 'enforce',
  SHANNON_DEFEND_SELF_BAN: '1',
  SHANNON_DEFEND_SELF_BAN_MODE: 'enforce',
});

const { startDashboard } = await import('./packages/dashboard/server.mjs');
const edb = await import('./packages/dashboard/enterprise-db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

const get = (path, headers = {}) => fetch(base + path, { headers });

test('HSTS is sent only over HTTPS', async () => {
  assert.equal((await get('/pricing')).headers.get('strict-transport-security'), null);
  const secure = await get('/pricing', { 'x-forwarded-proto': 'https' });
  assert.equal(secure.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
});

test('enforce mode: strict attacks are blocked, ordinary traffic passes, a honeypot bans and persists', async () => {
  // Each attacker gets its own forwarded IP (trust proxy is on), so bans do not bleed between steps.
  const as = (ip) => ({ 'x-forwarded-for': ip });

  assert.equal((await get('/?name=O%27Brien', as('198.51.100.1'))).status, 200);
  assert.equal((await get('/?q=%3Cscript%3Ealert(1)%3C/script%3E', as('198.51.100.1'))).status, 403);
  const login = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...as('198.51.100.2') },
    body: JSON.stringify({ email: "x' OR '1'='1", password: 'x' }),
  });
  assert.equal(login.status, 403);
  const normalLogin = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...as('198.51.100.3') },
    body: JSON.stringify({ email: "o'brien@example.com", password: 'wrong-password' }),
  });
  assert.notEqual(normalLogin.status, 403, 'an apostrophe in an email is not an attack');

  assert.equal((await get('/.env', as('198.51.100.66'))).status, 404);
  const banned = await get('/pricing', as('198.51.100.66'));
  assert.equal(banned.status, 403);
  assert.match((await banned.json()).error, /repeat offender/);
  assert.equal((await get('/pricing', as('198.51.100.67'))).status, 200);

  await new Promise((r) => setTimeout(r, 20));
  const stored = await edb.defenderBans.list({}, { orderBy: 'until' });
  assert.ok(
    stored.some((row) => row.ip === '198.51.100.66' && row.reason === 'honeypot'),
    'ban persisted',
  );
});
