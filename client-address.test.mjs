// The visitor's address behind a host whose proxy puts it in its own header (Railway: X-Real-IP).
// What depends on it: limits per address, and "is this the same machine as before?".
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { clientIpHeader, headerAddress } from './packages/dashboard/client-address.mjs';

test('which header holds the visitor’s address', () => {
  assert.equal(clientIpHeader({ RAILWAY_ENVIRONMENT_ID: 'e' }), 'x-real-ip', 'on Railway it is X-Real-IP');
  assert.equal(clientIpHeader({ RAILWAY_SERVICE_ID: 's' }), 'x-real-ip');
  assert.equal(clientIpHeader({}), '', 'elsewhere Express’s own answer is kept');
  assert.equal(
    clientIpHeader({ SHANNON_CLIENT_IP_HEADER: 'CF-Connecting-IP' }),
    'cf-connecting-ip',
    'another host’s header can be named',
  );
  assert.equal(
    clientIpHeader({ RAILWAY_ENVIRONMENT_ID: 'e', SHANNON_CLIENT_IP_HEADER: 'none' }),
    '',
    'and it can be switched off',
  );
});

test('a header is used only when it holds an address', () => {
  assert.equal(headerAddress({ 'x-real-ip': '203.0.113.10' }, 'x-real-ip'), '203.0.113.10');
  assert.equal(headerAddress({ 'x-real-ip': ' 2001:db8::1 ' }, 'x-real-ip'), '2001:db8::1');
  assert.equal(headerAddress({ 'x-real-ip': ['203.0.113.10', '198.51.100.1'] }, 'x-real-ip'), '203.0.113.10');
  assert.equal(headerAddress({ 'x-real-ip': '<script>' }, 'x-real-ip'), null);
  assert.equal(headerAddress({ 'x-real-ip': '' }, 'x-real-ip'), null);
  assert.equal(headerAddress({}, 'x-real-ip'), null);
  assert.equal(headerAddress({ 'x-real-ip': '203.0.113.10' }, ''), null, 'no header named: nothing is read');
});

// ---------- through the real server, set up the way it runs on Railway ----------
const dataDir = mkdtempSync(join(tmpdir(), 'shannon-client-address-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'client-address-test-secret-that-is-long-enough',
  SHANNON_ENCRYPTION_KEY: 'client-address-test-encryption-key',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_CLIENT_IP_HEADER: 'x-real-ip',
  NODE_ENV: 'test',
});
for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'ZHIPU_API_KEY'])
  Reflect.deleteProperty(process.env, name);
const { startDashboard } = await import('./packages/dashboard/server.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

let edge = 1;
// Every request arrives through a different edge server (the last X-Forwarded-For entry), as on
// Railway; `from` is the visitor's own address, which the edge writes into X-Real-IP.
async function request(path, { method = 'GET', cookie, body, from, headers = {} } = {}) {
  const send = { 'x-forwarded-for': `192.0.2.200, 152.233.29.${edge++ % 250}`, ...headers };
  if (from) send['x-real-ip'] = from;
  if (cookie) send.cookie = cookie;
  if (body !== undefined) send['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers: send,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    json: await response.json().catch(() => ({})),
    cookie: (response.headers.get('set-cookie') || '').split(';')[0],
  };
}

test('limits count the visitor, not the edge server the request came through', async () => {
  const ask = (from) =>
    request('/api/auth/password/request', { method: 'POST', from, body: { email: 'nobody@example.test' } });
  const statuses = [];
  for (let i = 0; i < 7; i++) statuses.push((await ask('203.0.113.10')).status);
  assert.deepEqual(
    statuses,
    [200, 200, 200, 200, 200, 429, 429],
    'five an hour for one visitor, whichever edge server carries them',
  );
  assert.equal((await ask('203.0.113.11')).status, 200, 'another visitor is not affected');
});

test('a machine can be installed again from its own address, and not from someone else’s', async () => {
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    from: '203.0.113.50',
    body: {
      email: 'machines@example.test',
      name: 'Owner',
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  assert.equal(signup.status, 200);
  const made = await request('/api/guard/endpoints/enroll-token', {
    method: 'POST',
    from: '203.0.113.50',
    cookie: signup.cookie,
  });
  assert.equal(made.status, 201);
  const machine = {
    token: made.json.token,
    hostname: 'OFFICE-PC',
    os: 'windows',
    version: '0.1.2',
    machineId: 'office-pc-id',
  };

  const first = await request('/api/endpoint-agent/v1/enroll', { method: 'POST', from: '203.0.113.50', body: machine });
  assert.equal(first.status, 201, JSON.stringify(first.json));
  // The install did not finish, and is run again a moment later: same machine, another edge server.
  const retry = await request('/api/endpoint-agent/v1/enroll', { method: 'POST', from: '203.0.113.50', body: machine });
  assert.equal(retry.status, 201, JSON.stringify(retry.json));
  assert.equal(retry.json.agentId, first.json.agentId);
  // Someone else with a copy of the command, from their own address.
  const stranger = await request('/api/endpoint-agent/v1/enroll', {
    method: 'POST',
    from: '198.51.100.77',
    body: machine,
  });
  assert.equal(stranger.status, 409);
  assert.match(stranger.json.error, /already enrolled and is online from another network/);
});
