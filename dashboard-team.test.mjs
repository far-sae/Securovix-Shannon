import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-team-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'dashboard-team-test-secret-that-is-long-enough';
process.env.NODE_ENV = 'test';

const { startDashboard } = await import('./packages/dashboard/server.mjs');
const { totpCode } = await import('./packages/dashboard/enterprise-security.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body, headers: extraHeaders = {} } = {}) {
  const headers = { ...extraHeaders };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  return { response, json, setCookie: response.headers.get('set-cookie') || '' };
}

async function signup(email, name) {
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: { email, name, password: 'correct-horse-battery-staple', acceptedTerms: true },
  });
  assert.equal(out.response.status, 200);
  return { ...out, cookie: out.setCookie.split(';')[0] };
}

test('dashboard APIs require authentication and enforce organization roles', async () => {
  const anonymous = await request('/api/scans');
  assert.equal(anonymous.response.status, 401);

  const owner = await signup('owner@example.test', 'Owner');
  const orgId = owner.json.organizations[0].id;
  const project = await request(`/api/team/${orgId}/projects`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { name: 'Payments', criticality: 'critical' },
  });
  assert.equal(project.response.status, 201);

  const viewer = await signup('viewer@example.test', 'Viewer');
  const added = await request(`/api/team/${orgId}/members`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { email: 'viewer@example.test', role: 'viewer' },
  });
  assert.equal(added.response.status, 201);

  const active = await request('/api/team/active', {
    method: 'POST',
    cookie: viewer.cookie,
    body: { orgId },
  });
  assert.equal(active.response.status, 200);
  const orgCookie = active.setCookie.split(';')[0];
  const viewerCookies = `${viewer.cookie}; ${orgCookie}`;

  const readable = await request(`/api/team/${orgId}/projects`, { cookie: viewerCookies });
  assert.equal(readable.response.status, 200);
  assert.equal(readable.json.projects.length, 1);

  const forbidden = await request(`/api/team/${orgId}/projects`, {
    method: 'POST',
    cookie: viewerCookies,
    body: { name: 'Should not exist' },
  });
  assert.equal(forbidden.response.status, 403);
});

test('MFA supports password reauthentication, TOTP login, recovery rotation and secure disable', async () => {
  const password = 'correct-horse-battery-staple';
  const account = await signup('mfa-owner@example.test', 'MFA Owner');

  const initial = await request('/api/auth/mfa/status', { cookie: account.cookie });
  assert.equal(initial.response.status, 200);
  assert.equal(initial.json.enabled, false);
  assert.equal(initial.json.passwordReauthenticationRequired, true);

  const rejectedSetup = await request('/api/auth/mfa/setup', {
    method: 'POST',
    cookie: account.cookie,
    body: { password: 'wrong-password' },
  });
  assert.equal(rejectedSetup.response.status, 401);

  const setup = await request('/api/auth/mfa/setup', {
    method: 'POST',
    cookie: account.cookie,
    body: { password },
  });
  assert.equal(setup.response.status, 200);
  assert.match(setup.json.uri, /^otpauth:\/\/totp\//);
  assert.match(setup.json.qrDataUrl, /^data:image\/png;base64,/);

  const invalidEnable = await request('/api/auth/mfa/enable', {
    method: 'POST',
    cookie: account.cookie,
    body: { code: '000000' },
  });
  assert.equal(invalidEnable.response.status, 400);

  const enabled = await request('/api/auth/mfa/enable', {
    method: 'POST',
    cookie: account.cookie,
    body: { code: totpCode(setup.json.secret) },
  });
  assert.equal(enabled.response.status, 200);
  assert.equal(enabled.json.recoveryCodes.length, 10);
  let currentCookie = enabled.setCookie.split(';')[0];

  const oldSession = await request('/api/auth/mfa/status', { cookie: account.cookie });
  assert.equal(oldSession.response.status, 401);
  const status = await request('/api/auth/mfa/status', { cookie: currentCookie });
  assert.equal(status.json.enabled, true);
  assert.equal(status.json.recoveryCodesRemaining, 10);

  const passwordLogin = await request('/api/auth/login', {
    method: 'POST',
    body: { email: 'mfa-owner@example.test', password },
  });
  assert.equal(passwordLogin.json.mfaRequired, true);
  const recoveryLogin = await request('/api/auth/mfa/login', {
    method: 'POST',
    body: { challenge: passwordLogin.json.challenge, code: enabled.json.recoveryCodes[0] },
  });
  assert.equal(recoveryLogin.response.status, 200);

  const secondPasswordLogin = await request('/api/auth/login', {
    method: 'POST',
    body: { email: 'mfa-owner@example.test', password },
  });
  const replayedRecovery = await request('/api/auth/mfa/login', {
    method: 'POST',
    body: { challenge: secondPasswordLogin.json.challenge, code: enabled.json.recoveryCodes[0] },
  });
  assert.equal(replayedRecovery.response.status, 401);

  const rotated = await request('/api/auth/mfa/recovery-codes', {
    method: 'POST',
    cookie: currentCookie,
    body: { code: totpCode(setup.json.secret) },
  });
  assert.equal(rotated.response.status, 200);
  assert.equal(rotated.json.recoveryCodes.length, 10);
  assert.notDeepEqual(rotated.json.recoveryCodes, enabled.json.recoveryCodes);
  currentCookie = rotated.setCookie.split(';')[0];

  const disabled = await request('/api/auth/mfa', {
    method: 'DELETE',
    cookie: currentCookie,
    body: { code: rotated.json.recoveryCodes[0] },
  });
  assert.equal(disabled.response.status, 200);
  currentCookie = disabled.setCookie.split(';')[0];
  const finalStatus = await request('/api/auth/mfa/status', { cookie: currentCookie });
  assert.equal(finalStatus.json.enabled, false);
  assert.equal(finalStatus.json.recoveryCodesRemaining, 0);
});

test('production readiness reports real dependencies and billing never grants fake entitlements', async () => {
  const owner = await signup('readiness-owner@example.test', 'Readiness Owner');
  const readiness = await request('/api/system/readiness', { cookie: owner.cookie });
  assert.equal(readiness.response.status, 200);
  assert.ok(Array.isArray(readiness.json.checks));
  assert.ok(readiness.json.checks.some((item) => item.key === 'worker'));
  assert.ok(readiness.json.checks.some((item) => item.key === 'browser'));
  assert.ok(readiness.json.checks.some((item) => item.key === 'sandbox'));

  const plans = await request('/api/auth/plans');
  assert.equal(plans.response.status, 200);
  assert.equal(plans.json.billingEnabled, false);
  assert.deepEqual(plans.json.plans.map((plan) => plan.plan), ['free']);

  const subscribe = await request('/api/auth/subscribe', {
    method: 'POST',
    cookie: owner.cookie,
    body: { plan: 'pro', cycle: 'monthly' },
  });
  assert.equal(subscribe.response.status, 410);
});

test('Defender supports incident workflow and revocable SDK credentials', async () => {
  const owner = await signup('defender-owner@example.test', 'Defender Owner');

  const sdk = await request('/api/defender/sdk', { cookie: owner.cookie });
  assert.equal(sdk.response.status, 200);
  assert.match(sdk.json.apiKey, /^sk_/);

  const edgeRoutes = await request('/api/defender/edge/routes', {
    headers: { authorization: `Bearer ${sdk.json.apiKey}`, 'x-shannon-edge-instance': 'edge-test' },
  });
  assert.equal(edgeRoutes.response.status, 200);
  const readiness = await request('/api/system/readiness', { cookie: owner.cookie });
  assert.equal(readiness.json.checks.find((item) => item.key === 'edge').status, 'ready');

  const reported = await request('/api/defender/report', {
    method: 'POST',
    headers: { authorization: `Bearer ${sdk.json.apiKey}` },
    body: {
      detections: [
        {
          method: 'POST',
          url: '/api/admin?next=../../etc/passwd',
          cls: 'path-traversal',
          enforced: false,
          srcIp: '203.0.113.10',
        },
      ],
    },
  });
  assert.equal(reported.response.status, 200);
  assert.equal(reported.json.accepted, 1);

  const overview = await request('/api/defender/overview', { cookie: owner.cookie });
  assert.equal(overview.response.status, 200);
  assert.equal(overview.json.stats.open, 1);
  assert.equal(overview.json.events[0].severity, 'high');
  assert.equal(overview.json.events[0].source, 'sdk');

  const incident = overview.json.events[0];
  const triaged = await request(`/api/defender/events/${incident.id}`, {
    method: 'PATCH',
    cookie: owner.cookie,
    body: { status: 'investigating' },
  });
  assert.equal(triaged.response.status, 200);
  assert.equal(triaged.json.event.status, 'investigating');

  const rotated = await request('/api/defender/sdk/rotate', { method: 'POST', cookie: owner.cookie });
  assert.equal(rotated.response.status, 200);
  assert.notEqual(rotated.json.apiKey, sdk.json.apiKey);

  const oldCredential = await request('/api/defender/report', {
    method: 'POST',
    headers: { authorization: `Bearer ${sdk.json.apiKey}` },
    body: { detections: [{ method: 'GET', url: '/', cls: 'xss' }] },
  });
  assert.equal(oldCredential.response.status, 401);

  const newCredential = await request('/api/defender/report', {
    method: 'POST',
    headers: { authorization: `Bearer ${rotated.json.apiKey}` },
    body: { detections: [{ method: 'GET', url: '/', cls: 'xss' }] },
  });
  assert.equal(newCredential.response.status, 200);
});
