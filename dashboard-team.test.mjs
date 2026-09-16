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
