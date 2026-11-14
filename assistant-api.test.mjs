import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-assistant-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'assistant-test-secret-that-is-long-enough-123';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.NODE_ENV = 'test';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-not-real';
Reflect.deleteProperty(process.env, 'SHANNON_ASSISTANT_MODEL');

// Fake Claude: records every request, never touches the network.
const calls = [];
let nextChat = () => ({
  content: [{ type: 'text', text: '**Fix the SQL injection first.**\n<script>alert(1)</script>' }],
  stop_reason: 'end_turn',
});
const fakeClient = {
  beta: {
    messages: {
      create: async (params) => {
        calls.push({ kind: 'create', params });
        return { model: params.model, usage: { input_tokens: 10, output_tokens: 20 }, ...nextChat(params) };
      },
      stream: (params) => {
        calls.push({ kind: 'stream', params });
        return {
          finalMessage: async () => ({
            model: params.model,
            stop_reason: 'end_turn',
            usage: {},
            content: [{ type: 'text', text: '# Assessment\n\nAll good. <img src=x onerror=alert(1)>' }],
          }),
        };
      },
    },
  },
};
const ai = await import('./packages/dashboard/assistant-ai.mjs');
ai.setAssistantClientFactory(() => fakeClient);

const { startDashboard } = await import('./packages/dashboard/server.mjs');
const db = await import('./packages/dashboard/db.mjs');
const edb = await import('./packages/dashboard/enterprise-db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  if (body !== undefined) h['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json = {};
  try {
    json = JSON.parse(text);
  } catch {}
  return { response, json, text };
}

async function signup(email) {
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: { email, name: email.split('@')[0], password: 'correct-horse-battery-staple', acceptedTerms: true },
  });
  assert.equal(out.response.status, 200, out.text);
  const cookie = out.response.headers.get('set-cookie').split(';')[0];
  const me = await request('/api/auth/me', { cookie });
  return { cookie, orgId: out.json.organizations[0].id, userId: me.json.user?.id || out.json.user?.id };
}

const owner = await signup('assistant-owner@example.test');
const stranger = await signup('assistant-stranger@example.test');

test('chat sends org context as data with the documented model settings', async () => {
  const before = calls.length;
  const first = await request('/api/assistant/chat', {
    method: 'POST',
    cookie: owner.cookie,
    body: { message: 'What should we fix first?' },
  });
  assert.equal(first.response.status, 200, first.text);
  assert.equal(calls.length, before + 1);
  const { params } = calls.at(-1);
  assert.equal(params.model, 'claude-opus-5-5');
  assert.deepEqual(params.thinking, { type: 'adaptive' });
  assert.deepEqual(params.output_config, { effort: 'medium' });
  assert.equal(params.fallbacks, 'default');
  assert.deepEqual(params.betas, ['server-side-fallback-2026-07-01']);
  assert.match(params.system[0].text, /Securovix security assistant/);
  assert.deepEqual(params.system[0].cache_control, { type: 'ephemeral' });
  assert.match(params.system[1].text, /^<org_context>/);
  assert.deepEqual(params.messages, [{ role: 'user', content: 'What should we fix first?' }]);
  assert.match(first.json.reply.html, /<strong>Fix the SQL injection first.<\/strong>/);
  assert.doesNotMatch(first.json.reply.html, /<script>/);

  const conversationId = first.json.conversation.id;
  const second = await request('/api/assistant/chat', {
    method: 'POST',
    cookie: owner.cookie,
    body: { message: 'And after that?', conversationId },
  });
  assert.equal(second.response.status, 200);
  assert.equal(calls.at(-1).params.messages.length, 3);

  const foreign = await request('/api/assistant/chat', {
    method: 'POST',
    cookie: stranger.cookie,
    body: { message: 'hi', conversationId },
  });
  assert.equal(foreign.response.status, 404);
  assert.equal(
    (await request(`/api/assistant/conversations/${conversationId}`, { cookie: stranger.cookie })).response.status,
    404,
  );
  const mine = await request(`/api/assistant/conversations/${conversationId}`, { cookie: owner.cookie });
  assert.equal(mine.json.conversation.messages.length, 4);
});

test('/remember saves organization memory without calling the model, and later chats include it', async () => {
  const before = calls.length;
  const saved = await request('/api/assistant/chat', {
    method: 'POST',
    cookie: owner.cookie,
    body: { message: '/remember Our API runs on Express 5 behind Cloudflare' },
  });
  assert.equal(saved.response.status, 200);
  assert.equal(calls.length, before, 'no model call for /remember');
  assert.match(saved.json.reply.content, /Saved to organization memory/);
  const memory = await request('/api/assistant/memory', { cookie: owner.cookie });
  assert.ok(memory.json.notes.some((note) => note.text.includes('Express 5')));
  assert.equal((await request('/api/assistant/memory', { cookie: stranger.cookie })).json.notes.length, 0);

  await request('/api/assistant/chat', {
    method: 'POST',
    cookie: owner.cookie,
    body: { message: 'Anything stack-specific?' },
  });
  assert.match(calls.at(-1).params.system[1].text, /Express 5 behind Cloudflare/);

  const note = memory.json.notes[0];
  assert.equal(
    (await request(`/api/assistant/memory/${note.id}`, { method: 'DELETE', cookie: stranger.cookie })).response.status,
    404,
  );
  assert.equal(
    (await request(`/api/assistant/memory/${note.id}`, { method: 'DELETE', cookie: owner.cookie })).response.status,
    200,
  );
});

test('a model refusal is stored as a refusal, not as an answer', async () => {
  nextChat = () => ({ content: [], stop_reason: 'refusal', stop_details: { category: 'cyber' } });
  try {
    const out = await request('/api/assistant/chat', {
      method: 'POST',
      cookie: owner.cookie,
      body: { message: 'something disallowed' },
    });
    assert.equal(out.response.status, 200);
    assert.equal(out.json.reply.refusal, true);
    assert.match(out.json.reply.content, /can't help with that/);
  } finally {
    nextChat = () => ({ content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn' });
  }
});

test('research needs a verified domain, runs in the background, and can be shared safely', async () => {
  const blocked = await request('/api/assistant/research', {
    method: 'POST',
    cookie: owner.cookie,
    body: { domain: 'example.com' },
  });
  assert.equal(blocked.response.status, 403);
  assert.equal(blocked.json.needsVerification, 'example.com');

  db.addVerified(owner.userId, 'example.com', { method: 'test', verifiedAt: Date.now() });
  const started = await request('/api/assistant/research', {
    method: 'POST',
    cookie: owner.cookie,
    body: { domain: 'https://example.com/app' },
  });
  assert.equal(started.response.status, 202, started.text);
  assert.equal(started.json.report.domain, 'example.com');
  const id = started.json.report.id;

  let report;
  for (let i = 0; i < 50; i++) {
    report = (await request(`/api/assistant/research/${id}`, { cookie: owner.cookie })).json.report;
    if (report.status !== 'running') break;
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.equal(report.status, 'completed', JSON.stringify(report));
  const streamCall = calls.findLast((call) => call.kind === 'stream');
  assert.equal(streamCall.params.max_tokens, 64000);
  assert.deepEqual(streamCall.params.output_config, { effort: 'high' });
  assert.match(streamCall.params.messages[0].content, /^<evidence>/);
  assert.doesNotMatch(report.html, /<img/);
  assert.equal((await request(`/api/assistant/research/${id}`, { cookie: stranger.cookie })).response.status, 404);

  const shared = await request('/api/share-links', {
    method: 'POST',
    cookie: owner.cookie,
    body: { resourceType: 'research', resourceId: id, days: 3 },
  });
  assert.equal(shared.response.status, 201, shared.text);
  const path = new URL(shared.json.url).pathname;
  const page = await request(path);
  assert.equal(page.response.status, 200);
  assert.match(page.text, /Security assessment: example.com/);
  assert.match(page.text, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.equal(page.response.headers.get('x-robots-tag'), 'noindex, nofollow');

  const tampered = path.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  assert.equal((await request(tampered)).response.status, 404);
  assert.equal((await request('/share/not-a-token')).response.status, 404);

  const strangerShare = await request('/api/share-links', {
    method: 'POST',
    cookie: stranger.cookie,
    body: { resourceType: 'research', resourceId: id },
  });
  assert.equal(strangerShare.response.status, 404);

  const links = await request('/api/share-links', { cookie: owner.cookie });
  assert.equal(links.json.links[0].views, 1);
  assert.equal(
    (await request(`/api/share-links/${shared.json.link.id}`, { method: 'DELETE', cookie: owner.cookie })).response
      .status,
    200,
  );
  assert.equal((await request(path)).response.status, 404);

  const second = await request('/api/share-links', {
    method: 'POST',
    cookie: owner.cookie,
    body: { resourceType: 'research', resourceId: id },
  });
  const link = await edb.shareLinks.get(second.json.link.id);
  await edb.shareLinks.save({ ...link, expiresAt: Date.now() - 1 });
  assert.equal((await request(new URL(second.json.url).pathname)).response.status, 404, 'expired link');
});

test('developer API keys: scoped bearer access, gates preserved, revocation', async () => {
  const created = await request('/api/developer/keys', {
    method: 'POST',
    cookie: owner.cookie,
    body: { name: 'CI', scopes: ['scans:read', 'findings:read'] },
  });
  assert.equal(created.response.status, 201, created.text);
  const token = created.json.token;
  // The secret is everything after `svx_<id>_` and may itself contain `_` or `-`.
  const secret = token.split('_').slice(2).join('_');
  assert.ok(secret.length >= 20, 'token carries a secret');
  assert.ok(!JSON.stringify(created.json.key).includes(secret), 'stored key never contains the secret');
  const auth = { authorization: `Bearer ${token}` };

  const me = await request('/api/v1/me', { headers: auth });
  assert.equal(me.response.status, 200, me.text);
  assert.equal(me.json.organization.id, owner.orgId);
  assert.equal((await request('/api/v1/scans', { headers: auth })).response.status, 200);
  assert.equal((await request('/api/v1/findings', { headers: auth })).response.status, 200);

  assert.equal(
    (await request('/api/v1/scans', { cookie: owner.cookie })).response.status,
    401,
    'cookies do not work on /api/v1',
  );
  assert.equal(
    (await request('/api/v1/scans', { headers: { authorization: `Bearer ${token.slice(0, -1)}x` } })).response.status,
    401,
  );
  assert.equal((await request('/api/v1/team/members', { headers: auth })).response.status, 404);
  const noWrite = await request('/api/v1/scans', {
    method: 'POST',
    headers: auth,
    body: { targetUrl: 'https://example.org', authorized: true },
  });
  assert.equal(noWrite.response.status, 403);

  const writer = await request('/api/developer/keys', {
    method: 'POST',
    cookie: owner.cookie,
    body: { name: 'Scanner', scopes: ['scans:write'] },
  });
  const unverified = await request('/api/v1/scans', {
    method: 'POST',
    headers: { authorization: `Bearer ${writer.json.token}` },
    body: { targetUrl: 'https://not-verified.example.org', authorized: true },
  });
  assert.equal(unverified.response.status, 403, 'domain ownership gate still applies to API keys');
  assert.ok(unverified.json.needsVerification);

  assert.equal((await request('/api/developer/keys', { cookie: stranger.cookie })).json.keys.length, 0);
  assert.equal(
    (await request(`/api/developer/keys/${created.json.key.id}`, { method: 'DELETE', cookie: stranger.cookie }))
      .response.status,
    404,
  );
  assert.equal(
    (await request(`/api/developer/keys/${created.json.key.id}`, { method: 'DELETE', cookie: owner.cookie })).response
      .status,
    200,
  );
  assert.equal((await request('/api/v1/me', { headers: auth })).response.status, 401, 'revoked key');
});
