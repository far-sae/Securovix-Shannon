import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-commerce-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'commerce-test-secret-that-is-long-enough-123';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.NODE_ENV = 'test';
process.env.SHANNON_PAY_CRYPTO_WALLETS = 'BTC=bc1qcommercetestaddress000000';
Reflect.deleteProperty(process.env, 'SHANNON_COMMERCE_ENABLED');
Reflect.deleteProperty(process.env, 'STRIPE_SECRET_KEY');
Reflect.deleteProperty(process.env, 'STRIPE_WEBHOOK_SECRET');

const { startDashboard, consumeOrgAllowance } = await import('./packages/dashboard/server.mjs');
const db = await import('./packages/dashboard/enterprise-db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  if (body !== undefined || raw !== undefined) h['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers: h,
    body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
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
  return { cookie: out.response.headers.get('set-cookie').split(';')[0], orgId: out.json.organizations[0].id };
}

test('public pages render and the catalog is anonymous and address-free', async () => {
  const catalog = await request('/api/commerce/catalog');
  assert.equal(catalog.response.status, 200);
  assert.equal(catalog.json.enabled, false);
  assert.deepEqual(catalog.json.methods.crypto, ['BTC']);
  assert.doesNotMatch(catalog.text, /bc1qcommerce/);

  const pricing = await request('/pricing');
  assert.equal(pricing.response.status, 200);
  assert.match(pricing.text, /Free during beta/);
  assert.match(pricing.text, /Verified URL scan/);

  const area = await request('/security-testing/api-security');
  assert.equal(area.response.status, 200);
  assert.match(area.text, /BOLA \/ BFLA/);
  assert.equal((await request('/security-testing/not-a-page')).response.status, 404);
  assert.match((await request('/sitemap.xml')).text, /\/security-testing\/llm-security/);
  assert.match((await request('/robots.txt')).text, /Disallow: \/api\//);
});

test('purchases are closed during beta', async () => {
  const owner = await signup('beta-owner@example.test');
  const out = await request('/api/commerce/orders', {
    method: 'POST',
    cookie: owner.cookie,
    body: { itemId: 'scans-10', method: 'crypto' },
  });
  assert.equal(out.response.status, 503);
  assert.equal(out.json.code, 'COMMERCE_DISABLED');
  const account = await request('/api/commerce/account', { cookie: owner.cookie });
  assert.equal(account.response.status, 200);
  assert.deepEqual(account.json.credits, { scans: 0, codeFiles: 0, agentRuns: 0 });
});

test('manual crypto order: create, evidence, review, credits, org isolation', async () => {
  process.env.SHANNON_COMMERCE_ENABLED = '1';
  try {
    const owner = await signup('buyer@example.test');
    const other = await signup('stranger@example.test');

    const anonymous = await request('/api/commerce/orders', {
      method: 'POST',
      body: { itemId: 'scans-10', method: 'crypto' },
    });
    assert.equal(anonymous.response.status, 401);
    const noCard = await request('/api/commerce/orders', {
      method: 'POST',
      cookie: owner.cookie,
      body: { itemId: 'scans-10', method: 'card' },
    });
    assert.equal(noCard.json.code, 'METHOD_UNAVAILABLE');
    const forged = await request('/api/commerce/orders', {
      method: 'POST',
      cookie: owner.cookie,
      body: { itemId: 'scans-10', method: 'crypto', amount: 0.01 },
    });
    assert.equal(forged.json.order.amount, 19, 'client cannot set the price');

    const created = await request('/api/commerce/orders', {
      method: 'POST',
      cookie: owner.cookie,
      body: { itemId: 'scans-10', method: 'crypto' },
    });
    assert.equal(created.response.status, 201, created.text);
    const orderId = created.json.order.id;
    assert.equal(created.json.order.status, 'pending_evidence');
    assert.equal(created.json.instructions.wallets[0].address, 'bc1qcommercetestaddress000000');

    const foreign = await request(`/api/commerce/orders/${orderId}/evidence`, {
      method: 'POST',
      cookie: other.cookie,
      body: { reference: '0xfeedface' },
    });
    assert.equal(foreign.response.status, 404);
    assert.equal(
      (await request(`/api/commerce/orders/${orderId}/instructions`, { cookie: other.cookie })).response.status,
      404,
    );

    const evidence = await request(`/api/commerce/orders/${orderId}/evidence`, {
      method: 'POST',
      cookie: owner.cookie,
      body: { reference: '0xfeedface', note: 'sent from my wallet' },
    });
    assert.equal(evidence.response.status, 200, evidence.text);
    assert.equal(evidence.json.order.status, 'pending_review');

    const queue = await request('/api/platform/commerce/orders', { cookie: owner.cookie });
    assert.equal(queue.response.status, 200);
    assert.ok(queue.json.orders.some((order) => order.id === orderId));

    const approved = await request(`/api/platform/commerce/orders/${orderId}/review`, {
      method: 'POST',
      cookie: owner.cookie,
      body: { decision: 'approve' },
    });
    assert.equal(approved.response.status, 200, approved.text);
    assert.equal(approved.json.order.status, 'approved');
    assert.equal(approved.json.grant.created, true);
    const again = await request(`/api/platform/commerce/orders/${orderId}/review`, {
      method: 'POST',
      cookie: owner.cookie,
      body: { decision: 'approve' },
    });
    assert.equal(again.response.status, 409);

    const account = await request('/api/commerce/account', { cookie: owner.cookie });
    assert.equal(account.json.credits.scans, 10);
    const strangerAccount = await request('/api/commerce/account', { cookie: other.cookie });
    assert.equal(strangerAccount.json.credits.scans, 0);
    assert.equal(strangerAccount.json.orders.length, 0);

    const usage = await request(`/api/team/${owner.orgId}/usage`, { cookie: owner.cookie });
    assert.equal(usage.json.credits.scans, 10);

    assert.deepEqual(await db.consumeCredits(owner.orgId, 'scans', 4), { allowed: true, remaining: 6 });
    assert.equal((await db.consumeCredits(owner.orgId, 'scans', 7)).allowed, false);

    const second = await request('/api/commerce/orders', {
      method: 'POST',
      cookie: owner.cookie,
      body: { itemId: 'agent-100', method: 'crypto' },
    });
    const cancelled = await request(`/api/commerce/orders/${second.json.order.id}/cancel`, {
      method: 'POST',
      cookie: owner.cookie,
      body: {},
    });
    assert.equal(cancelled.json.order.status, 'cancelled');
  } finally {
    Reflect.deleteProperty(process.env, 'SHANNON_COMMERCE_ENABLED');
  }
});

test('quota uses the daily allowance first, then prepaid credits, then refuses', async () => {
  const owner = await signup('quota@example.test');
  const now = Date.now();
  await db.saveCommerceOrder({
    id: 'quota-order',
    orgId: owner.orgId,
    userId: 'u',
    itemId: 'agent-100',
    itemName: '100 agent runs',
    kind: 'pack',
    method: 'bank',
    amount: 19,
    currency: 'GBP',
    grants: { agentRuns: 2 },
    reference: 'SVX-QUOTAORD',
    status: 'approved',
    evidence: null,
    review: null,
    providerRef: null,
    createdAt: now,
    updatedAt: now,
    history: [],
  });
  await db.addCreditGrant({
    id: 'grant:quota-order',
    orgId: owner.orgId,
    orderId: 'quota-order',
    grants: { agentRuns: 2 },
    remaining: { agentRuns: 2 },
    expiresAt: now + 86_400_000,
    createdAt: now,
  });

  const sources = [];
  for (let i = 0; i < 13; i++) sources.push((await consumeOrgAllowance(owner.orgId, 'agentRuns', 1)).source);
  // Free plan: 10 agent runs a day, then 2 prepaid credits, then nothing.
  assert.deepEqual(sources, [...Array(10).fill('daily'), 'credits', 'credits', null]);
});

test('signed Stripe webhook approves a card order once and checks the amount', async () => {
  process.env.STRIPE_SECRET_KEY = 'sk_test_commerce';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_commerce_test';
  try {
    const owner = await signup('card-buyer@example.test');
    const now = Date.now();
    const order = {
      id: 'card-order-1',
      orgId: owner.orgId,
      userId: 'u',
      itemId: 'code-audit',
      itemName: 'Code audit (Git repository)',
      kind: 'offer',
      method: 'card',
      amount: 79,
      currency: 'GBP',
      grants: { codeFiles: 300, agentRuns: 10 },
      reference: 'SVX-CARDORDE',
      status: 'pending_payment',
      evidence: null,
      review: null,
      providerRef: 'cs_test',
      createdAt: now,
      updatedAt: now,
      history: [],
    };
    await db.saveCommerceOrder(order);

    const send = (amount) => {
      const payload = JSON.stringify({
        id: `evt_${amount}_${Math.random()}`,
        type: 'checkout.session.completed',
        created: Math.floor(Date.now() / 1000),
        data: {
          object: {
            id: 'cs_test',
            payment_status: 'paid',
            amount_total: amount,
            currency: 'gbp',
            payment_intent: 'pi_test',
            metadata: { kind: 'commerce', orderId: order.id, orgId: owner.orgId },
          },
        },
      });
      const t = Math.floor(Date.now() / 1000);
      const sig = createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(`${t}.${payload}`).digest('hex');
      return request('/api/billing/webhook', {
        method: 'POST',
        raw: payload,
        headers: { 'stripe-signature': `t=${t},v1=${sig}` },
      });
    };

    const unsigned = await request('/api/billing/webhook', {
      method: 'POST',
      raw: '{}',
      headers: { 'stripe-signature': 't=1,v1=bad' },
    });
    assert.equal(unsigned.response.status, 400);

    const wrong = await send(100);
    assert.equal(wrong.json.ignored, 'amount mismatch');
    assert.equal((await db.getCommerceOrder(order.id)).status, 'pending_payment');

    const paid = await send(7900);
    assert.equal(paid.response.status, 200, paid.text);
    assert.equal(paid.json.applied, true);
    assert.equal((await db.getCommerceOrder(order.id)).status, 'approved');

    const replay = await send(7900);
    assert.equal(replay.json.applied, false);
    assert.equal(replay.json.grant.created, false);
    const grants = await db.listCreditGrants(owner.orgId);
    assert.equal(grants.length, 1, 'replayed webhook must not double-credit');
    assert.equal(grants[0].remaining.codeFiles, 300);
  } finally {
    Reflect.deleteProperty(process.env, 'STRIPE_SECRET_KEY');
    Reflect.deleteProperty(process.env, 'STRIPE_WEBHOOK_SECRET');
  }
});
