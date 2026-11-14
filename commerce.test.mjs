import assert from 'node:assert/strict';
import { test } from 'node:test';

const commerce = await import('./packages/dashboard/commerce.mjs');
const {
  CREDIT_PACKS,
  SCAN_OFFERS,
  METRICS,
  availableMethodIds,
  cancelOrder,
  catalogItem,
  consumeFromGrants,
  creditBalance,
  creditGrantFor,
  markCardPaid,
  newOrder,
  parseCryptoWallets,
  paymentInstructions,
  paymentMethods,
  publicCatalog,
  reviewOrder,
  submitEvidence,
} = commerce;

const ENV = {
  SHANNON_COMMERCE_ENABLED: '1',
  SHANNON_PAY_CRYPTO_WALLETS:
    'BTC=bc1qexampleaddress0000000000;eth=0xAbC0000000000000000000000000000000000000;bad entry;X=short',
  SHANNON_PAY_QR_IMAGE_URL: 'https://example.test/qr.png',
  SHANNON_PAY_BANK_DETAILS: 'Sort code 00-00-00\nAccount 12345678',
};

test('catalog items are unique, priced and grant only known metrics', () => {
  const ids = [...SCAN_OFFERS, ...CREDIT_PACKS].map((item) => item.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const item of [...SCAN_OFFERS, ...CREDIT_PACKS]) {
    assert.ok(item.price > 0, item.id);
    assert.ok(Object.keys(item.grants).length > 0, item.id);
    for (const [metric, amount] of Object.entries(item.grants)) {
      assert.ok(METRICS.includes(metric), `${item.id} grants unknown metric ${metric}`);
      assert.ok(Number.isInteger(amount) && amount > 0);
    }
  }
  assert.equal(catalogItem('verified-url-scan').price, 49);
  assert.equal(catalogItem('nope'), null);
  assert.throws(() => {
    catalogItem('scans-10').grants.scans = 999;
  });
});

test('crypto wallet parsing keeps valid entries and drops malformed ones', () => {
  assert.deepEqual(parseCryptoWallets(ENV.SHANNON_PAY_CRYPTO_WALLETS), [
    { asset: 'BTC', address: 'bc1qexampleaddress0000000000' },
    { asset: 'ETH', address: '0xAbC0000000000000000000000000000000000000' },
  ]);
  assert.deepEqual(parseCryptoWallets(''), []);
  assert.deepEqual(parseCryptoWallets('BTC=<script>alert(1)</script>'), []);
});

test('public catalog never exposes wallet addresses or bank details', () => {
  const catalog = publicCatalog(ENV, { cardReady: false, freeLimits: { scans: 5 } });
  assert.equal(catalog.enabled, true);
  assert.deepEqual(catalog.methods, { card: false, crypto: ['BTC', 'ETH'], qr: true, bank: true });
  const json = JSON.stringify(catalog);
  assert.doesNotMatch(json, /bc1qexample/);
  assert.doesNotMatch(json, /Sort code/);
  assert.equal(publicCatalog({}).enabled, false);
});

test('QR image URLs must be https or a local path', () => {
  assert.equal(paymentMethods({ SHANNON_PAY_QR_IMAGE_URL: 'javascript:alert(1)' }).qr, null);
  assert.equal(paymentMethods({ SHANNON_PAY_QR_IMAGE_URL: 'http://example.test/qr.png' }).qr, null);
  assert.equal(paymentMethods({ SHANNON_PAY_QR_IMAGE_URL: '/../secret' }).qr, null);
  assert.equal(paymentMethods({ SHANNON_PAY_QR_IMAGE_URL: '/payments/qr.png' }).qr.imageUrl, '/payments/qr.png');
});

test('manual order lifecycle: evidence, review, credits', () => {
  const methods = paymentMethods(ENV);
  assert.deepEqual(availableMethodIds(methods), ['crypto', 'qr', 'bank']);
  assert.equal(
    newOrder({ id: 'o1', orgId: 'org', userId: 'u', itemId: 'scans-10', method: 'card', methods }).code,
    'METHOD_UNAVAILABLE',
  );
  assert.equal(
    newOrder({ id: 'o1', orgId: 'org', userId: 'u', itemId: 'nope', method: 'crypto', methods }).code,
    'UNKNOWN_ITEM',
  );

  const created = newOrder({
    id: 'abcd-1234-efgh',
    orgId: 'org',
    userId: 'u',
    itemId: 'scans-10',
    method: 'crypto',
    methods,
    now: 1000,
  });
  assert.equal(created.ok, true);
  const order = created.order;
  assert.equal(order.status, 'pending_evidence');
  assert.equal(order.amount, 19);
  assert.equal(order.reference, 'SVX-ABCD1234');

  const ins = paymentInstructions(order, ENV);
  assert.equal(ins.wallets.length, 2);
  assert.match(ins.note, /SVX-ABCD1234/);

  assert.equal(submitEvidence(order, { reference: 'ab' }).code, 'INVALID_EVIDENCE');
  assert.equal(reviewOrder(order, { decision: 'approve' }).code, 'INVALID_STATE');
  const submitted = submitEvidence(order, { reference: '  0xdeadbeef\u0000 ', note: 'paid', userId: 'u', now: 2000 });
  assert.equal(submitted.order.status, 'pending_review');
  assert.equal(submitted.order.evidence.reference, '0xdeadbeef');
  assert.equal(submitEvidence(submitted.order, { reference: 'again' }).code, 'INVALID_STATE');

  assert.equal(reviewOrder(submitted.order, { decision: 'maybe' }).code, 'INVALID_DECISION');
  const approved = reviewOrder(submitted.order, { decision: 'approve', reviewer: 'ops@example.test', now: 3000 });
  assert.equal(approved.order.status, 'approved');
  assert.deepEqual(
    approved.order.history.map((h) => h.status),
    ['pending_evidence', 'pending_review', 'approved'],
  );
  assert.equal(cancelOrder(approved.order, { userId: 'u' }).code, 'INVALID_STATE');

  const grant = creditGrantFor(approved.order, 3000);
  assert.equal(grant.id, 'grant:abcd-1234-efgh');
  assert.deepEqual(grant.remaining, { scans: 10 });
  assert.equal(creditGrantFor(order), null);
});

test('card orders are approved once and replays are idempotent', () => {
  const methods = paymentMethods({}, { cardReady: true });
  const { order } = newOrder({
    id: 'card-1',
    orgId: 'org',
    userId: 'u',
    itemId: 'code-audit',
    method: 'card',
    methods,
  });
  assert.equal(order.status, 'pending_payment');
  const paid = markCardPaid(order, { providerRef: 'pi_1' });
  assert.equal(paid.order.status, 'approved');
  assert.equal(paid.order.providerRef, 'pi_1');
  assert.equal(markCardPaid(paid.order, {}).alreadyApplied, true);
  const cancelled = cancelOrder(order, { userId: 'u' });
  assert.equal(markCardPaid(cancelled.order, {}).code, 'INVALID_STATE');
});

test('credits are spent all-or-nothing, soonest-expiring first, ignoring expired grants', () => {
  const now = 10_000;
  const grants = [
    { id: 'late', remaining: { scans: 5 }, expiresAt: now + 2000 },
    { id: 'expired', remaining: { scans: 100 }, expiresAt: now - 1 },
    { id: 'soon', remaining: { scans: 2, agentRuns: 1 }, expiresAt: now + 1000 },
  ];
  assert.deepEqual(creditBalance(grants, now), { scans: 7, codeFiles: 0, agentRuns: 1 });

  const spent = consumeFromGrants(grants, 'scans', 3, now);
  assert.equal(spent.allowed, true);
  assert.equal(spent.remaining, 4);
  assert.deepEqual(
    spent.grants.map((g) => g.remaining.scans),
    [4, 100, 0],
  );
  assert.equal(grants[2].remaining.scans, 2, 'input not mutated');

  const tooMuch = consumeFromGrants(spent.grants, 'scans', 5, now);
  assert.equal(tooMuch.allowed, false);
  assert.equal(tooMuch.grants, spent.grants);
  assert.equal(consumeFromGrants(grants, 'bogus', 1, now).allowed, false);
});
