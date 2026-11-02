// Commerce: the one place prices, payment methods, the manual-payment order lifecycle and prepaid
// credit arithmetic live. Pure — no I/O — so the server, the public pricing page (via
// GET /api/commerce/catalog) and the SPA can never disagree about a price, and every transition
// is unit-testable.
//
// Everything is OFF until the operator sets SHANNON_COMMERCE_ENABLED=1. While off, the catalog is
// still published (so /pricing can show launch prices) but every purchase answers "free during beta".

export const CURRENCY = 'GBP';
export const METRICS = Object.freeze(['scans', 'codeFiles', 'agentRuns']);
export const CREDIT_VALIDITY_DAYS = 90;
const DAY_MS = 86_400_000;

const freezeItem = (item) =>
  Object.freeze({
    ...item,
    grants: Object.freeze({ ...item.grants }),
    deliverables: Object.freeze([...(item.deliverables || [])]),
  });

// Fixed-price, one-off verified engagements. Each grants prepaid credits on top of the daily free
// allowance; the engine's proof gate still decides what becomes a finding.
export const SCAN_OFFERS = Object.freeze(
  [
    {
      id: 'verified-url-scan',
      kind: 'offer',
      name: 'Verified URL scan',
      price: 49,
      grants: { scans: 3, agentRuns: 5 },
      summary: 'A proof-gated assessment of one web application on a domain you have verified you own.',
      deliverables: [
        'All web and API check classes, each confirmed by a reproducible proof',
        'TLS, DNS / subdomain-takeover and public cloud-storage exposure checks',
        'Detection rules for every confirmed payload finding',
        'Downloadable report with remediation steps',
      ],
    },
    {
      id: 'code-audit',
      kind: 'offer',
      name: 'Code audit (Git repository)',
      price: 79,
      grants: { codeFiles: 300, agentRuns: 10 },
      summary: 'Red-vs-Blue review of a repository with patched files and SARIF output.',
      deliverables: [
        'Up to 300 source files reviewed by the Red and Blue agents',
        'A patched copy of every affected file',
        'SARIF export for GitHub code scanning and CI',
      ],
    },
    {
      id: 'attack-surface-review',
      kind: 'offer',
      name: 'Attack-surface review',
      price: 199,
      grants: { scans: 10, agentRuns: 40, codeFiles: 300 },
      summary: 'Several verified scans plus the multi-agent team across your domains and code.',
      deliverables: [
        'Up to 10 verified scans across your verified domains',
        'Multi-agent engagement with attack-path chaining',
        'Code audit of up to 300 files',
        'Consolidated report and detection rules',
      ],
    },
  ].map(freezeItem),
);

// Prepaid top-ups for when the daily allowance runs out.
export const CREDIT_PACKS = Object.freeze(
  [
    { id: 'scans-10', kind: 'pack', name: '10 extra scans', price: 19, grants: { scans: 10 } },
    { id: 'scans-50', kind: 'pack', name: '50 extra scans', price: 79, grants: { scans: 50 } },
    { id: 'code-500', kind: 'pack', name: '500 code-scan files', price: 29, grants: { codeFiles: 500 } },
    { id: 'agent-100', kind: 'pack', name: '100 agent runs', price: 19, grants: { agentRuns: 100 } },
  ].map(freezeItem),
);

const ITEMS = new Map([...SCAN_OFFERS, ...CREDIT_PACKS].map((item) => [item.id, item]));

export function catalogItem(id) {
  return ITEMS.get(String(id || '')) || null;
}

export function commerceEnabled(env = process.env) {
  return env.SHANNON_COMMERCE_ENABLED === '1';
}

// "BTC=bc1q...;ETH=0xabc..." -> [{ asset, address }]. Malformed entries are dropped, never echoed.
export function parseCryptoWallets(value) {
  return String(value || '')
    .split(/[;\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const at = entry.indexOf('=');
      if (at < 1) return null;
      const asset = entry.slice(0, at).trim().toUpperCase();
      const address = entry.slice(at + 1).trim();
      if (!/^[A-Z0-9]{2,10}$/.test(asset) || !/^[A-Za-z0-9:_.-]{10,128}$/.test(address)) return null;
      return { asset, address };
    })
    .filter(Boolean);
}

function safeImageUrl(value) {
  const url = String(value || '').trim();
  if (/^\/[A-Za-z0-9/_.-]+$/.test(url) && !url.includes('..')) return url;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.href : null;
  } catch {
    return null;
  }
}

// Full operator configuration, including addresses. Only paymentInstructions() hands these to a
// buyer, and only for an order they own.
export function paymentMethods(env = process.env, { cardReady = false } = {}) {
  const wallets = parseCryptoWallets(env.SHANNON_PAY_CRYPTO_WALLETS);
  const qrImage = safeImageUrl(env.SHANNON_PAY_QR_IMAGE_URL);
  const bank = String(env.SHANNON_PAY_BANK_DETAILS || '')
    .trim()
    .slice(0, 600);
  return {
    card: !!cardReady,
    crypto: wallets.length ? { wallets } : null,
    qr: qrImage ? { imageUrl: qrImage, label: String(env.SHANNON_PAY_QR_LABEL || 'Scan to pay').slice(0, 80) } : null,
    bank: bank ? { details: bank } : null,
  };
}

export const MANUAL_METHODS = Object.freeze(['crypto', 'qr', 'bank']);

export function availableMethodIds(methods) {
  return ['card', ...MANUAL_METHODS].filter((id) => !!methods[id]);
}

const publicItem = (item) => ({
  id: item.id,
  kind: item.kind,
  name: item.name,
  price: item.price,
  currency: CURRENCY,
  grants: { ...item.grants },
  summary: item.summary || '',
  deliverables: [...item.deliverables],
});

// What anyone (signed in or not) may see. Wallet addresses and bank details are deliberately absent.
export function publicCatalog(env = process.env, { cardReady = false, plans = [], freeLimits = {} } = {}) {
  const methods = paymentMethods(env, { cardReady });
  return {
    enabled: commerceEnabled(env),
    currency: CURRENCY,
    creditValidityDays: CREDIT_VALIDITY_DAYS,
    freeLimits: { ...freeLimits },
    plans,
    offers: SCAN_OFFERS.map(publicItem),
    packs: CREDIT_PACKS.map(publicItem),
    methods: {
      card: methods.card,
      crypto: methods.crypto ? methods.crypto.wallets.map((wallet) => wallet.asset) : [],
      qr: !!methods.qr,
      bank: !!methods.bank,
    },
  };
}

export function paymentInstructions(order, env = process.env) {
  const methods = paymentMethods(env);
  const base = { method: order.method, amount: order.amount, currency: order.currency, reference: order.reference };
  if (order.method === 'crypto' && methods.crypto) {
    return {
      ...base,
      wallets: methods.crypto.wallets,
      note: `Send the ${order.currency} ${order.amount} equivalent, then submit the transaction hash. Include ${order.reference} in the memo where the network supports one.`,
    };
  }
  if (order.method === 'qr' && methods.qr) {
    return {
      ...base,
      ...methods.qr,
      note: `Scan, pay ${order.currency} ${order.amount}, put ${order.reference} in the payment note, then submit the transaction reference.`,
    };
  }
  if (order.method === 'bank' && methods.bank) {
    return {
      ...base,
      details: methods.bank.details,
      note: `Transfer ${order.currency} ${order.amount} using ${order.reference} as the payment reference, then submit your bank's transaction reference.`,
    };
  }
  return base;
}

// ----- Order lifecycle -----------------------------------------------------------------------
//
// card:   pending_payment --(signed Stripe webhook)--> approved
// manual: pending_evidence --(buyer submits reference)--> pending_review --(operator)--> approved | rejected
// Any open state can be cancelled by the buyer. approved/rejected/cancelled are final.

export const ORDER_STATUSES = Object.freeze([
  'pending_payment',
  'pending_evidence',
  'pending_review',
  'approved',
  'rejected',
  'cancelled',
]);
export const OPEN_STATUSES = Object.freeze(['pending_payment', 'pending_evidence', 'pending_review']);

const fail = (code, error) => ({ ok: false, code, error });
const step = (order, status, now, by, extra = {}) => ({
  ok: true,
  order: {
    ...order,
    ...extra,
    status,
    updatedAt: now,
    history: [...(order.history || []), { status, at: now, by: by || null }],
  },
});

function cleanText(value, max) {
  // Replace control characters (C0 and DEL) with spaces; keep printable text only.
  const text = Array.from(String(value || ''), (ch) => {
    const code = ch.charCodeAt(0);
    return code < 32 || code === 127 ? ' ' : ch;
  }).join('');
  return text.trim().slice(0, max);
}

export function newOrder({ id, orgId, userId, itemId, method, methods, now = Date.now() }) {
  const item = catalogItem(itemId);
  if (!item) return fail('UNKNOWN_ITEM', 'Unknown product.');
  if (!id || !orgId || !userId) return fail('INVALID_ORDER', 'Order needs an id, organization and user.');
  if (!availableMethodIds(methods || {}).includes(method))
    return fail('METHOD_UNAVAILABLE', 'That payment method is not available.');
  const status = method === 'card' ? 'pending_payment' : 'pending_evidence';
  return {
    ok: true,
    order: {
      id: String(id),
      orgId: String(orgId),
      userId: String(userId),
      itemId: item.id,
      itemName: item.name,
      kind: item.kind,
      method,
      amount: item.price,
      currency: CURRENCY,
      grants: { ...item.grants },
      reference: `SVX-${String(id)
        .replace(/[^A-Za-z0-9]/g, '')
        .slice(0, 8)
        .toUpperCase()}`,
      status,
      evidence: null,
      review: null,
      providerRef: null,
      createdAt: now,
      updatedAt: now,
      history: [{ status, at: now, by: String(userId) }],
    },
  };
}

export function submitEvidence(order, { reference, note, userId, now = Date.now() }) {
  if (order.status !== 'pending_evidence')
    return fail('INVALID_STATE', `Order is ${order.status}; evidence can only be added while awaiting payment proof.`);
  const ref = cleanText(reference, 200);
  if (ref.length < 4)
    return fail('INVALID_EVIDENCE', 'Enter the transaction hash or payment reference (at least 4 characters).');
  return step(order, 'pending_review', now, userId, {
    evidence: { reference: ref, note: cleanText(note, 500), submittedAt: now, submittedBy: userId || null },
  });
}

export function reviewOrder(order, { decision, reviewer, reason, now = Date.now() }) {
  if (order.status !== 'pending_review')
    return fail('INVALID_STATE', `Order is ${order.status}; only orders awaiting review can be decided.`);
  if (decision !== 'approve' && decision !== 'reject')
    return fail('INVALID_DECISION', 'Decision must be approve or reject.');
  const status = decision === 'approve' ? 'approved' : 'rejected';
  return step(order, status, now, reviewer, {
    review: { decision, reviewer: reviewer || null, reason: cleanText(reason, 300), at: now },
  });
}

export function cancelOrder(order, { userId, now = Date.now() }) {
  if (!OPEN_STATUSES.includes(order.status)) return fail('INVALID_STATE', `Order is already ${order.status}.`);
  return step(order, 'cancelled', now, userId);
}

// Idempotent: a replayed webhook for an approved order reports alreadyApplied instead of failing.
export function markCardPaid(order, { providerRef, now = Date.now() }) {
  if (order.status === 'approved') return { ok: true, order, alreadyApplied: true };
  if (order.method !== 'card' || order.status !== 'pending_payment')
    return fail('INVALID_STATE', `Order is ${order.status}; it cannot be marked paid by card.`);
  return step(order, 'approved', now, 'stripe', { providerRef: providerRef ? String(providerRef) : null });
}

// ----- Prepaid credits ---------------------------------------------------------------------

export function creditGrantFor(order, now = Date.now()) {
  if (order.status !== 'approved') return null;
  return {
    id: `grant:${order.id}`,
    orgId: order.orgId,
    orderId: order.id,
    grants: { ...order.grants },
    remaining: { ...order.grants },
    expiresAt: now + CREDIT_VALIDITY_DAYS * DAY_MS,
    createdAt: now,
  };
}

const live = (grant, now) => grant.expiresAt > now;

export function creditBalance(grants, now = Date.now()) {
  const balance = Object.fromEntries(METRICS.map((metric) => [metric, 0]));
  for (const grant of grants || []) {
    if (!live(grant, now)) continue;
    for (const metric of METRICS) balance[metric] += Math.max(0, Number(grant.remaining?.[metric] || 0));
  }
  return balance;
}

// All-or-nothing, soonest-expiring first. Returns new grant objects; inputs are not mutated.
export function consumeFromGrants(grants, metric, amount, now = Date.now()) {
  const need = Math.max(1, Math.floor(Number(amount) || 1));
  if (!METRICS.includes(metric)) return { allowed: false, grants, remaining: 0 };
  const available = creditBalance(grants, now)[metric];
  if (available < need) return { allowed: false, grants, remaining: available };
  let left = need;
  const order = [...(grants || [])]
    .map((grant, index) => ({ grant, index }))
    .sort((a, b) => a.grant.expiresAt - b.grant.expiresAt);
  const next = [...(grants || [])];
  for (const { grant, index } of order) {
    if (!left) break;
    if (!live(grant, now)) continue;
    const have = Math.max(0, Number(grant.remaining?.[metric] || 0));
    if (!have) continue;
    const take = Math.min(have, left);
    next[index] = { ...grant, remaining: { ...grant.remaining, [metric]: have - take } };
    left -= take;
  }
  return { allowed: true, grants: next, remaining: available - need };
}
