// Server-rendered /pricing page. Takes the same object GET /api/commerce/catalog returns, so the page
// and the API cannot drift, and every price is crawlable without JavaScript.

const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
  );

const SYMBOL = { GBP: '£', USD: '$', EUR: '€' };
const money = (amount, currency) =>
  `${SYMBOL[currency] || `${currency} `}${Number(amount).toLocaleString('en-GB', { minimumFractionDigits: 0, maximumFractionDigits: 2 })}`;

const METRIC_LABEL = { scans: 'verified scans', codeFiles: 'code-scan files', agentRuns: 'agent runs' };
const grantText = (grants) =>
  Object.entries(grants || {})
    .filter(([, n]) => n > 0)
    .map(([metric, n]) => `${n} ${METRIC_LABEL[metric] || metric}`)
    .join(' · ');

const STYLE = `*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t1);font-family:Inter,system-ui,sans-serif;line-height:1.6}
a{color:var(--acc2)}.top{display:flex;gap:18px;align-items:center;justify-content:space-between;max-width:1080px;margin:0 auto;padding:22px 24px;flex-wrap:wrap}
.brand{display:flex;gap:10px;align-items:center;text-decoration:none;color:var(--t0);font-weight:700}.brand img{width:32px;height:32px;border-radius:9px}
.top nav{display:flex;gap:18px;flex-wrap:wrap;font-size:14px}.top nav a{color:var(--t2);text-decoration:none}.top nav a:hover{color:var(--t0)}
.wrap{max-width:1080px;margin:0 auto;padding:36px 24px 96px}h1{font-size:clamp(30px,5vw,46px);line-height:1.1;color:var(--t0);margin:0 0 12px}
.lede{font-size:18px;color:var(--t2);max-width:720px;margin:0 0 22px}h2{color:var(--t0);font-size:22px;margin:46px 0 6px}.sub{color:var(--t2);margin:0 0 18px;font-size:14px}
.banner{border:1px solid rgba(212,247,69,.35);background:var(--s1);border-radius:12px;padding:14px 18px;margin:0 0 26px;font-size:14px}.banner b{color:var(--acc2)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}.card{border:1px solid var(--brd);background:var(--s1);border-radius:14px;padding:20px;display:flex;flex-direction:column}
.card.hl{border-color:rgba(212,247,69,.45)}.card h3{margin:0 0 4px;color:var(--t0);font-size:16px}.price{font-size:30px;font-weight:700;color:var(--t0);margin:6px 0 2px}.price small{font-size:13px;font-weight:500;color:var(--t3)}
.card p{margin:6px 0;color:var(--t2);font-size:13.5px}.card ul{margin:10px 0 16px;padding-left:18px;color:var(--t2);font-size:13.5px}.card li{margin:3px 0}.grants{font-size:12.5px;color:var(--acc2);margin:4px 0 10px}
.btn{margin-top:auto;display:block;text-align:center;padding:10px 14px;border-radius:10px;font-weight:600;text-decoration:none;font-size:14px;border:1px solid var(--brd2);color:var(--t0)}
.btn-p{background:var(--acc);color:#0b0b0b;border-color:transparent}.btn[aria-disabled=true]{opacity:.55;pointer-events:none}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:8px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--brd)}th{color:var(--t0)}td{color:var(--t2)}
.pay{display:flex;gap:10px;flex-wrap:wrap}.chip{border:1px solid var(--brd2);border-radius:999px;padding:6px 13px;font-size:13px;color:var(--t1)}.chip.off{opacity:.45}
details{border-bottom:1px solid var(--brd);padding:12px 0}summary{cursor:pointer;color:var(--t0);font-weight:600}details p{color:var(--t2);font-size:14px;margin:8px 0 0}
footer{border-top:1px solid var(--brd);margin-top:56px;padding-top:22px;font-size:12px;color:var(--t3)}footer a{color:var(--t3)}`;

function buyButton(item, enabled) {
  return enabled
    ? `<a class="btn btn-p" href="/#billing/${encodeURIComponent(item.id)}">Buy</a>`
    : `<a class="btn" aria-disabled="true" href="#">Available after beta</a>`;
}

export function renderPricingPage(catalog, { baseUrl = '' } = {}) {
  const {
    enabled,
    currency,
    freeLimits = {},
    plans = [],
    offers = [],
    packs = [],
    methods = {},
    creditValidityDays,
  } = catalog;
  const pro = plans.find((plan) => plan.plan === 'pro');
  const free = plans.find((plan) => plan.plan === 'free');

  const banner = enabled
    ? ''
    : `<div class="banner"><b>Free during beta.</b> Every feature is free while Securovix is in beta, within the daily limits below. The prices shown are launch prices; nothing is charged until paid plans open.</div>`;

  const planCards = `
<div class="card hl"><h3>Free</h3><div class="price">${money(0, currency)}<small> / forever</small></div>
<p>The full platform with a daily allowance per organization.</p>
<ul><li>${esc(freeLimits.scans ?? 0)} verified scans a day</li><li>${esc(freeLimits.codeFiles ?? 0)} code-scan files a day</li><li>${esc(freeLimits.agentRuns ?? 0)} agent runs a day</li>
${(free?.features || []).map((feature) => `<li>${esc(feature)}</li>`).join('')}</ul>
<a class="btn btn-p" href="/">Start free</a></div>
<div class="card"><h3>Pro</h3>${
    pro
      ? `<div class="price">${money(pro.pricing.monthly, pro.pricing.currency)}<small> / month</small></div><p>or ${money(pro.pricing.yearly, pro.pricing.currency)} a year</p>
<ul><li>${esc(pro.limits.scans)} verified scans a day</li><li>${esc(pro.limits.codeFiles)} code-scan files a day</li><li>${esc(pro.limits.agentRuns)} agent runs a day</li>${pro.features.map((feature) => `<li>${esc(feature)}</li>`).join('')}</ul>
<a class="btn" href="/#cfg">Upgrade in Settings</a>`
      : `<div class="price">Coming soon</div><p>Higher daily limits, SSO/SCIM and priority support for teams that outgrow the free allowance.</p><a class="btn" aria-disabled="true" href="#">Opens after beta</a>`
  }</div>`;

  const offerCards = offers
    .map(
      (
        item,
      ) => `<div class="card"><h3>${esc(item.name)}</h3><div class="price">${money(item.price, item.currency)}<small> one-off</small></div>
<p>${esc(item.summary)}</p><ul>${item.deliverables.map((line) => `<li>${esc(line)}</li>`).join('')}</ul>
<div class="grants">Includes ${esc(grantText(item.grants))}</div>${buyButton(item, enabled)}</div>`,
    )
    .join('');

  const packRows = packs
    .map(
      (item) =>
        `<tr><td>${esc(item.name)}</td><td>${esc(grantText(item.grants))}</td><td>${money(item.price, item.currency)}</td><td>${enabled ? `<a href="/#billing/${encodeURIComponent(item.id)}">Buy</a>` : 'After beta'}</td></tr>`,
    )
    .join('');

  const chip = (on, label) => `<span class="chip${on ? '' : ' off'}">${esc(label)}</span>`;
  const cryptoLabel = methods.crypto?.length ? `Crypto (${methods.crypto.join(', ')})` : 'Crypto';
  const payments = `<div class="pay">${chip(methods.card, 'Card (Stripe)')}${chip(methods.crypto?.length, cryptoLabel)}${chip(methods.qr, 'QR payment')}${chip(methods.bank, 'Bank transfer')}</div>
<p class="sub" style="margin-top:12px">Card payments are confirmed automatically. Crypto, QR and bank payments are confirmed by our team after you submit the transaction reference, usually within one business day.${enabled ? '' : ' Payment options open after beta.'}</p>`;

  const faq = [
    [
      'Is it really free?',
      'Yes. During beta every feature is free within the daily limits. When paid plans open, the free tier stays.',
    ],
    [
      'What happens when I hit the daily limit?',
      'Counters reset at 00:00 UTC. Once purchases open, prepaid credits from a scan offer or credit pack are used automatically after the daily allowance runs out.',
    ],
    [
      'How long do credits last?',
      `Prepaid credits are valid for ${esc(creditValidityDays)} days from purchase and are used soonest-expiring first.`,
    ],
    [
      'Can I scan any website?',
      'No. Active checks only run against domains you have verified you own. Proofs are benign and read-only.',
    ],
    ['Do you store card details?', 'No. Card payments are handled by Stripe; Securovix never sees your card number.'],
  ]
    .map(([q, a]) => `<details><summary>${esc(q)}</summary><p>${a}</p></details>`)
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pricing · Securovix</title>
<meta name="description" content="Securovix is free during beta. Proof-gated security testing with daily limits, fixed-price verified scans and prepaid credit packs.">
<link rel="canonical" href="${esc(baseUrl)}/pricing">
<link rel="icon" href="/favicon.png"><link rel="stylesheet" href="/tokens.css">
<style>${STYLE}</style>
</head>
<body>
<header class="top"><a class="brand" href="/"><img src="/favicon.png" alt="">Securovix</a>
<nav><a href="/security-testing">Security testing</a><a href="/pricing">Pricing</a><a href="/security">Trust</a><a href="/">Sign in</a></nav></header>
<main class="wrap">
<h1>Simple pricing</h1><p class="lede">Start free. Pay only for the verified scans and credits you need.</p>
${banner}
<h2>Plans</h2><p class="sub">Daily limits apply per organization and reset at 00:00 UTC.</p>
<div class="grid">${planCards}</div>
<h2>Fixed-price verified scans</h2><p class="sub">One-off engagements. Every confirmed finding comes with a reproducible proof.</p>
<div class="grid">${offerCards}</div>
<h2>Credit packs</h2><p class="sub">Top up when the daily allowance runs out. Credits last ${esc(creditValidityDays)} days.</p>
<table><thead><tr><th>Pack</th><th>Includes</th><th>Price</th><th></th></tr></thead><tbody>${packRows}</tbody></table>
<h2>Ways to pay</h2>${payments}
<h2>Questions</h2>${faq}
<footer><a href="/terms">Terms</a> · <a href="/privacy">Privacy</a> · <a href="/security">Security</a> · Prices in ${esc(currency)}, excluding any applicable taxes.</footer>
</main>
</body></html>`;
}
