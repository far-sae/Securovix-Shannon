// Public "security testing" landing pages, one per area the engine actually covers.
//
// Engine-backed areas list exact PROBERS class ids; security-pages.test.mjs fails if a class is
// renamed or removed, or if a new engine class is not listed on some page — so these pages can
// never advertise a check the engine does not run. OWASP/CWE labels come from the engine's own
// COMPLIANCE map, not from copy written here.

export const CLASS_LABELS = Object.freeze({
  sqli: 'SQL injection (error-based, boolean-blind, time-based)',
  'sqli-auth-bypass': 'SQL injection login bypass',
  nosql: 'NoSQL injection',
  xss: 'Cross-site scripting (reflected, stored, DOM)',
  'rce-ssti': 'Server-side template injection',
  'cmd-injection': 'OS command injection',
  'path-traversal': 'Path traversal',
  xxe: 'XML external entities (out-of-band)',
  'rce-deser': 'Insecure deserialization',
  ssrf: 'Server-side request forgery',
  'open-redirect': 'Open redirect',
  crlf: 'CRLF / response-header injection',
  'host-header': 'Host-header injection',
  csrf: 'Cross-site request forgery',
  'cors-misconfig': 'CORS misconfiguration',
  'security-headers': 'Missing security headers',
  'verbose-errors': 'Verbose error and stack-trace disclosure',
  'secrets-exposure': 'Exposed secrets and sensitive files',
  templates: 'Known-issue template checks',
  'authz-bypass': 'Broken object / function-level authorization (BOLA / BFLA)',
  'graphql-idor': 'GraphQL insecure direct object references',
  'graphql-advanced': 'GraphQL abuse (introspection, suggestions, batching)',
  'mass-assignment': 'Mass assignment',
  'api-data-exposure': 'API excessive data exposure',
  'token-forgery': 'Token forgery with weak signing secrets',
  'auth-testing': 'Authentication testing (weak credentials, rate limiting, user enumeration)',
  'llm-prompt-injection': 'Direct prompt injection',
  'llm-indirect-injection': 'Indirect (second-order) prompt injection',
});

export const SECURITY_AREAS = Object.freeze([
  {
    slug: 'web-application-security',
    title: 'Web application security testing',
    tagline:
      'Injection, request-forgery and misconfiguration checks against your live web app, with a reproducible proof for every confirmed finding.',
    intro:
      'Securovix crawls the application on a domain you have verified you own, then runs each check class against the parameters and forms it discovered. A finding is reported as confirmed only when the engine can reproduce it; anything weaker is kept as an unverified lead.',
    engineClasses: [
      'sqli',
      'sqli-auth-bypass',
      'nosql',
      'xss',
      'rce-ssti',
      'cmd-injection',
      'path-traversal',
      'xxe',
      'rce-deser',
      'ssrf',
      'open-redirect',
      'crlf',
      'host-header',
      'csrf',
      'cors-misconfig',
      'security-headers',
      'verbose-errors',
      'secrets-exposure',
      'templates',
    ],
  },
  {
    slug: 'api-security',
    title: 'API and authentication security testing',
    tagline:
      'Authorization, GraphQL and authentication checks for REST and GraphQL APIs, including multi-identity BOLA/BFLA testing.',
    intro:
      'API checks look for access-control gaps that only appear when the same request is replayed as different users, plus GraphQL-specific abuse and weak authentication. Supply test identities to unlock the multi-identity authorization checks.',
    engineClasses: [
      'authz-bypass',
      'graphql-idor',
      'graphql-advanced',
      'mass-assignment',
      'api-data-exposure',
      'token-forgery',
      'auth-testing',
    ],
  },
  {
    slug: 'llm-security',
    title: 'LLM and AI application security testing',
    tagline:
      'Prompt-injection testing for apps with a language model behind the HTTP surface, mapped to the OWASP LLM Top 10 (2025).',
    intro:
      'Securovix finds where a model sits behind your endpoints and confirms injection only when the model emits a computed marker that is absent from a control request. No LLM judge decides the result. Impact is shown with a benign, read-only system-prompt-leak proof.',
    engineClasses: ['llm-prompt-injection', 'llm-indirect-injection'],
  },
  {
    slug: 'tls-ssl',
    title: 'TLS / SSL configuration testing',
    tagline: 'Find deprecated protocols, weak keys and certificate problems before your users or an auditor do.',
    intro: 'The TLS check connects to your host and reports what it actually negotiates and presents.',
    module: { file: 'tls-scan.mjs', export: 'runTlsScan' },
    checks: [
      'Deprecated protocol versions accepted',
      'Expired certificates',
      'Self-signed certificates',
      'Hostname mismatch',
      'Weak public keys',
    ],
  },
  {
    slug: 'subdomain-takeover',
    title: 'DNS attack surface and subdomain takeover',
    tagline:
      'Enumerate subdomains from certificate transparency and catch dangling DNS records before someone claims them.',
    intro:
      "Subdomains are discovered from public certificate-transparency logs. Each one is checked for a dangling CNAME that points at a de-provisioned third-party service, confirmed with that service's fingerprint.",
    module: { file: 'attack-surface.mjs', export: 'runAttackSurface' },
    checks: [
      'Subdomain enumeration from certificate transparency (crt.sh)',
      'Dangling CNAME detection',
      'Service fingerprinting for takeover confirmation',
    ],
  },
  {
    slug: 'cloud-storage-exposure',
    title: 'Cloud storage exposure testing',
    tagline: 'Detect publicly listable S3, Google Cloud Storage and Azure buckets that your own site references.',
    intro:
      'Bucket names are taken from the pages of your site, then each is checked for public listing. Only buckets your site actually references are tested.',
    module: { file: 'cloud-exposure.mjs', export: 'runCloudExposure' },
    checks: ['Amazon S3 public listing', 'Google Cloud Storage public listing', 'Azure Blob Storage public listing'],
  },
  {
    slug: 'network-services',
    title: 'Exposed network service testing',
    tagline: 'Opt-in checks for data stores and file services left open to the internet without authentication.',
    intro: 'Network checks are off by default and run only when you enable them for a host you have verified.',
    module: { file: 'network-scan.mjs', export: 'runNetworkScan' },
    checks: ['Unauthenticated Redis', 'Unauthenticated Memcached', 'Unauthenticated Elasticsearch', 'Anonymous FTP'],
  },
]);

export function securityArea(slug) {
  return SECURITY_AREAS.find((area) => area.slug === slug) || null;
}

const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
  );

const STYLE = `*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t1);font-family:Inter,system-ui,sans-serif;line-height:1.65}
a{color:var(--acc2)}.top{display:flex;gap:18px;align-items:center;justify-content:space-between;max-width:1040px;margin:0 auto;padding:22px 24px;flex-wrap:wrap}
.brand{display:flex;gap:10px;align-items:center;text-decoration:none;color:var(--t0);font-weight:700}.brand img{width:32px;height:32px;border-radius:9px}
.top nav{display:flex;gap:18px;flex-wrap:wrap;font-size:14px}.top nav a{color:var(--t2);text-decoration:none}.top nav a:hover{color:var(--t0)}
.wrap{max-width:1040px;margin:0 auto;padding:40px 24px 96px}h1{font-size:clamp(30px,5vw,46px);line-height:1.1;color:var(--t0);margin:0 0 14px}
.lede{font-size:18px;color:var(--t2);max-width:760px;margin:0 0 28px}h2{color:var(--t0);font-size:21px;margin:40px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}.card{border:1px solid var(--brd);background:var(--s1);border-radius:14px;padding:18px 20px}
.card h3{margin:0 0 6px;color:var(--t0);font-size:15px}.card p{margin:0;color:var(--t2);font-size:13.5px}.tags{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:11.5px;border:1px solid var(--brd2);border-radius:999px;padding:2px 9px;color:var(--t2)}.cta{display:flex;gap:12px;flex-wrap:wrap;margin:26px 0}
.btn{display:inline-block;padding:11px 18px;border-radius:10px;font-weight:600;text-decoration:none;font-size:14px;border:1px solid var(--brd2);color:var(--t0)}
.btn-p{background:var(--acc);color:#0b0b0b;border-color:transparent}.note{border:1px solid var(--brd);background:var(--s1);border-radius:12px;padding:14px 18px;font-size:13.5px;color:var(--t2);margin-top:28px}
footer{border-top:1px solid var(--brd);margin-top:56px;padding-top:22px;font-size:12px;color:var(--t3)}footer a{color:var(--t3)}`;

function shell({ title, description, canonical, body }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Securovix</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(canonical)}">
<meta property="og:title" content="${esc(title)} · Securovix"><meta property="og:description" content="${esc(description)}"><meta property="og:type" content="website">
<link rel="icon" href="/favicon.png"><link rel="stylesheet" href="/tokens.css">
<style>${STYLE}</style>
</head>
<body>
<header class="top"><a class="brand" href="/"><img src="/favicon.png" alt="">Securovix</a>
<nav><a href="/security-testing">Security testing</a><a href="/pricing">Pricing</a><a href="/security">Trust</a><a href="/">Sign in</a></nav></header>
<main class="wrap">${body}
<footer><a href="/terms">Terms</a> · <a href="/privacy">Privacy</a> · <a href="/security">Security</a> · Only test systems you own or are explicitly authorized to assess.</footer>
</main>
</body></html>`;
}

const ctas = `<div class="cta"><a class="btn btn-p" href="/">Start free</a><a class="btn" href="/pricing">See pricing</a></div>`;
const ownershipNote = `<div class="note"><b>Ownership first.</b> Active checks run only against domains you have verified you own. Proofs are benign and read-only by design: they demonstrate a weakness without damaging data or disrupting the service.</div>`;

function checkCards(area, compliance) {
  if (area.engineClasses) {
    return area.engineClasses
      .map((cls) => {
        const map = compliance[cls] || {};
        const tags = [map.owasp, map.cwe]
          .filter(Boolean)
          .map((tag) => `<span class="tag">${esc(tag)}</span>`)
          .join('');
        return `<div class="card"><h3>${esc(CLASS_LABELS[cls] || cls)}</h3><p>Check id <code>${esc(cls)}</code></p>${tags ? `<div class="tags">${tags}</div>` : ''}</div>`;
      })
      .join('');
  }
  return area.checks.map((check) => `<div class="card"><h3>${esc(check)}</h3></div>`).join('');
}

export function renderSecurityArea(area, { baseUrl = '', compliance = {} } = {}) {
  const count = area.engineClasses ? area.engineClasses.length : area.checks.length;
  const others = SECURITY_AREAS.filter((item) => item.slug !== area.slug)
    .map(
      (item) =>
        `<div class="card"><h3><a href="/security-testing/${esc(item.slug)}">${esc(item.title)}</a></h3><p>${esc(item.tagline)}</p></div>`,
    )
    .join('');
  const body = `<h1>${esc(area.title)}</h1><p class="lede">${esc(area.tagline)}</p>${ctas}
<h2>How it works</h2><p>${esc(area.intro)}</p>
<h2>${count} check${count === 1 ? '' : 's'} in this area</h2><div class="grid">${checkCards(area, compliance)}</div>
${ownershipNote}
<h2>Other security testing areas</h2><div class="grid">${others}</div>`;
  return shell({
    title: area.title,
    description: area.tagline,
    canonical: `${baseUrl}/security-testing/${area.slug}`,
    body,
  });
}

export function renderSecurityIndex({ baseUrl = '' } = {}) {
  const cards = SECURITY_AREAS.map((area) => {
    const count = area.engineClasses ? area.engineClasses.length : area.checks.length;
    return `<div class="card"><h3><a href="/security-testing/${esc(area.slug)}">${esc(area.title)}</a></h3><p>${esc(area.tagline)}</p><div class="tags"><span class="tag">${count} check${count === 1 ? '' : 's'}</span></div></div>`;
  }).join('');
  const body = `<h1>Proof-gated security testing</h1><p class="lede">Every confirmed finding comes with a reproducible proof. Unconfirmed signals stay labelled as leads, so you only fix what is real.</p>${ctas}
<h2>Testing areas</h2><div class="grid">${cards}</div>${ownershipNote}`;
  return shell({
    title: 'Security testing',
    description: 'Proof-gated web, API, LLM, TLS, DNS, cloud and network security testing for domains you own.',
    canonical: `${baseUrl}/security-testing`,
    body,
  });
}

export function renderSitemap(baseUrl) {
  const paths = [
    '/',
    '/pricing',
    '/security-testing',
    ...SECURITY_AREAS.map((area) => `/security-testing/${area.slug}`),
    '/security',
    '/terms',
    '/privacy',
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${paths.map((path) => `  <url><loc>${esc(baseUrl + path)}</loc></url>`).join('\n')}\n</urlset>\n`;
}
