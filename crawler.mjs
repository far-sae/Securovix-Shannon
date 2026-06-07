#!/usr/bin/env node
/**
 * Shannon crawler — pure-Node, in-scope BFS spider that turns "test one URL" into
 * "test the whole app". Discovers pages, query parameters, HTML forms, and API paths
 * referenced in inline/linked JavaScript. Honors an auth header/cookie so it can crawl
 * behind a login, and seeds from robots.txt + sitemap.xml. Stays on the target origin.
 *
 * Safety (hardened after adversarial review):
 *  - redirect:'manual' — never auto-follow off-origin redirects; the Location is re-enqueued
 *    only if it stays same-origin (no scope escape, no credential leak to other hosts).
 *  - auth headers are sent ONLY to the target origin.
 *  - response bodies are byte-capped (no OOM on a giant/endless body).
 *  - bounded queue + per-page sub-fetch cap + global request budget (no runaway crawl).
 *  - refuses to fetch loopback/RFC1918/link-local/metadata hosts (no scanner-side SSRF).
 */

const ASSET_RE = /\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webm|pdf|zip|map)(\?|$)/i;
const MAX_BODY_BYTES = 3 * 1024 * 1024;

function isBlockedHost(hostname, allowHost) {
  const h = (hostname || '').toLowerCase();
  if (allowHost && h === allowHost) return false; // the deliberate target host is allowed
  if (h === 'localhost' || h === '::1' || /^127\./.test(h)) return true;
  if (h === '169.254.169.254' || /^169\.254\./.test(h)) return true; // cloud metadata / link-local
  if (/^10\./.test(h) || /^192\.168\./.test(h)) return true;
  const m = h.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  return false;
}

// Read a response body but stop at MAX_BODY_BYTES (defends against OOM on huge/endless bodies).
async function readCapped(r) {
  const len = Number(r.headers.get('content-length') || 0);
  if (len && len > MAX_BODY_BYTES) return '';
  if (!r.body) return await r.text().catch(() => '');
  const reader = r.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_BODY_BYTES) {
        try {
          await reader.cancel();
        } catch {}
        break;
      }
      chunks.push(value);
    }
  } catch {
    /* stream error */
  }
  return Buffer.concat(chunks).toString('utf-8');
}

async function get(url, headers, timeoutMs, allowHost) {
  if (isBlockedHost(new URL(url).hostname, allowHost)) return { status: 0, body: '', ct: '', location: null };
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), timeoutMs);
  try {
    const r = await fetch(url, { headers, redirect: 'manual', signal: c.signal });
    if (r.status >= 300 && r.status < 400)
      return { status: r.status, body: '', ct: '', location: r.headers.get('location') };
    const ct = r.headers.get('content-type') || '';
    const body = /text|html|json|javascript|xml/i.test(ct) ? await readCapped(r) : '';
    return { status: r.status, body, ct, location: null };
  } catch {
    return { status: 0, body: '', ct: '', location: null };
  } finally {
    clearTimeout(t);
  }
}

function abs(href, base) {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}
const sameOrigin = (u, origin) => {
  try {
    return new URL(u).origin === origin;
  } catch {
    return false;
  }
};

export function parseForms(html, base) {
  const forms = [];
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = fm[1];
    const action = (attrs.match(/action\s*=\s*["']([^"']*)["']/i) || [])[1] || '';
    const method = ((attrs.match(/method\s*=\s*["']([^"']*)["']/i) || [])[1] || 'get').toLowerCase();
    const params = [];
    let csrf = null;
    for (const inp of fm[2].matchAll(/<(?:input|textarea|select)\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      params.push(inp[1]);
      if (/csrf|token|authenticity|_token|xsrf/i.test(inp[1])) {
        const val = (inp[0].match(/value\s*=\s*["']([^"']*)["']/i) || [])[1];
        if (val) csrf = { name: inp[1], value: val };
      }
    }
    const url = abs(action || base, base);
    if (url) forms.push({ url, method, params, csrf });
  }
  return forms;
}

export async function crawl({
  target,
  maxPages = 40,
  maxDepth = 3,
  headers = {},
  timeoutMs = 8000,
  maxRequests = 300,
} = {}) {
  // Resolve the SEED's own canonical redirect (apex->www, http->https) and adopt that origin as
  // the scope — so a site that 308s its apex to www is still crawled. SECURITY: only follow the
  // chain to the SAME SITE (registrable domain), so a seed that redirects to an attacker host is
  // NOT chased and the auth/session headers are never sent off-site.
  const seedSite = new URL(target).hostname.toLowerCase().split('.').slice(-2).join('.');
  const sameSite = (h) => h.toLowerCase().split('.').slice(-2).join('.') === seedSite;
  let startUrl = target;
  for (let i = 0; i < 5; i++) {
    const r = await get(startUrl, headers, timeoutMs, new URL(startUrl).hostname.toLowerCase());
    if (r.location) {
      const d = abs(r.location, startUrl);
      if (d && d !== startUrl && sameSite(new URL(d).hostname)) {
        startUrl = d;
        continue;
      }
    }
    break;
  }
  const origin = new URL(startUrl).origin;
  const allowHost = new URL(startUrl).hostname.toLowerCase();
  // Auth headers go ONLY to the target origin.
  const authFor = (u) => (sameOrigin(u, origin) ? headers : {});
  const seen = new Set();
  const queued = new Set();
  const queue = [];
  const pages = [];
  const paramNames = new Set();
  const forms = [];
  const apiPaths = new Set();
  let requests = 0;
  const QUEUE_CAP = maxPages * 20;

  const enqueue = (u, depth) => {
    if (!u) return;
    const clean = u.split('#')[0];
    if (!sameOrigin(clean, origin) || ASSET_RE.test(clean) || queued.has(clean) || depth > maxDepth) return;
    if (queued.size >= QUEUE_CAP) return;
    queued.add(clean);
    queue.push([clean, depth]);
  };
  const fetchOnce = async (u) => {
    if (requests >= maxRequests) return { status: 0, body: '', ct: '', location: null };
    requests++;
    return get(u, authFor(u), timeoutMs, allowHost);
  };

  enqueue(startUrl, 0);
  for (const seed of ['/robots.txt', '/sitemap.xml']) {
    const { body } = await fetchOnce(origin + seed);
    for (const m of body.matchAll(/(?:Allow|Disallow|Sitemap):\s*(\S+)/gi)) enqueue(abs(m[1], origin), 1);
    for (const m of body.matchAll(/<loc>([^<]+)<\/loc>/gi)) enqueue(m[1].trim(), 1);
  }

  while (queue.length && pages.length < maxPages && requests < maxRequests) {
    const [url, depth] = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
    const { status, body, ct, location } = await fetchOnce(url);
    if (location) {
      // Record the redirecting URL as a page (its params are still worth probing), and re-enqueue
      // the Location ONLY if it stays same-origin (off-origin redirects are dropped — no scope escape).
      pages.push({ url, status });
      for (const k of new URL(url).searchParams.keys()) paramNames.add(k);
      const dest = abs(location, url);
      if (dest && sameOrigin(dest, origin)) enqueue(dest, depth);
      continue;
    }
    if (!status) continue;
    pages.push({ url, status });
    for (const k of new URL(url).searchParams.keys()) paramNames.add(k);
    if (depth >= maxDepth || !/html/i.test(ct)) continue;

    for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
      const u = abs(m[1], url);
      if (u && sameOrigin(u, origin)) {
        enqueue(u, depth + 1);
        for (const k of new URL(u).searchParams.keys()) paramNames.add(k);
      }
    }
    for (const m of body.matchAll(/["'](\/(?:api|v\d|graphql|rest|auth|admin|user|account)[a-zA-Z0-9_\-\/.]*)["']/gi)) {
      const u = abs(m[1], origin);
      if (u) {
        apiPaths.add(new URL(u).pathname);
        enqueue(u, depth + 1);
      }
    }
    for (const f of parseForms(body, url)) {
      forms.push(f);
      for (const p of f.params) paramNames.add(p);
    }

    // Mine external JS for more API paths — capped per page so a script-heavy page can't fan out unbounded.
    let scripts = 0;
    for (const m of body.matchAll(/<script\b[^>]*src\s*=\s*["']([^"']+\.js[^"']*)["']/gi)) {
      if (scripts++ >= 8 || requests >= maxRequests) break;
      const js = abs(m[1], url);
      if (!js || !sameOrigin(js, origin)) continue;
      const { body: jsb } = await fetchOnce(js);
      for (const mm of jsb.matchAll(
        /["'](\/(?:api|v\d|graphql|rest|auth|admin|user|account)[a-zA-Z0-9_\-\/.]*)["']/gi,
      )) {
        const u = abs(mm[1], origin);
        if (u) {
          apiPaths.add(new URL(u).pathname);
          enqueue(u, depth + 1);
        }
      }
    }
  }

  return { origin, pages, paramNames: [...paramNames], forms, apiPaths: [...apiPaths], requests };
}
