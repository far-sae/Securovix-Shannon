#!/usr/bin/env node
/**
 * OPTIONAL headless (Playwright) crawl for JS-heavy SPAs — renders each page, follows in-scope
 * links from the rendered DOM, reads forms, and captures XHR/fetch endpoints from live network
 * traffic. Returns the SAME surface shape as crawler.mjs ({origin, pages, paramNames, forms,
 * apiPaths}). Strictly opt-in.
 *
 * Fail-safe by design: if `playwright` isn't installed OR a browser can't launch, it returns null
 * so the caller falls back to the pure-HTTP crawler. (Unverified in environments without browser
 * binaries — it activates only where Playwright + a Chromium build are present, e.g. the worker
 * image. The default scan path does NOT use this.)
 */

export async function crawlHeadless({ target, maxPages = 30, headers = {}, timeoutMs = 15000 } = {}) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null; // playwright not installed → caller falls back to HTTP crawl
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    return null; // no browser binary → fall back
  }
  try {
    const origin = new URL(target).origin;
    const sameOrigin = (u) => {
      try {
        return new URL(u).origin === origin;
      } catch {
        return false;
      }
    };
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    // SECURITY: attach the auth/session headers ONLY to same-origin requests — off-origin
    // subresources (CDNs, analytics) and any off-origin redirect must NOT receive credentials.
    if (headers && Object.keys(headers).length) {
      const lower = {};
      for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
      await ctx.route('**/*', (route) => {
        try {
          if (sameOrigin(route.request().url()))
            return route.continue({ headers: { ...route.request().headers(), ...lower } });
        } catch {}
        return route.continue();
      });
    }
    const seen = new Set();
    const queued = new Set([target]);
    const queue = [target];
    const pages = [];
    const paramNames = new Set();
    const forms = [];
    const apiPaths = new Set();

    const enqueue = (u) => {
      const c = (u || '').split('#')[0];
      if (c && sameOrigin(c) && !queued.has(c) && queued.size < maxPages * 20) {
        queued.add(c);
        queue.push(c);
      }
    };

    while (queue.length && pages.length < maxPages) {
      const url = queue.shift();
      if (seen.has(url) || !sameOrigin(url)) continue;
      seen.add(url);
      const page = await ctx.newPage();
      const reqs = [];
      page.on('request', (r) => {
        try {
          if (sameOrigin(r.url())) reqs.push(r.url());
        } catch {}
      });
      let status = 0;
      try {
        const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: timeoutMs });
        status = resp ? resp.status() : 0;
      } catch {
        await page.close().catch(() => {});
        continue;
      }
      pages.push({ url, status });
      for (const k of new URL(url).searchParams.keys()) paramNames.add(k);
      const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.href)).catch(() => []);
      for (const h of hrefs) {
        enqueue(h);
        try {
          for (const k of new URL(h).searchParams.keys()) paramNames.add(k);
        } catch {}
      }
      const fdata = await page
        .$$eval('form', (fs) =>
          fs.map((f) => ({
            action: f.action || location.href,
            method: (f.method || 'get').toLowerCase(),
            params: [...f.querySelectorAll('[name]')].map((e) => e.name).filter(Boolean),
          })),
        )
        .catch(() => []);
      for (const f of fdata) {
        forms.push({ url: f.action, method: f.method, params: f.params, csrf: null });
        for (const p of f.params) paramNames.add(p);
      }
      for (const ru of reqs) {
        try {
          const pu = new URL(ru);
          if (/\/(api|v\d|graphql|rest|auth|user|account|admin)/i.test(pu.pathname)) apiPaths.add(pu.pathname);
          if (pu.search) {
            for (const k of pu.searchParams.keys()) paramNames.add(k);
            enqueue(ru);
          }
        } catch {}
      }
      await page.close().catch(() => {});
    }
    await browser.close().catch(() => {});
    // A near-empty headless result (e.g. an apex->www redirect the renderer didn't descend) is worse
    // than the HTTP crawler — return null so the caller falls back to it.
    if (!pages.length) return null;
    return { origin, pages, paramNames: [...paramNames], forms, apiPaths: [...apiPaths], headless: true };
  } catch {
    try {
      await browser.close();
    } catch {}
    return null;
  }
}
