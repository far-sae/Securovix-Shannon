#!/usr/bin/env node
/**
 * Attack-surface mapping + SUBDOMAIN TAKEOVER — the second non-web module. Subdomains of a domain
 * the client already verified are in scope (they own *.example.com), and enumeration via public
 * Certificate Transparency logs (crt.sh) is passive and safe.
 *
 * Subdomain takeover is PROVABLE, zero-FP: a subdomain's CNAME points at a known third-party service
 * AND that service returns its "unclaimed / no such resource" fingerprint — meaning an attacker can
 * register the resource and serve content from the victim's subdomain. Both conditions are required.
 *
 * Dependencies (crt.sh fetch, DNS CNAME resolution, HTTP fetch) are injectable so the logic is
 * unit-testable without network access.
 */

import { resolveCname as dnsResolveCname } from 'node:dns/promises';

// cname: the fingerprint of the third-party service in the CNAME target.
// fingerprint: the body signature the service returns when the resource is UNCLAIMED.
const TAKEOVER_SERVICES = [
  {
    name: 'AWS S3',
    cname: /\.s3[.-][\w.-]*amazonaws\.com$|\.s3\.amazonaws\.com$/i,
    fingerprint: /NoSuchBucket|The specified bucket does not exist/i,
  },
  {
    name: 'GitHub Pages',
    cname: /\.github\.io$/i,
    fingerprint: /There isn't a GitHub Pages site here|For root URLs \(like https?:\/\//i,
  },
  {
    name: 'Heroku',
    cname: /\.herokuapp\.com$|\.herokudns\.com$/i,
    fingerprint: /No such app|herokucdn\.com\/error-pages\/no-such-app/i,
  },
  {
    name: 'Azure',
    cname: /\.azurewebsites\.net$|\.cloudapp\.net$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$/i,
    fingerprint: /404 Web Site not found|The resource you are looking for has been removed/i,
  },
  { name: 'Fastly', cname: /\.fastly\.net$/i, fingerprint: /Fastly error: unknown domain/i },
  { name: 'Shopify', cname: /\.myshopify\.com$/i, fingerprint: /Sorry, this shop is currently unavailable/i },
  { name: 'Zendesk', cname: /\.zendesk\.com$/i, fingerprint: /Help Center Closed|this help center no longer exists/i },
  { name: 'Surge.sh', cname: /\.surge\.sh$/i, fingerprint: /project not found/i },
  { name: 'Bitbucket', cname: /\.bitbucket\.io$/i, fingerprint: /Repository not found/i },
  {
    name: 'Ghost',
    cname: /\.ghost\.io$/i,
    fingerprint: /Domain error|The thing you were looking for is no longer here/i,
  },
  { name: 'Pantheon', cname: /\.pantheonsite\.io$/i, fingerprint: /The gods are wise|404 error unknown site/i },
];

const F = (severity, target, detail) => ({
  tool: 'attack-surface',
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool: 'attack-surface', detail }),
});

// Pull subdomains from Certificate Transparency (crt.sh). Passive; public.
async function defaultFetchCrt(domain) {
  const out = new Set();
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 12_000);
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: c.signal });
    clearTimeout(t);
    const rows = await r.json().catch(() => []);
    for (const row of rows || [])
      for (const name of String(row.name_value || '').split(/\n/)) {
        const h = name.trim().replace(/^\*\./, '').toLowerCase();
        if (h.endsWith(`.${domain}`) && !h.includes('*')) out.add(h);
      }
  } catch {}
  return [...out];
}

async function defaultFetchUrl(url) {
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 8000);
    const r = await fetch(url, { redirect: 'follow', signal: c.signal });
    const body = await r.text().catch(() => '');
    clearTimeout(t);
    return { status: r.status, body };
  } catch {
    return { status: 0, body: '' };
  }
}

export async function runAttackSurface(domain, deps = {}) {
  const { fetchCrt = defaultFetchCrt, resolveCname = dnsResolveCname, fetchUrl = defaultFetchUrl, limit = 60 } = deps;
  const subdomains = await fetchCrt(domain);
  const findings = [];
  for (const sub of subdomains.slice(0, limit)) {
    let cnames = [];
    try {
      cnames = await resolveCname(sub);
    } catch {
      continue; // no CNAME (A record / NXDOMAIN) → not a CNAME-takeover candidate
    }
    for (const cname of cnames || []) {
      const svc = TAKEOVER_SERVICES.find((s) => s.cname.test(cname));
      if (!svc) continue;
      const resp = await fetchUrl(`https://${sub}/`).catch(() => ({ status: 0, body: '' }));
      const body = resp.body || (await fetchUrl(`http://${sub}/`).catch(() => ({ body: '' }))).body || '';
      if (svc.fingerprint.test(body))
        findings.push(
          F(
            'critical',
            sub,
            `Subdomain takeover: ${sub} has a dangling CNAME to ${svc.name} (${cname}) and the service is UNCLAIMED (its "${svc.name}" not-found fingerprint is served) — an attacker can claim it and serve content from your subdomain`,
          ),
        );
      break; // one service per subdomain
    }
  }
  return { subdomains, findings };
}

export { TAKEOVER_SERVICES };
