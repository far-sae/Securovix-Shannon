#!/usr/bin/env node
/**
 * Cloud storage exposure — third non-web module. Attribution + proof, both required for zero-FP:
 *   attribution — only buckets the client's OWN pages reference are checked (so the bucket is
 *                 provably theirs, not some random global-namespace bucket), and
 *   proof       — the bucket is confirmed PUBLICLY LISTABLE (its contents are enumerable), shown by
 *                 the provider's own directory-listing XML. A private bucket (AccessDenied) is not
 *                 reported.
 *
 * Covers AWS S3, Google Cloud Storage, and Azure Blob. fetchUrl is injectable for testing.
 */

// Extract cloud-storage bucket references from a page body → [{ id, provider, listUrl, signature }].
export function extractBuckets(body) {
  const found = new Map();
  const add = (id, provider, listUrl, signature) => {
    if (!found.has(id)) found.set(id, { id, provider, listUrl, signature });
  };
  const text = body || '';
  // AWS S3 — bucket.s3[.region].amazonaws.com
  for (const m of text.matchAll(/https?:\/\/([a-z0-9][a-z0-9.-]{1,61}\.s3[.-][a-z0-9-]*\.?amazonaws\.com)/gi)) {
    const host = m[1].toLowerCase();
    add(host, 'AWS S3', `https://${host}/`, /<ListBucketResult/i);
  }
  // AWS S3 — path style: s3[.region].amazonaws.com/bucket
  for (const m of text.matchAll(/https?:\/\/(s3[.-][a-z0-9-]*\.?amazonaws\.com)\/([a-z0-9][a-z0-9._-]{1,61})/gi)) {
    const id = `${m[1]}/${m[2]}`.toLowerCase();
    add(id, 'AWS S3', `https://${m[1]}/${m[2]}/`, /<ListBucketResult/i);
  }
  // Google Cloud Storage — storage.googleapis.com/bucket
  for (const m of text.matchAll(/https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61})/gi)) {
    const bucket = m[1].toLowerCase();
    add(`gcs:${bucket}`, 'Google Cloud Storage', `https://storage.googleapis.com/${bucket}`, /<ListBucketResult/i);
  }
  // Azure Blob — account.blob.core.windows.net/container
  for (const m of text.matchAll(/https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9-]{3,63})/gi)) {
    const acct = m[1].toLowerCase();
    const container = m[2].toLowerCase();
    add(
      `azure:${acct}/${container}`,
      'Azure Blob',
      `https://${acct}.blob.core.windows.net/${container}?restype=container&comp=list`,
      /<EnumerationResults/i,
    );
  }
  return [...found.values()];
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

const F = (severity, target, detail) => ({
  tool: 'cloud-exposure',
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool: 'cloud-exposure', detail }),
});

export async function runCloudExposure({ origin, pages = [], fetchUrl = defaultFetchUrl, limit = 8 } = {}) {
  const toScan = [...new Set([`${origin}/`, ...pages])].slice(0, 6);
  const buckets = new Map();
  for (const p of toScan) {
    const { body } = await fetchUrl(p);
    for (const b of extractBuckets(body)) buckets.set(b.id, b);
  }
  const findings = [];
  for (const b of [...buckets.values()].slice(0, limit)) {
    const { body } = await fetchUrl(b.listUrl);
    if (b.signature.test(body || ''))
      findings.push(
        F(
          'medium',
          b.listUrl,
          `Publicly listable cloud storage: ${b.provider} bucket "${b.id}" is referenced by the site and its contents are publicly enumerable (attackers can list unlinked/sensitive objects)`,
        ),
      );
  }
  return { buckets: [...buckets.keys()], findings };
}
