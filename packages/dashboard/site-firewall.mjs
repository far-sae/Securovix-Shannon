// Which protection answered a refused request, judged only from what the reply says about itself.
// Used to tell the owner whose firewall cut a test run short: their host's, their CDN's, or ours.
// Returns a name to show, or null when the reply does not say.
export function refusedBy(headers, body = '') {
  const get = (name) => {
    try {
      const value = typeof headers?.get === 'function' ? headers.get(name) : headers?.[name];
      return value == null ? '' : String(Array.isArray(value) ? value[0] : value);
    } catch {
      return '';
    }
  };
  const server = get('server').toLowerCase();
  if (
    String(body || '')
      .slice(0, 4000)
      .includes('Blocked by Securovix Defender')
  )
    return 'Securovix Defender';
  if (get('x-vercel-mitigated')) return 'the Vercel Firewall';
  if (get('cf-mitigated') || server.includes('cloudflare')) return 'Cloudflare';
  if (get('x-amzn-waf-action') || server.includes('awselb') || server.includes('cloudfront')) return 'the AWS firewall';
  if (server.includes('akamai')) return 'Akamai';
  if (get('x-sucuri-id') || server.includes('sucuri')) return 'Sucuri';
  if (server.includes('vercel')) return 'Vercel (the website’s host)';
  return null;
}
