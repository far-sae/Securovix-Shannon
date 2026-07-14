#!/usr/bin/env node
/**
 * IP / range ownership — the authorization layer for NETWORK-level scanning. Scanning an IP you do
 * not control is illegal, so a network target is authorized only when EITHER:
 *   (a) it is the IP the client's already-verified DOMAIN resolves to (they proved they own the app
 *       that runs there — derived automatically, no extra step), OR
 *   (b) its /8–/32 CIDR range has been explicitly VERIFIED: the client attests ownership AND proves
 *       control by serving an HMAC token at http://<an-ip-in-range>/.well-known/shannon-verify.txt.
 *
 * IPv4 only for CIDR membership (IPv6 ranges are attested but membership isn't computed here). The
 * DNS resolver and HTTP fetcher are injectable so the logic is unit-testable without the network.
 */

import { createHmac } from 'node:crypto';

export function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

// "203.0.113.0/24" → { base, bits, mask } or null.
export function parseCidr(cidr) {
  const [ipPart, bitsPart] = String(cidr).trim().split('/');
  const base = ipToInt(ipPart);
  const bits = Number(bitsPart);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, bits, mask };
}

export function ipInCidr(ip, cidr) {
  const n = ipToInt(ip);
  const c = parseCidr(cidr);
  if (n === null || !c) return false;
  return (n & c.mask) >>> 0 === c.base;
}

// Deterministic per-(user, cidr) token — recomputable, so we never store the token itself.
export function ipVerifyToken(secret, userId, cidr) {
  return createHmac('sha256', secret).update(`ipverify:${userId}:${cidr}`).digest('hex').slice(0, 40);
}

export function verificationInstructions(cidr, token) {
  return {
    cidr,
    token,
    method: `Serve this token at http://<any-IP-in-${cidr}>/.well-known/shannon-verify.txt`,
    content: token,
    note: 'Proves you control a host in the range. Combined with your ownership attestation, this authorizes network testing of the range.',
  };
}

// Prove control: fetch the well-known token from an IP in the range (Host header optional).
export async function checkIpControl(ip, token, fetcher = fetch, host) {
  for (const scheme of ['https', 'http']) {
    try {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 8000);
      const r = await fetcher(`${scheme}://${ip}/.well-known/shannon-verify.txt`, {
        signal: c.signal,
        headers: host ? { Host: host } : {},
      });
      const body = await r.text().catch(() => '');
      clearTimeout(t);
      if (r.ok && body.includes(token)) return true;
    } catch {}
  }
  return false;
}

// Resolve verified domains → the set of IPv4 addresses that legitimately serve the client's app.
export async function deriveAuthorizedIps(domains, resolve4) {
  const ips = new Set();
  for (const d of domains || []) {
    try {
      for (const ip of (await resolve4(d)) || []) if (ipToInt(ip) !== null) ips.add(ip);
    } catch {}
  }
  return ips;
}

// Is a network target authorized? Resolve its host; authorized if any resolved IP is a verified-domain
// IP OR falls inside a verified CIDR. Never authorizes an unlisted internet host.
export async function isHostAuthorizedForNetworkScan(
  host,
  { authorizedIps = new Set(), verifiedCidrs = [] },
  resolve4,
) {
  const direct = ipToInt(host) !== null ? [host] : await resolve4(host).catch(() => []);
  const ips = direct && direct.length ? direct : [];
  if (!ips.length) return false;
  return ips.every((ip) => authorizedIps.has(ip) || verifiedCidrs.some((c) => ipInCidr(ip, c)));
}
