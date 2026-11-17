// Is an address on the public internet? Used wherever the server is about to contact an address a
// user supplied (a test target, a webhook, an identity provider), by the dashboard and by the worker.
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

export function isLocalHost(h) {
  return h === 'localhost' || h === '::1' || /^127\./.test(h) || h.endsWith('.local');
}

// A block list (not string prefixes) so that every way of writing an address is covered, including
// an IPv4 address wrapped in IPv6 (::ffff:169.254.169.254) and the NAT64 range, which reach the same
// private hosts.
const PRIVATE_ADDRESSES = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 3],
])
  PRIVATE_ADDRESSES.addSubnet(network, prefix, 'ipv4');
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
])
  PRIVATE_ADDRESSES.addSubnet(network, prefix, 'ipv6');

export function isPrivateAddress(address) {
  const value = String(address || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  const family = isIP(value);
  return family ? PRIVATE_ADDRESSES.check(value, family === 6 ? 'ipv6' : 'ipv4') : false;
}

// True when the URL is http(s), is not a local name, and every address its host resolves to is public.
export async function publicOriginAllowed(url) {
  const parsed = url instanceof URL ? url : new URL(url);
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    isLocalHost(parsed.hostname) ||
    isPrivateAddress(parsed.hostname)
  )
    return false;
  try {
    const addresses = await lookup(parsed.hostname.replace(/^\[|\]$/g, ''), { all: true, verbatim: true });
    return addresses.length > 0 && addresses.every((x) => !isPrivateAddress(x.address));
  } catch {
    return false;
  }
}
