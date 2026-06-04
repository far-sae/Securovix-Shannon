export type SpecialKind = 'private' | 'loopback' | 'link-local' | 'metadata';

export function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const m = /^(.+)\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const base = ipv4ToInt(m[1]);
  const ipInt = ipv4ToInt(ip);
  if (base === null || ipInt === null) return false;
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

const METADATA_IPS = ['169.254.169.254', '100.100.200.200'];

export function isPrivateOrSpecial(ip: string): SpecialKind | null {
  if (METADATA_IPS.includes(ip)) return 'metadata';
  if (ipInCidr(ip, '127.0.0.0/8')) return 'loopback';
  if (ipInCidr(ip, '169.254.0.0/16')) return 'link-local';
  if (ipInCidr(ip, '10.0.0.0/8') || ipInCidr(ip, '172.16.0.0/12') || ipInCidr(ip, '192.168.0.0/16')) {
    return 'private';
  }
  return null;
}
