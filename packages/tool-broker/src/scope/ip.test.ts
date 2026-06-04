import { describe, expect, it } from 'vitest';
import { ipInCidr, ipv4ToInt, isPrivateOrSpecial } from './ip.js';

describe('ipv4ToInt', () => {
  it('parses dotted-quad to a 32-bit int', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0);
    expect(ipv4ToInt('255.255.255.255')).toBe(0xffffffff);
    expect(ipv4ToInt('10.0.0.1')).toBe(0x0a000001);
  });
  it('returns null for malformed input', () => {
    expect(ipv4ToInt('256.0.0.1')).toBeNull();
    expect(ipv4ToInt('10.0.0')).toBeNull();
  });
});

describe('ipInCidr', () => {
  it('matches addresses inside the block', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(ipInCidr('192.168.1.5', '192.168.1.0/24')).toBe(true);
  });
  it('rejects addresses outside the block', () => {
    expect(ipInCidr('11.0.0.1', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('192.168.2.5', '192.168.1.0/24')).toBe(false);
  });
  it('/32 matches only the exact host', () => {
    expect(ipInCidr('1.2.3.4', '1.2.3.4/32')).toBe(true);
    expect(ipInCidr('1.2.3.5', '1.2.3.4/32')).toBe(false);
  });
});

describe('isPrivateOrSpecial', () => {
  it('flags RFC1918, loopback, link-local, and cloud metadata', () => {
    expect(isPrivateOrSpecial('10.0.0.1')).toBe('private');
    expect(isPrivateOrSpecial('172.16.5.5')).toBe('private');
    expect(isPrivateOrSpecial('192.168.0.9')).toBe('private');
    expect(isPrivateOrSpecial('127.0.0.1')).toBe('loopback');
    expect(isPrivateOrSpecial('169.254.169.254')).toBe('metadata');
    expect(isPrivateOrSpecial('169.254.1.1')).toBe('link-local');
  });
  it('returns null for normal public IPs', () => {
    expect(isPrivateOrSpecial('93.184.216.34')).toBeNull();
  });
});
