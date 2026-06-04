import { describe, expect, it } from 'vitest';
import { isValidCidr, matchesPath } from './scope-rules.js';

describe('matchesPath', () => {
  it('treats a bare path as a prefix (back-compat)', () => {
    expect(matchesPath('/api/', '/api/users')).toBe(true);
    expect(matchesPath('/api/', '/admin')).toBe(false);
  });

  it('supports * (single segment) and ** (multi segment) globs', () => {
    expect(matchesPath('/api/*/edit', '/api/users/edit')).toBe(true);
    expect(matchesPath('/api/*/edit', '/api/users/1/edit')).toBe(false);
    expect(matchesPath('/api/**', '/api/users/1/edit')).toBe(true);
  });

  it('supports explicit regex via re: prefix', () => {
    expect(matchesPath('re:^/v[0-9]+/users$', '/v2/users')).toBe(true);
    expect(matchesPath('re:^/v[0-9]+/users$', '/users')).toBe(false);
  });
});

describe('isValidCidr', () => {
  it('accepts valid IPv4 CIDRs', () => {
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('192.168.1.0/24')).toBe(true);
  });

  it('rejects malformed CIDRs', () => {
    expect(isValidCidr('10.0.0.0')).toBe(false);
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
    expect(isValidCidr('999.0.0.0/8')).toBe(false);
  });
});
