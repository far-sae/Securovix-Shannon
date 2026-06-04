import { describe, expect, it } from 'vitest';
import { ACTIVE_VULN_CATEGORIES, isActiveCategory } from './categories.js';

describe('active categories', () => {
  it('lists the six pipeline categories including business-logic', () => {
    expect(ACTIVE_VULN_CATEGORIES).toEqual(['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic']);
  });

  it('business-logic is at a valid (non-negative) index — guards the agentIndex bug', () => {
    expect(ACTIVE_VULN_CATEGORIES.indexOf('business-logic')).toBeGreaterThanOrEqual(0);
  });

  it('isActiveCategory recognizes members and rejects non-members', () => {
    expect(isActiveCategory('sqli')).toBe(true);
    expect(isActiveCategory('rce-ssti')).toBe(false);
  });
});
