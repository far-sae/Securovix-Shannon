import { describe, it, expect } from 'vitest';
import { categoryAgentIndex } from './vuln-agents.js';

describe('categoryAgentIndex', () => {
  it('returns a 1-based index for every active category (business-logic is NOT 0)', () => {
    expect(categoryAgentIndex('sqli')).toBe(1);
    expect(categoryAgentIndex('business-logic')).toBe(6);
  });

  it('throws for an unknown category instead of silently returning 0', () => {
    expect(() => categoryAgentIndex('rce-ssti')).toThrow(/unknown.*category/i);
  });
});
