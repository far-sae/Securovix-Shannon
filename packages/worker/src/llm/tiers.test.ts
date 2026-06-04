import { describe, it, expect } from 'vitest';
import { AGENT_TIERS, validateAgentTiers } from './tiers.js';
import { ACTIVE_VULN_CATEGORIES } from '../workflows/categories.js';

describe('validateAgentTiers', () => {
  it('passes: every active category has vuln- and exploit- tiers', () => {
    expect(() => validateAgentTiers()).not.toThrow();
  });

  it('every active category is registered in AGENT_TIERS', () => {
    for (const c of ACTIVE_VULN_CATEGORIES) {
      expect(AGENT_TIERS[`vuln-${c}`]).toBeDefined();
      expect(AGENT_TIERS[`exploit-${c}`]).toBeDefined();
    }
  });
});
