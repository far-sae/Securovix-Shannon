import { describe, expect, it } from 'vitest';
import { EvidenceChainHasher } from './hasher.js';
import { makeMetadata, makePayload } from './test-helpers.js';

describe('EvidenceChainHasher', () => {
  it('produces a verifiable two-entry chain', () => {
    const h = new EvidenceChainHasher();
    const e1 = h.computeHash('agent', 'checkpoint', makePayload('one'), makeMetadata());
    const e2 = h.computeHash('agent', 'checkpoint', makePayload('two'), makeMetadata());
    expect(e1.sequenceNumber).toBe(0);
    expect(e1.previousHash).toBe('0'.repeat(64));
    expect(e2.previousHash).toBe(e1.currentHash);
    expect(EvidenceChainHasher.verifyChain([e1, e2]).valid).toBe(true);
  });

  it('seedState continues the chain from a given cursor', () => {
    const h = new EvidenceChainHasher();
    h.seedState('a'.repeat(64), 5);
    const e = h.computeHash('agent', 'checkpoint', makePayload('x'), makeMetadata());
    expect(e.sequenceNumber).toBe(5);
    expect(e.previousHash).toBe('a'.repeat(64));
  });
});
