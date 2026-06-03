import { join } from 'node:path';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { EvidenceStore } from './evidence-store.js';
import { makeMetadata, makePayload, tmpWorkspace } from './test-helpers.js';

describe('EvidenceStore resume', () => {
  it('continues the chain across reopen without forking', () => {
    const ws = tmpWorkspace();
    const s1 = new EvidenceStore(ws);
    s1.record('agent', 'checkpoint', makePayload('a'), makeMetadata());
    s1.record('agent', 'checkpoint', makePayload('b'), makeMetadata());
    s1.close();

    const s2 = new EvidenceStore(ws); // reopen triggers restoreHasherState
    s2.record('agent', 'checkpoint', makePayload('c'), makeMetadata());
    const all = s2.getAll();
    expect(all.map((e) => e.sequenceNumber)).toEqual([0, 1, 2]);
    expect(s2.verifyIntegrity().valid).toBe(true);
    s2.close();
  });

  it('throws on reopen when the last entry was tampered with', () => {
    const ws = tmpWorkspace();
    const s1 = new EvidenceStore(ws);
    s1.record('agent', 'checkpoint', makePayload('a'), makeMetadata());
    s1.close();

    const db = new Database(join(ws, 'evidence.db'));
    db.prepare('UPDATE evidence_chain SET current_hash = ? WHERE sequence_number = 0').run('f'.repeat(64));
    db.close();

    expect(() => new EvidenceStore(ws)).toThrow(/integrity error/i);
  });
});

describe('EvidenceStore concurrency invariant', () => {
  it('keeps a valid, contiguous chain under concurrent record() calls', async () => {
    const ws = tmpWorkspace();
    const store = new EvidenceStore(ws);
    await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        Promise.resolve().then(() => store.record('agent', 'checkpoint', makePayload(`e${i}`), makeMetadata())),
      ),
    );
    const all = store.getAll();
    expect(all).toHaveLength(50);
    expect(all.map((e) => e.sequenceNumber)).toEqual(Array.from({ length: 50 }, (_, i) => i));
    expect(store.verifyIntegrity().valid).toBe(true);
    store.close();
  });

  it('record() is synchronous (returns an entry, not a Promise)', () => {
    // This is the assertion that actually locks the invariant: if a future change
    // makes record() async (returning a Promise), this fails — catching exactly the
    // regression the comment in evidence-store.ts warns against.
    const ws = tmpWorkspace();
    const store = new EvidenceStore(ws);
    const result = store.record('agent', 'checkpoint', makePayload('x'), makeMetadata());
    expect(result instanceof Promise).toBe(false);
    expect(result.sequenceNumber).toBe(0);
    store.close();
  });
});
