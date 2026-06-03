import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import { join } from 'node:path';
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
