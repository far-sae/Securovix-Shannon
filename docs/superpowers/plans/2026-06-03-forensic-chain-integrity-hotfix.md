# Forensic Chain Integrity Hotfix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Shannon's forensic SHA-256 evidence chain actually tamper-evident across resume, single-writer, and concurrency-safe — fixing three defects before Track B builds on it.

**Architecture:** The `EvidenceStore` (per-scan, owns the only `EvidenceChainHasher`) is the sole writer. On reopen it seeds the hasher cursor from the last persisted row (fixing the resume fork) and fails loud if that row's hash doesn't recompute (tamper detection). The public write surface is `record()`; raw `append()` becomes private. The duplicate hasher in the DI container is removed.

**Tech Stack:** TypeScript (ESM, NodeNext), better-sqlite3, Node crypto (SHA-256), **vitest** (added by this plan — the worker has no test runner today).

**Spec:** [2026-06-03-forensic-chain-integrity-hotfix-design.md](../specs/2026-06-03-forensic-chain-integrity-hotfix-design.md)

**Key facts verified against source before writing this plan:**
- `record()` is synchronous (`hasher.computeHash` → `append`, no `await`), so concurrent `Promise.all` calls cannot interleave today. Bug 3 is therefore an **invariant to lock with a regression test**, not a mutex to add.
- `append()` ([evidence-store.ts:51](../../../packages/worker/src/forensic/evidence-store.ts#L51)) is called only by `record()` ([:74](../../../packages/worker/src/forensic/evidence-store.ts#L74)) — no external callers, safe to make private.
- `container.evidenceHasher` ([di/container.ts:51,68,111](../../../packages/worker/src/di/container.ts#L51)) is constructed and exposed but never read anywhere — dead, safe to remove.
- `EvidenceChainHasher` has no cursor setter — Task 2 adds `seedState()`.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `packages/worker/package.json` | worker package manifest | add vitest devDep + `test` script |
| `packages/worker/vitest.config.ts` | test runner config (resolves NodeNext `.js`→`.ts`) | **create** |
| `packages/worker/src/forensic/test-helpers.ts` | shared test fixtures | **create** |
| `packages/worker/src/forensic/hasher.ts` | hash-chain cursor + verify | add `seedState()` |
| `packages/worker/src/forensic/hasher.test.ts` | hasher unit tests | **create** |
| `packages/worker/src/forensic/evidence-store.ts` | SQLite chain store (sole writer) | fix `restoreHasherState()`, make `append()` private, document `record()` invariant |
| `packages/worker/src/forensic/evidence-store.test.ts` | store resume/tamper/concurrency tests | **create** |
| `packages/worker/src/di/container.ts` | DI assembly | remove dead `evidenceHasher` + its import |

---

## Task 1: Set up vitest + shared test fixtures

**Files:**
- Modify: `packages/worker/package.json`
- Create: `packages/worker/vitest.config.ts`
- Create: `packages/worker/src/forensic/test-helpers.ts`
- Create: `packages/worker/src/forensic/hasher.test.ts`

- [ ] **Step 1: Add vitest to the worker package**

Run (from repo root):
```bash
pnpm --filter @shannon/worker add -D vitest@^2.1.0
```
Expected: `package.json` gains `"vitest": "^2.1.x"` under devDependencies and `pnpm-lock.yaml` updates.

- [ ] **Step 2: Add the `test` script**

In `packages/worker/package.json`, add to `"scripts"`:
```json
    "test": "vitest run",
    "test:watch": "vitest"
```

- [ ] **Step 3: Create the vitest config**

Create `packages/worker/vitest.config.ts`. The `js-to-ts` plugin makes NodeNext `.js` import specifiers (e.g. `./hasher.js`) resolve to their `.ts` source under vitest:
```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    {
      name: 'js-to-ts',
      enforce: 'pre',
      async resolveId(source, importer) {
        if (importer && source.startsWith('.') && source.endsWith('.js')) {
          const resolved = await this.resolve(source.replace(/\.js$/, '.ts'), importer, {
            skipSelf: true,
          });
          if (resolved) return resolved;
        }
        return null;
      },
    },
  ],
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
```

- [ ] **Step 4: Create shared test fixtures**

Create `packages/worker/src/forensic/test-helpers.ts`:
```ts
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CustodyMetadata, ForensicPayload } from './types.js';

export function tmpWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'shannon-forensic-'));
}

export function makeMetadata(): CustodyMetadata {
  return {
    scanId: 'test-scan',
    operatorId: 'op-1',
    machineId: 'machine-1',
    shannonVersion: '0.0.0-test',
    configHash: 'deadbeef',
    timezone: 'UTC',
  };
}

export function makePayload(description: string): ForensicPayload {
  return { description };
}
```

- [ ] **Step 5: Write the smoke test (also proves `.js`→`.ts` resolution works)**

Create `packages/worker/src/forensic/hasher.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
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
});
```

- [ ] **Step 6: Run the smoke test**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — 1 test passing. (If imports fail with "Cannot find module './hasher.js'", the `js-to-ts` plugin in Step 3 was not applied — re-check the config.)

- [ ] **Step 7: Commit**

```bash
git add packages/worker/package.json pnpm-lock.yaml packages/worker/vitest.config.ts packages/worker/src/forensic/test-helpers.ts packages/worker/src/forensic/hasher.test.ts
git commit -m "test(worker): add vitest + forensic test fixtures and hasher smoke test"
```

---

## Task 2: Add `seedState()` to EvidenceChainHasher

**Files:**
- Modify: `packages/worker/src/forensic/hasher.ts`
- Test: `packages/worker/src/forensic/hasher.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `packages/worker/src/forensic/hasher.test.ts` inside the `describe` block:
```ts
  it('seedState continues the chain from a given cursor', () => {
    const h = new EvidenceChainHasher();
    h.seedState('a'.repeat(64), 5);
    const e = h.computeHash('agent', 'checkpoint', makePayload('x'), makeMetadata());
    expect(e.sequenceNumber).toBe(5);
    expect(e.previousHash).toBe('a'.repeat(64));
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `seedState` is not a function / type error.

- [ ] **Step 3: Implement `seedState`**

In `packages/worker/src/forensic/hasher.ts`, add this method to the `EvidenceChainHasher` class (e.g. just after `getHead()`):
```ts
  seedState(previousHash: string, sequenceNumber: number): void {
    this.previousHash = previousHash;
    this.sequenceNumber = sequenceNumber;
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — both hasher tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/forensic/hasher.ts packages/worker/src/forensic/hasher.test.ts
git commit -m "feat(forensic): add EvidenceChainHasher.seedState for chain continuation"
```

---

## Task 3: Fix `restoreHasherState()` — resume continuation + tamper detection

**Files:**
- Modify: `packages/worker/src/forensic/evidence-store.ts:36-49`
- Test: `packages/worker/src/forensic/evidence-store.test.ts` (create)

- [ ] **Step 1: Write the failing tests**

Create `packages/worker/src/forensic/evidence-store.test.ts`:
```ts
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — the "continues across reopen" test errors with a SQLite PRIMARY KEY/UNIQUE constraint (the broken restore resets the cursor to 0 and re-inserts seq 0), and the tamper test fails because no error is thrown today.

- [ ] **Step 3: Replace `restoreHasherState()`**

In `packages/worker/src/forensic/evidence-store.ts`, replace the entire `restoreHasherState()` method (currently lines 36-49) with:
```ts
  private restoreHasherState(): void {
    const last = this.db
      .prepare('SELECT * FROM evidence_chain ORDER BY sequence_number DESC LIMIT 1')
      .get() as
      | {
          sequence_number: number;
          timestamp: string;
          previous_hash: string;
          current_hash: string;
          agent_name: string;
          action_type: string;
          payload: string;
          metadata: string;
        }
      | undefined;

    if (!last) return; // empty chain — hasher stays at genesis

    // Recompute the last entry's hash from its stored fields. A mismatch means the
    // evidence.db was corrupted or tampered with — fail loud rather than silently
    // resetting to genesis (which would fork the chain on the next append).
    const recomputed = createHash('sha256')
      .update(
        JSON.stringify({
          sequenceNumber: last.sequence_number,
          timestamp: last.timestamp,
          previousHash: last.previous_hash,
          agentName: last.agent_name,
          actionType: last.action_type,
          payload: JSON.parse(last.payload),
          metadata: JSON.parse(last.metadata),
        }),
      )
      .digest('hex');

    if (recomputed !== last.current_hash) {
      throw new Error(
        `Evidence chain integrity error: last entry (seq ${last.sequence_number}) hash ` +
          'does not recompute on restore. evidence.db may be corrupted or tampered with.',
      );
    }

    // Continue the chain from the last persisted entry.
    this.hasher.seedState(last.current_hash, last.sequence_number + 1);
  }
```
Note: the `JSON.stringify` field order (`sequenceNumber, timestamp, previousHash, agentName, actionType, payload, metadata`) must match `EvidenceChainHasher.computeHash` and `verifyChain` exactly — it does.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — both resume tests pass; smoke + seedState tests still pass.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/forensic/evidence-store.ts packages/worker/src/forensic/evidence-store.test.ts
git commit -m "fix(forensic): restore hasher cursor on reopen + fail loud on tamper (no chain fork)"
```

---

## Task 4: Make `append()` private (single-writer enforcement)

**Files:**
- Modify: `packages/worker/src/forensic/evidence-store.ts:51`

- [ ] **Step 1: Make `append` private**

In `packages/worker/src/forensic/evidence-store.ts`, change the method signature on line 51 from:
```ts
  append(entry: ForensicEntry): void {
```
to:
```ts
  private append(entry: ForensicEntry): void {
```
(`record()` at line 74 calls `this.append(entry)` — unaffected.)

- [ ] **Step 2: Verify the whole worker still type-checks (proves no external caller)**

Run: `pnpm --filter @shannon/worker typecheck`
Expected: PASS — no errors. (If any file outside `evidence-store.ts` called `.append()`, this would fail; verified beforehand that none do.)

- [ ] **Step 3: Run tests**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all forensic tests still pass (record → append path intact).

- [ ] **Step 4: Commit**

```bash
git add packages/worker/src/forensic/evidence-store.ts
git commit -m "refactor(forensic): make append() private so record() is the only chain writer"
```

---

## Task 5: Remove the dead duplicate hasher from the DI container

**Files:**
- Modify: `packages/worker/src/di/container.ts:8,51,68,111`

- [ ] **Step 1: Write the failing test**

Create `packages/worker/src/di/container.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { createContainer } from './container.js';

describe('createContainer', () => {
  it('builds without a workspace and exposes no standalone evidenceHasher', () => {
    const c = createContainer();
    expect('evidenceHasher' in c).toBe(false);
    expect(c.evidenceStore).toBeUndefined(); // no workspace → no store
    expect(c.configLoader).toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `'evidenceHasher' in c` is currently `true`.

- [ ] **Step 3: Remove the dead `evidenceHasher`**

In `packages/worker/src/di/container.ts` make three edits:

1. Delete the import on line 8:
```ts
import { EvidenceChainHasher } from '../forensic/hasher.js';
```
2. Delete the interface field on line 51:
```ts
  evidenceHasher: EvidenceChainHasher;
```
3. Delete the construction on line 68:
```ts
  const evidenceHasher = new EvidenceChainHasher();
```
4. Delete the line `evidenceHasher,` in the returned object (line 111).

- [ ] **Step 4: Run test + typecheck to verify they pass**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — container test passes.
Run: `pnpm --filter @shannon/worker typecheck`
Expected: PASS — no unused-import / missing-symbol errors.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/di/container.ts packages/worker/src/di/container.test.ts
git commit -m "refactor(di): remove dead duplicate evidenceHasher; EvidenceStore owns the only hasher"
```

---

## Task 6: Lock the concurrency invariant (Bug 3 — regression guard)

**Files:**
- Modify: `packages/worker/src/forensic/evidence-store.ts:67-76` (comment only)
- Test: `packages/worker/src/forensic/evidence-store.test.ts`

- [ ] **Step 1: Write the regression test**

Add to `packages/worker/src/forensic/evidence-store.test.ts` a new block:
```ts
describe('EvidenceStore concurrency invariant', () => {
  it('keeps a valid, contiguous chain under concurrent record() calls', async () => {
    const ws = tmpWorkspace();
    const store = new EvidenceStore(ws);
    await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        Promise.resolve().then(() =>
          store.record('agent', 'checkpoint', makePayload(`e${i}`), makeMetadata()),
        ),
      ),
    );
    const all = store.getAll();
    expect(all).toHaveLength(50);
    expect(all.map((e) => e.sequenceNumber)).toEqual(Array.from({ length: 50 }, (_, i) => i));
    expect(store.verifyIntegrity().valid).toBe(true);
    store.close();
  });
});
```

- [ ] **Step 2: Run the test (it passes — the invariant already holds for sync record())**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS. This characterizes and protects the invariant: because `record()` performs `computeHash` + `append` with no `await` in between, the single-threaded event loop serializes each call atomically.

- [ ] **Step 3: Document the invariant in code**

In `packages/worker/src/forensic/evidence-store.ts`, add this comment directly above the `record(` method (line 67):
```ts
  // INVARIANT (chain integrity): record() must remain fully synchronous — no `await`
  // between hasher.computeHash() (which mutates the in-memory cursor) and append()
  // (the DB insert). The single-threaded event loop then serializes concurrent
  // record() calls atomically. Track B's broker path must finish all async work
  // (HMAC validation, OOB correlation) BEFORE calling record(). See
  // evidence-store.test.ts "concurrency invariant". If record() ever becomes async,
  // add an explicit concurrency-1 queue around the compute+insert critical section.
```

- [ ] **Step 4: Run the full suite once more**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all tests green.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/forensic/evidence-store.ts packages/worker/src/forensic/evidence-store.test.ts
git commit -m "test(forensic): lock synchronous record() concurrency invariant + document it"
```

---

## Task 7: Final verification (release gate)

**Files:** none (verification only)

- [ ] **Step 1: Run the full worker test suite**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all tests across `hasher.test.ts`, `evidence-store.test.ts`, `container.test.ts` (target: ~7 tests).

- [ ] **Step 2: Run typecheck**

Run: `pnpm --filter @shannon/worker typecheck`
Expected: PASS — no type errors.

- [ ] **Step 3: Run lint**

Run (from repo root): `pnpm lint`
Expected: PASS (or auto-fixable). If Biome flags formatting, run `pnpm lint:fix` and re-commit.

- [ ] **Step 4: Confirm the gate scenario manually (the spec's acceptance criterion)**

The "continues across reopen + verifyIntegrity valid" test in Task 3 IS the spec's gate (write N → reopen → append → `verifyIntegrity().valid === true`). Confirm it is present and green in the Step 1 output.

- [ ] **Step 5: Final commit if lint changed anything**

```bash
git add -A
git commit -m "chore(forensic): lint/format pass for forensic hotfix" || echo "nothing to commit"
```

---

## Done criteria
- Reopen continues the chain (no fork); tamper on reopen throws.
- `append()` is private; `record()` is the only writer.
- No `evidenceHasher` on the container; `EvidenceStore` owns the single hasher.
- Concurrency invariant test green + documented.
- `test`, `typecheck`, `lint` all pass.

This unblocks Track B Phase 0.
