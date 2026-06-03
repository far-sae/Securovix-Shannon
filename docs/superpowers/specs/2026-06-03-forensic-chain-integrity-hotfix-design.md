# Forensic Chain Integrity Hotfix — Design

**Date:** 2026-06-03
**Status:** Design — ready for implementation plan
**Ships:** BEFORE Track B (the Deeper Exploitation Engine). Track B's safety-decision logging depends on a correct chain.
**Scope size:** Small, focused, backward-compatible patch.

---

## 1. Problem

Shannon's forensic evidence store is meant to be a **tamper-evident SHA-256 hash chain** for legal/compliance defensibility (chain-of-custody, integrity report). Three pre-existing correctness bugs break that guarantee *today*, independent of any new feature. They were verified directly against source during design validation.

### Bug 1 — Chain forks on resume (CRITICAL)
`restoreHasherState()` ([packages/worker/src/forensic/evidence-store.ts:36-49](../../../packages/worker/src/forensic/evidence-store.ts#L36-L49)) reads the last row, recreates the hasher, then runs a replay loop **with an empty body** — it iterates and does nothing. After any crash/resume the in-memory hasher resets to `sequenceNumber 0` / genesis `previousHash`, so the next append **silently forks the chain**. The tamper-evident record is not tamper-evident across the one event (resume) it most needs to survive.

### Bug 2 — Hasher is bypassable (CRITICAL)
`append()` ([evidence-store.ts:51](../../../packages/worker/src/forensic/evidence-store.ts#L51)) is **public** and inserts a caller-supplied `ForensicEntry` verbatim, skipping the hasher entirely. Any component holding the store reference can forge or insert unhashed entries. The "only the hasher writes the chain" invariant is unenforced.

### Bug 3 — No write serialization (CRITICAL/HIGH)
`record()` → `hasher.computeHash()` mutates the in-memory `previousHash` / `sequenceNumber` with **no mutex or queue**. `scan.ts` fans out vuln/exploit pairs under `Promise.all` ([workflows/scan.ts:70](../../../packages/worker/src/workflows/scan.ts#L70)), so multiple activities complete concurrently in one worker process. `better-sqlite3` serializes the DB insert, but the cursor mutation is **not atomic with the insert** → interleaved completions yield non-monotonic / aliased sequence numbers and an invalid chain.

### Bug 4 — Two unconnected hashers (correctness hazard)
The DI container constructs a standalone `evidenceHasher = new EvidenceChainHasher()` ([di/container.ts:51,68,111](../../../packages/worker/src/di/container.ts#L51)), while `EvidenceStore` constructs its **own private** `this.hasher` through which all real writes flow. Two cursors over one chain invites silent forks the moment anything hashes through the wrong one.

---

## 2. Goals / Success Criteria

1. After a crash/resume, appending **continues** the existing chain; `verifyIntegrity().valid === true`.
2. The **only** way to write a chain entry is through the hasher (`record()`); raw `append()` is not publicly reachable.
3. Concurrent `record()` calls produce a **strictly monotonic, valid** chain.
4. **One** hasher instance is the single source of truth for the chain cursor.
5. Every fix is gated by a regression test that fails on the current code and passes after.

Non-goals: the `tool-invocation` action type / payload fields and broker HMAC verification — those belong to the Track B spec and build on this.

---

## 3. Design

### 3.1 Fix resume (Bug 1)
On store open, if the table is non-empty: seed the hasher cursor from the last row —
`previousHash = last.current_hash`, `sequenceNumber = last.sequence_number + 1`. If empty, start at genesis. Expose `EvidenceChainHasher.seedState(previousHash, sequenceNumber)` ([forensic/hasher.ts](../../../packages/worker/src/forensic/hasher.ts)) so the store can set this explicitly rather than relying on a replay loop.
**Fail loud, not silent:** if the last row's stored `current_hash` doesn't match a recomputation of that row, do **not** silently reset to genesis — surface an integrity error so the operator decides (the chain may have been tampered with or corrupted).

### 3.2 Enforce single writer (Bug 2)
Make `append()` **private** (rename to `#appendRaw` / `private appendRaw`). The only public write surface is `record(entryWithoutHash)`, which computes the hash via the single hasher and then inserts atomically. Audit all current callers of `append()` and migrate them to `record()`.

### 3.3 Serialize writes (Bug 3)
Route all `record()` calls through an **in-process concurrency-1 async queue** so hash-compute + insert is one atomic critical section. Reuse the existing mutex pattern in [audit/mutex.ts](../../../packages/worker/src/audit/mutex.ts) if it fits; otherwise a small promise-chained mutex on the `EvidenceStore`. Confirm (and assert in DI) that `EvidenceStore` is a **per-scan singleton** — one writer instance per `evidence.db`.

### 3.4 Unify the hasher (Bug 4)
Remove `container.evidenceHasher`. The `EvidenceStore` owns the only `EvidenceChainHasher`. Anything that needs hashing goes through the store. Update [di/container.ts](../../../packages/worker/src/di/container.ts) and any references.

---

## 4. Components touched

| File | Change |
|------|--------|
| `forensic/evidence-store.ts` | Fix `restoreHasherState`; make `append` private; add concurrency-1 queue around `record` |
| `forensic/hasher.ts` | Add `seedState(previousHash, sequenceNumber)`; recompute-verify helper |
| `di/container.ts` | Drop `evidenceHasher`; ensure single per-scan `EvidenceStore` |
| `forensic/package-builder.ts` | Confirm `verifyIntegrity()` reflects the corrected cursor logic |

---

## 5. Testing (TDD — write these first)

- **Resume:** write N entries → close → reopen store → append M → `verifyIntegrity().valid === true`; sequence numbers contiguous `0..N+M-1`.
- **Concurrency:** fire K concurrent `record()` calls → exactly K entries, strictly monotonic sequence, valid chain.
- **Encapsulation:** `append()` is not on the public type and not callable externally; only `record()` advances the chain.
- **Single hasher:** the container exposes no second hasher; all writes share one cursor.
- **Tamper-detection:** corrupt one row's `current_hash` → reopen → integrity error surfaced (not silent genesis reset).
- **Regression:** existing forensic package build + integrity report still pass.

---

## 6. Rollout

Backward-compatible patch release. Existing chains keep verifying; reopened chains now correctly **continue** instead of forking. No data migration. This is a prerequisite gate for Track B Phase 0.
