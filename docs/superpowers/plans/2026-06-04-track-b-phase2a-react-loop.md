# Track B Phase 2a — ReAct Tool-Use Loop + Circuit Breaker (host-testable) — Plan

**Goal:** Give LLM agents the ability to actually call the broker's tools (the ReAct tool-use loop), and the resilience to degrade gracefully when the broker is down (circuit breaker). Both pure TS, host-testable with a mocked LLM client — no Temporal, no Docker.

**Spec:** [Track B engine](../specs/2026-06-03-deeper-exploitation-engine-design.md) §2.6 + §13 Phase 2. Builds on the merged Phase 1b broker (`ToolClient`).

**Scope split:** Phase 2a = the two pure modules below (this plan). **Phase 2b (Temporal-gated)** = `runBrokerTool`/`runVerifyGate` activities + workflow wiring + degrade path; needs a Temporal worker to verify — separate plan.

---

## Task 1: CircuitBreaker (pure)

**Files:** create `packages/worker/src/broker/circuit-breaker.ts` (+ `.test.ts`).

States: `closed` → (≥threshold failures) → `open` → (after cooldown) → `half-open` → (success) `closed` | (failure) `open`. Injectable clock for deterministic tests.

- [ ] Write `circuit-breaker.test.ts`: opens after N failures; `canProceed()` false while open; after cooldown becomes half-open (canProceed true); success closes it; a failure in half-open re-opens.
- [ ] Implement `CircuitBreaker` with `canProceed()`, `recordSuccess()`, `recordFailure()`, `getState()`, constructor `{ failureThreshold, cooldownMs, now? }`.
- [ ] Run worker test (pass), typecheck (0). Commit `feat(worker): CircuitBreaker for broker-unavailable degradation`.

## Task 2: executeAgentWithTools (ReAct loop, pure)

**Files:** create `packages/worker/src/agents/tool-loop.ts` (+ `.test.ts`).

A loop that calls an injected Anthropic-shaped LLM client with `tools`, dispatches each `tool_use` block via an injected `dispatch` (which the real wiring routes to `ToolClient`), appends `tool_result`, and repeats until `stop_reason !== 'tool_use'` or a hard `maxTurns` cap (runaway guard). Optional `onTurn` hook for per-turn forensic snapshots.

- [ ] Write `tool-loop.test.ts` with a fake client: (a) immediate end_turn → returns text, 0 tool calls; (b) one tool_use then end_turn → dispatch called with name/input, returns final text, toolCalls=1, turns=2; (c) always tool_use → throws past maxTurns; (d) onTurn fires each turn.
- [ ] Implement `executeAgentWithTools(userMessage, opts)` + the minimal `LlmClient`/block types.
- [ ] Run worker test (pass), typecheck (0). Commit `feat(worker): executeAgentWithTools ReAct tool-use loop with hard turn cap`.

## Done criteria
- CircuitBreaker state machine correct under injected clock.
- ReAct loop drives multi-turn tool use, caps runaway loops, surfaces final text — proven with a mocked client (no real LLM/Temporal/Docker).
- Worker suite green, typecheck clean.

**Phase 2b (next, Temporal-gated):** wire `executeAgentWithTools` + `ToolClient` + `CircuitBreaker` into `runBrokerTool`/`runVerifyGate` Temporal activities and the scan workflow (separate `proxyActivities` 5m/60s; circuit-open → degrade to LLM+Playwright). Then **Phase 3** = SSTI agents = MVP.
