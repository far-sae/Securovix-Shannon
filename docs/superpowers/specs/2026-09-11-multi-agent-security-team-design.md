# Multi-Agent Security Team — a blackboard architecture for autonomous pentest

Date: 2026-09-11
Status: Approved (direction chosen: "multi-agent security team")
Author: Shannon / Securovix

## 1. Goal

Move Shannon from a set of separately-triggered autonomous steps toward a
**self-coordinating team** of role-specialized agents that run a full engagement
hands-off. Agents do not follow a fixed pipeline; they **share a blackboard** and
**hand off work autonomously** by posting and reacting to typed facts. The
deterministic proof engine remains the source of truth, so the zero-false-positive
contract holds across every agent.

## 2. Architecture

### 2.1 Blackboard (shared state + autonomous handoff)

A blackboard is a shared, append-only, observable store of typed entries. Agents
communicate ONLY through it; a handoff is one agent posting a fact that another
agent subscribes to.

`Blackboard`:
- `post(type, data, by)` → appends `{ id, type, data, by, t }`, notifies subscribers.
- `all(type)` → entries of a type; `snapshot()` → everything.
- `subscribe(type, handler)` → react to new entries of a type.
- `claim(taskId, by)` → atomic single-winner claim (so two exploit agents never
  run the same task). Returns true to exactly one caller.

Entry types: `target`, `plan`, `task`, `finding`, `impact`, `fix`, `report`, `log`.

### 2.2 Roles

Each role is a small, pure-ish function over the blackboard + injected `deps`.

- **Recon agent** — from the crawled surface, runs `analyzeSurface`, posts each
  `target` and a prioritized `plan` (attack classes per target).
- **Coordinator** — turns the `plan` into `task` entries (`{ key, target }`),
  dispatches the **exploit pool**, then lets remediation and reporting drain.
- **Exploit agents (pool of N)** — loop: `claim` an unclaimed task, run
  `deps.probe(key, target)` (the engine's real zero-FP prober), post any confirmed
  `finding`, and on a hit post an `escalate` request that `deps.escalate` fulfils
  into an `impact` entry. Bounded concurrency via the existing `runConcurrent`.
- **Remediation agent** — subscribes to `finding`; runs `deps.locate(finding, files)`
  then `deps.patch(...)`, posts a `fix` labeled "suggested — review before applying".
- **Report agent** — aggregates confirmed `finding`s + `fix`es (+ leads kept
  separate) via `deps.report(run)` and posts the consolidated `report`.

### 2.3 Orchestrator

`runSecurityTeam({ surface, deps, roster, onEvent })`:
- `deps = { probe, escalate, locate, patch, report, files }` — injected. The server
  wires the real engine (`PROBERS`, impact demonstrators, `locateFinding`,
  `generatePatch`, `toMarkdown/toJson/toSarif`); tests wire fakes.
- `roster = { exploitAgents, remediation, report }` — sizes/toggles (default 4
  exploit agents).
- Emits a narrated timeline and builds a first-class **graph**:
  `{ nodes: [{ id, role, label }], edges: [{ from, to, type, t }] }`. Nodes are the
  role agents + the target; an edge records each handoff (recon→coordinator→exploit
  →remediation→report). The graph is returned AND streamed, so the dashboard renders
  real role-typed agents with animated handoffs, and the structure is unit-tested.
- Returns `{ findings, fixes, report, timeline, graph, stats }`.

## 3. Integration

- **Server**: `POST /api/agent/team` and `GET /api/agent/team/stream` (SSE), reusing
  `agentGateAndCrawl` (domain + IP ownership gate + crawl) and `agentDeps(target,
  headers)` for probe/escalate, extended with locate/patch/report deps. Persist via
  the existing `persistRun`.
- **Dashboard**: a "Security Team" panel; extend the existing `buildAgentGraph` /
  `pulseAgent` viz to render role nodes (recon · exploit×N · remediation · report)
  and animate handoff edges from the emitted graph/events.
- **Zero-FP preserved**: exploit agents post a `finding` only from an engine-confirmed
  prober; `fix`es are labeled suggested; the report keeps confirmed vs leads separate.

## 4. Tests (`agent-team.test.mjs`, node:test, offline)

1. Blackboard: post/all/subscribe deliver; `claim` yields a single winner.
2. Recon agent posts targets + a plan from a surface.
3. Exploit pool consumes tasks, posts findings from a fake probe, dedupes, respects
   concurrency, and posts nothing when the probe abstains (zero-FP).
4. Remediation agent turns a finding into a suggested fix via fake locate/patch.
5. Report agent aggregates findings + fixes.
6. `runSecurityTeam` end-to-end with fakes → findings + fixes + report + a graph
   whose edges include recon→exploit→remediation→report handoffs.

All offline, no API key, added to `npm test` and CI.

## 5. Non-goals / refusals

- No new offensive capability; this orchestrates the existing zero-FP probers.
- No destructive actions; remediation only suggests fixes (PRs stay the existing,
  separately-authorized step).
- No confirmation of a finding by anything other than the engine's proof.

## 6. Success criteria

1. `runSecurityTeam` runs recon → exploit pool → remediation → report hands-off with
   injected deps, producing findings, suggested fixes, a report, and a handoff graph.
2. Blackboard `claim` guarantees no double-execution of a task.
3. Zero findings when probers abstain (zero-FP intact).
4. New suite green; whole existing suite stays green.
5. Whitepaper committed.
