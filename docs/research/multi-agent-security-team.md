# A Blackboard Architecture for Autonomous, Zero-False-Positive Penetration Testing

**Role-specialized AI agents that coordinate through shared state and hand off work autonomously**

Shannon / Securovix — Purple Engine · 2026-09-11

---

## Abstract

Autonomous penetration testing is converging on multi-agent designs, but published
systems (HPTSA, MAPTA, xOffense, PentestGPT-style pipelines) either follow a fixed
pipeline or judge exploitation with a language model, which reintroduces false
positives. This work presents a **blackboard architecture** for an autonomous
security *team*: role-specialized agents — recon, an exploit pool, remediation, and
reporting — that communicate only through a shared, observable board and hand off
work by posting and reacting to typed facts. Crucially, the team is layered on top
of a **deterministic proof engine**: an exploit agent may post a finding *only* when
a benign proof signal fires, so the zero-false-positive contract is preserved across
every agent. The result is a self-coordinating team that runs a full engagement
hands-off — recon to report — while never emitting an unproven "confirmed" finding.

## 1. Motivation

Shannon already had the individual capabilities of an autonomous pentest —
understanding, probing, impact escalation, remediation suggestion, reporting — but a
human triggered each step. Moving to *full automation* means letting the steps
coordinate themselves. Two design choices dominate that move:

1. **How agents coordinate.** A fixed pipeline is brittle: it cannot let a finding in
   one place trigger work somewhere else, and it wastes the natural parallelism of
   probing many endpoints. A **blackboard** — a shared store that agents read, write,
   and subscribe to — lets coordination emerge from posted facts instead of hard-coded
   sequencing. It is a classic AI architecture (Hearsay-II, HASP) now well suited to
   LLM-era agent teams.
2. **What counts as a real finding.** If agents decide truth by argument or by asking
   a model, false positives return. Shannon keeps the **engine** as the sole arbiter:
   agents orchestrate, the deterministic prover confirms.

## 2. Architecture

### 2.1 The blackboard

An append-only, observable store of typed entries `{ id, type, data, by, t }`. Agents
interact through four operations: `post`, `all`, `subscribe`, and an atomic `claim`.
A **handoff** is simply one agent posting a fact that another subscribes to.
`claim(taskId)` guarantees a single winner, so two exploit agents never run the same
probe — the concurrency-safety property the team relies on.

Entry types: `target`, `plan`, `task`, `finding`, `impact`, `fix`, `report`, `log`.

### 2.2 The roles

- **Recon agent** — understands the crawled surface and posts targets plus a
  prioritized attack plan.
- **Coordinator** — turns the surface into concrete, claimable, prober-keyed tasks and
  dispatches the exploit pool.
- **Exploit pool (N agents)** — each agent claims an unclaimed task, runs the engine's
  real zero-FP prober, posts any confirmed finding, and escalates a hit into a benign
  impact demonstration. Bounded concurrency; order-independent.
- **Remediation agent** — subscribes to findings and posts a *labeled, suggested* fix
  for each (never applies anything).
- **Report agent** — aggregates confirmed findings, impacts, and suggested fixes
  (leads kept separate) into one consolidated report.

### 2.3 The orchestrator and the handoff graph

`runSecurityTeam` wires the roles hands-off, narrates a timeline, and builds a
first-class **graph** artifact: role nodes plus an edge for every handoff
(recon → coordinator → exploit → remediation → report). The graph is returned and
streamed, so the operator watches a real team of role-typed agents pass work between
them, and the structure is unit-tested rather than being a mere animation.

## 3. Preserving zero false positives across a team

The property that distinguishes Shannon from LLM-judged multi-agent pentesters is
that **agency never confers truth**. An exploit agent is a scheduler around a
deterministic prober; it can only surface what the prover already confirmed by a
benign proof signal. Remediation output is explicitly labeled *suggested*. The report
separates confirmed findings from unproven leads. Adding more agents increases
throughput and coordination, never the false-positive rate.

## 4. Evaluation

Run against a local application exposing a SQL-injection endpoint and an
LLM-backed chat endpoint, the team autonomously:

- ran recon → coordinator → a four-agent exploit pool → remediation → report;
- confirmed real findings including SQL injection and **prompt injection** (the new
  LLM attack-surface class), each by deterministic proof;
- produced suggested fixes and a consolidated report;
- emitted a handoff graph (role nodes + edges) rendered live in the dashboard.

A dedicated offline suite (`agent-team.test.mjs`, 8 tests) covers the blackboard
(including single-winner `claim`), each role, the end-to-end run, and the zero-FP
invariant (no finding when probers abstain). The whole project suite stays green.

## 5. Novelty statement

To our knowledge this is the first autonomous multi-agent penetration-testing team
that combines a **blackboard coordination model** with a **deterministic,
zero-false-positive proof engine as the sole arbiter of findings**. Where comparable
systems accept the false positives of LLM-judged exploitation, this design keeps
false positives at zero by construction while gaining the coordination and
parallelism of a role-specialized agent team.

## 6. Safety and scope

The team adds no offensive capability; it orchestrates the existing zero-FP probers.
Remediation only suggests fixes; opening pull requests remains a separate,
explicitly-authorized action. All activity runs behind the platform's existing
domain- and IP-ownership gating.

## References

- R. Fang et al. — Teams of LLM agents can exploit zero-day vulnerabilities (HPTSA).
- MAPTA — Multi-Agent Penetration Testing AI for the Web. arXiv:2508.20816.
- xOffense — An autonomous multi-agent framework for penetration testing. arXiv:2509.13021.
- L. D. Erman et al. — The Hearsay-II speech-understanding system: the blackboard model.
- OWASP Web Security Testing Guide; OWASP LLM Top 10 (2025).
