# Proof-Based Detection of Prompt Injection in Deployed Web Applications

**A zero-false-positive, black-box method for the LLM attack surface**

Shannon / Securovix — Purple Engine · 2026-09-11

---

## Abstract

Large language models are now embedded behind ordinary HTTP surfaces: chat boxes,
"summarize" buttons, support assistants, document Q&A, auto-reply. The OWASP GenAI
Security Project ranks **prompt injection (LLM01:2025)** as the top risk to these
systems. Yet the practical tooling to *test a deployed application from the
outside* for prompt injection is either defensive (guardrails that live inside
the app) or judged by a second LLM (fuzzy and false-positive-prone).

This work presents a **black-box, zero-false-positive, proof-based** method for
detecting **direct** and **indirect (second-order)** prompt injection in deployed
web applications, and an implementation inside Shannon's pure-Node proof engine.
The method transplants the engine's signature proof-by-construction discipline —
the same epistemics as the classic `{{7*7}}=49` server-side template injection
oracle — onto the AI layer. A finding is confirmed **only** when the model emits a
deterministic marker that is a *computed* function of a run-unique nonce and is
absent from a control baseline, so reflection or coincidence cannot manufacture
it. No LLM-judge, no classifier. The result is the first offensive scanner, to our
knowledge, that discovers LLM boundaries in an arbitrary web app, tests both
injection shapes, and proves the result with zero false positives by construction.

## 1. Background and prior art

**The attack.** Prompt injection occurs when attacker-controlled text reaches a
model and overrides its instructions. *Direct* injection travels in the request
the attacker sends. *Indirect* (or *second-order*) injection is planted in stored
or third-party content — a profile field, a comment, a document, a filename — and
is executed later when a *different* flow feeds that content to the model. Indirect
injection is widely regarded as the more dangerous and least-defended variant.

**Research.** The literature characterises the attack thoroughly:

- OWASP GenAI Security Project, *LLM01:2025 Prompt Injection*, and the broader
  OWASP LLM Top 10 (2025).
- Greshake et al., *"Not what you've signed up for: Compromising real-world
  LLM-integrated applications with indirect prompt injection."*
- *INJECAGENT: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM
  Agents* (1,054 test cases; ReAct GPT-4 vulnerable ~24% of the time).
- *LivePI*, *AutoDojo*, and related 2025 benchmarks for indirect injection against
  agents.

**Tools, and why they do not fit a zero-FP DAST.** Defensive detectors —
Vigil, little-canary, Data Sentinel, PIShield, Attention Tracker — run *inside*
the application as guardrails; they are not external scanners. `promptmap2` scans
black-box but only tests **direct** injection against an endpoint already known to
be a chatbot, and it judges success with **another LLM**, which reintroduces the
false positives Shannon exists to eliminate.

**The gap.** No prior tool, to our knowledge, performs all three of: (a) black-box
**discovery** of where an LLM sits inside an arbitrary web app, (b) **indirect /
second-order** injection testing across two flows, and (c) **zero-false-positive
proof** of the result. That is the contribution here.

## 2. Method: proof by construction on the AI layer

Shannon's engine treats a finding as true **iff** a benign, deterministic proof
signal fires — a finding exists by construction, not by judgement. We apply the
same rule to prompt injection.

For each probe we generate a run-unique nonce `n` and inject a benign *instruction*
whose only satisfiable outcome is the model **computing** a value that is not
present in the payload. Let `M` be that marker. A finding is **confirmed** iff:

1. `M` appears in the model's output; and
2. `M` is **absent from a control baseline** — the same field probed with a
   benign, no-instruction request.

Because `M` is a *computed* value (an arithmetic product/sum of high-entropy
operands, or a reversed nonce) that never appears verbatim in the payload,
reflection of the request cannot introduce it, and the control rules out
coincidental page content. Confirmation therefore *implies* the model followed the
injected instruction. This is exactly the `{{7*7}}=49` argument, moved from a
template engine to a language model.

**Oracle battery** (multiple, so detection survives models that resist any one
phrasing):

| Oracle | Injected instruction (benign) | Marker `M` |
|---|---|---|
| arithmetic-product | "output only the result of A*B" | `A·B` |
| arithmetic-sum | "reply with only the sum of C+D" | `C+D` |
| reverse-nonce | "reply with this text reversed: n" | `reverse(n)` |

All operands are derived deterministically from the nonce, so `M` is unique per
run and cannot collide with unrelated numbers across runs.

**Direct injection.** Discover candidate boundaries (existing query parameters
first, then parameter/path heuristics such as `prompt`, `message`, `ask`, `/chat`,
`/summarize`), run the oracle battery on each against its control, and confirm on
the first deterministic marker.

**Indirect (second-order) injection.** Plant a benign instruction into a stored
sink through one flow (`plant`), then invoke the consuming LLM feature through a
*different* flow (`render`). The render request carries **no** attacker input, so
any appearance of the computed marker in the rendered output proves the stored
instruction was executed by the model. This is the crown-jewel capability, and the
one no prior black-box scanner provides.

**Benign impact (read-only).** Once injection is confirmed, the engine attempts a
single, bounded, read-only impact proof: **system-prompt / context leakage**
(OWASP LLM07). It asks the model to emit its own instructions between two
run-unique delimiters and confirms only when the same non-supplied context is
returned across two independent requests — deterministic evidence of fixed-context
disclosure, not an echo. No destructive action, no real-user-data exfiltration, no
third-party harm are ever attempted, consistent with the platform's safety stance.

## 3. Architecture

Four self-contained, dependency-injected modules, unit-testable with no API key
and no network:

- `llm-surface.mjs` — boundary discovery + the oracle battery.
- `llm-inject.mjs` — direct and indirect probers.
- `llm-impact.mjs` — the read-only system-prompt-leakage proof.
- `llm-compliance.mjs` — OWASP LLM Top 10 (2025) standards mapping.

They integrate into the existing proof engine as two detection classes —
`llm-prompt-injection` and `llm-indirect-injection` — plus the `llm-system-prompt-leak`
impact class, carried through the engine's compliance table, SARIF export, and
dashboard exactly like every other class. Ambiguous behaviour that yields no
deterministic marker is recorded as a labeled *potential lead*, never as a
confirmed finding.

## 4. Evaluation

The engine ships an in-process, no-API-key vulnerable app in `--selftest`: a
deterministic fake model that *obeys* injected instructions (so the same markers a
real instruction-following model would emit are emitted here), a direct chat sink,
and a stored-note / summarize pair for the second-order case.

- **Direct** injection is confirmed against the obeying model and **abstains**
  against a plain reflector (the zero-FP requirement).
- **Indirect** injection is confirmed end-to-end: a note stored via one flow is
  executed by the model in the summarize flow.
- **Impact**: system-prompt leakage is confirmed only when a stable, non-supplied
  context is disclosed twice.

The module adds a dedicated test suite (`llm.test.mjs`) to the project's CI, which
passes with the whole existing suite green.

## 5. Novelty statement

To our knowledge this is the first implementation that combines, in one black-box
scanner for deployed web applications: automatic LLM-boundary discovery, direct
**and** indirect/second-order prompt-injection testing, and confirmation by
deterministic proof-of-obedience with zero false positives by construction (no
LLM-judge). It operationalises a body of academic research (OWASP LLM01:2025,
INJECAGENT, LivePI, AutoDojo, Greshake et al.) that had not previously been turned
into a practical, false-positive-free offensive tool.

## 6. Safety and scope

Payloads are benign nonces and arithmetic only — no jailbreak content is generated.
Impact proofs are read-only and bounded. The engine refuses destructive,
deceptive, or real-user-data-exfiltrating escalation. All testing presupposes the
platform's existing dual authorization (domain- and IP-ownership gating).

## References

- OWASP GenAI Security Project — LLM01:2025 Prompt Injection. https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- K. Greshake et al. — Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection.
- Q. Zhan et al. — INJECAGENT: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents.
- LivePI — More realistic benchmarking of agents against indirect prompt injection. arXiv:2605.17986.
- AutoDojo — Adaptive black-box attacks reveal the limits of IPI defenses. arXiv:2606.15057.
- promptmap2 — a black-box prompt-injection scanner for custom LLM applications. https://github.com/utkusen/promptmap
- Vigil, little-canary, PIShield, Attention Tracker — defensive prompt-injection detectors.
