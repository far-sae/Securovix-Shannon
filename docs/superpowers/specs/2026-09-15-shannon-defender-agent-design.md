# Shannon Defender — Agentic Live Blue-Team Defense

**Status:** Approved design (pre-implementation)
**Date:** 2026-09-15
**Author:** Shannon team (via Claude Code brainstorming)

---

## 1. Summary

Shannon today is an **autonomous, proof-based offensive** pentest platform: it
attacks a target, proves each finding with a benign signal (zero false positives
by construction), and emits detection rules plus a live inline proxy that blocks
the re-run exploit. This design adds a **live blue-team defender**: an agentic AI
that watches real traffic, judges whether an event is a genuine attack, and
responds (block inline, block IP, alert, isolate) — and a **Defender page** where
an external user connects their own system or network to be protected.

The defender is built *on top of* the existing engine and multi-agent
infrastructure, and it **preserves Shannon's core identity**:

> Zero false positives by construction. The deterministic engine is the source of
> truth. The LLM layer is judgment, never authority — it can raise an alert,
> explain, or downgrade a finding, but it can **never, by itself, cause a block.**

### Non-goals (this design)
- Full IDS/IPS packet inspection at line rate.
- Replacing an enterprise firewall or SIEM.
- Destructive response (Shannon never DoSes, drops data, or attacks back).
- Auto-blocking on LLM suspicion alone.

---

## 2. Architecture overview

Three isolated layers connected by one normalized event type:

```
   [ user's system ]                          ┌─────────────────────────┐
        │  traffic / logs / net events        │   Defender page (SPA)   │
        ▼                                      │  connect · live view ·  │
  ┌───────────────┐   AttackEvent   ┌──────────┤  monitor⇄enforce toggle │
  │  CONNECTORS    │───────────────▶│ DEFENDER  │  agent graph + timeline │
  │ (sources)      │                │  AGENT    └─────────────────────────┘
  │ • http-proxy   │                │ detect→   │
  │ • log-stream   │◀── verdict ───▶│  decide→  │──▶ ┌─────────────┐
  │ • network      │   (inline 403) │  respond  │    │ RESPONDERS  │
  └───────────────┘                └───────────┘    │ block-inline│
                                                     │ block-ip    │
                                                     │ alert       │
                                                     │ isolate     │
                                                     └─────────────┘
```

- **Connectors** normalize any source into an `AttackEvent` stream.
- **Defender agent** (on the existing blackboard) runs detect → decide → respond
  and emits a live handoff graph + timeline.
- **Responders** enforce a graduated, safe-by-default response.

Everything is dependency-injected and testable with fakes and no network, matching
the rest of the repository.

---

## 3. Reused building blocks (already in the codebase)

| Need | Reuse | Location |
|------|-------|----------|
| Inline filtering reverse proxy | `startProxy(origin, filter, onBlock)` | `purple-engine.mjs:1348` |
| Per-class attack signatures | `PROBERS[cls].filter(url, body)` where `blockable:true` | `purple-engine.mjs:445-1346` |
| Human-readable rule strings | `detectionRule(cls)` | `purple-engine.mjs:1390` |
| Host-block guard / inline allow | `isBlockedHost` / `INLINE_ALLOW` | `purple-engine.mjs:47-72` |
| Finding shape | `F(tool, severity, target, detail)` | `purple-engine.mjs:234` |
| Blackboard coordination | `makeBlackboard()` (`post/all/subscribe/claim/snapshot`) | `packages/dashboard/agent-team.mjs:16` |
| Team orchestration + handoff graph + timeline | `runSecurityTeam(...)` | `packages/dashboard/agent-team.mjs:162` |
| Bounded concurrency | `runConcurrent(items, worker, limit)` | `packages/dashboard/agent-loop.mjs:28` |
| LLM propose→verify, key-gated | `makeLlmProposer(apiKey, model)` (returns `null` w/o key) | `ai-reason.mjs:24` |
| LLM refute-only judge | `makeLlmJudge(apiKey, model)` | `access-control.mjs:89` |
| Alerting | `sendMonitorAlert(...)` | `monitor.mjs` |
| Domain ownership gate | `/api/verify/request` + `/api/verify/check`, `isVerified`, `domainToken` | `packages/dashboard/server.mjs:1447-1562` |
| IP/CIDR ownership gate | `ip-ownership.mjs` (`checkIpControl`, `ipVerifyToken`, `ipInCidr`) + `/api/verify/ip/*` | `ip-ownership.mjs`, `server.mjs:1574-1609` |
| Live in-process run + SSE model | `csRuns` Map + `/api/code-scan/multi/:id/events` | `packages/dashboard/server.mjs:1014-1104` |
| Auth primitive | `getUser(req)` | `packages/dashboard/server.mjs:171` |
| SPA router + page pattern | `go(p,d)` dispatch map + `pgDomains()` | `packages/dashboard/public/index.html:1684, 2279` |

---

## 4. Core data types

```js
// Emitted by every connector; the single normalized unit the agent reasons over.
AttackEvent = {
  at,          // ISO timestamp
  source,      // 'http-proxy' | 'log-stream' | 'network'
  srcIp,       // string | null
  method,      // HTTP method | null
  url,         // request URL | null
  headers,     // object | null
  body,        // string | null
  connId,      // opaque per-connection id (for inline correlation) | null
  raw,         // original line/record for audit
}

// Produced by the classifier for each AttackEvent.
Verdict = {
  attack,            // boolean — deterministic attack confirmed?
  cls,               // vuln/attack class (e.g. 'sqli','xss','rce-ssti','port-scan') | null
  confidence,        // 'confirmed' | 'suspected' | 'benign'
  signal,            // human string: which signature/threshold fired
  recommendedAction, // 'observe' | 'alert' | 'block-inline' | 'block-ip' | 'isolate'
}

// A connected, ownership-verified system under protection.
ProtectedSystem = {
  id, userId, kind,  // 'web' | 'log' | 'network'
  origin,            // upstream URL (web) | null
  cidr,              // verified CIDR (network) | null
  ingestToken,       // for log/network ingest auth
  mode,              // 'monitor' | 'enforce'  (default 'monitor')
  createdAt,
}
```

---

## 5. Connectors (`defender/connectors.mjs`)

Common interface:

```js
connector.start({ onEvent }) -> { stop(), meta }
// onEvent(AttackEvent) is called for each observed request/log line/net event.
// meta describes how the user routes data in (proxy URL, ingest URL, etc).
```

### 5.1 HttpProxyConnector (inline, can block in-flight)
- Wraps `startProxy(origin, filter, onBlock)` from `purple-engine.mjs:1348`.
- Inversion of control: instead of a fixed per-class `filter`, it passes a
  `filter(url, body)` that (a) constructs an `AttackEvent`, (b) calls the
  **fast synchronous** classifier, (c) returns `true` (block → 403) only when the
  system is in `enforce` mode **and** the verdict is `confirmed`. In `monitor`
  mode it always returns `false` (forward) but still emits the event + verdict.
- `onBlock` → post a `defense` fact + SSE notify.
- Sets `INLINE_ALLOW` appropriately if the connector itself needs `fetchT`
  (mind `isBlockedHost`, `purple-engine.mjs:47-72`).
- **Only** source that can stop an attack before it reaches the app.
- Requires exporting `startProxy` + a new `buildCompositeFilter()` (see §6).

### 5.2 LogStreamConnector (after-the-fact)
- Two intake modes: token-authed `POST /api/defender/ingest/:id` of log lines
  (JSON or common access-log format), and/or a local file tail.
- Parses lines → `AttackEvent`. Cannot inline-block; responders limited to
  `observe`/`alert`/`block-ip`.

### 5.3 NetworkConnector (heaviest; ships last)
- Ingests connection/scan telemetry (netflow-style JSON, firewall logs, or an
  optional tiny host-agent that POSTs events to `/api/defender/ingest/:id`).
- Threshold-based detection (port-scan burst, connection flood).
- Responders: `alert`, `block-ip` / firewall-rule emit, `isolate` (rule emitted;
  active enforcement stubbed with a clear TODO for a future host-agent).
- Deliverable includes a documented event schema and an optional host-agent
  snippet; not a kernel/packet-level sensor.

---

## 6. Detection / decision (`defender/classify.mjs`) — zero-FP guardian

`classify(event, { llm }) -> Verdict`

1. **Deterministic first, always authoritative.**
   - HTTP: match against `buildCompositeFilter()` — a new exported helper in
     `purple-engine.mjs` that ORs every `PROBERS[cls].filter` with
     `blockable:true`, returning the matched `cls`. These are the same regexes the
     engine already trusts to prove-and-block.
   - Network/log: explicit thresholds and known-bad signatures.
   - A deterministic match ⇒ `confidence:'confirmed'`, `attack:true`.
2. **LLM = judgment, never creation.** Optional and key-gated via the
   `makeLlmProposer` / `makeLlmJudge` pattern (`ai-reason.mjs:24`,
   `access-control.mjs:89`). It may raise a benign event to `suspected` (→ alert)
   or explain, and may downgrade a `confirmed` event to refuted only on an
   explicit parseable "refuted" (any error/ambiguity → the deterministic verdict
   stands). **An automatic block only ever fires on a `confirmed` deterministic
   signal.** With no API key the whole LLM path is skipped and the defender still
   works fully.
3. `classify` is pure and synchronous for the deterministic path (so the inline
   proxy filter can call it without awaiting); the optional LLM enrichment runs
   asynchronously and can only *escalate to alert* or *annotate*, never block.

---

## 7. Response (`defender/respond.mjs`) — graduated, safe-by-default

`applyResponse(verdict, ctx, { mode, deps }) -> ResponseResult`

Escalation ladder: `observe` → `alert` → `block-inline` → `block-ip` → `isolate`.

- `alert` reuses `sendMonitorAlert(...)` (`monitor.mjs`).
- `block-inline` = the 403 path (HTTP only).
- `block-ip` / `isolate` emit a rule string from `detectionRule(cls)`
  (`purple-engine.mjs:1390`); active OS/firewall enforcement is behind an injected
  `deps.enforce` (stubbed by default, real enforcer optional).

**Two mandatory safety invariants (outward-facing):**
1. **Monitor-only by default.** A newly connected system is `mode:'monitor'`; no
   block/isolate is enforced until the user explicitly switches it to `enforce`.
   Observation and alerting still happen in monitor mode.
2. **Fail-open inline.** If the classifier throws on an HTTP event, the proxy
   **forwards** the request (never breaks the user's app) and raises an alert.
   The defender must never fail-closed by accident.

Responder actions are rate-limited to avoid alert storms / block storms.

---

## 8. Agentic integration (`defender/agent.mjs` + `agent-team.mjs`)

`defenderAgent(bb, { deps, onEvent })` runs on `makeBlackboard()`:
- Subscribes to a new `attack-event` fact type (posted by connectors).
- For each event: `classify` → `applyResponse` (mode-gated) → post a
  `defense`/`mitigation` fact.
- Builds the same **handoff graph (`nodes`/`edges`) + narrated timeline** as
  `runSecurityTeam` (`agent-team.mjs:162`) so the Defender page renders a live
  "graph of agents" defending in real time.
- Uses `runConcurrent` (`agent-loop.mjs:28`) for bounded concurrency.

Orchestrator `runDefender({ connector, deps, mode, onEvent })` wires a connector to
the agent and returns `{ stop, blackboard, graph, timeline, stats }`.

---

## 9. Backend API (`packages/dashboard/server.mjs`)

New `/api/defender/*` routes, all `getUser`-gated (401 if unauthenticated).
Live/**in-process** model (a `defenders` Map + SSE), following the `csRuns`
war-room pattern (`server.mjs:1014`), **not** the spawn+workspace model.

| Method + path | Purpose |
|---------------|---------|
| `POST /api/defender/connect` | Register a `ProtectedSystem`; requires verified ownership (§10). Returns routing meta (proxy URL / ingest URL + token). |
| `GET /api/defender/list` | List the user's connected systems + status. |
| `POST /api/defender/disconnect` | Stop + remove a system. |
| `POST /api/defender/:id/start` \| `stop` | Start/stop the connector + defender agent. |
| `POST /api/defender/:id/mode` | Toggle `monitor` ⇄ `enforce`. |
| `POST /api/defender/ingest/:id` | Token-authed log/network event intake. |
| `GET /api/defender/:id/events` | SSE stream: attack events, verdicts, actions, graph updates. |

State: `defenders` Map keyed by id → `{ system, connector, stop, mode, events[],
sseClients, stats }`. Registrations persist via `db.mjs`; defense history to
`workspaces/defender-<id>/` for report continuity.

---

## 10. Connect flow & ownership gating (`packages/dashboard/public/index.html`)

New `pgDefender()` page mirroring `pgDomains()` (`index.html:2279`); add a sidebar
button `id="n-defender"` and a `defender:pgDefender` entry in the `go()` dispatch
map (`index.html:1690`). Reuse helpers `api()`, `H()`, `ico()`, and `.crd`/`.btn`
CSS classes.

**You cannot point a blocker at a system you do not own** — reuse the existing
ownership gates wholesale:
1. Choose system type → **web app** verifies via `/api/verify/*` (domain);
   **network** via `/api/verify/ip/*` (CIDR). `/api/defender/connect` refuses
   (403 `needsVerification`) if `isVerified(user.id, host)` / verified CIDR is
   absent — same enforcement as scan-launch (`server.mjs:2346-2363`).
2. On connect: web app gets a **proxy endpoint** to route traffic through;
   log/network get an **ingest URL + token** (+ optional host-agent snippet).
3. Live view: SSE stream of events → verdicts → actions, the agent graph/timeline,
   and the **Monitor-only ⇄ Enforce** toggle.

---

## 11. New / changed files

**New**
- `defender/connectors.mjs` — `HttpProxyConnector`, `LogStreamConnector`, `NetworkConnector`.
- `defender/classify.mjs` — deterministic classifier + optional LLM enrichment.
- `defender/respond.mjs` — responders + mode/rate-limit gating.
- `defender/agent.mjs` — `defenderAgent` + `runDefender`.
- `defender.test.mjs` — zero-FP + unit tests (see §12).

**Changed**
- `purple-engine.mjs` — export `startProxy`; add + export `buildCompositeFilter()`.
- `packages/dashboard/server.mjs` — `/api/defender/*` routes + `defenders` Map.
- `packages/dashboard/public/index.html` — `pgDefender()` + sidebar + router entry.
- `packages/dashboard/agent-team.mjs` — register `defenderAgent` / `defense` fact type (if co-located).
- `package.json` — add `defender.test.mjs` to the `test` script.

---

## 12. Testing (matches existing zero-FP philosophy)

`defender.test.mjs` (node:test, no network — inject fakes):
- **Classifier zero-FP gate:** confirms on a malicious event, **abstains on a
  benign one**, for each supported class — the regression-gated property, mirroring
  `probers.test.mjs` / `flows.test.mjs`.
- **Connector normalization:** each connector maps its raw input to a correct
  `AttackEvent`; the http-proxy connector blocks a malicious request (403) in
  `enforce` mode and forwards it (with event emitted) in `monitor` mode.
- **Responder gating:** `monitor` never enforces block/isolate; `enforce` does;
  fail-open on classifier error; rate-limiting caps action volume.
- **Agent:** posts `attack-event` → `defense` facts and builds graph/timeline nodes.
- **LLM non-authority:** with a stub LLM that says "attack," no block occurs
  without a deterministic signal; with no key, the path is skipped cleanly.

---

## 13. Build order (designed together, shipped in safe slices)

All slices sit behind the §4–§5 interfaces so later work never forces a refactor.

1. **Slice 1 — core + inline web defense.** `classify.mjs`, `respond.mjs`,
   `HttpProxyConnector`, `defenderAgent`/`runDefender`, `startProxy` +
   `buildCompositeFilter()` exports, `/api/defender/*` (connect/list/start/stop/
   mode/events), `pgDefender()` page, monitor/enforce, `defender.test.mjs`.
   Prove end-to-end with Shannon's own attack engine as the traffic generator.
2. **Slice 2 — log source.** `LogStreamConnector`, `ingest/:id`, `block-ip`
   responder, domain/IP-scoped alerting.
3. **Slice 3 — network source.** `NetworkConnector`, threshold detection,
   `isolate`/firewall-rule emit, optional host-agent snippet + schema docs.

---

## 14. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Defender blocks legitimate traffic (false positive takes down a real app) | Monitor-only default; block only on `confirmed` deterministic signal; fail-open inline. |
| User points defense at a system they don't own | Mandatory ownership verification reused from scan-launch; connect refuses unverified targets. |
| LLM hallucination causes a block | LLM can never cause a block — deterministic authority only; refute-only judge; runs with no key. |
| Ingest endpoint abused | Per-system `ingestToken`; `getUser` gating on management routes; rate limiting. |
| Alert/action storms | Rate-limit responder actions per system. |
| Inline proxy latency | Deterministic classifier is synchronous regex matching; LLM enrichment is async and off the block path. |
