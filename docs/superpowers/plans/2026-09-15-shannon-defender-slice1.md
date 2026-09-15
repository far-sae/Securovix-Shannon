# Shannon Defender — Slice 1 (Core + Inline Web Defense) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a live, agentic blue-team defender that sits inline in front of an ownership-verified web app, deterministically detects attacks, and blocks them in real time — with a dashboard page where a user connects their system and toggles monitor⇄enforce.

**Architecture:** Three isolated layers joined by one normalized `AttackEvent`: a **connector** (a filtering reverse proxy that emits every request and honors a block decision), a **defender agent** running on the existing blackboard (`classify` → `applyResponse` → post `defense` facts), and **responders** (alert / block-inline) gated by a per-system mode. The deterministic engine is the sole blocking authority; the LLM layer may only escalate to an alert or annotate, never block.

**Tech Stack:** Node.js ≥18 ESM (`.mjs`), `node:test` + `node:assert/strict`, `node:http`/`node:https`, Express (dashboard), vanilla-JS SPA (no build step), Biome for lint/format.

**Spec:** `docs/superpowers/specs/2026-09-15-shannon-defender-agent-design.md`

## Global Constraints

- Node.js ≥ 18, ESM `.mjs` only. No new runtime dependencies.
- **Zero false positives by construction.** A block fires only on a deterministic signature match. The LLM can never produce `confidence:'confirmed'` and can never cause a block.
- **Monitor-only by default.** A newly connected system is `mode:'monitor'`; no enforcement until the user explicitly sets `enforce`.
- **Fail-open inline.** If classification throws, the proxy forwards the request; it must never fail-closed.
- Every module is dependency-injected and unit-testable with fakes; **tests must not touch the network** (bind `127.0.0.1` ephemeral ports only).
- Changes to `purple-engine.mjs` are **additive only** — do not alter `startProxy` or `defendAndReport` behavior; the existing defend loop depends on them.
- Tests live at repo root as `defender.test.mjs` and must be added to the `test` script in `package.json`.
- Run lint before each commit: `pnpm lint`.

## Deviations from the spec (deliberate, approved refinements)

1. **The spec says "export `startProxy`" — this plan does not.** `startProxy`
   (`purple-engine.mjs:1348`) hardcodes `listen(0, '127.0.0.1')`, has no event hook, and no
   fail-open path, and `defendAndReport` depends on its exact behavior. Task 4 therefore builds a
   purpose-built `httpProxyConnector` modeled on its proven forwarding logic, leaving
   `purple-engine.mjs` **additive-only** (just `buildCompositeFilter`). Lower risk, same reuse.
2. **`start`/`stop` routes are folded into `connect`/`disconnect`.** The spec listed
   `POST /api/defender/:id/start|stop` separately; Slice 1 starts the runtime on connect and stops it
   on disconnect, which is the whole lifecycle for a single-connector system. Separate start/stop can
   return in Slice 2 when a system may have multiple connectors.

---

### Task 1: Composite attack-signature matcher

Expose the engine's existing per-class WAF regexes as one reusable matcher. This is the deterministic authority the whole defender rests on.

**Files:**
- Modify: `purple-engine.mjs` (add function near `detectionRule`, ~line 1390; extend the export list at line 1728)
- Create/Test: `defender.test.mjs`
- Modify: `package.json` (add `./defender.test.mjs` to the `test` script)

**Interfaces:**
- Consumes: `PROBERS` (existing, `purple-engine.mjs:445`) — entries shaped `{ blockable, filter(url, body), probe() }`.
- Produces: `buildCompositeFilter() -> (url: string, body: string) => string | null` — returns the matching vuln class name, or `null` when nothing matches.

- [ ] **Step 1: Write the failing test**

Create `defender.test.mjs`:

```js
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildCompositeFilter } from './purple-engine.mjs';

// ---------- composite signature matcher ----------
test('composite filter: flags an SSTI payload with its class', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/?q={{7*7}}', ''), 'rce-ssti');
});
test('composite filter: flags an XSS payload', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/search?q=<script>alert(1)</script>', ''), 'xss');
});
test('composite filter: matches on the request BODY too', () => {
  const match = buildCompositeFilter();
  assert.ok(match('/login', 'user=admin&note={{7*7}}'));
});
test('composite filter: abstains on benign traffic (zero-FP)', () => {
  const match = buildCompositeFilter();
  assert.equal(match('/products?page=2&sort=price', ''), null);
  assert.equal(match('/api/users/42', '{"name":"Ada Lovelace"}'), null);
});
test('composite filter: a throwing prober filter never breaks matching', () => {
  const match = buildCompositeFilter();
  assert.doesNotThrow(() => match('/%E0%A4%A', ''));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ./defender.test.mjs`
Expected: FAIL — `buildCompositeFilter is not a function` / import error.

- [ ] **Step 3: Write minimal implementation**

In `purple-engine.mjs`, add immediately **above** `function detectionRule(cls) {` (~line 1390):

```js
// Build one matcher from every blockable class's WAF filter. Returns the matched class or null.
// This is the deterministic blocking authority reused by the live Defender.
function buildCompositeFilter() {
  const entries = Object.entries(PROBERS).filter(([, p]) => p.blockable && typeof p.filter === 'function');
  return (url, body) => {
    for (const [cls, p] of entries) {
      try {
        if (p.filter(url || '', body || '')) return cls;
      } catch {}
    }
    return null;
  };
}
```

Then extend the export list at line 1728 — replace:

```js
export { detectionRule, fetchT, injectParam, injReq, mergeCookies, PROBERS, setParam, targetUrlOf };
```

with:

```js
export { buildCompositeFilter, detectionRule, fetchT, injectParam, injReq, mergeCookies, PROBERS, setParam, targetUrlOf };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test ./defender.test.mjs`
Expected: PASS (5 tests).

- [ ] **Step 5: Register the suite and confirm nothing regressed**

In `package.json`, append ` ./defender.test.mjs` to the end of the `test` script value (after `./agent-team.test.mjs`).

Run: `npm test`
Expected: the full suite passes, now including the defender tests.

- [ ] **Step 6: Commit**

```bash
pnpm lint
git add purple-engine.mjs defender.test.mjs package.json
git commit -m "feat(defender): expose buildCompositeFilter for live defense"
```

---

### Task 2: Deterministic classifier

Turn an `AttackEvent` into a `Verdict`. This file owns the zero-FP contract.

**Files:**
- Create: `defender/classify.mjs`
- Modify: `defender.test.mjs` (append section)

**Interfaces:**
- Consumes: `buildCompositeFilter()` from Task 1.
- Produces:
  - `classify(event) -> Verdict` where `Verdict = { attack, cls, confidence, signal, recommendedAction }`, `confidence ∈ 'confirmed'|'suspected'|'benign'`, `recommendedAction ∈ 'observe'|'alert'|'block-inline'|'block-ip'|'isolate'`.
  - `applyLlmJudgment(verdict, llmOpinion) -> Verdict` where `llmOpinion = { suspicious: boolean, reason?: string } | null`.

- [ ] **Step 1: Write the failing test**

Append to `defender.test.mjs`:

```js
import { applyLlmJudgment, classify } from './defender/classify.mjs';

const httpEvent = (url, body = '') => ({
  at: '2026-09-15T00:00:00.000Z', source: 'http-proxy', srcIp: '10.0.0.9',
  method: 'GET', url, headers: {}, body, connId: null, raw: `GET ${url}`,
});

// ---------- classifier ----------
test('classify: confirms a signature-matching request and recommends an inline block', () => {
  const v = classify(httpEvent('/?q={{7*7}}'));
  assert.equal(v.attack, true);
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.cls, 'rce-ssti');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('classify: abstains on benign traffic (zero-FP)', () => {
  const v = classify(httpEvent('/products?page=2&sort=price'));
  assert.equal(v.attack, false);
  assert.equal(v.confidence, 'benign');
  assert.equal(v.recommendedAction, 'observe');
});
test('classify: non-http sources get no HTTP signature verdict', () => {
  const v = classify({ ...httpEvent('/?q={{7*7}}'), source: 'log-stream' });
  assert.equal(v.confidence, 'benign');
});
test('LLM judgment: suspicion escalates a benign verdict to ALERT only — never a block', () => {
  const base = classify(httpEvent('/products?page=2'));
  const v = applyLlmJudgment(base, { suspicious: true, reason: 'odd user agent' });
  assert.equal(v.confidence, 'suspected');
  assert.equal(v.recommendedAction, 'alert');
  assert.notEqual(v.confidence, 'confirmed', 'LLM must never produce a confirmed verdict');
});
test('LLM judgment: cannot weaken a deterministic confirmation', () => {
  const base = classify(httpEvent('/?q={{7*7}}'));
  const v = applyLlmJudgment(base, { suspicious: false, reason: 'looks fine to me' });
  assert.equal(v.confidence, 'confirmed');
  assert.equal(v.recommendedAction, 'block-inline');
});
test('LLM judgment: absent opinion is a no-op', () => {
  const base = classify(httpEvent('/products'));
  assert.deepEqual(applyLlmJudgment(base, null), base);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ./defender.test.mjs`
Expected: FAIL — cannot find module `./defender/classify.mjs`.

- [ ] **Step 3: Write minimal implementation**

Create `defender/classify.mjs`:

```js
// defender/classify.mjs — deterministic attack classification for the live Defender.
//
// ZERO-FP CONTRACT: only a deterministic signature match may produce confidence:'confirmed',
// and only a 'confirmed' verdict may ever lead to a block. The LLM layer (applyLlmJudgment)
// can raise a benign event to 'suspected' (→ alert) but can NEVER create a confirmation.
import { buildCompositeFilter } from '../purple-engine.mjs';

const matchClass = buildCompositeFilter();

const benign = (signal = 'no deterministic signature matched') => ({
  attack: false,
  cls: null,
  confidence: 'benign',
  signal,
  recommendedAction: 'observe',
});

export function classify(event) {
  if (!event || event.source !== 'http-proxy') return benign('source carries no HTTP signature surface');
  let cls = null;
  try {
    cls = matchClass(event.url || '', event.body || '');
  } catch {
    return benign('classifier error — failing open');
  }
  if (!cls) return benign();
  return {
    attack: true,
    cls,
    confidence: 'confirmed',
    signal: `signature match: ${cls}`,
    recommendedAction: 'block-inline',
  };
}

// The LLM may only escalate an unconfirmed event to an alert, or annotate. It is never authority.
export function applyLlmJudgment(verdict, llmOpinion) {
  if (!llmOpinion) return verdict;
  if (verdict.confidence === 'confirmed') return verdict; // deterministic authority stands
  if (llmOpinion.suspicious) {
    return {
      ...verdict,
      confidence: 'suspected',
      signal: `LLM suspicion: ${llmOpinion.reason || 'unspecified'}`,
      recommendedAction: 'alert',
    };
  }
  return verdict;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test ./defender.test.mjs`
Expected: PASS (all classifier tests green).

- [ ] **Step 5: Commit**

```bash
pnpm lint
git add defender/classify.mjs defender.test.mjs
git commit -m "feat(defender): deterministic classifier with non-authoritative LLM judgment"
```

---

### Task 3: Graduated responder + rate limiter

Decide what actually happens, honoring monitor-vs-enforce and capping action volume.

**Files:**
- Create: `defender/respond.mjs`
- Modify: `defender.test.mjs` (append section)

**Interfaces:**
- Consumes: a `Verdict` from Task 2.
- Produces:
  - `applyResponse(verdict, ctx, opts) -> { action, enforced, wanted, reason }` where `opts = { mode: 'monitor'|'enforce', deps: { alert?, enforce? }, allow?: () => boolean }`.
  - `makeRateLimiter({ max, windowMs, now }) -> () => boolean` (returns `false` once the window budget is spent).

- [ ] **Step 1: Write the failing test**

Append to `defender.test.mjs`:

```js
import { applyResponse, makeRateLimiter } from './defender/respond.mjs';

const blockVerdict = { attack: true, cls: 'rce-ssti', confidence: 'confirmed', signal: 's', recommendedAction: 'block-inline' };
const benignVerdict = { attack: false, cls: null, confidence: 'benign', signal: 's', recommendedAction: 'observe' };

// ---------- responder ----------
test('respond: MONITOR mode never enforces — it alerts instead', () => {
  const calls = [];
  const r = applyResponse(blockVerdict, {}, { mode: 'monitor', deps: { alert: () => calls.push('alert'), enforce: () => calls.push('enforce') } });
  assert.equal(r.enforced, false);
  assert.equal(r.action, 'alert');
  assert.deepEqual(calls, ['alert'], 'alerted but did not enforce');
});
test('respond: ENFORCE mode blocks and calls the enforcer', () => {
  const calls = [];
  const r = applyResponse(blockVerdict, {}, { mode: 'enforce', deps: { alert: () => calls.push('alert'), enforce: (a) => calls.push(`enforce:${a}`) } });
  assert.equal(r.enforced, true);
  assert.equal(r.action, 'block-inline');
  assert.deepEqual(calls, ['alert', 'enforce:block-inline']);
});
test('respond: a benign verdict does nothing at all', () => {
  const calls = [];
  const r = applyResponse(benignVerdict, {}, { mode: 'enforce', deps: { alert: () => calls.push('alert') } });
  assert.equal(r.action, 'observe');
  assert.equal(r.enforced, false);
  assert.deepEqual(calls, []);
});
test('respond: a throwing enforcer never propagates (defender must not crash)', () => {
  assert.doesNotThrow(() => applyResponse(blockVerdict, {}, { mode: 'enforce', deps: { enforce: () => { throw new Error('firewall down'); } } }));
});
test('respond: rate limiting suppresses action storms', () => {
  const r = applyResponse(blockVerdict, {}, { mode: 'enforce', allow: () => false, deps: {} });
  assert.equal(r.enforced, false);
  assert.match(r.reason, /rate limited/);
});
test('rate limiter: allows up to max per window, then refuses', () => {
  let t = 0;
  const allow = makeRateLimiter({ max: 2, windowMs: 1000, now: () => t });
  assert.equal(allow(), true);
  assert.equal(allow(), true);
  assert.equal(allow(), false, 'budget spent');
  t = 1001;
  assert.equal(allow(), true, 'window rolled over');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ./defender.test.mjs`
Expected: FAIL — cannot find module `./defender/respond.mjs`.

- [ ] **Step 3: Write minimal implementation**

Create `defender/respond.mjs`:

```js
// defender/respond.mjs — graduated, safe-by-default response.
//
// SAFETY: enforcement (block/isolate) happens ONLY in mode 'enforce'. In 'monitor' the defender
// still alerts, so a newly connected system is never broken by a bad read. Responder failures are
// swallowed — a broken enforcer must never take the defender down with it.
const ENFORCING = new Set(['block-inline', 'block-ip', 'isolate']);

export function makeRateLimiter({ max = 20, windowMs = 60_000, now = () => Date.now() } = {}) {
  const hits = [];
  return () => {
    const t = now();
    while (hits.length && t - hits[0] > windowMs) hits.shift();
    if (hits.length >= max) return false;
    hits.push(t);
    return true;
  };
}

export function applyResponse(verdict, ctx = {}, opts = {}) {
  const { mode = 'monitor', deps = {}, allow = () => true } = opts;
  const wanted = verdict?.recommendedAction || 'observe';

  if (wanted === 'observe') return { action: 'observe', enforced: false, wanted, reason: 'no action required' };
  if (!allow()) return { action: 'observe', enforced: false, wanted, reason: 'rate limited' };

  try {
    deps.alert?.(verdict, ctx);
  } catch {}

  if (!ENFORCING.has(wanted)) return { action: 'alert', enforced: false, wanted, reason: 'alert only' };
  if (mode !== 'enforce')
    return { action: 'alert', enforced: false, wanted, reason: 'monitor mode — enforcement withheld' };

  try {
    deps.enforce?.(wanted, verdict, ctx);
  } catch {}
  return { action: wanted, enforced: true, wanted, reason: 'enforced' };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test ./defender.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm lint
git add defender/respond.mjs defender.test.mjs
git commit -m "feat(defender): graduated responder with monitor/enforce gating and rate limiting"
```

---

### Task 4: Inline HTTP proxy connector

The connector that sits in front of the user's app: emits every request as an `AttackEvent` and honors the returned block decision.

**Files:**
- Create: `defender/connectors.mjs`
- Modify: `defender.test.mjs` (append section)

**Interfaces:**
- Consumes: nothing from prior tasks (deliberately decoupled — the decision arrives via the `onEvent` callback).
- Produces: `httpProxyConnector({ origin, port, host, onEvent }) -> Promise<{ meta, port, stop() }>`.
  - `onEvent(event: AttackEvent) -> { block?: boolean } | undefined`, called synchronously per request. Returning `{ block: true }` yields a 403; **any thrown error forwards the request (fail-open)**.
  - `meta = { kind: 'http-proxy', url, origin }`.

- [ ] **Step 1: Write the failing test**

Append to `defender.test.mjs`:

```js
import http from 'node:http';
import { httpProxyConnector } from './defender/connectors.mjs';

// Minimal upstream "customer app" for proxy tests (loopback only, no network).
async function upstream(handler = (_req, res) => { res.writeHead(200); res.end('upstream-ok'); }) {
  const srv = http.createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { origin: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}

// ---------- http proxy connector ----------
test('connector: forwards a benign request to the upstream app', async () => {
  const app = await upstream();
  const seen = [];
  const c = await httpProxyConnector({ origin: app.origin, onEvent: (e) => { seen.push(e); return { block: false }; } });
  const res = await fetch(`${c.meta.url}/products?page=2`);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'upstream-ok');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].source, 'http-proxy');
  assert.equal(seen[0].url, '/products?page=2');
  await c.stop(); await app.close();
});
test('connector: returns 403 and does NOT reach upstream when told to block', async () => {
  let hits = 0;
  const app = await upstream((_req, res) => { hits++; res.writeHead(200); res.end('upstream-ok'); });
  const c = await httpProxyConnector({ origin: app.origin, onEvent: () => ({ block: true }) });
  const res = await fetch(`${c.meta.url}/?q={{7*7}}`);
  assert.equal(res.status, 403);
  assert.equal(hits, 0, 'attack never reached the protected app');
  await c.stop(); await app.close();
});
test('connector: FAILS OPEN — a throwing decision forwards rather than breaking the app', async () => {
  const app = await upstream();
  const c = await httpProxyConnector({ origin: app.origin, onEvent: () => { throw new Error('classifier exploded'); } });
  const res = await fetch(`${c.meta.url}/checkout`);
  assert.equal(res.status, 200, 'must never fail closed');
  await c.stop(); await app.close();
});
test('connector: captures the request body in the event', async () => {
  const app = await upstream();
  const seen = [];
  const c = await httpProxyConnector({ origin: app.origin, onEvent: (e) => { seen.push(e); } });
  await fetch(`${c.meta.url}/login`, { method: 'POST', body: 'user=admin&note=hi' });
  assert.equal(seen[0].method, 'POST');
  assert.equal(seen[0].body, 'user=admin&note=hi');
  await c.stop(); await app.close();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ./defender.test.mjs`
Expected: FAIL — cannot find module `./defender/connectors.mjs`.

- [ ] **Step 3: Write minimal implementation**

Create `defender/connectors.mjs`:

```js
// defender/connectors.mjs — live traffic sources, normalized to one AttackEvent stream.
//
// Modeled on the engine's proven filtering reverse proxy (purple-engine.mjs startProxy), but
// purpose-built for continuous defense: configurable bind, an event hook that also carries the
// block decision, and FAIL-OPEN semantics (a classifier error forwards traffic, never blocks it).
import http from 'node:http';
import https from 'node:https';

export function httpProxyConnector({ origin, port = 0, host = '127.0.0.1', onEvent }) {
  const o = new URL(origin);
  const agent = o.protocol === 'https:' ? https : http;

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => {
      body += d;
    });
    req.on('end', () => {
      const event = {
        at: new Date().toISOString(),
        source: 'http-proxy',
        srcIp: req.socket?.remoteAddress || null,
        method: req.method,
        url: req.url,
        headers: req.headers,
        body,
        connId: null,
        raw: `${req.method} ${req.url}`,
      };

      let block = false;
      try {
        block = onEvent?.(event)?.block === true;
      } catch {
        block = false; // FAIL-OPEN: never break the protected app on our own error
      }

      if (block) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('Blocked by Shannon Defender');
        return;
      }

      const fwd = agent.request(
        {
          hostname: o.hostname,
          port: o.port || (o.protocol === 'https:' ? 443 : 80),
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: o.host },
          timeout: 10_000,
        },
        (up) => {
          res.writeHead(up.statusCode || 502, up.headers);
          up.pipe(res);
        },
      );
      fwd.on('error', () => {
        res.writeHead(502);
        res.end('upstream error');
      });
      if (body) fwd.write(body);
      fwd.end();
    });
  });

  return new Promise((resolve) =>
    server.listen(port, host, () =>
      resolve({
        meta: { kind: 'http-proxy', url: `http://${host}:${server.address().port}`, origin },
        port: server.address().port,
        stop: () => new Promise((r) => server.close(r)),
      }),
    ),
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test ./defender.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
pnpm lint
git add defender/connectors.mjs defender.test.mjs
git commit -m "feat(defender): inline http proxy connector with fail-open semantics"
```

---

### Task 5: Defender agent on the blackboard

Wire classify → respond into the existing multi-agent blackboard, producing `defense` facts, a handoff graph, and a timeline the UI can render.

**Files:**
- Create: `defender/agent.mjs`
- Modify: `defender.test.mjs` (append section)

**Interfaces:**
- Consumes: `makeBlackboard()` (`packages/dashboard/agent-team.mjs:16`), `classify` (Task 2), `applyResponse` + `makeRateLimiter` (Task 3), `httpProxyConnector` (Task 4).
- Produces:
  - `defenderAgent(bb, { getMode, deps, allow }) -> (event) => ({ block: boolean })` — the `onEvent` handler a connector calls.
  - `runDefender({ connect, mode, deps, onUpdate }) -> Promise<{ blackboard, graph, timeline, meta, stats(), setMode(m), stop() }>` where `connect({ onEvent })` is any connector factory.

- [ ] **Step 1: Write the failing test**

Append to `defender.test.mjs`:

```js
import { defenderAgent, runDefender } from './defender/agent.mjs';
import { makeBlackboard } from './packages/dashboard/agent-team.mjs';

// ---------- defender agent ----------
test('agent: an attack in ENFORCE mode blocks and posts a defense fact', () => {
  const bb = makeBlackboard();
  const handle = defenderAgent(bb, { getMode: () => 'enforce', deps: {} });
  const out = handle(httpEvent('/?q={{7*7}}'));
  assert.equal(out.block, true);
  assert.equal(bb.all('attack-event').length, 1);
  assert.equal(bb.all('defense').length, 1);
  assert.equal(bb.all('defense')[0].data.verdict.cls, 'rce-ssti');
});
test('agent: the same attack in MONITOR mode records but does NOT block', () => {
  const bb = makeBlackboard();
  const handle = defenderAgent(bb, { getMode: () => 'monitor', deps: {} });
  assert.equal(handle(httpEvent('/?q={{7*7}}')).block, false);
  assert.equal(bb.all('defense').length, 1, 'still recorded for the operator');
});
test('agent: benign traffic posts an event but no defense fact', () => {
  const bb = makeBlackboard();
  const handle = defenderAgent(bb, { getMode: () => 'enforce', deps: {} });
  assert.equal(handle(httpEvent('/products?page=2')).block, false);
  assert.equal(bb.all('attack-event').length, 1);
  assert.equal(bb.all('defense').length, 0);
});
test('runDefender: end-to-end — blocks a live attack, forwards benign traffic, tracks stats', async () => {
  const app = await upstream();
  const d = await runDefender({
    connect: ({ onEvent }) => httpProxyConnector({ origin: app.origin, onEvent }),
    mode: 'enforce',
  });
  assert.equal((await fetch(`${d.meta.url}/products`)).status, 200);
  assert.equal((await fetch(`${d.meta.url}/?q={{7*7}}`)).status, 403);
  assert.equal(d.stats().events, 2);
  assert.equal(d.stats().defenses, 1);
  assert.ok(d.timeline.length >= 1, 'timeline narrates the defense');
  assert.ok(d.graph.nodes.length >= 3, 'handoff graph present for the UI');
  await d.stop(); await app.close();
});
test('runDefender: setMode flips enforcement live', async () => {
  const app = await upstream();
  const d = await runDefender({
    connect: ({ onEvent }) => httpProxyConnector({ origin: app.origin, onEvent }),
    mode: 'monitor',
  });
  assert.equal((await fetch(`${d.meta.url}/?q={{7*7}}`)).status, 200, 'monitor lets it through');
  d.setMode('enforce');
  assert.equal((await fetch(`${d.meta.url}/?q={{7*7}}`)).status, 403, 'enforce now blocks');
  await d.stop(); await app.close();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ./defender.test.mjs`
Expected: FAIL — cannot find module `./defender/agent.mjs`.

- [ ] **Step 3: Write minimal implementation**

Create `defender/agent.mjs`:

```js
// defender/agent.mjs — the agentic defender: detect → decide → respond, on the shared blackboard.
//
// Mirrors the multi-agent security team's contract (agent-team.mjs): an agent is a plain function
// whose capabilities are injected, and which coordinates only by posting typed facts. Facts:
//   'attack-event' (every observed request)  →  'defense' (a verdict + the action taken)
import { makeBlackboard } from '../packages/dashboard/agent-team.mjs';
import { classify } from './classify.mjs';
import { applyResponse, makeRateLimiter } from './respond.mjs';

export function defenderAgent(bb, { getMode = () => 'monitor', deps = {}, allow } = {}) {
  return function handle(event) {
    bb.post('attack-event', event, 'connector');
    const verdict = classify(event);
    const result = applyResponse(verdict, { event }, { mode: getMode(), deps, allow });
    if (verdict.attack || result.action !== 'observe') {
      bb.post('defense', { event, verdict, result }, 'defender');
    }
    return { block: result.enforced && result.action === 'block-inline' };
  };
}

export async function runDefender({ connect, mode = 'monitor', deps = {}, onUpdate } = {}) {
  let current = mode;
  const bb = makeBlackboard();
  const allow = makeRateLimiter();
  const timeline = [];
  const graph = {
    nodes: [
      { id: 'connector', label: 'Connector', role: 'source' },
      { id: 'defender', label: 'Defender', role: 'agent' },
      { id: 'responder', label: 'Responder', role: 'action' },
    ],
    edges: [
      { from: 'connector', to: 'defender' },
      { from: 'defender', to: 'responder' },
    ],
  };

  bb.subscribe('defense', (e) => {
    const { event, verdict, result } = e.data;
    timeline.push({ at: event.at, phase: 'defend', detail: `${verdict.signal} → ${result.action}` });
    try {
      onUpdate?.(e.data);
    } catch {}
  });

  const handle = defenderAgent(bb, { getMode: () => current, deps, allow });
  const conn = await connect({ onEvent: handle });

  return {
    blackboard: bb,
    graph,
    timeline,
    meta: conn.meta,
    stop: conn.stop,
    setMode: (m) => {
      current = m === 'enforce' ? 'enforce' : 'monitor';
      return current;
    },
    getMode: () => current,
    stats: () => ({ events: bb.all('attack-event').length, defenses: bb.all('defense').length }),
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test ./defender.test.mjs`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `npm test`
Expected: all suites pass — no regression in the engine tests.

- [ ] **Step 6: Commit**

```bash
pnpm lint
git add defender/agent.mjs defender.test.mjs
git commit -m "feat(defender): blackboard defender agent with live mode switching"
```

---

### Task 6: Dashboard API — connect, control, stream

Expose the defender over HTTP with authentication and mandatory ownership verification.

**Files:**
- Modify: `packages/dashboard/server.mjs` (add imports at top; insert routes immediately **before** the boot IIFE at ~line 2682)

**Interfaces:**
- Consumes: `runDefender` + `httpProxyConnector` (Tasks 4–5); existing `getUser(req)` (`server.mjs:171`), `isVerified(userId, host)` (`server.mjs:1447-1472`), `hostOf(u)`, `isLocalHost(h)`.
- Produces: REST surface `/api/defender/*` and an in-memory `defenders` Map keyed by system id.

- [ ] **Step 1: Add the imports**

At the top of `packages/dashboard/server.mjs`, alongside the other `../../` imports (near line 13–23):

```js
import { httpProxyConnector } from '../../defender/connectors.mjs';
import { runDefender } from '../../defender/agent.mjs';
```

- [ ] **Step 2: Insert the routes**

Immediately **before** the final boot IIFE (`await initDb(); app.listen(...)`, ~line 2682), insert:

```js
// ── Live Defender ───────────────────────────────────────────────────────────────────────────────
// A connected system is protected inline by a filtering reverse proxy. Ownership verification is
// mandatory (you may not point a blocker at a host you do not own) and monitor mode is the default.
const defenders = new Map(); // id -> { system, runtime, sseClients, events }

function defBroadcast(entry, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const c of entry.sseClients) {
    try {
      c.write(line);
    } catch {}
  }
}

app.post('/api/defender/connect', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'auth required' });

  const { origin } = req.body || {};
  if (!origin) return res.status(400).json({ error: 'origin required' });

  let host;
  try {
    host = hostOf(origin);
  } catch {
    return res.status(400).json({ error: 'invalid origin URL' });
  }
  if (!isLocalHost(host) && !isVerified(user.id, host)) {
    return res.status(403).json({ error: 'needsVerification', host });
  }

  const id = `def-${Math.random().toString(16).slice(2, 10)}`;
  const system = { id, userId: user.id, kind: 'web', origin, mode: 'monitor', createdAt: new Date().toISOString() };
  const entry = { system, runtime: null, sseClients: [], events: [] };
  defenders.set(id, entry);

  const runtime = await runDefender({
    connect: ({ onEvent }) => httpProxyConnector({ origin, onEvent }),
    mode: 'monitor',
    deps: {},
    onUpdate: (d) => {
      entry.events.push(d);
      if (entry.events.length > 500) entry.events.shift();
      defBroadcast(entry, { type: 'defense', ...d });
    },
  });
  entry.runtime = runtime;

  res.json({ id, mode: 'monitor', proxyUrl: runtime.meta.url, origin, graph: runtime.graph });
});

app.get('/api/defender/list', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'auth required' });
  const rows = [...defenders.values()]
    .filter((e) => e.system.userId === user.id)
    .map((e) => ({ ...e.system, proxyUrl: e.runtime?.meta?.url || null, stats: e.runtime?.stats?.() || { events: 0, defenses: 0 } }));
  res.json({ systems: rows });
});

app.post('/api/defender/:id/mode', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'auth required' });
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id) return res.status(404).json({ error: 'not found' });
  const mode = entry.runtime.setMode(req.body?.mode);
  entry.system.mode = mode;
  defBroadcast(entry, { type: 'mode', mode });
  res.json({ id: entry.system.id, mode });
});

app.post('/api/defender/:id/disconnect', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'auth required' });
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id) return res.status(404).json({ error: 'not found' });
  try {
    await entry.runtime?.stop?.();
  } catch {}
  defenders.delete(req.params.id);
  res.json({ ok: true });
});

app.get('/api/defender/:id/events', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).end();
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id) return res.status(404).end();
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
  res.write(`data: ${JSON.stringify({ type: 'hello', mode: entry.system.mode, stats: entry.runtime.stats() })}\n\n`);
  entry.sseClients.push(res);
  req.on('close', () => {
    const i = entry.sseClients.indexOf(res);
    if (i >= 0) entry.sseClients.splice(i, 1);
  });
});
```

- [ ] **Step 3: Verify the server boots and the routes are gated**

Run: `node packages/dashboard/server.mjs`
Then in a second shell:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3000/api/defender/connect -H 'content-type: application/json' -d '{"origin":"http://example.com"}'
```

Expected: `401` (unauthenticated). Stop the server with Ctrl-C.

- [ ] **Step 4: Commit**

```bash
pnpm lint
git add packages/dashboard/server.mjs
git commit -m "feat(defender): dashboard API for connect, mode control, and live SSE"
```

---

### Task 7: Defender page in the dashboard SPA

The page where a user connects a system, watches live defenses, and flips monitor⇄enforce.

**Files:**
- Modify: `packages/dashboard/public/index.html` (sidebar ~line 733-740; router map ~line 1690; new `pgDefender()` near `pgDomains()` ~line 2279)

**Interfaces:**
- Consumes: `/api/defender/*` (Task 6); existing SPA helpers `api(url, opts)` (`:1692`), `$(id)` (`:773`), `H()` (HTML-escape), `go(p, d)` (`:1684`), `sList()`, CSS classes `.pg`, `.crd`, `.btn`, `.btn-p`.
- Produces: `pgDefender()` page renderer plus `defConnect()`, `defToggleMode()`, `defStream()` handlers.

- [ ] **Step 1: Add the sidebar entry**

In the sidebar nav block (~lines 733-740), add alongside the existing buttons:

```html
<button onclick="go('defender')" id="n-defender">Defender</button>
```

- [ ] **Step 2: Register the route**

In the `go(p, d)` dispatch map (~line 1690), add `defender:pgDefender` to the object:

```js
({dash:pgDash,new:pgNew,domains:pgDomains,agent:pgAgent,cfg:pgCfg,scan:pgScan,live:pgLive,code:pgCode,billing:pgBilling,defender:pgDefender})[p]?.(d);
```

- [ ] **Step 3: Add the page renderer**

Insert near `pgDomains()` (~line 2279):

```js
let DEF_ID = null, DEF_EVT = null;

function pgDefender() {
  CID = null; sList();
  M.innerHTML = `
    <div class="pg">
      <h1 class="h-display">Defender</h1>
      <p class="sub">Connect a system you own. Shannon watches every request, confirms attacks with the
      same zero-false-positive signatures the engine uses, and can block them before they land.</p>

      <div class="crd">
        <h3>Connect a web app</h3>
        <p>Your app's URL must be a domain you've verified on the Domains page.</p>
        <input id="def-origin" placeholder="https://app.example.com" style="width:100%;margin:8px 0">
        <button class="btn btn-p" onclick="defConnect()">Connect</button>
        <div id="def-connect-out"></div>
      </div>

      <div class="crd">
        <h3>Protected systems</h3>
        <div id="def-list">Loading…</div>
      </div>

      <div class="crd">
        <h3>Live activity</h3>
        <div id="def-live"><em>Connect a system to see live defenses.</em></div>
      </div>
    </div>`;
  defLoad();
}

async function defLoad() {
  try {
    const { systems } = await api('/defender/list');
    $('def-list').innerHTML = systems.length
      ? systems.map((s) => `
        <div class="crd" style="margin:8px 0">
          <b>${H(s.origin)}</b><br>
          <small>Route your traffic through: <code>${H(s.proxyUrl || '—')}</code></small><br>
          <small>Mode: <b>${H(s.mode)}</b> · events ${s.stats.events} · defenses ${s.stats.defenses}</small><br>
          <button class="btn" onclick="defToggleMode('${s.id}','${s.mode === 'enforce' ? 'monitor' : 'enforce'}')">
            Switch to ${s.mode === 'enforce' ? 'Monitor-only' : 'Enforce (block attacks)'}
          </button>
          <button class="btn" onclick="defStream('${s.id}')">Watch live</button>
        </div>`).join('')
      : '<em>No systems connected yet.</em>';
  } catch (e) {
    $('def-list').innerHTML = `<span class="err">${H(e.message || 'failed to load')}</span>`;
  }
}

async function defConnect() {
  const origin = $('def-origin').value.trim();
  const out = $('def-connect-out');
  out.innerHTML = '<span class="sp"></span> Connecting…';
  try {
    const r = await api('/defender/connect', { method: 'POST', body: JSON.stringify({ origin }) });
    out.innerHTML = `<p>Connected in <b>monitor-only</b> mode. Route traffic through
      <code>${H(r.proxyUrl)}</code>, then switch to Enforce when you're ready to block.</p>`;
    defLoad();
    defStream(r.id);
  } catch (e) {
    out.innerHTML = e.status === 403
      ? '<span class="err">You must verify ownership of that domain first (Domains page).</span>'
      : `<span class="err">${H(e.message || 'connect failed')}</span>`;
  }
}

async function defToggleMode(id, mode) {
  if (mode === 'enforce' && !confirm('Enforce mode will BLOCK requests Shannon confirms as attacks. Continue?')) return;
  await api(`/defender/${id}/mode`, { method: 'POST', body: JSON.stringify({ mode }) });
  defLoad();
}

function defStream(id) {
  if (DEF_EVT) { DEF_EVT.close(); DEF_EVT = null; }
  DEF_ID = id;
  const live = $('def-live');
  live.innerHTML = '<em>Listening…</em>';
  DEF_EVT = new EventSource(`/api/defender/${id}/events`);
  DEF_EVT.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.type === 'hello') return;
    if (d.type === 'mode') { defLoad(); return; }
    if (live.querySelector('em')) live.innerHTML = '';
    const row = document.createElement('div');
    row.innerHTML = `<code>${H(d.event.method)} ${H(d.event.url)}</code> —
      <b>${H(d.verdict.cls || 'benign')}</b> — ${H(d.result.action)}${d.result.enforced ? ' <b>(blocked)</b>' : ''}`;
    live.prepend(row);
  };
}
```

- [ ] **Step 4: Verify in the browser**

Run: `node packages/dashboard/server.mjs`, open `http://localhost:3000`, sign in, click **Defender**.
Expected: the page renders, "Protected systems" shows *No systems connected yet*, and connecting an unverified domain shows the verification error.

- [ ] **Step 5: Commit**

```bash
pnpm lint
git add packages/dashboard/public/index.html
git commit -m "feat(defender): Defender page with connect flow, live feed, and mode toggle"
```

---

### Task 8: End-to-end proof + documentation

Prove the full loop with Shannon's own attack payloads, and document the feature.

**Files:**
- Create: `workspaces/defender-verify.mjs`
- Modify: `README.md` (add a Defender subsection under "Platform intelligence", ~line 41-56)

**Interfaces:**
- Consumes: `runDefender`, `httpProxyConnector` (Tasks 4–5).
- Produces: a runnable verification script printing PASS/FAIL checks, exiting non-zero on failure (matching the house style of `workspaces/attack-surface-verify.mjs`).

- [ ] **Step 1: Write the verification script**

Create `workspaces/defender-verify.mjs`:

```js
// Proves the live defender blocks real attack payloads and never touches benign traffic (no network).
//   node workspaces/defender-verify.mjs
import http from 'node:http';
import { runDefender } from '../defender/agent.mjs';
import { httpProxyConnector } from '../defender/connectors.mjs';

let reached = 0;
const app = http.createServer((_req, res) => {
  reached++;
  res.writeHead(200);
  res.end('app-ok');
});
await new Promise((r) => app.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${app.address().port}`;

const d = await runDefender({
  connect: ({ onEvent }) => httpProxyConnector({ origin, onEvent }),
  mode: 'enforce',
});

const ATTACKS = ['/?q={{7*7}}', '/search?q=<script>alert(1)</script>'];
const BENIGN = ['/products?page=2&sort=price', '/api/users/42'];

let pass = 0;
let blocked = 0;
for (const a of ATTACKS) if ((await fetch(d.meta.url + a)).status === 403) blocked++;
if (blocked === ATTACKS.length) pass++, console.log(`PASS  blocked ${blocked}/${ATTACKS.length} attack payloads`);
else console.log(`FAIL  blocked only ${blocked}/${ATTACKS.length}`);

const before = reached;
let ok = 0;
for (const b of BENIGN) if ((await fetch(d.meta.url + b)).status === 200) ok++;
if (ok === BENIGN.length) pass++, console.log(`PASS  forwarded ${ok}/${BENIGN.length} benign requests (no FP)`);
else console.log(`FAIL  forwarded only ${ok}/${BENIGN.length}`);

if (reached - before === BENIGN.length) pass++, console.log('PASS  only benign traffic reached the app');
else console.log('FAIL  attack traffic leaked to the app');

d.setMode('monitor');
if ((await fetch(`${d.meta.url}/?q={{7*7}}`)).status === 200) pass++, console.log('PASS  monitor mode observes without blocking');
else console.log('FAIL  monitor mode blocked traffic');

if (d.stats().defenses >= ATTACKS.length) pass++, console.log(`PASS  recorded ${d.stats().defenses} defenses on the blackboard`);
else console.log('FAIL  defenses not recorded');

console.log(`\n${pass}/5 checks passed`);
await d.stop();
await new Promise((r) => app.close(r));
process.exit(pass === 5 ? 0 : 1);
```

- [ ] **Step 2: Run it**

Run: `node workspaces/defender-verify.mjs`
Expected: `5/5 checks passed`, exit code 0.

- [ ] **Step 3: Document the feature**

In `README.md`, under **Platform intelligence** (after the multi-agent bullet, ~line 52-56), add:

```markdown
- **Live Defender (blue team)** — connect a system you own on the **Defender** page and Shannon sits
  inline in front of it: every request is matched against the same deterministic signatures the proof
  engine uses, confirmed attacks are blocked (403) before they reach your app, and each defense is
  posted to a live blackboard with a narrated timeline. **Monitor-only by default** (it never blocks
  until you switch to Enforce) and **fail-open** (a classifier error forwards traffic, never breaks
  your app). The LLM layer may raise an alert or explain, but can never cause a block.
```

- [ ] **Step 4: Run the whole suite one last time**

Run: `npm test && node workspaces/defender-verify.mjs`
Expected: all tests pass and `5/5 checks passed`.

- [ ] **Step 5: Commit**

```bash
pnpm lint
git add workspaces/defender-verify.mjs README.md
git commit -m "test(defender): end-to-end block/forward proof + document the Defender"
```

---

## Out of scope for this plan (future slices)

- **Slice 2 — log/event source:** `LogStreamConnector`, token-authed `POST /api/defender/ingest/:id`, `block-ip` responder.
- **Slice 3 — network source:** `NetworkConnector`, port-scan thresholds, `isolate` / firewall-rule emit, optional host-agent.
- Persisting connected systems across restarts via `db.mjs` (Slice 1 keeps them in the in-memory `defenders` Map, matching the existing `csRuns` war-room pattern).
