# Track B Phase 1b — Tool-Broker Body — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Wrap the Phase 1a broker core in the runnable broker "body" — the authorization pipeline, output parsers, the sandboxed executor, the HTTP API, the scope-pinning forward-proxy, the worker-side client, and the Docker wiring — so the worker can actually run a real tool through the broker, safely, end to end.

**Architecture:** The Phase 1a package `@shannon/tool-broker` gains: (1) a pure `authorizeRequest()` pipeline that composes scope-lock + ScopeEnforcer + ToolRegistry + BudgetLedger into one allow/deny decision; (2) an `OutputNormalizer` that turns raw tool stdout into normalized findings; (3) [Docker-gated] a `Sandbox` executor, an HTTP `BrokerAPI` wrapping authorize→execute→sign, a `ForwardProxy` that resolves+pins the target IP and runs `ScopeEnforcer.evaluate` per request, and Docker/compose wiring. The worker gains a `ToolClient`.

**Tech Stack:** TypeScript (ESM, NodeNext), vitest, `node:crypto`. Docker-gated tasks add: `node:child_process`/`execFile`, a minimal HTTP server (`node:http`), Docker Compose. No new runtime deps for the host-testable tasks.

**Spec:** [Track B engine](../specs/2026-06-03-deeper-exploitation-engine-design.md) §4–§5, §10. Depends on Phase 1a (merged `ef75626`).

**Build-state split (IMPORTANT):**
- **Tasks 1–3 are host-authorable AND host-testable now** (pure TS; no Docker). Build them today.
- **Tasks 4–9 are DOCKER-GATED** — they require the Docker daemon running (it was off during authoring) and a Linux egress environment for real verification. They are specified at outline level; expand each into full TDD tasks when Docker is up. Do NOT mark them done without running them against real containers.

---

## File Structure

| File | Responsibility | Phase |
|------|----------------|-------|
| `packages/tool-broker/src/core/authorize.ts` (+ test) | compose scope-lock + scope + registry + budget into one decision | 1b host |
| `packages/tool-broker/src/normalize/normalizer.ts` (+ test) | parse sqlmap/nuclei/ffuf output → normalized findings | 1b host |
| `packages/tool-broker/src/index.ts` | export the new public surface | 1b host |
| `packages/tool-broker/src/exec/sandbox.ts` | `docker run` executor (cap-drop, ro, egress, caps, timeout) | 1b Docker |
| `packages/tool-broker/src/proxy/forward-proxy.ts` | resolve+pin target IP, per-request `ScopeEnforcer.evaluate` | 1b Docker |
| `packages/tool-broker/src/api/server.ts` | HTTP BrokerAPI: authorize → execute → normalize → sign record | 1b Docker |
| `packages/worker/src/broker/tool-client.ts` | worker-side HTTP client to the broker | 1b Docker |
| `docker-compose.yml` / `docker-compose.local.yml` / `Dockerfile` | add broker service + `lab` profile; remove `network_mode: host`; strip tools from worker image | 1b Docker |

---

## Task 1: `authorizeRequest()` — the broker's allow/deny pipeline (host-testable)

**Files:**
- Create: `packages/tool-broker/src/core/authorize.ts`, `packages/tool-broker/src/core/authorize.test.ts`

This composes every Phase 1a primitive into the single decision the BrokerAPI will make before any tool runs. Pure function (no I/O except the budget ledger's file, injected by the caller) → fully host-testable with the real primitives.

- [ ] **Step 1: Write the failing test `packages/tool-broker/src/core/authorize.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authorizeRequest } from './authorize.js';
import { ScopeEnforcer } from '../scope/enforcer.js';
import { ToolRegistry } from '../registry/registry.js';
import { DESCRIPTORS } from '../registry/descriptors.js';
import { BudgetLedger } from '../budget/ledger.js';
import { signScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolRequest } from '../types.js';

const KEY = 'scan-key';
const scope: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};
function deps(limit = 10) {
  return {
    scopeConfig: scope,
    scopeKey: KEY,
    enforcer: new ScopeEnforcer(scope),
    registry: new ToolRegistry(DESCRIPTORS),
    ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'auth-')), 'b.json'), { toolInvocations: limit }),
  };
}
function req(overrides: Partial<ToolRequest> = {}): ToolRequest {
  return {
    tool: 'sqlmap',
    params: { url: 'https://app.example.com/p?id=1' },
    scanId: 's1',
    scopeToken: signScopeToken(scope, KEY),
    ...overrides,
  };
}

describe('authorizeRequest', () => {
  it('authorizes an in-scope, valid, budgeted request and returns argv', () => {
    const r = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, deps());
    expect(r.authorized).toBe(true);
    if (r.authorized) expect(r.argv).toEqual(['sqlmap', '-u', 'https://app.example.com/p?id=1']);
  });

  it('rejects a forged scope token (scope status, no budget spent)', () => {
    const d = deps();
    const r = authorizeRequest(req({ scopeToken: 'forged' }), { ip: '93.184.216.34', path: '/p' }, d);
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
    // budget not consumed → a valid request still succeeds
    const r2 = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, { ...d });
    expect(r2.authorized).toBe(true);
  });

  it('rejects an out-of-scope target IP', () => {
    const r = authorizeRequest(req(), { ip: '8.8.8.8', path: '/p' }, deps());
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
  });

  it('rejects metadata IP even with a valid token', () => {
    const r = authorizeRequest(req(), { ip: '169.254.169.254', path: '/' }, deps());
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('scope');
  });

  it('rejects a request whose args fail the registry (blocked status)', () => {
    const r = authorizeRequest(
      req({ params: { url: 'https://app.example.com/p', level: '9' } }),
      { ip: '93.184.216.34', path: '/p' },
      deps(),
    );
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('blocked');
  });

  it('rejects once the budget is exhausted', () => {
    const d = deps(1);
    expect(authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, d).authorized).toBe(true);
    const r = authorizeRequest(req(), { ip: '93.184.216.34', path: '/p' }, d);
    expect(r.authorized).toBe(false);
    if (!r.authorized) expect(r.result.status).toBe('budget');
  });
});
```

- [ ] **Step 2: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/core/authorize.ts`**
```ts
import type { BudgetLedger } from '../budget/ledger.js';
import type { ToolRegistry } from '../registry/registry.js';
import type { ScopeEnforcer } from '../scope/enforcer.js';
import { verifyScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolRequest, ToolResult } from '../types.js';

export interface AuthorizeDeps {
  scopeConfig: ScopeConfig;
  scopeKey: string;
  enforcer: ScopeEnforcer;
  registry: ToolRegistry;
  ledger: BudgetLedger;
}

export interface ResolvedTarget {
  ip: string; // the connect-time-pinned IP for the request's target host
  path: string; // the request's URL path
}

export type AuthorizeResult =
  | { authorized: true; argv: string[] }
  | { authorized: false; result: ToolResult };

function denied(tool: string, status: ToolResult['status'], detail: string): AuthorizeResult {
  return { authorized: false, result: { tool, status, stderr: detail } };
}

// Order matters: verify the (free) scope authorization first, then evaluate the
// concrete IP/path, then validate the argv — and ONLY THEN consume budget, so a
// denied or malformed request never burns a budget unit.
export function authorizeRequest(req: ToolRequest, target: ResolvedTarget, deps: AuthorizeDeps): AuthorizeResult {
  if (!verifyScopeToken(req.scopeToken, deps.scopeConfig, deps.scopeKey)) {
    return denied(req.tool, 'scope', 'scope-lock token invalid');
  }

  const decision = deps.enforcer.evaluate(target.ip, target.path);
  if (!decision.allowed) {
    return denied(req.tool, 'scope', `${decision.reason}: ${decision.detail ?? ''}`.trim());
  }

  let argv: string[];
  try {
    argv = deps.registry.buildArgv(req.tool, req.params);
  } catch (e) {
    return denied(req.tool, 'blocked', e instanceof Error ? e.message : String(e));
  }

  const budget = deps.ledger.tryConsume('toolInvocations', 1);
  if (!budget.ok) {
    return denied(req.tool, 'budget', 'tool invocation budget exhausted');
  }

  return { authorized: true, argv };
}
```

- [ ] **Step 4: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 5: Commit**
```bash
git add packages/tool-broker/src/core/authorize.ts packages/tool-broker/src/core/authorize.test.ts
git commit -m "feat(tool-broker): authorizeRequest pipeline (scope-lock + scope + registry + budget)"
```

---

## Task 2: `OutputNormalizer` — parse tool output into findings (host-testable)

**Files:**
- Create: `packages/tool-broker/src/normalize/normalizer.ts`, `packages/tool-broker/src/normalize/normalizer.test.ts`

Pure parsing of machine-readable tool output. **Note:** the golden samples below are representative of the documented formats; when Docker is up (Task 8) validate the parsers against *real* tool output and adjust field mapping if needed.

- [ ] **Step 1: Write the failing test `packages/tool-broker/src/normalize/normalizer.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { normalizeSqlmapCsv, normalizeNucleiJsonl, normalizeFfufJson } from './normalizer.js';

describe('normalizeSqlmapCsv', () => {
  it('parses the results CSV into findings', () => {
    const csv = 'Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://app/v.php?id=1,GET,id,BEUST,\n';
    const f = normalizeSqlmapCsv(csv);
    expect(f).toHaveLength(1);
    expect(f[0].tool).toBe('sqlmap');
    expect(f[0].target).toBe('http://app/v.php?id=1');
    expect(f[0].detail).toContain('id');
  });
  it('returns [] for a header-only / empty CSV', () => {
    expect(normalizeSqlmapCsv('Target URL,Place,Parameter,Technique(s),Note(s)\n')).toEqual([]);
    expect(normalizeSqlmapCsv('')).toEqual([]);
  });
});

describe('normalizeNucleiJsonl', () => {
  it('parses JSONL lines and maps severity', () => {
    const jsonl =
      '{"template-id":"cve-x","info":{"severity":"high","name":"X"},"host":"http://app","matched-at":"http://app/x"}\n' +
      '\n' +
      '{"template-id":"cve-y","info":{"severity":"low","name":"Y"},"host":"http://app","matched-at":"http://app/y"}\n';
    const f = normalizeNucleiJsonl(jsonl);
    expect(f).toHaveLength(2);
    expect(f[0].severity).toBe('high');
    expect(f[0].target).toBe('http://app/x');
  });
  it('skips malformed lines without throwing', () => {
    expect(normalizeNucleiJsonl('not json\n{bad')).toEqual([]);
  });
});

describe('normalizeFfufJson', () => {
  it('parses the results array', () => {
    const json = JSON.stringify({ results: [{ url: 'http://app/admin', status: 200, length: 10 }] });
    const f = normalizeFfufJson(json);
    expect(f).toHaveLength(1);
    expect(f[0].target).toBe('http://app/admin');
    expect(f[0].detail).toContain('200');
  });
  it('returns [] for empty / malformed json', () => {
    expect(normalizeFfufJson('')).toEqual([]);
    expect(normalizeFfufJson('{')).toEqual([]);
  });
});
```

- [ ] **Step 2: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/normalize/normalizer.ts`**
```ts
export interface NormalizedToolFinding {
  tool: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  detail: string;
  raw: string;
}

// sqlmap --results-file CSV: "Target URL,Place,Parameter,Technique(s),Note(s)".
export function normalizeSqlmapCsv(csv: string): NormalizedToolFinding[] {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length <= 1) return [];
  const out: NormalizedToolFinding[] = [];
  for (const line of lines.slice(1)) {
    const cols = line.split(',');
    if (cols.length < 4) continue;
    const [target, place, parameter, technique] = cols;
    out.push({
      tool: 'sqlmap',
      severity: 'high',
      target,
      detail: `SQL injection in parameter '${parameter}' (${place}) via technique ${technique}`,
      raw: line,
    });
  }
  return out;
}

// nuclei -jsonl: one JSON object per line.
export function normalizeNucleiJsonl(jsonl: string): NormalizedToolFinding[] {
  const out: NormalizedToolFinding[] = [];
  for (const line of jsonl.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const o = JSON.parse(trimmed) as {
        'template-id'?: string;
        info?: { severity?: string; name?: string };
        host?: string;
        'matched-at'?: string;
      };
      const sev = o.info?.severity as NormalizedToolFinding['severity'] | undefined;
      out.push({
        tool: 'nuclei',
        severity: sev,
        target: o['matched-at'] ?? o.host ?? '',
        detail: `${o['template-id'] ?? 'template'}: ${o.info?.name ?? ''}`.trim(),
        raw: trimmed,
      });
    } catch {
      // malformed line — skip
    }
  }
  return out;
}

// ffuf -of json: { results: [{ url, status, length }] }.
export function normalizeFfufJson(json: string): NormalizedToolFinding[] {
  if (!json.trim()) return [];
  try {
    const o = JSON.parse(json) as { results?: Array<{ url?: string; status?: number; length?: number }> };
    return (o.results ?? []).map((r) => ({
      tool: 'ffuf',
      severity: 'info' as const,
      target: r.url ?? '',
      detail: `status=${r.status ?? '?'} length=${r.length ?? '?'}`,
      raw: JSON.stringify(r),
    }));
  } catch {
    return [];
  }
}
```

- [ ] **Step 4: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 5: Export from the barrel** — add to `packages/tool-broker/src/index.ts`:
```ts
export { authorizeRequest } from './core/authorize.js';
export type { AuthorizeDeps, AuthorizeResult, ResolvedTarget } from './core/authorize.js';
export { normalizeSqlmapCsv, normalizeNucleiJsonl, normalizeFfufJson } from './normalize/normalizer.js';
export type { NormalizedToolFinding } from './normalize/normalizer.js';
```

- [ ] **Step 6: Commit**
```bash
git add packages/tool-broker/src/normalize packages/tool-broker/src/index.ts
git commit -m "feat(tool-broker): OutputNormalizer for sqlmap/nuclei/ffuf output"
```

---

## Task 3: Final verification (host)

- [ ] **Step 1:** `pnpm --filter @shannon/tool-broker test` → all green.
- [ ] **Step 2:** `pnpm --filter @shannon/tool-broker typecheck` → exit 0.
- [ ] **Step 3:** `npx biome check --write packages/tool-broker/src/core packages/tool-broker/src/normalize packages/tool-broker/src/index.ts` then re-run the suite; commit any formatting:
```bash
git add -A && git commit -m "style(tool-broker): biome format Phase 1b host files" || echo "nothing to format"
```

---

## Tasks 4–9 — DOCKER-GATED (expand to full TDD tasks when the daemon is up)

> These cannot be verified without Docker (and a Linux egress environment for the packet-level claim). Each is an outline; turn it into bite-sized TDD steps at execution time. **Gate before any of these ship a real tool: the GPL legal sign-off.**

- [ ] **Task 4 — `Sandbox` executor** (`exec/sandbox.ts`): run a validated argv in an ephemeral container via `docker run --rm --network <scan-net> --cap-drop=ALL --security-opt=no-new-privileges --read-only --tmpfs /tmp --memory --cpus --pids-limit --user <non-root>` with a wall-clock `timeout` and broker-side `docker kill` deadline. Returns `{ stdout, stderr, exitCode, durationMs }` or a `timeout` status. Pre-scan **canary container** must fail to reach `1.1.1.1` and `169.254.169.254` or the scan aborts. Test: against a trivial image, assert egress to an out-of-scope IP is dropped.

- [ ] **Task 5 — `ForwardProxy`** (`proxy/forward-proxy.ts`): resolve the target host ONCE, pin the IP, force all tool egress through the proxy (`HTTP_PROXY`/`HTTPS_PROXY`), run `ScopeEnforcer.evaluate(pinnedIp, path)` on every forwarded request, re-validate post-redirect `Location`, and drop tool-native DNS. Test: a rebinding attempt (resolver returns in-scope then metadata) is blocked at connect time.

- [ ] **Task 6 — HTTP `BrokerAPI`** (`api/server.ts`): `POST /tool` → `authorizeRequest()` → `Sandbox.run()` → `OutputNormalizer` → `buildInvocationRecord()` (signed) → respond with `ToolResult` + record. `/health`, `/metrics`. Every allow/deny emits a record. Test in-process (no Docker) with a stubbed Sandbox; Docker test for the real path.

- [ ] **Task 7 — worker `ToolClient`** (`packages/worker/src/broker/tool-client.ts`) + DI wiring: HTTP client posting `ToolRequest` (with the scan's signed scope token) to `BROKER_URL`; the worker **validates the returned InvocationRecord's HMAC** before calling `EvidenceStore.record()` (uses the Phase-0/hotfix forensic chain). Add `toolClient` to the DI container.

- [ ] **Task 8 — Docker wiring**: add the `tool-broker` service to `docker-compose.yml`; add a `lab` profile with a deliberately-vulnerable SSTI app; **remove `network_mode: host`** from `docker-compose.local.yml`; inject `BROKER_URL`; **strip offensive tools + build toolchains from the worker image** (no unbrokered path). Validate the OutputNormalizer parsers against real sqlmap/nuclei/ffuf output here.

- [ ] **Task 9 — integration + safety release gate**: end-to-end against the lab — a brokered tool runs, returns a normalized finding, and a signed record lands in the chain; an out-of-scope target is BLOCKED; the **negative-capability test** (poisoned content telling the agent to hit `evil.com`/metadata → broker blocks, one `scope` record emitted). This is the Phase 1 release gate.

---

## Done criteria (Phase 1b host portion = Tasks 1–3)
- `authorizeRequest()` composes scope-lock + scope + registry + budget with correct ordering (no budget spent on denied/malformed requests), proven by a 6-case matrix.
- `OutputNormalizer` parses sqlmap CSV / nuclei JSONL / ffuf JSON resiliently (skips malformed input), unit-tested.
- Broker package typecheck clean, all tests green.

Then **Phase 2** (ReAct tool-use loop + Temporal `runBrokerTool`/`runVerifyGate` activities + circuit breaker + reflected-first OOB) and **Phase 3** (SSTI end-to-end + release gate = MVP).
