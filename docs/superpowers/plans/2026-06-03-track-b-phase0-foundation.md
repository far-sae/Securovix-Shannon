# Track B Phase 0 — Foundation Prerequisites — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the pure-TypeScript, host-testable foundation the Track B tool-broker stands on — a single source of truth for vuln categories (fixing a latent index bug), a widened `VulnCategory` type with MITRE/graph wiring, scope/budget-aware error classification, glob path matching, and the broker/scope/budget/OOB config schema with validation.

**Architecture:** All changes are inside `packages/worker` and are pure TS (no Docker, no native deps beyond the already-built `better-sqlite3`, no LLM calls). Each is unit-tested with vitest on the host. This plan deliberately stops short of the broker sidecar, sandbox, forward-proxy, ReAct loop, and OOB service — those are Phase 1.

**Tech Stack:** TypeScript (ESM, NodeNext), vitest, AJV (being removed where dead). No new runtime dependencies.

**Spec:** [Track B — Deeper Exploitation Engine](../specs/2026-06-03-deeper-exploitation-engine-design.md) §2 (Phase 0) and §4.2 (scope), informed by these locked decisions: app-layer scope primary + Linux packet DiD; **scope-lock built in Phase 1** (Phase 0 adds only the config fields); `focus`/`avoid` **upgraded to glob** (bare path = prefix, for back-compat); secrets-by-handle is Phase 1 (Phase 0 adds the broker config shape only).

**Decision encoded — two category concepts (do not conflate):**
- **Active pipeline categories** = what the workflow actually runs agents for. Currently 6: `sqli, xss, auth-bypass, authz-bypass, ssrf, business-logic`. New classes are NOT added here until their agents exist (Phase 3+).
- **`VulnCategory` type union** (`attack-graph/types.ts`) = everything a finding/graph node can be typed as. Widened now with the 6 future classes so findings/graph code compiles when those agents land.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `packages/worker/src/workflows/categories.ts` | single source of truth for ACTIVE vuln/exploit categories | **create** (pure module, workflow-safe) |
| `packages/worker/src/workflows/categories.test.ts` | category list tests | **create** |
| `packages/worker/src/workflows/scan.ts` | Temporal workflow | build `vulnExploitPairs` from `categories.ts` |
| `packages/worker/src/workflows/activities/vuln-agents.ts` | vuln agent activity | use `categories.ts`; fix `agentIndex` bug |
| `packages/worker/src/workflows/activities/chain-analysis.ts` | graph builder | use `categories.ts`; extend infer maps |
| `packages/worker/src/attack-graph/types.ts` | `VulnCategory` union + `VulnNode` | widen union |
| `packages/worker/src/attack-graph/chain-scorer.ts` | MITRE mapping | extend `categoryToTactic` |
| `packages/worker/src/config/scope-rules.ts` | glob path matcher + CIDR validation | **create** (pure util) |
| `packages/worker/src/config/scope-rules.test.ts` | path/CIDR tests | **create** |
| `packages/worker/src/config/schema.ts` | config types | add broker/scope/budget/oob types |
| `config/shannon.schema.json` | JSON schema | add broker block |
| `packages/worker/src/config/loader.ts` | config load + validate | validate broker config; remove dead AJV |
| `packages/worker/src/config/loader.test.ts` | config validation tests | **create** |
| `packages/worker/src/llm/tiers.ts` | agent→tier map | add `validateAgentTiers()` assertion |
| `packages/worker/src/llm/tiers.test.ts` | tier assertion test | **create** |
| `packages/worker/src/temporal/error-classification.ts` | re-export shim (see Task 4) | none / verify |

---

## Task 1: Single source of truth for active categories

**Files:**
- Create: `packages/worker/src/workflows/categories.ts`
- Create: `packages/worker/src/workflows/categories.test.ts`

- [ ] **Step 1: Write the failing test**

Create `packages/worker/src/workflows/categories.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { ACTIVE_VULN_CATEGORIES, isActiveCategory } from './categories.js';

describe('active categories', () => {
  it('lists the six pipeline categories including business-logic', () => {
    expect(ACTIVE_VULN_CATEGORIES).toEqual([
      'sqli',
      'xss',
      'auth-bypass',
      'authz-bypass',
      'ssrf',
      'business-logic',
    ]);
  });

  it('business-logic is at a valid (non-negative) index — guards the agentIndex bug', () => {
    expect(ACTIVE_VULN_CATEGORIES.indexOf('business-logic')).toBeGreaterThanOrEqual(0);
  });

  it('isActiveCategory recognizes members and rejects non-members', () => {
    expect(isActiveCategory('sqli')).toBe(true);
    expect(isActiveCategory('rce-ssti')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `./categories.js` does not exist.

- [ ] **Step 3: Create the module**

Create `packages/worker/src/workflows/categories.ts` (pure constants/types only — NO Node imports, so the Temporal workflow `scan.ts` can import it safely):
```ts
// Single source of truth for the ACTIVE vuln/exploit pipeline categories — the
// ones the workflow actually runs agents for. Adding a new class here (with its
// agents, prompts, and tier) is what activates it end to end.
// NOTE: this is a strict subset of the broader `VulnCategory` type union in
// attack-graph/types.ts (which also includes future, not-yet-active classes).
export const ACTIVE_VULN_CATEGORIES = [
  'sqli',
  'xss',
  'auth-bypass',
  'authz-bypass',
  'ssrf',
  'business-logic',
] as const;

export type ActiveVulnCategory = (typeof ACTIVE_VULN_CATEGORIES)[number];

export function isActiveCategory(value: string): value is ActiveVulnCategory {
  return (ACTIVE_VULN_CATEGORIES as readonly string[]).includes(value);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — 3 new tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/workflows/categories.ts packages/worker/src/workflows/categories.test.ts
git commit -m "feat(workflows): single source of truth for active vuln categories"
```

---

## Task 2: Wire consumers to categories.ts (fixes the business-logic agentIndex bug)

**Files:**
- Modify: `packages/worker/src/workflows/scan.ts:40-47`
- Modify: `packages/worker/src/workflows/activities/vuln-agents.ts:14,33`
- Modify: `packages/worker/src/workflows/activities/chain-analysis.ts:12,29`
- Test: `packages/worker/src/workflows/activities/vuln-agents.test.ts` (create)

- [ ] **Step 1: Write the failing test for the agentIndex fix**

Create `packages/worker/src/workflows/activities/vuln-agents.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { categoryAgentIndex } from './vuln-agents.js';

describe('categoryAgentIndex', () => {
  it('returns a 1-based index for every active category (business-logic is NOT 0)', () => {
    expect(categoryAgentIndex('sqli')).toBe(1);
    expect(categoryAgentIndex('business-logic')).toBe(6);
  });

  it('throws for an unknown category instead of silently returning 0', () => {
    expect(() => categoryAgentIndex('rce-ssti')).toThrow(/unknown.*category/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `categoryAgentIndex` is not exported.

- [ ] **Step 3: Update `vuln-agents.ts`**

In `packages/worker/src/workflows/activities/vuln-agents.ts`:

1. Replace the import-region line 14:
```ts
const VULN_CATEGORIES = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf'] as const;
```
with an import (add to the existing import block at the top) and an exported helper:
```ts
import { ACTIVE_VULN_CATEGORIES } from '../categories.js';

export function categoryAgentIndex(category: string): number {
  const idx = ACTIVE_VULN_CATEGORIES.indexOf(category as (typeof ACTIVE_VULN_CATEGORIES)[number]);
  if (idx < 0) {
    throw new Error(`Unknown vuln category: ${category}. Add it to workflows/categories.ts.`);
  }
  return idx + 1;
}
```

2. Replace the body of line 33:
```ts
  const agentIndex = VULN_CATEGORIES.indexOf(input.category as typeof VULN_CATEGORIES[number]) + 1;
```
with:
```ts
  const agentIndex = categoryAgentIndex(input.category);
```

- [ ] **Step 4: Update `chain-analysis.ts`**

In `packages/worker/src/workflows/activities/chain-analysis.ts`, replace line 12:
```ts
const CATEGORIES = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic'] as const;
```
with an import (add near the other imports) and use it:
```ts
import { ACTIVE_VULN_CATEGORIES } from '../categories.js';
```
Then change the loop at line 29 `for (const category of CATEGORIES) {` to `for (const category of ACTIVE_VULN_CATEGORIES) {`.

- [ ] **Step 5: Update `scan.ts`**

In `packages/worker/src/workflows/scan.ts`, replace the hardcoded `vulnExploitPairs` array (lines 40-47) with one derived from the shared list:
```ts
import { ACTIVE_VULN_CATEGORIES } from './categories.js';
```
(add to the imports at top), and replace lines 40-47 with:
```ts
  // Phase 3 & 4: Vuln + Exploit agents (paired, parallel across categories).
  // Categories come from the single source of truth in categories.ts.
  const vulnExploitPairs = ACTIVE_VULN_CATEGORIES.map((c) => ({ vuln: c, exploit: c }));
```

- [ ] **Step 6: Run test + typecheck**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — `categoryAgentIndex` tests pass; category tests still pass.
Run: `pnpm --filter @shannon/worker typecheck`
Expected: only the 2 pre-existing `@temporalio/common` errors; no new errors.

- [ ] **Step 7: Commit**

```bash
git add packages/worker/src/workflows/scan.ts packages/worker/src/workflows/activities/vuln-agents.ts packages/worker/src/workflows/activities/chain-analysis.ts packages/worker/src/workflows/activities/vuln-agents.test.ts
git commit -m "refactor(workflows): consume categories.ts everywhere; fix business-logic agentIndex bug"
```

---

## Task 3: Widen VulnCategory + MITRE + graph infer maps for the 6 future classes

**Files:**
- Modify: `packages/worker/src/attack-graph/types.ts:1`
- Modify: `packages/worker/src/attack-graph/chain-scorer.ts:83-92`
- Modify: `packages/worker/src/workflows/activities/chain-analysis.ts:115-151`
- Test: `packages/worker/src/attack-graph/chain-scorer.test.ts` (create)

- [ ] **Step 1: Write the failing test**

Create `packages/worker/src/attack-graph/chain-scorer.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import type { VulnCategory } from './types.js';

// Compile-time assertion: each new category is assignable to VulnCategory.
const NEW_CATEGORIES: VulnCategory[] = [
  'rce-ssti',
  'rce-deser',
  'token-forgery',
  'prompt-injection',
  'graphql-idor',
  'request-smuggling',
];

describe('VulnCategory widening', () => {
  it('accepts the six new Track B categories', () => {
    expect(NEW_CATEGORIES).toHaveLength(6);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL (type error) — the new literals are not assignable to `VulnCategory` yet.

- [ ] **Step 3: Widen the union**

In `packages/worker/src/attack-graph/types.ts`, line 1 currently is:
```ts
export type VulnCategory = 'sqli' | 'xss' | 'ssrf' | 'auth-bypass' | 'authz-bypass' | 'rce' | 'credential-theft' | 'business-logic';
```
Replace it with:
```ts
export type VulnCategory =
  | 'sqli'
  | 'xss'
  | 'ssrf'
  | 'auth-bypass'
  | 'authz-bypass'
  | 'rce'
  | 'credential-theft'
  | 'business-logic'
  // Track B classes (typed now; agents added in Phase 3+)
  | 'rce-ssti'
  | 'rce-deser'
  | 'token-forgery'
  | 'prompt-injection'
  | 'graphql-idor'
  | 'request-smuggling';
```

- [ ] **Step 4: Extend MITRE mapping**

In `packages/worker/src/attack-graph/chain-scorer.ts`, add these entries to the `categoryToTactic` object (after the `'business-logic'` line at :91):
```ts
      'rce-ssti': ['TA0002', 'TA0003'],
      'rce-deser': ['TA0002', 'TA0003'],
      'token-forgery': ['TA0001', 'TA0004', 'TA0006'],
      'prompt-injection': ['TA0001', 'TA0002'],
      'graphql-idor': ['TA0001', 'TA0007', 'TA0009'],
      'request-smuggling': ['TA0001', 'TA0005'],
```

- [ ] **Step 5: Extend graph infer maps**

In `packages/worker/src/workflows/activities/chain-analysis.ts`, add cases to `inferPreconditions` (after the `business-logic` case at :123):
```ts
    case 'graphql-idor':
      pre.push('authenticated');
      break;
    case 'token-forgery':
      pre.push('authenticated');
      break;
```
and add cases to `inferPostconditions` (after the `business-logic` case at :148):
```ts
    case 'rce-ssti':
      post.push('remote-code-execution', 'internal-network-access');
      break;
    case 'rce-deser':
      post.push('remote-code-execution', 'admin-access');
      break;
    case 'token-forgery':
      post.push('authenticated', 'elevated-privileges');
      break;
    case 'prompt-injection':
      post.push('data-access', 'workflow-manipulation');
      break;
    case 'graphql-idor':
      post.push('data-access');
      break;
    case 'request-smuggling':
      post.push('session-hijack', 'data-access');
      break;
```

- [ ] **Step 6: Run test + typecheck**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — the widening test compiles and passes.
Run: `pnpm --filter @shannon/worker typecheck`
Expected: only the 2 pre-existing `@temporalio/common` errors.

- [ ] **Step 7: Commit**

```bash
git add packages/worker/src/attack-graph/types.ts packages/worker/src/attack-graph/chain-scorer.ts packages/worker/src/workflows/activities/chain-analysis.ts packages/worker/src/attack-graph/chain-scorer.test.ts
git commit -m "feat(attack-graph): widen VulnCategory + MITRE/precondition maps for Track B classes"
```

---

## Task 4: Scope/budget-aware error classification

**Files:**
- Modify: `packages/worker/src/config/validation.ts`
- Test: `packages/worker/src/config/validation.test.ts` (create)

Background: `classifyError()` falls back to `retryable=true` for anything unmatched, so a broker "out of scope" response would be retried up to 50× — firing 50 out-of-scope probes and spamming the forensic chain. Scope/budget denials must be **non-retryable**; broker-unavailable must be **retryable** (to drive the Phase 1 circuit breaker).

- [ ] **Step 1: Write the failing tests**

Create `packages/worker/src/config/validation.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { classifyError } from './validation.js';

describe('classifyError — broker/scope/budget', () => {
  it('classifies out-of-scope as non-retryable SCOPE_DENIED', () => {
    const e = classifyError(new Error('Request blocked: out of scope host evil.com'));
    expect(e.code).toBe('SCOPE_DENIED');
    expect(e.retryable).toBe(false);
  });

  it('classifies budget exhaustion as non-retryable BUDGET_EXHAUSTED', () => {
    const e = classifyError(new Error('budget exceeded: max tool invocations reached'));
    expect(e.code).toBe('BUDGET_EXHAUSTED');
    expect(e.retryable).toBe(false);
  });

  it('classifies broker unavailability as retryable BROKER_UNAVAILABLE', () => {
    const e = classifyError(new Error('tool-broker unavailable: connection refused'));
    expect(e.code).toBe('BROKER_UNAVAILABLE');
    expect(e.retryable).toBe(true);
  });

  it('still falls back to retryable UNKNOWN for unrecognized errors', () => {
    const e = classifyError(new Error('something weird happened'));
    expect(e.code).toBe('UNKNOWN');
    expect(e.retryable).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — the first three get `UNKNOWN`/retryable today.

- [ ] **Step 3: Implement**

In `packages/worker/src/config/validation.ts`, add the three matchers **before** the final `return new ShannonError(truncated, true, 'UNKNOWN');`. Insert after the existing non-retryable block (after the OOM check, before the retryable block):
```ts
  if (isScopeError(message)) {
    return new ShannonError(truncated, false, 'SCOPE_DENIED');
  }
  if (isBudgetError(message)) {
    return new ShannonError(truncated, false, 'BUDGET_EXHAUSTED');
  }
```
and add `isBrokerUnavailable` to the retryable block (before `isNetworkError`):
```ts
  if (isBrokerUnavailable(message)) {
    return new ShannonError(truncated, true, 'BROKER_UNAVAILABLE');
  }
```
Then add these helper functions at the bottom of the file:
```ts
function isScopeError(msg: string): boolean {
  return /out.?of.?scope|scope.*(denied|block)|blocked.*scope|not in scope/i.test(msg);
}

function isBudgetError(msg: string): boolean {
  return /budget.*(exceed|exhaust)|max.*(tool.*invocation|http.*request|cost)|cost.*limit/i.test(msg);
}

function isBrokerUnavailable(msg: string): boolean {
  return /broker.*(unavailable|unreachable|down)|tool-broker.*(refused|unavailable)/i.test(msg);
}
```
Order matters: `isBrokerUnavailable` must be checked before `isNetworkError` (a broker "connection refused" should map to BROKER_UNAVAILABLE, not NETWORK_ERROR). Both are retryable, so behaviour is equivalent, but the code is more specific.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all four classification tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/config/validation.ts packages/worker/src/config/validation.test.ts
git commit -m "fix(temporal): classify scope/budget denials non-retryable, broker-unavailable retryable"
```

---

## Task 5: Glob path matcher + CIDR validation utility

**Files:**
- Create: `packages/worker/src/config/scope-rules.ts`
- Create: `packages/worker/src/config/scope-rules.test.ts`

This implements the locked decision to upgrade `focus`/`avoid` to glob, while a **bare path with no glob metacharacters is treated as a prefix** (back-compat with existing configs). It also provides `isValidCidr` used by config validation (Task 7) and the Phase 1 ScopeEnforcer.

- [ ] **Step 1: Write the failing tests**

Create `packages/worker/src/config/scope-rules.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { matchesPath, isValidCidr } from './scope-rules.js';

describe('matchesPath', () => {
  it('treats a bare path as a prefix (back-compat)', () => {
    expect(matchesPath('/api/', '/api/users')).toBe(true);
    expect(matchesPath('/api/', '/admin')).toBe(false);
  });

  it('supports * (single segment) and ** (multi segment) globs', () => {
    expect(matchesPath('/api/*/edit', '/api/users/edit')).toBe(true);
    expect(matchesPath('/api/*/edit', '/api/users/1/edit')).toBe(false);
    expect(matchesPath('/api/**', '/api/users/1/edit')).toBe(true);
  });

  it('supports explicit regex via re: prefix', () => {
    expect(matchesPath('re:^/v[0-9]+/users$', '/v2/users')).toBe(true);
    expect(matchesPath('re:^/v[0-9]+/users$', '/users')).toBe(false);
  });
});

describe('isValidCidr', () => {
  it('accepts valid IPv4 CIDRs', () => {
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('192.168.1.0/24')).toBe(true);
  });

  it('rejects malformed CIDRs', () => {
    expect(isValidCidr('10.0.0.0')).toBe(false);
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
    expect(isValidCidr('999.0.0.0/8')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `./scope-rules.js` does not exist.

- [ ] **Step 3: Implement**

Create `packages/worker/src/config/scope-rules.ts`:
```ts
// Path matching for scope rules (target.urls.focus / avoid).
// Rules:
//   - "re:<pattern>"  → explicit RegExp match against the path
//   - contains * or ? → glob (`*` = one path segment, `**` = any depth, `?` = one char)
//   - otherwise       → prefix match (back-compat with legacy bare-path configs)
export function matchesPath(rule: string, path: string): boolean {
  if (rule.startsWith('re:')) {
    return new RegExp(rule.slice(3)).test(path);
  }
  if (rule.includes('*') || rule.includes('?')) {
    return globToRegExp(rule).test(path);
  }
  return path.startsWith(rule);
}

function globToRegExp(glob: string): RegExp {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*'; // ** = any number of segments/chars
        i++;
      } else {
        re += '[^/]*'; // * = within a single segment
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`${re}$`);
}

// Validates an IPv4 CIDR like "10.0.0.0/8". (IPv6 CIDR validation is a Phase 1
// concern alongside the ScopeEnforcer; Phase 0 only needs IPv4 config validation.)
export function isValidCidr(cidr: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some((o) => o > 255)) return false;
  const prefix = Number(m[5]);
  return prefix >= 0 && prefix <= 32;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all matcher and CIDR tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/config/scope-rules.ts packages/worker/src/config/scope-rules.test.ts
git commit -m "feat(config): glob/prefix/regex path matcher + IPv4 CIDR validation"
```

---

## Task 6: Broker/scope/budget/OOB config types

**Files:**
- Modify: `packages/worker/src/config/schema.ts`

- [ ] **Step 1: Add the types**

In `packages/worker/src/config/schema.ts`, add these interfaces above `ShannonConfig`:
```ts
export interface ScopeConfig {
  // Extra in-scope IPv4 CIDRs beyond the target host (always implicitly in scope).
  allowlistCidrs?: string[];
  // Private/link-local CIDRs to explicitly re-allow (overrides the broker's baked-in
  // deny of RFC1918/metadata/localhost). Use with care; Phase 1 broker enforces this.
  allowPrivateCidrs?: string[];
}

export interface BudgetConfig {
  maxToolInvocations?: number;
  maxHttpRequests?: number;
  maxWallClockMs?: number;
  maxCostUsd?: number;
}

export type OOBMode = 'reflected-only' | 'self-hosted';

export interface OOBConfig {
  mode?: OOBMode; // default 'reflected-only' in Phase 1
  serverUrl?: string; // self-hosted interactsh server base URL
  // Auth token is a SECRET HANDLE (resolved by the broker), never a raw secret here.
  tokenHandle?: string;
}

export interface BrokerConfig {
  // Phase 1 wires runtime enforcement; Phase 0 only validates the shape.
  allowStateChanging?: boolean; // default false
  // PEM public key (or handle) used to verify the signed scope-lock token. Phase 1.
  scopeLockPublicKey?: string;
  scope?: ScopeConfig;
  budgets?: BudgetConfig;
  oob?: OOBConfig;
}
```
Then add `broker?: BrokerConfig;` as a field on the `ShannonConfig` interface (after `models?`).

- [ ] **Step 2: Verify typecheck**

Run: `pnpm --filter @shannon/worker typecheck`
Expected: only the 2 pre-existing `@temporalio/common` errors; nothing new.

- [ ] **Step 3: Commit**

```bash
git add packages/worker/src/config/schema.ts
git commit -m "feat(config): add broker/scope/budget/oob config types"
```

---

## Task 7: JSON schema + loader validation for broker config

**Files:**
- Modify: `config/shannon.schema.json`
- Modify: `packages/worker/src/config/loader.ts`
- Test: `packages/worker/src/config/loader.test.ts` (create)

- [ ] **Step 1: Write the failing tests**

Create `packages/worker/src/config/loader.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { isErr, isOk } from '../result.js';
import { validateConfig } from './loader.js';
import type { ShannonConfig } from './schema.js';

const base: ShannonConfig = { target: { url: 'https://example.com' } };

describe('validateConfig — broker', () => {
  it('accepts a valid broker block', () => {
    const r = validateConfig({
      ...base,
      broker: {
        allowStateChanging: false,
        scope: { allowlistCidrs: ['10.0.0.0/8'] },
        budgets: { maxToolInvocations: 100, maxHttpRequests: 5000 },
        oob: { mode: 'reflected-only' },
      },
    });
    expect(isOk(r)).toBe(true);
  });

  it('rejects an invalid CIDR', () => {
    const r = validateConfig({ ...base, broker: { scope: { allowlistCidrs: ['10.0.0.0/33'] } } });
    expect(isErr(r)).toBe(true);
  });

  it('rejects a non-positive budget', () => {
    const r = validateConfig({ ...base, broker: { budgets: { maxToolInvocations: 0 } } });
    expect(isErr(r)).toBe(true);
  });

  it('rejects an unknown oob mode', () => {
    const r = validateConfig({
      ...base,
      broker: { oob: { mode: 'carrier-pigeon' as unknown as 'reflected-only' } },
    });
    expect(isErr(r)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `validateConfig` is not exported and `isOk`/`isErr` usage / broker validation don't exist yet. (Confirm `result.ts` exports `isOk`/`isErr`; it does per the codebase summary. If not, use `r.ok === true`.)

- [ ] **Step 3: Refactor loader.ts to expose `validateConfig` and validate the broker block**

Replace the contents of `packages/worker/src/config/loader.ts` with:
```ts
import { existsSync, readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { type Result, err, ok } from '../result.js';
import { isValidCidr } from './scope-rules.js';
import type { ShannonConfig } from './schema.js';

export function validateConfig(config: ShannonConfig): Result<ShannonConfig> {
  if (!config.target?.url) {
    return err(new Error('Config must specify target.url'));
  }

  if (config.pipeline?.maxConcurrentPipelines !== undefined) {
    const max = config.pipeline.maxConcurrentPipelines;
    if (max < 1 || max > 5) {
      return err(new Error('maxConcurrentPipelines must be between 1 and 5'));
    }
  }

  const broker = config.broker;
  if (broker) {
    for (const cidr of broker.scope?.allowlistCidrs ?? []) {
      if (!isValidCidr(cidr)) return err(new Error(`Invalid CIDR in broker.scope.allowlistCidrs: ${cidr}`));
    }
    for (const cidr of broker.scope?.allowPrivateCidrs ?? []) {
      if (!isValidCidr(cidr)) return err(new Error(`Invalid CIDR in broker.scope.allowPrivateCidrs: ${cidr}`));
    }
    const budgets = broker.budgets;
    if (budgets) {
      for (const [key, val] of Object.entries(budgets)) {
        if (val !== undefined && (typeof val !== 'number' || val <= 0)) {
          return err(new Error(`broker.budgets.${key} must be a positive number`));
        }
      }
    }
    const mode = broker.oob?.mode;
    if (mode !== undefined && mode !== 'reflected-only' && mode !== 'self-hosted') {
      return err(new Error(`broker.oob.mode must be 'reflected-only' or 'self-hosted', got: ${mode}`));
    }
  }

  return ok(config);
}

export class ConfigLoader {
  load(path: string): Result<ShannonConfig> {
    if (!existsSync(path)) {
      return err(new Error(`Config file not found: ${path}`));
    }
    try {
      const raw = readFileSync(path, 'utf-8');
      const config = parseYaml(raw) as ShannonConfig;
      return validateConfig(config);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }
}
```
Note: this removes the dead AJV instantiation (`new Ajv(...)` was never used against any schema) — the loader has always validated imperatively. `validateConfig` is extracted so it's unit-testable without touching the filesystem.

- [ ] **Step 4: Add the broker block to the JSON schema**

In `config/shannon.schema.json`, add a `broker` property inside the top-level `properties` object (after `loginInstructions`, before the closing of `properties`):
```json
    "broker": {
      "type": "object",
      "properties": {
        "allowStateChanging": { "type": "boolean", "default": false },
        "scopeLockPublicKey": { "type": "string" },
        "scope": {
          "type": "object",
          "properties": {
            "allowlistCidrs": { "type": "array", "items": { "type": "string" } },
            "allowPrivateCidrs": { "type": "array", "items": { "type": "string" } }
          },
          "additionalProperties": false
        },
        "budgets": {
          "type": "object",
          "properties": {
            "maxToolInvocations": { "type": "integer", "minimum": 1 },
            "maxHttpRequests": { "type": "integer", "minimum": 1 },
            "maxWallClockMs": { "type": "integer", "minimum": 1 },
            "maxCostUsd": { "type": "number", "minimum": 0 }
          },
          "additionalProperties": false
        },
        "oob": {
          "type": "object",
          "properties": {
            "mode": { "type": "string", "enum": ["reflected-only", "self-hosted"] },
            "serverUrl": { "type": "string" },
            "tokenHandle": { "type": "string" }
          },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all broker validation tests pass.
Run: `pnpm --filter @shannon/worker typecheck`
Expected: only the 2 pre-existing `@temporalio/common` errors.

- [ ] **Step 6: Commit**

```bash
git add config/shannon.schema.json packages/worker/src/config/loader.ts packages/worker/src/config/loader.test.ts
git commit -m "feat(config): validate broker/scope/budget/oob block; extract validateConfig; drop dead AJV"
```

---

## Task 8: Agent-tier startup assertion

**Files:**
- Modify: `packages/worker/src/llm/tiers.ts`
- Test: `packages/worker/src/llm/tiers.test.ts` (create)

Prevents the silent `'medium'` fallback for an active category that lacks a tier (a quiet cost/quality bug). Asserts every active vuln/exploit agent has a tier entry.

- [ ] **Step 1: Write the failing test**

Create `packages/worker/src/llm/tiers.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { AGENT_TIERS, validateAgentTiers } from './tiers.js';
import { ACTIVE_VULN_CATEGORIES } from '../workflows/categories.js';

describe('validateAgentTiers', () => {
  it('passes: every active category has vuln- and exploit- tiers', () => {
    expect(() => validateAgentTiers()).not.toThrow();
  });

  it('every active category is registered in AGENT_TIERS', () => {
    for (const c of ACTIVE_VULN_CATEGORIES) {
      expect(AGENT_TIERS[`vuln-${c}`]).toBeDefined();
      expect(AGENT_TIERS[`exploit-${c}`]).toBeDefined();
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @shannon/worker test`
Expected: FAIL — `validateAgentTiers` is not exported.

- [ ] **Step 3: Implement**

In `packages/worker/src/llm/tiers.ts`, add at the bottom:
```ts
import { ACTIVE_VULN_CATEGORIES } from '../workflows/categories.js';

// Fail loud at startup if an active category is missing a tier (avoids the silent
// 'medium' fallback in client.ts). Call once during worker bootstrap.
export function validateAgentTiers(): void {
  const missing: string[] = [];
  for (const c of ACTIVE_VULN_CATEGORIES) {
    if (!AGENT_TIERS[`vuln-${c}`]) missing.push(`vuln-${c}`);
    if (!AGENT_TIERS[`exploit-${c}`]) missing.push(`exploit-${c}`);
  }
  if (missing.length > 0) {
    throw new Error(`Missing model tier for agents: ${missing.join(', ')}. Add them to AGENT_TIERS in tiers.ts.`);
  }
}
```
(All six active categories already have `vuln-`/`exploit-` entries in `AGENT_TIERS`, so the assertion passes today. Importing `categories.ts` here is safe — it's a pure module.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/worker/src/llm/tiers.ts packages/worker/src/llm/tiers.test.ts
git commit -m "feat(llm): validateAgentTiers startup assertion (no silent medium fallback)"
```

---

## Task 9: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full suite**

Run: `pnpm --filter @shannon/worker test`
Expected: PASS — all suites green (the 7 forensic/DI tests from the hotfix plus the new Phase 0 suites: categories, vuln-agents, chain-scorer, validation, scope-rules, loader, tiers).

- [ ] **Step 2: Typecheck**

Run: `pnpm --filter @shannon/worker typecheck`
Expected: ONLY the 2 pre-existing `@temporalio/common` errors in `src/temporal/*.ts`. No new errors.

- [ ] **Step 3: Lint the authored/changed files**

Run biome on the files this plan created or modified (NOT the whole repo — avoid pre-existing noise):
```bash
npx biome check --write packages/worker/src/workflows/categories.ts packages/worker/src/workflows/categories.test.ts packages/worker/src/workflows/activities/vuln-agents.test.ts packages/worker/src/attack-graph/chain-scorer.test.ts packages/worker/src/config/scope-rules.ts packages/worker/src/config/scope-rules.test.ts packages/worker/src/config/loader.ts packages/worker/src/config/loader.test.ts packages/worker/src/config/validation.test.ts packages/worker/src/llm/tiers.test.ts
```
Then re-run `pnpm --filter @shannon/worker test` to confirm formatting didn't break anything. Commit any formatting:
```bash
git add -A && git commit -m "style(worker): biome format Phase 0 files" || echo "nothing to format"
```

---

## Done criteria
- One source of truth for active categories; `business-logic` agentIndex bug fixed (was silently 0).
- `VulnCategory` widened with the 6 Track B classes; MITRE + graph infer maps cover them.
- Scope/budget denials are non-retryable; broker-unavailable is retryable.
- Glob/prefix/regex path matcher + IPv4 CIDR validation, unit-tested.
- Broker/scope/budget/OOB config types + JSON schema + loader validation.
- `validateAgentTiers()` guards the silent-medium fallback.
- All tests green; typecheck clean except the pre-existing temporal errors.

This unblocks **Track B Phase 1** (the tool-broker sidecar: ToolRegistry, ScopeEnforcer using `scope-rules.ts`, BudgetLedger, Sandbox, SessionProvider, secrets-by-handle, forward-proxy, scope-lock verification, OOB service).
