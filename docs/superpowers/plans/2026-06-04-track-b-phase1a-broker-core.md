# Track B Phase 1a — Tool-Broker Core (host-testable) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure-TypeScript, security-critical core of the tool-broker as a new `packages/tool-broker` package — scope enforcement, argument-allowlist tool registry, signed scope-lock, persisted budget ledger, signed invocation records, and secrets redaction — all unit-tested on the host with zero Docker/network/native dependencies.

**Architecture:** A standalone library package (`@shannon/tool-broker`). It contains NO process boundary, HTTP server, or container runner yet — those are Phase 1b. By building the enforcement logic as a pure, exhaustively-tested library first, the dangerous parts (what is in scope, which args are allowed, whether a scope token is authentic) are proven before any tool can run. Phase 1b wraps this core in the sidecar process (HTTP API + sandbox + forward-proxy) and adds the worker-side `ToolClient`.

**Tech Stack:** TypeScript (ESM, NodeNext), vitest, `node:crypto` (HMAC-SHA256). No runtime dependencies, no native modules. Persistence uses plain JSON files (atomic write via temp-rename).

**Spec:** [Track B — Deeper Exploitation Engine](../specs/2026-06-03-deeper-exploitation-engine-design.md) §4 (broker internals) and §10 (safety contract). Depends on Phase 0 (merged: `e15b8cc`).

**Locked decisions encoded here:** app-layer ScopeEnforcer is the PRIMARY control (this package IS that control); scope-lock token required to authorize scope (signed at scan start, verified on every request); glob/prefix path rules (reuse the matching approach from Phase 0's `scope-rules.ts`, re-implemented here for enforcement with real IP-in-CIDR containment); secrets handled by redaction + handles (raw secrets never logged).

**Explicitly OUT of scope for Phase 1a (→ Phase 1b, needs Docker daemon up):** the HTTP `BrokerAPI` server; the `Sandbox` container runner; the `ForwardProxy` (connect-time DNS pinning at the packet/socket layer); the worker-side `ToolClient`; `SessionProvider` (Playwright login); `OutputNormalizer` wired to real tool output; OOB self-hosted interactsh server; Temporal `runBrokerTool`/`runVerifyGate` activities. Phase 1a builds the brains; Phase 1b builds the body.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `packages/tool-broker/package.json` | package manifest | **create** |
| `packages/tool-broker/tsconfig.json` | TS config (extends root) | **create** |
| `packages/tool-broker/vitest.config.ts` | test runner (NodeNext `.js`→`.ts`) | **create** |
| `pnpm-workspace.yaml` | workspace members | add `packages/tool-broker` |
| `packages/tool-broker/src/types.ts` | shared broker contract types | **create** |
| `packages/tool-broker/src/scope/ip.ts` | IPv4 parse + CIDR containment | **create** |
| `packages/tool-broker/src/scope/enforcer.ts` | ScopeEnforcer (denylist + allowlist + paths) | **create** |
| `packages/tool-broker/src/scope/lock.ts` | sign/verify scope-lock token | **create** |
| `packages/tool-broker/src/registry/registry.ts` | ToolRegistry + argv builder + blocklist | **create** |
| `packages/tool-broker/src/registry/descriptors.ts` | tool descriptors (sqlmap/nuclei/ffuf/sstimap) | **create** |
| `packages/tool-broker/src/budget/ledger.ts` | persisted atomic budget counters | **create** |
| `packages/tool-broker/src/forensic/invocation-record.ts` | build + HMAC-sign InvocationRecord | **create** |
| `packages/tool-broker/src/secrets/redact.ts` | secret-pattern redaction filter | **create** |
| `packages/tool-broker/src/index.ts` | package barrel exports | **create** |
| (matching `*.test.ts` beside each module) | unit tests | **create** |

---

## Task 1: Scaffold the `@shannon/tool-broker` package

**Files:**
- Create: `packages/tool-broker/package.json`, `tsconfig.json`, `vitest.config.ts`, `src/index.ts`, `src/smoke.test.ts`
- Modify: `pnpm-workspace.yaml`

- [ ] **Step 1: Create `packages/tool-broker/package.json`**
```json
{
  "name": "@shannon/tool-broker",
  "version": "0.0.0-development",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.6.0",
    "vitest": "^2.1.0"
  },
  "engines": { "node": ">=18.0.0" }
}
```

- [ ] **Step 2: Create `packages/tool-broker/tsconfig.json`**
```json
{
  "extends": "../../tsconfig.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src"],
  "exclude": ["src/**/*.test.ts", "src/**/test-helpers.ts"]
}
```

- [ ] **Step 3: Create `packages/tool-broker/vitest.config.ts`** (same NodeNext `.js`→`.ts` resolver as the worker)
```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    {
      name: 'js-to-ts',
      enforce: 'pre',
      async resolveId(source, importer) {
        if (importer && source.startsWith('.') && source.endsWith('.js')) {
          const resolved = await this.resolve(source.replace(/\.js$/, '.ts'), importer, { skipSelf: true });
          if (resolved) return resolved;
        }
        return null;
      },
    },
  ],
  test: { include: ['src/**/*.test.ts'], environment: 'node' },
});
```

- [ ] **Step 4: Add to the workspace**

In `pnpm-workspace.yaml`, add `- 'packages/tool-broker'` under the existing `packages/worker` line.

- [ ] **Step 5: Create `packages/tool-broker/src/index.ts`** (barrel — starts empty; filled in as modules land in Task 2 and Task 8)
```ts
export {};
```

- [ ] **Step 6: Create the smoke test `packages/tool-broker/src/smoke.test.ts`**
```ts
import { describe, it, expect } from 'vitest';

describe('tool-broker package', () => {
  it('runs vitest', () => {
    expect(1 + 1).toBe(2);
  });
});
```

- [ ] **Step 7: Install**

Run (repo root): `pnpm install`
Expected: `@shannon/tool-broker` linked into the workspace; vitest available.

- [ ] **Step 8: Run the smoke test**

Run: `pnpm --filter @shannon/tool-broker test`
Expected: PASS — 1 test.

- [ ] **Step 9: Commit**
```bash
git add packages/tool-broker pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "feat(tool-broker): scaffold @shannon/tool-broker package with vitest"
```

---

## Task 2: Broker contract types

**Files:**
- Create: `packages/tool-broker/src/types.ts`

- [ ] **Step 1: Create `packages/tool-broker/src/types.ts`**
```ts
// The pure data contract shared across the broker core. No behavior here.

export type ScopeDecisionReason =
  | 'in-scope'
  | 'out-of-scope-host'
  | 'denied-private'
  | 'denied-metadata'
  | 'denied-loopback'
  | 'denied-link-local'
  | 'path-not-allowed'
  | 'path-avoided';

export interface ScopeDecision {
  allowed: boolean;
  reason: ScopeDecisionReason;
  detail?: string;
}

export interface ScopeConfig {
  targetHost: string; // always in-scope by host
  targetIps: string[]; // IPs pinned at scan start (always in-scope)
  allowlistCidrs: string[]; // extra in-scope IPv4 CIDRs
  allowPrivateCidrs: string[]; // explicit re-allow of otherwise-denied private ranges
  focusPaths: string[]; // glob/prefix; empty array = all paths allowed
  avoidPaths: string[]; // glob/prefix; takes precedence over focus
}

export interface ToolParamSpec {
  name: string; // logical param name (key in ToolRequest.params)
  flag?: string; // CLI flag, e.g. '-u'. Omit for a positional arg.
  required?: boolean;
  pattern?: string; // RegExp source the value must fully match
  enumValues?: string[]; // if set, value must be one of these
}

export interface ToolDescriptor {
  id: string;
  bin: string; // pinned binary name
  params: ToolParamSpec[]; // ALLOWLIST — only these params may be supplied
  blocklist: string[]; // tokens that must never appear in the final argv
  oobRequired?: boolean;
}

export interface ToolRequest {
  tool: string;
  params: Record<string, string | number>;
  scanId: string;
  scopeToken: string; // signed scope-lock token; broker verifies before acting
}

export type ToolStatus =
  | 'success'
  | 'blocked'
  | 'rate-limited'
  | 'error'
  | 'timeout'
  | 'budget'
  | 'scope'
  | 'oob-blocked'
  | 'auth-expired';

export interface ToolResult {
  tool: string;
  status: ToolStatus;
  argv?: string[];
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  durationMs?: number;
  oobHits?: string[];
  rawArtifactRef?: string;
}

export interface InvocationRecord {
  scanId: string;
  tool: string;
  argvHash: string; // sha256 of the argv array
  status: ToolStatus;
  exitCode?: number;
  durationMs?: number;
  timestamp: string; // ISO; passed in (no Date.now in pure core)
  signature: string; // HMAC-SHA256 over the canonical record body
}

export type BudgetKind = 'toolInvocations' | 'httpRequests' | 'wallClockMs' | 'costUsd';
```

- [ ] **Step 2: Verify**

Run: `pnpm --filter @shannon/tool-broker typecheck`
Expected: exit 0.
Run: `pnpm --filter @shannon/tool-broker test`
Expected: PASS (smoke still green). The barrel `index.ts` stays empty until Task 8 populates the public surface.

- [ ] **Step 3: Commit**
```bash
git add packages/tool-broker/src/types.ts
git commit -m "feat(tool-broker): core contract types (scope/tool/result/record)"
```

---

## Task 3: IPv4 parsing + CIDR containment

**Files:**
- Create: `packages/tool-broker/src/scope/ip.ts`, `packages/tool-broker/src/scope/ip.test.ts`

- [ ] **Step 1: Write the failing test `packages/tool-broker/src/scope/ip.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { ipv4ToInt, ipInCidr, isPrivateOrSpecial } from './ip.js';

describe('ipv4ToInt', () => {
  it('parses dotted-quad to a 32-bit int', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0);
    expect(ipv4ToInt('255.255.255.255')).toBe(0xffffffff);
    expect(ipv4ToInt('10.0.0.1')).toBe(0x0a000001);
  });
  it('returns null for malformed input', () => {
    expect(ipv4ToInt('256.0.0.1')).toBeNull();
    expect(ipv4ToInt('10.0.0')).toBeNull();
  });
});

describe('ipInCidr', () => {
  it('matches addresses inside the block', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(ipInCidr('192.168.1.5', '192.168.1.0/24')).toBe(true);
  });
  it('rejects addresses outside the block', () => {
    expect(ipInCidr('11.0.0.1', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('192.168.2.5', '192.168.1.0/24')).toBe(false);
  });
  it('/32 matches only the exact host', () => {
    expect(ipInCidr('1.2.3.4', '1.2.3.4/32')).toBe(true);
    expect(ipInCidr('1.2.3.5', '1.2.3.4/32')).toBe(false);
  });
});

describe('isPrivateOrSpecial', () => {
  it('flags RFC1918, loopback, link-local, and cloud metadata', () => {
    expect(isPrivateOrSpecial('10.0.0.1')).toBe('private');
    expect(isPrivateOrSpecial('172.16.5.5')).toBe('private');
    expect(isPrivateOrSpecial('192.168.0.9')).toBe('private');
    expect(isPrivateOrSpecial('127.0.0.1')).toBe('loopback');
    expect(isPrivateOrSpecial('169.254.169.254')).toBe('metadata');
    expect(isPrivateOrSpecial('169.254.1.1')).toBe('link-local');
  });
  it('returns null for normal public IPs', () => {
    expect(isPrivateOrSpecial('93.184.216.34')).toBeNull();
  });
});
```

- [ ] **Step 2: Run — expect FAIL** (`./ip.js` missing). `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/scope/ip.ts`**
```ts
export type SpecialKind = 'private' | 'loopback' | 'link-local' | 'metadata';

export function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((p) => p > 255)) return null;
  // >>> 0 keeps it an unsigned 32-bit int
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const m = /^(.+)\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const base = ipv4ToInt(m[1]);
  const ipInt = ipv4ToInt(ip);
  if (base === null || ipInt === null) return false;
  const prefix = Number(m[2]);
  if (prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

// Cloud metadata is checked BEFORE link-local because 169.254.169.254 is itself
// link-local — callers that block metadata specifically need the precise reason.
const METADATA_IPS = ['169.254.169.254', '100.100.200.200'];

export function isPrivateOrSpecial(ip: string): SpecialKind | null {
  if (METADATA_IPS.includes(ip)) return 'metadata';
  if (ipInCidr(ip, '127.0.0.0/8')) return 'loopback';
  if (ipInCidr(ip, '169.254.0.0/16')) return 'link-local';
  if (ipInCidr(ip, '10.0.0.0/8') || ipInCidr(ip, '172.16.0.0/12') || ipInCidr(ip, '192.168.0.0/16')) {
    return 'private';
  }
  return null;
}
```

- [ ] **Step 4: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 5: Commit**
```bash
git add packages/tool-broker/src/scope/ip.ts packages/tool-broker/src/scope/ip.test.ts
git commit -m "feat(tool-broker): IPv4 parsing + CIDR containment + private/metadata classification"
```

---

## Task 4: ScopeEnforcer (the primary safety control)

**Files:**
- Create: `packages/tool-broker/src/scope/path-match.ts` (enforcement path matcher), `packages/tool-broker/src/scope/enforcer.ts`, `packages/tool-broker/src/scope/enforcer.test.ts`

- [ ] **Step 1: Create the path matcher `packages/tool-broker/src/scope/path-match.ts`** (same semantics as Phase 0's `scope-rules.ts`, owned by the enforcer)
```ts
// "re:<pattern>" → RegExp; contains * or ? → glob (* within segment, ** any depth);
// otherwise → prefix. Mirrors worker config/scope-rules.ts for enforcement use.
export function matchesPath(rule: string, path: string): boolean {
  if (rule.startsWith('re:')) return new RegExp(rule.slice(3)).test(path);
  if (rule.includes('*') || rule.includes('?')) return globToRegExp(rule).test(path);
  return path.startsWith(rule);
}

function globToRegExp(glob: string): RegExp {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else {
        re += '[^/]*';
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
```

- [ ] **Step 2: Write the failing test `packages/tool-broker/src/scope/enforcer.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { ScopeEnforcer } from './enforcer.js';
import type { ScopeConfig } from '../types.js';

const cfg: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: ['203.0.113.0/24'],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: ['/logout'],
};

describe('ScopeEnforcer.evaluate', () => {
  const e = new ScopeEnforcer(cfg);

  it('allows the pinned target IP', () => {
    expect(e.evaluate('93.184.216.34', '/api/users').allowed).toBe(true);
  });
  it('allows an allowlisted CIDR', () => {
    expect(e.evaluate('203.0.113.7', '/').allowed).toBe(true);
  });
  it('hard-blocks cloud metadata even if someone allowlists nothing', () => {
    const d = e.evaluate('169.254.169.254', '/latest/meta-data/');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('denied-metadata');
  });
  it('hard-blocks RFC1918 and loopback by default', () => {
    expect(e.evaluate('10.1.2.3', '/').reason).toBe('denied-private');
    expect(e.evaluate('127.0.0.1', '/').reason).toBe('denied-loopback');
  });
  it('blocks an out-of-scope public IP', () => {
    const d = e.evaluate('8.8.8.8', '/');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('out-of-scope-host');
  });
  it('honours avoidPaths even for an in-scope IP', () => {
    const d = e.evaluate('93.184.216.34', '/logout');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('path-avoided');
  });
  it('re-allows a private CIDR only when explicitly opted in', () => {
    const e2 = new ScopeEnforcer({ ...cfg, allowPrivateCidrs: ['10.0.0.0/8'] });
    expect(e2.evaluate('10.1.2.3', '/').allowed).toBe(true);
  });
  it('enforces focusPaths when set (deny anything not matching)', () => {
    const e3 = new ScopeEnforcer({ ...cfg, focusPaths: ['/api/'] });
    expect(e3.evaluate('93.184.216.34', '/api/users').allowed).toBe(true);
    expect(e3.evaluate('93.184.216.34', '/admin').reason).toBe('path-not-allowed');
  });
});
```

- [ ] **Step 3: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 4: Implement `packages/tool-broker/src/scope/enforcer.ts`**
```ts
import type { ScopeConfig, ScopeDecision } from '../types.js';
import { ipInCidr, isPrivateOrSpecial } from './ip.js';
import { matchesPath } from './path-match.js';

export class ScopeEnforcer {
  constructor(private readonly cfg: ScopeConfig) {}

  evaluate(ip: string, path: string): ScopeDecision {
    // 1) Hard denies first — these cannot be overridden except allowPrivateCidrs.
    const special = isPrivateOrSpecial(ip);
    if (special === 'metadata') return deny('denied-metadata', ip);
    if (special === 'loopback') return deny('denied-loopback', ip);
    if (special === 'link-local') return deny('denied-link-local', ip);
    if (special === 'private') {
      const reAllowed = this.cfg.allowPrivateCidrs.some((c) => ipInCidr(ip, c));
      if (!reAllowed) return deny('denied-private', ip);
    }

    // 2) Host scope — must be a pinned target IP or in an allowlisted CIDR
    //    (a re-allowed private IP from step 1 also counts as in-scope).
    const inScopeIp =
      this.cfg.targetIps.includes(ip) ||
      this.cfg.allowlistCidrs.some((c) => ipInCidr(ip, c)) ||
      this.cfg.allowPrivateCidrs.some((c) => ipInCidr(ip, c));
    if (!inScopeIp) return deny('out-of-scope-host', ip);

    // 3) Path rules — avoid wins over focus.
    if (this.cfg.avoidPaths.some((r) => matchesPath(r, path))) return deny('path-avoided', path);
    if (this.cfg.focusPaths.length > 0 && !this.cfg.focusPaths.some((r) => matchesPath(r, path))) {
      return deny('path-not-allowed', path);
    }

    return { allowed: true, reason: 'in-scope' };
  }
}

function deny(reason: ScopeDecision['reason'], detail: string): ScopeDecision {
  return { allowed: false, reason, detail };
}
```

- [ ] **Step 5: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 6: Commit**
```bash
git add packages/tool-broker/src/scope/path-match.ts packages/tool-broker/src/scope/enforcer.ts packages/tool-broker/src/scope/enforcer.test.ts
git commit -m "feat(tool-broker): ScopeEnforcer — baked-in denylist + allowlist + path rules"
```

---

## Task 5: Scope-lock — sign & verify the scope token

**Files:**
- Create: `packages/tool-broker/src/scope/lock.ts`, `packages/tool-broker/src/scope/lock.test.ts`

This is the negative-capability anchor: scope is authorized by a token signed at scan start over the canonical scope config. The broker verifies it on every request, so a prompt-injected LLM cannot widen scope (it cannot forge the signature).

- [ ] **Step 1: Write the failing test `packages/tool-broker/src/scope/lock.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { signScopeToken, verifyScopeToken } from './lock.js';
import type { ScopeConfig } from '../types.js';

const KEY = 'test-scan-secret-key';
const cfg: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: [],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: [],
};

describe('scope-lock', () => {
  it('verifies a token signed over the same config', () => {
    const token = signScopeToken(cfg, KEY);
    expect(verifyScopeToken(token, cfg, KEY)).toBe(true);
  });
  it('rejects when the scope config was tampered with', () => {
    const token = signScopeToken(cfg, KEY);
    const widened = { ...cfg, allowlistCidrs: ['0.0.0.0/0'] };
    expect(verifyScopeToken(token, widened, KEY)).toBe(false);
  });
  it('rejects a token signed with a different key', () => {
    const token = signScopeToken(cfg, KEY);
    expect(verifyScopeToken(token, cfg, 'other-key')).toBe(false);
  });
  it('rejects a garbage token without throwing', () => {
    expect(verifyScopeToken('not-a-token', cfg, KEY)).toBe(false);
  });
});
```

- [ ] **Step 2: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/scope/lock.ts`**
```ts
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ScopeConfig } from '../types.js';

// Canonical, key-sorted serialization so equivalent configs hash identically.
function canonical(cfg: ScopeConfig): string {
  return JSON.stringify({
    targetHost: cfg.targetHost,
    targetIps: [...cfg.targetIps].sort(),
    allowlistCidrs: [...cfg.allowlistCidrs].sort(),
    allowPrivateCidrs: [...cfg.allowPrivateCidrs].sort(),
    focusPaths: [...cfg.focusPaths].sort(),
    avoidPaths: [...cfg.avoidPaths].sort(),
  });
}

export function signScopeToken(cfg: ScopeConfig, key: string): string {
  return createHmac('sha256', key).update(canonical(cfg)).digest('hex');
}

export function verifyScopeToken(token: string, cfg: ScopeConfig, key: string): boolean {
  const expected = signScopeToken(cfg, key);
  const a = Buffer.from(token, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
```
(Phase 1a uses a symmetric per-scan key — simplest correct primitive. The spec's optional asymmetric `scopeLockPublicKey` is a Phase 1b enhancement; the API here stays the same.)

- [ ] **Step 4: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 5: Commit**
```bash
git add packages/tool-broker/src/scope/lock.ts packages/tool-broker/src/scope/lock.test.ts
git commit -m "feat(tool-broker): scope-lock HMAC sign/verify (negative-capability anchor)"
```

---

## Task 6: ToolRegistry — arg allowlist + argv builder + hard blocklist

**Files:**
- Create: `packages/tool-broker/src/registry/descriptors.ts`, `packages/tool-broker/src/registry/registry.ts`, `packages/tool-broker/src/registry/registry.test.ts`

This is the destructive-flag defense: the broker only ever assembles an argv from declared, validated params, as an array (never a shell string). `--os-shell` etc. are unreachable by construction.

- [ ] **Step 1: Create descriptors `packages/tool-broker/src/registry/descriptors.ts`**
```ts
import type { ToolDescriptor } from '../types.js';

// Minimal Phase-1a descriptors. Phase 1b expands params per tool as classes land.
export const DESCRIPTORS: ToolDescriptor[] = [
  {
    id: 'sqlmap',
    bin: 'sqlmap',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      { name: 'level', flag: '--level', enumValues: ['1', '2', '3'] },
      { name: 'risk', flag: '--risk', enumValues: ['1', '2'] },
    ],
    blocklist: [
      '--os-shell', '--os-pwn', '--os-cmd', '--file-read', '--file-write',
      '--priv-esc', '--second-url', '--dns-domain', '--eval', '--tamper',
    ],
  },
  {
    id: 'nuclei',
    bin: 'nuclei',
    params: [
      { name: 'target', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      { name: 'severity', flag: '-severity', pattern: '^[a-z,]+$' },
    ],
    blocklist: ['-code', '-headless', '-iserver', '-itoken', '-duc'],
  },
  {
    id: 'ffuf',
    bin: 'ffuf',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+FUZZ[^\\s]*$' },
      { name: 'wordlist', flag: '-w', required: true, pattern: '^[\\w./-]+$' },
      { name: 'rate', flag: '-rate', pattern: '^\\d{1,3}$' },
    ],
    blocklist: ['-x', '-input-cmd'],
  },
  {
    id: 'sstimap',
    bin: 'sstimap',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      // Phase 1a allows only a fixed, server-side proof command set (no free-form).
      { name: 'osCmd', flag: '--os-cmd', enumValues: ['id', 'whoami', 'hostname'] },
    ],
    blocklist: ['--os-shell', '--upload', '--download', '--force-overwrite'],
  },
];
```

- [ ] **Step 2: Write the failing test `packages/tool-broker/src/registry/registry.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { ToolRegistry } from './registry.js';
import { DESCRIPTORS } from './descriptors.js';

const reg = new ToolRegistry(DESCRIPTORS);

describe('ToolRegistry.buildArgv', () => {
  it('builds a valid argv for an allowlisted tool + params', () => {
    const argv = reg.buildArgv('sqlmap', { url: 'https://app.example.com/p?id=1', level: '2' });
    expect(argv).toEqual(['sqlmap', '-u', 'https://app.example.com/p?id=1', '--level', '2']);
  });
  it('rejects an unknown tool', () => {
    expect(() => reg.buildArgv('metasploit', {})).toThrow(/unknown tool/i);
  });
  it('rejects an undeclared param (allowlist)', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y', osShell: 'true' })).toThrow(/not allowed/i);
  });
  it('rejects a value failing its pattern', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'file:///etc/passwd' })).toThrow(/invalid value/i);
  });
  it('rejects a value outside its enum', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y', level: '9' })).toThrow(/invalid value/i);
  });
  it('rejects a missing required param', () => {
    expect(() => reg.buildArgv('sqlmap', { level: '1' })).toThrow(/required/i);
  });
  it('rejects shell metacharacters in any value', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y;rm -rf /' })).toThrow(/invalid value/i);
  });
  it('a blocklisted token can never be produced — it is not even a declared param', () => {
    // --os-shell is not a param name, so supplying it is an undeclared-param rejection.
    expect(() => reg.buildArgv('sqlmap', { '--os-shell': '1' })).toThrow(/not allowed/i);
    // and the descriptor blocklist is asserted to contain it
    expect(reg.descriptor('sqlmap').blocklist).toContain('--os-shell');
  });
});
```

- [ ] **Step 3: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 4: Implement `packages/tool-broker/src/registry/registry.ts`**
```ts
import type { ToolDescriptor } from '../types.js';

// Any value containing a shell metacharacter is rejected outright. argv is always
// an array (execFile, never a shell), but this is defense-in-depth.
const SHELL_METACHARS = /[$`;|&><\n\r]/;

export class ToolRegistry {
  private readonly byId: Map<string, ToolDescriptor>;

  constructor(descriptors: ToolDescriptor[]) {
    this.byId = new Map(descriptors.map((d) => [d.id, d]));
  }

  descriptor(toolId: string): ToolDescriptor {
    const d = this.byId.get(toolId);
    if (!d) throw new Error(`Unknown tool: ${toolId}`);
    return d;
  }

  buildArgv(toolId: string, params: Record<string, string | number>): string[] {
    const d = this.descriptor(toolId);
    const allowed = new Set(d.params.map((p) => p.name));

    for (const key of Object.keys(params)) {
      if (!allowed.has(key)) throw new Error(`Param not allowed for ${toolId}: ${key}`);
    }

    const argv: string[] = [d.bin];
    for (const spec of d.params) {
      const raw = params[spec.name];
      if (raw === undefined) {
        if (spec.required) throw new Error(`Missing required param for ${toolId}: ${spec.name}`);
        continue;
      }
      const value = String(raw);
      if (SHELL_METACHARS.test(value)) {
        throw new Error(`Invalid value for ${spec.name}: shell metacharacter rejected`);
      }
      if (spec.enumValues && !spec.enumValues.includes(value)) {
        throw new Error(`Invalid value for ${spec.name}: not in [${spec.enumValues.join(', ')}]`);
      }
      if (spec.pattern && !new RegExp(`^(?:${spec.pattern})$`).test(value)) {
        throw new Error(`Invalid value for ${spec.name}: does not match pattern`);
      }
      if (spec.flag) argv.push(spec.flag);
      argv.push(value);
    }

    // Defense-in-depth: assert no blocklisted token ended up in the argv.
    for (const token of d.blocklist) {
      if (argv.includes(token)) throw new Error(`Blocklisted token in argv for ${toolId}: ${token}`);
    }
    return argv;
  }
}
```

- [ ] **Step 5: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 6: Commit**
```bash
git add packages/tool-broker/src/registry/descriptors.ts packages/tool-broker/src/registry/registry.ts packages/tool-broker/src/registry/registry.test.ts
git commit -m "feat(tool-broker): ToolRegistry arg-allowlist + argv builder + hard blocklist"
```

---

## Task 7: BudgetLedger — persisted atomic counters

**Files:**
- Create: `packages/tool-broker/src/budget/ledger.ts`, `packages/tool-broker/src/budget/ledger.test.ts`

- [ ] **Step 1: Write the failing test `packages/tool-broker/src/budget/ledger.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BudgetLedger } from './ledger.js';

function tmpFile(): string {
  return join(mkdtempSync(join(tmpdir(), 'broker-budget-')), 'budget.json');
}

describe('BudgetLedger', () => {
  it('consumes within budget and refuses past it', () => {
    const l = new BudgetLedger(tmpFile(), { toolInvocations: 2 });
    expect(l.tryConsume('toolInvocations', 1).ok).toBe(true);
    expect(l.tryConsume('toolInvocations', 1).ok).toBe(true);
    const third = l.tryConsume('toolInvocations', 1);
    expect(third.ok).toBe(false);
    expect(third.reason).toBe('budget');
  });

  it('treats an unset limit as unlimited', () => {
    const l = new BudgetLedger(tmpFile(), {});
    expect(l.tryConsume('httpRequests', 1000).ok).toBe(true);
  });

  it('persists spend across reopen (no reset)', () => {
    const f = tmpFile();
    const l1 = new BudgetLedger(f, { toolInvocations: 5 });
    l1.tryConsume('toolInvocations', 3);
    const l2 = new BudgetLedger(f, { toolInvocations: 5 });
    expect(l2.tryConsume('toolInvocations', 3).ok).toBe(false); // only 2 left
    expect(l2.tryConsume('toolInvocations', 2).ok).toBe(true);
  });
});
```

- [ ] **Step 2: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/budget/ledger.ts`**
```ts
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { BudgetKind } from '../types.js';

type Limits = Partial<Record<BudgetKind, number>>;
type Spent = Record<string, number>;

export interface ConsumeResult {
  ok: boolean;
  reason?: 'budget';
  remaining?: number;
}

// Synchronous (atomic in the single-threaded event loop, like the forensic store).
// Persists to a JSON file via temp-write + rename so a crash can't leave a partial.
export class BudgetLedger {
  private spent: Spent;

  constructor(
    private readonly path: string,
    private readonly limits: Limits,
  ) {
    this.spent = existsSync(path) ? (JSON.parse(readFileSync(path, 'utf-8')) as Spent) : {};
  }

  tryConsume(kind: BudgetKind, amount: number): ConsumeResult {
    const limit = this.limits[kind];
    const current = this.spent[kind] ?? 0;
    if (limit !== undefined && current + amount > limit) {
      return { ok: false, reason: 'budget', remaining: Math.max(0, limit - current) };
    }
    this.spent[kind] = current + amount;
    this.persist();
    return { ok: true, remaining: limit === undefined ? undefined : limit - this.spent[kind] };
  }

  private persist(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.spent));
    renameSync(tmp, this.path);
  }
}
```

- [ ] **Step 4: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 5: Commit**
```bash
git add packages/tool-broker/src/budget/ledger.ts packages/tool-broker/src/budget/ledger.test.ts
git commit -m "feat(tool-broker): persisted atomic BudgetLedger"
```

---

## Task 8: Signed InvocationRecord + secrets redaction

**Files:**
- Create: `packages/tool-broker/src/forensic/invocation-record.ts` + test
- Create: `packages/tool-broker/src/secrets/redact.ts` + test
- Modify: `packages/tool-broker/src/index.ts` (export the public surface)

- [ ] **Step 1: Write the failing tests**

`packages/tool-broker/src/forensic/invocation-record.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { buildInvocationRecord, verifyInvocationRecord } from './invocation-record.js';

const KEY = 'scan-key';
const TS = '2026-06-04T00:00:00.000Z';

describe('InvocationRecord', () => {
  it('builds a signed record that verifies', () => {
    const rec = buildInvocationRecord(
      { scanId: 's1', tool: 'sqlmap', argv: ['sqlmap', '-u', 'https://x/y'], status: 'success', exitCode: 0, durationMs: 12, timestamp: TS },
      KEY,
    );
    expect(rec.argvHash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyInvocationRecord(rec, KEY)).toBe(true);
  });
  it('fails verification if any field is tampered', () => {
    const rec = buildInvocationRecord(
      { scanId: 's1', tool: 'sqlmap', argv: ['sqlmap'], status: 'success', timestamp: TS },
      KEY,
    );
    expect(verifyInvocationRecord({ ...rec, status: 'blocked' }, KEY)).toBe(false);
  });
});
```

`packages/tool-broker/src/secrets/redact.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { redact } from './redact.js';

describe('redact', () => {
  it('masks AWS access keys and secret keys', () => {
    expect(redact('key=AKIAIOSFODNN7EXAMPLE')).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toContain('[REDACTED]');
  });
  it('masks bearer tokens and authorization headers', () => {
    const out = redact('Authorization: Bearer abcdef123456ghijkl');
    expect(out).not.toContain('abcdef123456ghijkl');
  });
  it('masks the cloud metadata credentials path marker', () => {
    expect(redact('GET /latest/meta-data/iam/security-credentials/role')).toContain('[REDACTED]');
  });
  it('leaves ordinary text untouched', () => {
    expect(redact('the quick brown fox')).toBe('the quick brown fox');
  });
});
```

- [ ] **Step 2: Run — expect FAIL.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 3: Implement `packages/tool-broker/src/forensic/invocation-record.ts`**
```ts
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { InvocationRecord, ToolStatus } from '../types.js';

export interface InvocationInput {
  scanId: string;
  tool: string;
  argv: string[];
  status: ToolStatus;
  exitCode?: number;
  durationMs?: number;
  timestamp: string; // ISO; supplied by caller (pure core: no clock)
}

function bodyToSign(rec: Omit<InvocationRecord, 'signature'>): string {
  return JSON.stringify({
    scanId: rec.scanId,
    tool: rec.tool,
    argvHash: rec.argvHash,
    status: rec.status,
    exitCode: rec.exitCode ?? null,
    durationMs: rec.durationMs ?? null,
    timestamp: rec.timestamp,
  });
}

export function buildInvocationRecord(input: InvocationInput, key: string): InvocationRecord {
  const argvHash = createHash('sha256').update(JSON.stringify(input.argv)).digest('hex');
  const unsigned: Omit<InvocationRecord, 'signature'> = {
    scanId: input.scanId,
    tool: input.tool,
    argvHash,
    status: input.status,
    exitCode: input.exitCode,
    durationMs: input.durationMs,
    timestamp: input.timestamp,
  };
  const signature = createHmac('sha256', key).update(bodyToSign(unsigned)).digest('hex');
  return { ...unsigned, signature };
}

export function verifyInvocationRecord(rec: InvocationRecord, key: string): boolean {
  const expected = createHmac('sha256', key).update(bodyToSign(rec)).digest('hex');
  const a = Buffer.from(rec.signature, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
```

- [ ] **Step 4: Implement `packages/tool-broker/src/secrets/redact.ts`**
```ts
// Strips high-confidence secret patterns before tool output enters any log,
// the forensic chain, or the LLM context. Conservative: only well-known shapes.
const PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g, // AWS access key id
  /aws_secret_access_key\s*[=:]\s*[^\s'"]+/gi,
  /(?:bearer\s+)[A-Za-z0-9._-]{12,}/gi, // bearer tokens
  /(authorization\s*:\s*)[^\s]+/gi, // auth headers
  /\/security-credentials\/[^\s'"]*/gi, // cloud metadata creds path
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
];

export function redact(text: string): string {
  let out = text;
  for (const re of PATTERNS) {
    out = out.replace(re, (match, p1?: string) =>
      typeof p1 === 'string' ? `${p1}[REDACTED]` : '[REDACTED]',
    );
  }
  return out;
}
```

- [ ] **Step 5: Update the barrel `packages/tool-broker/src/index.ts`**
```ts
export * from './types.js';
export { ScopeEnforcer } from './scope/enforcer.js';
export { matchesPath } from './scope/path-match.js';
export { ipInCidr, ipv4ToInt, isPrivateOrSpecial } from './scope/ip.js';
export { signScopeToken, verifyScopeToken } from './scope/lock.js';
export { ToolRegistry } from './registry/registry.js';
export { DESCRIPTORS } from './registry/descriptors.js';
export { BudgetLedger } from './budget/ledger.js';
export { buildInvocationRecord, verifyInvocationRecord } from './forensic/invocation-record.js';
export { redact } from './secrets/redact.js';
```

- [ ] **Step 6: Run — expect PASS.** `pnpm --filter @shannon/tool-broker test`

- [ ] **Step 7: Commit**
```bash
git add packages/tool-broker/src/forensic packages/tool-broker/src/secrets packages/tool-broker/src/index.ts
git commit -m "feat(tool-broker): signed InvocationRecord + secrets redaction; export public surface"
```

---

## Task 9: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full suite** — `pnpm --filter @shannon/tool-broker test` → all suites green.
- [ ] **Step 2: Typecheck** — `pnpm --filter @shannon/tool-broker typecheck` → exit 0.
- [ ] **Step 3: Worker still green** (workspace change) — `pnpm --filter @shannon/worker test` → still passes; `pnpm --filter @shannon/worker typecheck` → exit 0.
- [ ] **Step 4: Lint authored files** — `npx biome check --write packages/tool-broker/src` then re-run the broker suite; commit any formatting:
```bash
git add -A && git commit -m "style(tool-broker): biome format Phase 1a files" || echo "nothing to format"
```

---

## Done criteria
- `@shannon/tool-broker` package exists, in the workspace, vitest green.
- ScopeEnforcer hard-blocks metadata/RFC1918/loopback/link-local by default, honours allowlist CIDRs + pinned IPs + glob/avoid path rules, and re-allows private CIDRs only on explicit opt-in — proven by a test matrix.
- Scope-lock token sign/verify with tamper + wrong-key rejection (timing-safe).
- ToolRegistry makes destructive flags unreachable by construction (allowlist params + argv array + metachar rejection + blocklist assertion).
- BudgetLedger persists spend across reopen and refuses past-limit consumption.
- Signed InvocationRecord verifies and detects tampering; secrets redaction masks known credential shapes.
- Both packages typecheck clean and test green.

## Phase 1b (next plan — requires Docker daemon up)
The body around this brain: HTTP `BrokerAPI` (verifies scope-lock + budgets, dispatches to sandbox); `Sandbox` container runner (`--cap-drop=ALL`, read-only, egress-filtered, non-root, resource caps); `ForwardProxy` doing connect-time DNS resolution + IP pinning + per-request `ScopeEnforcer.evaluate`; `OutputNormalizer` parsers wired to real sqlmap/nuclei/ffuf output (golden files); worker-side `ToolClient` (HTTP) + DI wiring; `SessionProvider` (Playwright login → storageState); Temporal `runBrokerTool`/`runVerifyGate` activities + circuit breaker; reflected-first OOB then self-hosted interactsh. **Gate before any tool ships: the GPL legal sign-off.** Build it against the bundled vulnerable lab with the safety regression suite (incl. the negative-capability test) as the release gate.
