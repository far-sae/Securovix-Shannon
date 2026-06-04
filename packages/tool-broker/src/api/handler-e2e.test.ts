import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BudgetLedger } from '../budget/ledger.js';
import { runInSandbox } from '../exec/sandbox.js';
import { verifyInvocationRecord } from '../forensic/invocation-record.js';
import { normalizeNucleiJsonl } from '../normalize/normalizer.js';
import { ToolRegistry } from '../registry/registry.js';
import { ScopeEnforcer } from '../scope/enforcer.js';
import { signScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolDescriptor, ToolRequest } from '../types.js';
import { createBrokerHandler } from './handler.js';

function docker(args: string[]): string {
  return execFileSync('docker', args, { stdio: 'pipe' }).toString();
}
function ok(): boolean {
  try {
    docker(['version', '--format', '{{.Server.Version}}']);
    return true;
  } catch {
    return false;
  }
}
function imageExists(ref: string): boolean {
  try {
    docker(['image', 'inspect', ref]);
    return true;
  } catch {
    return false;
  }
}

const LAB_IMAGE = 'shannon-lab-ssti:local';
const PROBE_IMAGE = 'shannon-ssti-probe:local';
// Requires Docker + both locally-built images (lab/ssti-app and lab/ssti-probe). Skips otherwise.
const ENABLED = ok() && imageExists(LAB_IMAGE) && imageExists(PROBE_IMAGE);
const NET = 'shannon-mvp-net';
const LAB = 'shannon-mvp-lab';

const SCOPE_KEY = 'scope-key';
const RECORD_KEY = 'record-key';

// Lab-only descriptor for the in-house prober (kept out of the shipped registry).
const PROBE_DESCRIPTOR: ToolDescriptor = {
  id: 'ssti-probe',
  bin: 'ssti-probe',
  params: [{ name: 'url', required: true, pattern: '^https?://[^\\s]*INJECT[^\\s]*$' }],
  blocklist: [],
};

describe.skipIf(!ENABLED)('MVP e2e: full broker pipeline exploits the SSTI lab with an in-house tool', () => {
  let labIp = '';

  beforeAll(async () => {
    try {
      docker(['network', 'create', NET]);
    } catch {
      /* exists */
    }
    try {
      docker(['rm', '-f', LAB]);
    } catch {
      /* not running */
    }
    docker(['run', '-d', '--name', LAB, '--network', NET, LAB_IMAGE]);
    for (let i = 0; i < 30; i++) {
      let status = '';
      try {
        status = docker(['inspect', '-f', '{{.State.Health.Status}}', LAB]).trim();
      } catch {
        /* not ready */
      }
      if (status === 'healthy') break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    labIp = docker(['inspect', '-f', `{{(index .NetworkSettings.Networks "${NET}").IPAddress}}`, LAB]).trim();
    if (!labIp) throw new Error('could not determine lab IP');
  }, 90_000);

  afterAll(() => {
    try {
      docker(['rm', '-f', LAB]);
    } catch {
      /* ignore */
    }
    try {
      docker(['network', 'rm', NET]);
    } catch {
      /* ignore */
    }
  });

  // scopeTargetIp is what the scan is scoped to; resolveIp is what the request actually
  // resolves to (defaults to in-scope). Passing a different resolveIp exercises the
  // out-of-scope block path.
  function makeHandler(scopeTargetIp: string, resolveIp: string = scopeTargetIp) {
    // The lab's docker IP is in a private range, which the enforcer denies unless
    // explicitly re-allowed — mirroring an operator opting a private CIDR into scope.
    const scope: ScopeConfig = {
      targetHost: LAB,
      targetIps: [scopeTargetIp],
      allowlistCidrs: [],
      allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      focusPaths: [],
      avoidPaths: [],
    };
    return {
      scope,
      handle: createBrokerHandler({
        authorize: {
          scopeConfig: scope,
          scopeKey: SCOPE_KEY,
          enforcer: new ScopeEnforcer(scope),
          registry: new ToolRegistry([PROBE_DESCRIPTOR]),
          ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'mvp-')), 'b.json'), { toolInvocations: 10 }),
        },
        recordKey: RECORD_KEY,
        resolveTarget: () => ({ ip: resolveIp, path: '/' }),
        execute: (argv) => runInSandbox(argv, { image: PROBE_IMAGE, network: NET }),
        now: () => '2026-06-04T00:00:00.000Z',
        normalize: (_tool, stdout) => normalizeNucleiJsonl(stdout),
      }),
    };
  }

  function req(scope: ScopeConfig): ToolRequest {
    return {
      tool: 'ssti-probe',
      params: { url: `http://${LAB}:5000/?name=INJECT` },
      scanId: 'mvp',
      scopeToken: signScopeToken(scope, SCOPE_KEY),
    };
  }

  it('runs the in-house prober through the full pipeline and returns a verified SSTI finding', async () => {
    const { scope, handle } = makeHandler(labIp);
    const res = await handle(req(scope));

    expect(res.result.status).toBe('success');
    expect(res.findings.length).toBeGreaterThan(0);
    expect(res.findings[0].detail).toContain('SSTI');
    expect(res.findings[0].severity).toBe('critical');
    // The signed InvocationRecord verifies under the worker's key — safe to chain.
    expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
  }, 60_000);

  it('blocks an out-of-scope target through the same pipeline (no execution, signed scope record)', async () => {
    const { scope, handle } = makeHandler(labIp, '8.8.8.8'); // scoped to lab, but resolves out of scope
    const res = await handle(req(scope));
    expect(res.result.status).toBe('scope');
    expect(res.findings).toEqual([]);
    expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
  }, 60_000);
});
