import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verifyInvocationRecord } from '../forensic/invocation-record.js';
import { signScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolDescriptor, ToolRequest } from '../types.js';

// IN-CLUSTER e2e: the broker running as its OWN container (not in-process). Proves the
// real deployment topology that nothing else covers — the broker receives a ToolRequest
// over HTTP, spawns a hardened sandbox container via the MOUNTED DOCKER SOCKET, runs the
// in-house prober against the real SSTI lab on a shared network, normalizes, and returns
// an HMAC-signed InvocationRecord the caller verifies. Also proves an out-of-scope token
// is rejected by the containerized broker. Opt-in (costs nothing but needs Docker + images).
//
// Run with:
//   SHANNON_LIVE_E2E=1 pnpm --filter @shannon/tool-broker exec vitest run src/api/broker-container.e2e.test.ts
// Requires pre-built images: shannon-tool-broker:local, shannon-lab-ssti:local, shannon-ssti-probe:local.

function docker(args: string[]): string {
  return execFileSync('docker', args, { stdio: 'pipe' }).toString();
}
function dockerOk(): boolean {
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

const BROKER_IMAGE = 'shannon-tool-broker:local';
const LAB_IMAGE = 'shannon-lab-ssti:local';
const PROBE_IMAGE = 'shannon-ssti-probe:local';
const ENABLED =
  process.env.SHANNON_LIVE_E2E === '1' &&
  dockerOk() &&
  imageExists(BROKER_IMAGE) &&
  imageExists(LAB_IMAGE) &&
  imageExists(PROBE_IMAGE);

const NET = 'shannon-cluster-net';
const LAB = 'shannon-cluster-lab';
const BROKER = 'shannon-cluster-broker';
const HOST_PORT = '18443';
const BASE = `http://localhost:${HOST_PORT}`;

const SCOPE_KEY = 'cluster-scope-key';
const RECORD_KEY = 'cluster-record-key';

// Lab-only descriptor for the in-house prober, registered into the containerized broker
// via SHANNON_EXTRA_DESCRIPTORS (kept out of the shipped DESCRIPTORS by design).
const PROBE_DESCRIPTOR: ToolDescriptor = {
  id: 'ssti-probe',
  bin: 'ssti-probe',
  params: [{ name: 'url', required: true, pattern: '^https?://[^\\s]*INJECT[^\\s]*$' }],
  blocklist: [],
};

async function waitForHealth(timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((res) => setTimeout(res, 500));
  }
  return false;
}

describe.skipIf(!ENABLED)(
  'in-cluster e2e: containerized broker exploits the SSTI lab via the mounted docker socket',
  () => {
    let scope: ScopeConfig;

    beforeAll(async () => {
      for (const c of [BROKER, LAB]) {
        try {
          docker(['rm', '-f', c]);
        } catch {
          /* not running */
        }
      }
      try {
        docker(['network', 'create', NET]);
      } catch {
        /* exists */
      }

      // Lab on the shared network; wait until healthy, then capture its docker IP.
      docker(['run', '-d', '--name', LAB, '--network', NET, LAB_IMAGE]);
      let labIp = '';
      for (let i = 0; i < 30; i++) {
        try {
          const status = docker(['inspect', '-f', '{{.State.Health.Status}}', LAB]).trim();
          if (status === 'healthy') break;
        } catch {
          /* not ready */
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      labIp = docker(['inspect', '-f', `{{(index .NetworkSettings.Networks "${NET}").IPAddress}}`, LAB]).trim();
      if (!labIp) throw new Error('could not determine lab IP');

      // The lab IP is private; the enforcer denies private ranges unless re-allowed — mirror
      // an operator opting the lab CIDR into scope. The SAME scope is signed AND handed to the
      // broker via env, so the scope-lock canonical forms match.
      scope = {
        targetHost: LAB,
        targetIps: [labIp],
        allowlistCidrs: [],
        allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        focusPaths: [],
        avoidPaths: [],
      };

      // Launch the broker as a container: host docker socket mounted so its Sandbox can
      // spawn per-tool containers; scope/keys/scan-net/tool-images/extra-descriptors via env.
      docker([
        'run',
        '-d',
        '--name',
        BROKER,
        '-p',
        `${HOST_PORT}:8443`,
        '-v',
        '/var/run/docker.sock:/var/run/docker.sock',
        '-e',
        'BROKER_PORT=8443',
        '-e',
        `SHANNON_BROKER_SCOPE=${JSON.stringify(scope)}`,
        '-e',
        `SHANNON_BROKER_SCOPE_KEY=${SCOPE_KEY}`,
        '-e',
        `SHANNON_BROKER_RECORD_KEY=${RECORD_KEY}`,
        '-e',
        `SHANNON_SCAN_NET=${NET}`,
        '-e',
        `SHANNON_TOOL_IMAGES=${JSON.stringify({ 'ssti-probe': PROBE_IMAGE })}`,
        '-e',
        `SHANNON_EXTRA_DESCRIPTORS=${JSON.stringify([PROBE_DESCRIPTOR])}`,
        BROKER_IMAGE,
      ]);

      const healthy = await waitForHealth(20_000);
      if (!healthy) {
        let logs = '';
        try {
          logs = docker(['logs', BROKER]);
        } catch {
          /* ignore */
        }
        throw new Error(`broker container never became healthy. logs:\n${logs}`);
      }
    }, 120_000);

    afterAll(() => {
      for (const c of [BROKER, LAB]) {
        try {
          docker(['rm', '-f', c]);
        } catch {
          /* ignore */
        }
      }
      try {
        docker(['network', 'rm', NET]);
      } catch {
        /* ignore */
      }
    });

    function post(req: ToolRequest) {
      return fetch(`${BASE}/tool`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(req),
      }).then((r) => r.json());
    }

    it('runs the prober in a socket-spawned sandbox and returns a verified SSTI finding', async () => {
      const req: ToolRequest = {
        tool: 'ssti-probe',
        params: { url: `http://${LAB}:5000/?name=INJECT` },
        scanId: 'cluster',
        scopeToken: signScopeToken(scope, SCOPE_KEY),
      };
      const res = await post(req);

      expect(res.result.status).toBe('success');
      expect(res.findings.length).toBeGreaterThan(0);
      expect(res.findings[0].detail).toContain('SSTI');
      expect(res.findings[0].severity).toBe('critical');
      // The record is signed by the containerized broker and verifies under the shared key.
      expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
    }, 60_000);

    it('rejects a token signed under the wrong key (scope-lock holds over the wire)', async () => {
      const req: ToolRequest = {
        tool: 'ssti-probe',
        params: { url: `http://${LAB}:5000/?name=INJECT` },
        scanId: 'cluster',
        scopeToken: signScopeToken(scope, 'attacker-guessed-key'),
      };
      const res = await post(req);

      expect(res.result.status).toBe('scope');
      expect(res.findings).toEqual([]);
      expect(verifyInvocationRecord(res.record, RECORD_KEY)).toBe(true);
    }, 30_000);
  },
);
