import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runInSandbox } from './sandbox.js';

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

const LAB_IMAGE = 'shannon-lab-ssti:local';
// Requires both Docker and the locally-built lab image (build: docker build -t
// shannon-lab-ssti:local lab/ssti-app). Skips cleanly otherwise.
const ENABLED = dockerOk() && imageExists(LAB_IMAGE);
const NET = 'shannon-e2e-net';
const LAB = 'shannon-e2e-lab';

describe.skipIf(!ENABLED)('e2e: exploit the SSTI lab through the hardened sandbox', () => {
  beforeAll(async () => {
    try {
      docker(['network', 'create', NET]);
    } catch {
      /* may already exist */
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
        /* container not ready */
      }
      if (status === 'healthy') return;
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error('lab container did not become healthy');
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

  it('a tool in the sandbox injects {{7*7}} and the lab returns the evaluated 49', async () => {
    const r = await runInSandbox(['wget', '-qO-', `http://${LAB}:5000/?name={{7*7}}`], {
      image: 'alpine:3.20',
      network: NET,
    });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Hello 49!');
  }, 60_000);

  it('the same tool CANNOT reach the lab when sandboxed with --network none (egress isolation)', async () => {
    const r = await runInSandbox(
      ['sh', '-c', `wget -T 3 -qO- http://${LAB}:5000/?name=x >/dev/null 2>&1 && echo REACHED || echo ISOLATED`],
      { image: 'alpine:3.20' }, // default network 'none'
    );
    expect(r.stdout.trim()).toBe('ISOLATED');
  }, 60_000);
});
