import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { runInSandbox } from './sandbox.js';

function dockerAvailable(): boolean {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const HAS_DOCKER = dockerAvailable();
const IMAGE = 'alpine:3.20';

// Real container integration tests — only run when a Docker daemon is reachable.
describe.skipIf(!HAS_DOCKER)('runInSandbox (integration, requires docker)', () => {
  it('runs an argv and captures stdout + exit code', async () => {
    const r = await runInSandbox(['echo', 'hello-sandbox'], { image: IMAGE });
    expect(r.stdout.trim()).toBe('hello-sandbox');
    expect(r.exitCode).toBe(0);
    expect(r.timedOut).toBe(false);
  }, 30_000);

  it('runs as a non-root user', async () => {
    const r = await runInSandbox(['id', '-u'], { image: IMAGE });
    expect(r.stdout.trim()).toBe('65534');
  }, 30_000);

  it('mounts the root filesystem read-only', async () => {
    const r = await runInSandbox(['sh', '-c', 'echo x > /rotest 2>/dev/null && echo WROTE || echo READONLY'], {
      image: IMAGE,
    });
    expect(r.stdout.trim()).toBe('READONLY');
  }, 30_000);

  it('has no network egress by default (--network none)', async () => {
    const r = await runInSandbox(
      ['sh', '-c', 'wget -T 2 -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo NET || echo NONET'],
      {
        image: IMAGE,
      },
    );
    expect(r.stdout.trim()).toBe('NONET');
  }, 30_000);

  it('enforces the wall-clock timeout and reports timedOut', async () => {
    const r = await runInSandbox(['sleep', '30'], { image: IMAGE, timeoutMs: 2_000 });
    expect(r.timedOut).toBe(true);
  }, 30_000);

  it('propagates a non-zero exit code', async () => {
    const r = await runInSandbox(['sh', '-c', 'exit 7'], { image: IMAGE });
    expect(r.exitCode).toBe(7);
  }, 30_000);
});
