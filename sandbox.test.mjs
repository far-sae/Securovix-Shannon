// Tests for the hardened sandbox — the SECURITY flags are the thing that must never regress, so we
// assert every isolation flag is present in the docker argv.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildDockerArgs, sandboxImage } from './packages/dashboard/sandbox.mjs';

test('buildDockerArgs: every isolation flag is present (no silent weakening)', () => {
  const args = buildDockerArgs({ image: 'python:3-slim', cmd: ['python3', '-'], name: 'sx1' });
  const s = args.join(' ');
  assert.ok(/--network none/.test(s), 'network isolated');
  assert.ok(/--cap-drop ALL/.test(s), 'all capabilities dropped');
  assert.ok(/--security-opt no-new-privileges/.test(s), 'no privilege escalation');
  assert.ok(/--read-only/.test(s), 'read-only rootfs');
  assert.ok(/--tmpfs \/tmp:[^ ]*noexec/.test(s), 'tmp is noexec');
  assert.ok(/--user 65534:65534/.test(s), 'runs as non-root nobody');
  assert.ok(/--memory 256m/.test(s) && /--memory-swap 256m/.test(s), 'memory + swap capped (no swap escape)');
  assert.ok(/--pids-limit 128/.test(s), 'pids limited (fork-bomb guard)');
  assert.ok(/--cpus 0\.5/.test(s), 'cpu limited');
  assert.ok(s.endsWith('python:3-slim python3 -'), 'image + command come last');
});

test('buildDockerArgs: env is passed via -e (used to hand in the fetched response, base64)', () => {
  const args = buildDockerArgs({ image: 'x', cmd: ['sh'], env: { SX_INPUT: 'YWJj' } });
  const i = args.indexOf('-e');
  assert.ok(i > 0 && args[i + 1] === 'SX_INPUT=YWJj');
});

test('buildDockerArgs: --rm and interactive stdin so the container is ephemeral and fed the code', () => {
  const args = buildDockerArgs({ image: 'x', cmd: ['sh'] });
  assert.ok(args.includes('--rm') && args.includes('-i'));
});

test('sandboxImage: hosted SHANNON_SANDBOX_IMAGE wins; per-language public fallback otherwise', () => {
  const saved = process.env.SHANNON_SANDBOX_IMAGE;
  delete process.env.SHANNON_SANDBOX_IMAGE;
  assert.equal(sandboxImage('python'), 'python:3-slim');
  assert.equal(sandboxImage('node'), 'node:20-slim');
  process.env.SHANNON_SANDBOX_IMAGE = 'ghcr.io/me/shannon-sandbox:1';
  assert.equal(sandboxImage('python'), 'ghcr.io/me/shannon-sandbox:1', 'one hosted image serves both runtimes');
  assert.equal(sandboxImage('node'), 'ghcr.io/me/shannon-sandbox:1');
  if (saved === undefined) delete process.env.SHANNON_SANDBOX_IMAGE;
  else process.env.SHANNON_SANDBOX_IMAGE = saved;
});
