// HARDENED CODE SANDBOX — run LLM-authored (or user) analysis code SAFELY. Arbitrary code execution is
// only safe with real isolation, so this runs in an ephemeral Docker container locked down hard:
//   --network none      (no egress — can't reach internal hosts / metadata / anywhere)
//   --cap-drop=ALL + --security-opt=no-new-privileges   (no Linux capabilities, no privilege escalation)
//   --read-only + tmpfs /tmp (noexec)                    (immutable rootfs)
//   --user 65534 (nobody)                                (non-root)
//   --memory / --cpus / --pids-limit + a hard timeout    (resource-bounded; killed on overrun)
// The code receives the target response Shannon already fetched (SSRF-guarded) as SX_INPUT and prints a
// result to stdout — it never makes its own requests. Docker-gated: unavailable → returns cleanly.
// (True network-scoped exploit execution belongs in the tool-broker, which adds a scope-enforced proxy.)

import { spawn } from 'node:child_process';

// Pure: build the hardened `docker run` argv. Kept separate so the security flags are unit-tested and
// can never silently regress.
export function buildDockerArgs({ image, cmd = [], name, memory = '256m', cpus = '0.5', pids = 128, env = {} } = {}) {
  const args = [
    'run',
    '--rm',
    '-i',
    '--network',
    'none',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--read-only',
    '--tmpfs',
    '/tmp:rw,size=32m,noexec,nosuid',
    '--user',
    '65534:65534',
    '--memory',
    memory,
    '--memory-swap',
    memory,
    '--cpus',
    String(cpus),
    '--pids-limit',
    String(pids),
  ];
  if (name) args.push('--name', name);
  for (const [k, v] of Object.entries(env)) args.push('-e', `${k}=${v}`);
  args.push(image, ...cmd);
  return args;
}

let _dockerOk = null;
const RUNNER_URL = String(process.env.SHANNON_SANDBOX_RUNNER_URL || '').replace(/\/$/, '');
const RUNNER_TOKEN = String(process.env.SHANNON_SANDBOX_RUNNER_TOKEN || '');

function remoteRunnerConfigured() {
  if (!RUNNER_URL) return false;
  try {
    const url = new URL(RUNNER_URL);
    // A production runner carries untrusted code, so never send it over cleartext HTTP.
    return url.protocol === 'https:' && RUNNER_TOKEN.length >= 32;
  } catch {
    return false;
  }
}

async function runnerRequest(path, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetch(`${RUNNER_URL}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${RUNNER_TOKEN}`, ...(init.headers || {}) },
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Sandbox runner returned ${response.status}`);
    return body;
  } finally {
    clearTimeout(timer);
  }
}

export async function sandboxAvailable() {
  if (remoteRunnerConfigured()) {
    try {
      const status = await runnerRequest('/health');
      return status.ok === true && status.docker === true;
    } catch {
      return false;
    }
  }
  if (_dockerOk !== null) return _dockerOk;
  _dockerOk = await new Promise((res) => {
    try {
      const p = spawn('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'ignore' });
      p.on('error', () => res(false));
      p.on('close', (c) => res(c === 0));
    } catch {
      res(false);
    }
  });
  return _dockerOk;
}

const CMDS = { python: ['python3', '-'], node: ['node', '-'] };

// The sandbox image. A single HOSTED image (SHANNON_SANDBOX_IMAGE — build it from
// packages/dashboard/sandbox/Dockerfile) can carry BOTH runtimes + offline analysis libs; otherwise
// fall back to the public slim image per language so it still works out of the box.
export function sandboxImage(lang = 'python') {
  return process.env.SHANNON_SANDBOX_IMAGE || (lang === 'node' ? 'node:20-slim' : 'python:3-slim');
}

export async function runInSandbox({ code, lang = 'python', input = '', timeoutSecs = 20 } = {}) {
  if (remoteRunnerConfigured()) {
    try {
      return await runnerRequest('/v1/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code, lang, input, timeoutSecs }),
      });
    } catch (error) {
      return { ok: false, unavailable: true, stdout: '', stderr: `Sandbox runner unavailable: ${error.message}` };
    }
  }
  if (!(await sandboxAvailable()))
    return {
      ok: false,
      unavailable: true,
      stdout: '',
      stderr: 'Docker is not available on this host — the code sandbox needs it for isolation.',
    };
  const cmd = CMDS[lang] || CMDS.python;
  const image = sandboxImage(lang);
  const name = `sxsbx-${Math.random().toString(36).slice(2, 10)}`;
  const args = buildDockerArgs({
    image,
    cmd,
    name,
    env: { SX_INPUT: Buffer.from(String(input || '')).toString('base64') },
  });
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(v);
    };
    const timer = setTimeout(
      () => {
        try {
          spawn('docker', ['kill', name], { stdio: 'ignore' });
        } catch {}
        finish({ ok: false, timedOut: true, stdout: out.slice(0, 20000), stderr: 'sandbox timed out' });
      },
      (timeoutSecs + 5) * 1000,
    );
    let p;
    try {
      p = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      return finish({ ok: false, stdout: '', stderr: `docker spawn failed: ${e.message}` });
    }
    p.stdout.on('data', (d) => {
      if (out.length < 200000) out += d;
    });
    p.stderr.on('data', (d) => {
      if (err.length < 20000) err += d;
    });
    p.on('error', (e) => finish({ ok: false, stdout: '', stderr: `docker spawn failed: ${e.message}` }));
    p.on('close', (c) =>
      finish({ ok: c === 0, code: c, image, stdout: out.slice(0, 200000), stderr: err.slice(0, 20000) }),
    );
    try {
      p.stdin.write(String(code || ''));
      p.stdin.end();
    } catch {}
  });
}
