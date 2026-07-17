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
export async function sandboxAvailable() {
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

const IMAGES = {
  python: { image: 'python:3-slim', cmd: ['python3', '-'] },
  node: { image: 'node:20-slim', cmd: ['node', '-'] },
};

export async function runInSandbox({ code, lang = 'python', input = '', timeoutSecs = 20 } = {}) {
  if (!(await sandboxAvailable()))
    return {
      ok: false,
      unavailable: true,
      stdout: '',
      stderr: 'Docker is not available on this host — the code sandbox needs it for isolation.',
    };
  const spec = IMAGES[lang] || IMAGES.python;
  const name = `sxsbx-${Math.random().toString(36).slice(2, 10)}`;
  const args = buildDockerArgs({
    image: spec.image,
    cmd: spec.cmd,
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
    p.on('close', (c) => finish({ ok: c === 0, code: c, stdout: out.slice(0, 200000), stderr: err.slice(0, 20000) }));
    try {
      p.stdin.write(String(code || ''));
      p.stdin.end();
    } catch {}
  });
}
