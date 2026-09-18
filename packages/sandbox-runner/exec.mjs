import { spawn } from 'node:child_process';

const IMAGES = {
  python: process.env.SHANNON_SANDBOX_PYTHON_IMAGE || 'python:3.12-slim',
  node: process.env.SHANNON_SANDBOX_NODE_IMAGE || 'node:20-bookworm-slim',
};
const COMMANDS = { python: ['python3', '-'], node: ['node', '-'] };

export function validateRunRequest(body = {}) {
  const lang = body.lang === 'node' ? 'node' : body.lang === 'python' ? 'python' : null;
  if (!lang) return { error: 'lang must be python or node' };
  const code = String(body.code || '');
  const input = String(body.input || '');
  if (!code || code.length > 65_536) return { error: 'code must be between 1 and 65536 characters' };
  if (input.length > 131_072) return { error: 'input exceeds 131072 characters' };
  // The runner owns this cap; callers cannot request unbounded execution.
  const timeoutSecs = Math.max(1, Math.min(20, Number(body.timeoutSecs) || 20));
  return { lang, code, input, timeoutSecs };
}

function dockerArgs({ lang, input, name }) {
  return [
    'run', '--rm', '-i', '--network', 'none', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--read-only',
    '--tmpfs', '/tmp:rw,size=32m,noexec,nosuid', '--user', '65534:65534',
    '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5', '--pids-limit', '128',
    '--name', name, '-e', `SX_INPUT=${Buffer.from(input).toString('base64')}`,
    IMAGES[lang], ...COMMANDS[lang],
  ];
}

export async function dockerAvailable() {
  return new Promise((resolve) => {
    const p = spawn('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'ignore' });
    p.on('error', () => resolve(false));
    p.on('close', (code) => resolve(code === 0));
  });
}

export async function executeSandbox(body) {
  const job = validateRunRequest(body);
  if (job.error) return { ok: false, status: 400, error: job.error };
  if (!(await dockerAvailable())) return { ok: false, status: 503, error: 'Docker is unavailable on the sandbox runner' };
  const name = `sxsbx-${crypto.randomUUID().replaceAll('-', '').slice(0, 16)}`;
  const args = dockerArgs({ ...job, name });
  return new Promise((resolve) => {
    let stdout = ''; let stderr = ''; let done = false;
    const finish = (result) => { if (!done) { done = true; clearTimeout(timer); resolve(result); } };
    const timer = setTimeout(() => {
      spawn('docker', ['kill', name], { stdio: 'ignore' }).on('error', () => {});
      finish({ ok: false, timedOut: true, image: IMAGES[job.lang], stdout: stdout.slice(0, 200_000), stderr: 'sandbox timed out' });
    }, (job.timeoutSecs + 5) * 1000);
    const p = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    p.on('error', (error) => finish({ ok: false, stderr: `docker spawn failed: ${error.message}`, stdout: '' }));
    p.stdout.on('data', (chunk) => { if (stdout.length < 200_000) stdout += chunk; });
    p.stderr.on('data', (chunk) => { if (stderr.length < 20_000) stderr += chunk; });
    p.on('close', (code) => finish({ ok: code === 0, code, image: IMAGES[job.lang], stdout: stdout.slice(0, 200_000), stderr: stderr.slice(0, 20_000) }));
    p.stdin.end(job.code);
  });
}
