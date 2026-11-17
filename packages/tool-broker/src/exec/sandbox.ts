import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export interface SandboxLimits {
  image: string;
  network?: 'none' | string; // docker --network; default 'none' (no egress at all)
  memoryMb?: number; // --memory
  cpus?: number; // --cpus
  pidsLimit?: number; // --pids-limit
  timeoutMs?: number; // wall-clock deadline; container is killed past it
  user?: string; // --user; default '65534:65534' (nobody)
  maxOutputBytes?: number; // stdout/stderr cap
}

export interface SandboxResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
}

const DEFAULTS = {
  network: 'none' as const,
  memoryMb: 512,
  cpus: 1,
  pidsLimit: 256,
  timeoutMs: 120_000,
  user: '65534:65534',
  maxOutputBytes: 10 * 1024 * 1024,
};

// Runs a validated argv inside a hardened, ephemeral container. The argv MUST come
// from ToolRegistry.buildArgv (allowlisted, no shell). Hardening: cap-drop ALL,
// no-new-privileges, read-only rootfs + tmpfs /tmp, non-root user, memory/cpu/pids
// caps, and (by default) NO network — egress is meant to flow only through the
// broker forward-proxy, never the tool's own stack.
export function runInSandbox(
  argv: string[],
  limits: SandboxLimits,
  nowMs: () => number = () => Date.now(),
): Promise<SandboxResult> {
  const o = { ...DEFAULTS, ...limits };
  const name = `shannon-tool-${randomUUID()}`;
  const dockerArgs = [
    'run',
    '--rm',
    '--name',
    name,
    '--network',
    o.network,
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--read-only',
    '--tmpfs',
    '/tmp',
    '--user',
    o.user,
    '--memory',
    `${o.memoryMb}m`,
    '--cpus',
    String(o.cpus),
    '--pids-limit',
    String(o.pidsLimit),
    o.image,
    ...argv,
  ];

  const start = nowMs();
  return new Promise<SandboxResult>((resolve) => {
    // The deadline is ours, not execFile's. execFile's own timeout sends SIGTERM to the `docker run`
    // client, which passes it on to the tool as PID 1 of the container, where it is ignored: the
    // tool then runs to its natural end. So: stop the client outright, then remove the container by
    // name, and only report once the container is gone.
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, o.timeoutMs);
    const child = execFile('docker', dockerArgs, { maxBuffer: o.maxOutputBytes }, (err, stdout, stderr) => {
      clearTimeout(deadline);
      const durationMs = nowMs() - start;
      const exitCode = timedOut
        ? null
        : err && typeof (err as NodeJS.ErrnoException & { code?: number }).code === 'number'
          ? ((err as unknown as { code: number }).code as number)
          : err
            ? null
            : 0;
      const done = () => resolve({ stdout: stdout ?? '', stderr: stderr ?? '', exitCode, durationMs, timedOut });
      // Whenever the client ended without the container's own exit code (deadline, output over the
      // cap, client failure), the container may still be running: remove it before reporting.
      if (timedOut || (err && exitCode === null)) execFile('docker', ['rm', '-f', name], done);
      else done();
    });
  });
}
