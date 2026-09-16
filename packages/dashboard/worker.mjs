import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify as stringifyYaml } from 'yaml';
import {
  appendOperationalEvent,
  claimJobs,
  enterpriseHealth,
  getJob,
  purgeExpiredEnterpriseData,
  requeueStaleJobs,
  saveArtifact,
  updateJob,
  upsertScanFindings,
} from './enterprise-db.mjs';
import { deliverIntegrationJob, queueIntegrationEvent, sendEmail } from './enterprise-integrations.mjs';
import { decryptSecret } from './enterprise-security.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const WORKSPACES = join(ROOT, 'workspaces');
const INSTANCE = process.env.RAILWAY_REPLICA_ID || process.env.RAILWAY_DEPLOYMENT_ID || `worker-${randomUUID()}`;
const CONCURRENCY = Math.max(1, Math.min(10, Number(process.env.SHANNON_WORKER_CONCURRENCY || 2)));
const POLL_MS = Math.max(500, Number(process.env.SHANNON_WORKER_POLL_MS || 2500));
const MAX_ARTIFACT_BYTES = Math.max(1024, Number(process.env.SHANNON_MAX_ARTIFACT_BYTES || 100 * 1024 * 1024));
let stopping = false;
const activeChildren = new Set();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function contentType(path) {
  if (path.endsWith('.json')) return 'application/json';
  if (path.endsWith('.html')) return 'text/html; charset=utf-8';
  if (path.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (path.endsWith('.sarif')) return 'application/sarif+json';
  if (path.endsWith('.yaml') || path.endsWith('.yml')) return 'application/yaml';
  return 'text/plain; charset=utf-8';
}

function filesUnder(root) {
  const output = [];
  if (!existsSync(root)) return output;
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) output.push(path);
    }
  };
  visit(root);
  return output;
}

async function uploadScanArtifacts(job, scanId) {
  const workspace = join(WORKSPACES, scanId);
  const uploaded = [];
  for (const path of filesUnder(workspace)) {
    const stat = statSync(path);
    if (stat.size > MAX_ARTIFACT_BYTES) continue;
    const rel = relative(workspace, path).replaceAll('\\', '/');
    uploaded.push(
      await saveArtifact(
        {
          orgId: job.orgId,
          scanId,
          jobId: job.id,
          objectPath: `${job.orgId}/${scanId}/${rel}`,
          contentType: contentType(rel),
          metadata: { relativePath: rel },
        },
        readFileSync(path),
      ),
    );
  }
  return uploaded;
}

async function runChild(command, args, options, job) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    activeChildren.add(child);
    let tail = '';
    let cancelRequested = false;
    const capture = (chunk) => {
      tail = `${tail}${chunk}`.slice(-32_000);
    };
    child.stdout?.on('data', capture);
    child.stderr?.on('data', capture);
    const heartbeat = setInterval(() => {
      updateJob(job.id, { heartbeatAt: Date.now(), result: { outputTail: tail } }).catch(() => {});
    }, 15_000);
    const cancellation = setInterval(async () => {
      try {
        if ((await getJob(job.id))?.status === 'cancelled' && !cancelRequested) {
          cancelRequested = true;
          child.kill('SIGTERM');
          const force = setTimeout(() => {
            if (activeChildren.has(child)) child.kill('SIGKILL');
          }, 5000);
          force.unref?.();
        }
      } catch {}
    }, 3_000);
    heartbeat.unref?.();
    cancellation.unref?.();
    child.once('error', reject);
    child.once('close', (code) => {
      clearInterval(heartbeat);
      clearInterval(cancellation);
      activeChildren.delete(child);
      if (code === 0) resolve({ code, outputTail: tail });
      else reject(new Error(`scan process exited with code ${code}: ${tail.slice(-2000)}`));
    });
  });
}

async function executeScan(job) {
  const payload = job.payload || {};
  const secret = decryptSecret(job.secretEnc) || {};
  const scanId = payload.scanId;
  if (!scanId || !payload.config) throw new Error('scan job is missing its scan configuration');
  const config = structuredClone(payload.config);
  if (secret.authentication) config.authentication = secret.authentication;
  const tempDir = mkdtempSync(join(tmpdir(), 'shannon-scan-'));
  const configPath = join(tempDir, 'scan.yaml');
  writeFileSync(configPath, stringifyYaml(config), { mode: 0o600 });
  const env = {
    ...process.env,
    ANTHROPIC_API_KEY: secret.apiKey || process.env.ANTHROPIC_API_KEY || '',
    SHANNON_SCAN_ID: scanId,
    SHANNON_OWNER_USER_ID: job.userId || '',
    SHANNON_ORG_ID: job.orgId || '',
    SHANNON_PROJECT_ID: payload.projectId || '',
    SHANNON_MODEL: payload.model || process.env.SHANNON_MODEL || 'claude-opus-4-7',
  };
  if (!env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is not configured for the worker');
  if (payload.baseUrl) env.SHANNON_LLM_BASE_URL = payload.baseUrl;
  if (payload.warRoom) env.SHANNON_WAR_ROOM = '1';
  if (secret.providerKeys?.openai) env.OPENAI_API_KEY = secret.providerKeys.openai;
  if (secret.providerKeys?.gemini) env.GOOGLE_API_KEY = secret.providerKeys.gemini;
  if (secret.providerKeys?.glm) env.ZHIPU_API_KEY = secret.providerKeys.glm;
  if (secret.accessControl?.length >= 2) env.SHANNON_AC = JSON.stringify({ identities: secret.accessControl });
  if (payload.monitor) env.SHANNON_MONITOR = '1';
  if (secret.alertWebhook) env.SHANNON_ALERT_WEBHOOK = secret.alertWebhook;
  if (payload.networkScan) env.SHANNON_NETWORK_SCAN = '1';

  let processResult;
  try {
    processResult = await runChild(
      'node',
      [join(ROOT, 'run-scan.mjs'), '--config', configPath],
      {
        cwd: ROOT,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
      job,
    );
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
  const artifacts = await uploadScanArtifacts(job, scanId);
  const sessionPath = join(WORKSPACES, scanId, 'session.json');
  const session = existsSync(sessionPath) ? JSON.parse(readFileSync(sessionPath, 'utf8')) : {};
  const result = {
    scanId,
    status: session.status || 'completed',
    target: session.target || payload.targetUrl,
    startedAt: session.startedAt || null,
    completedAt: session.completedAt || new Date().toISOString(),
    artifactCount: artifacts.length,
    outputTail: processResult.outputTail,
  };
  const confirmed = [];
  const brokerDir = join(WORKSPACES, scanId, 'broker');
  if (existsSync(brokerDir)) {
    for (const path of filesUnder(brokerDir).filter((item) => item.endsWith(`${join('', 'findings.json')}`))) {
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf8'));
        if (Array.isArray(parsed)) confirmed.push(...parsed);
        else if (Array.isArray(parsed?.findings)) confirmed.push(...parsed.findings);
      } catch {}
    }
  }
  result.findingsImported = await upsertScanFindings({
    orgId: job.orgId,
    userId: job.userId,
    projectId: payload.projectId || null,
    scanId,
    findings: confirmed,
  });
  await queueIntegrationEvent(
    job.orgId,
    {
      id: `scan-completed:${scanId}`,
      type: 'scan.completed',
      at: new Date().toISOString(),
      data: result,
    },
    job.userId,
  );
  return result;
}

async function execute(job) {
  if (job.type === 'integration-delivery') return deliverIntegrationJob(job);
  if (job.type === 'email') return sendEmail(job.payload);
  if (job.type === 'scan') return executeScan(job);
  if (job.type === 'retention')
    return { ok: true, note: 'retention is enforced by Supabase lifecycle and scheduled SQL policies' };
  throw new Error(`unsupported job type: ${job.type}`);
}

async function handle(job) {
  try {
    const result = await execute(job);
    await updateJob(job.id, {
      status: 'succeeded',
      result,
      error: null,
      heartbeatAt: Date.now(),
      lockedBy: null,
      lockedAt: null,
    });
  } catch (error) {
    const current = await getJob(job.id).catch(() => null);
    if (current?.status === 'cancelled') return;
    const message = String(error?.message || error).slice(0, 4000);
    const exhausted = job.attempts >= job.maxAttempts;
    const delay = Math.min(60 * 60_000, 15_000 * 2 ** Math.max(0, job.attempts - 1));
    await updateJob(
      job.id,
      exhausted
        ? { status: 'dead-letter', error: message, heartbeatAt: Date.now(), lockedBy: null, lockedAt: null }
        : { status: 'queued', error: message, runAt: Date.now() + delay, lockedBy: null, lockedAt: null },
    );
    await appendOperationalEvent({
      service: 'worker',
      instanceId: INSTANCE,
      level: exhausted ? 'error' : 'warning',
      event: exhausted ? 'job.dead_letter' : 'job.retry_scheduled',
      orgId: job.orgId,
      metadata: { jobId: job.id, type: job.type, attempt: job.attempts, error: message },
    }).catch(() => {});
  }
}

export async function runWorker() {
  await enterpriseHealth();
  await requeueStaleJobs(Date.now() - Number(process.env.SHANNON_JOB_STALE_MS || 120_000));
  const retention = {
    authTokenDays: Number(process.env.SHANNON_AUTH_TOKEN_RETENTION_DAYS || 7),
    deliveryDays: Number(process.env.SHANNON_DELIVERY_RETENTION_DAYS || 90),
    operationalDays: Number(process.env.SHANNON_OPERATIONAL_RETENTION_DAYS || 30),
    completedJobDays: Number(process.env.SHANNON_JOB_RETENTION_DAYS || 30),
    artifactDays: Number(process.env.SHANNON_ARTIFACT_RETENTION_DAYS || 90),
  };
  await purgeExpiredEnterpriseData(retention).catch((error) =>
    console.error('[worker] retention failed:', error.message),
  );
  await appendOperationalEvent({
    service: 'worker',
    instanceId: INSTANCE,
    level: 'info',
    event: 'worker.started',
    metadata: { concurrency: CONCURRENCY },
  }).catch(() => {});
  let lastMaintenance = Date.now();
  let lastRetention = Date.now();
  while (!stopping) {
    if (Date.now() - lastMaintenance > 60_000) {
      await requeueStaleJobs(Date.now() - Number(process.env.SHANNON_JOB_STALE_MS || 120_000)).catch(() => {});
      lastMaintenance = Date.now();
    }
    if (Date.now() - lastRetention > 24 * 60 * 60_000) {
      await purgeExpiredEnterpriseData(retention).catch((error) =>
        console.error('[worker] retention failed:', error.message),
      );
      lastRetention = Date.now();
    }
    const jobs = await claimJobs(INSTANCE, CONCURRENCY);
    if (!jobs.length) {
      await sleep(POLL_MS);
      continue;
    }
    await Promise.all(jobs.map(handle));
  }
}

function shutdown() {
  stopping = true;
  for (const child of activeChildren) {
    try {
      child.kill('SIGTERM');
    } catch {}
  }
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

if (process.argv[1]?.endsWith('worker.mjs')) {
  runWorker().catch((error) => {
    console.error('[worker] fatal:', error);
    process.exitCode = 1;
  });
}
