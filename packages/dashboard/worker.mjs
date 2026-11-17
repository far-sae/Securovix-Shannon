import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify as stringifyYaml } from 'yaml';
import { publicOriginAllowed } from './public-address.mjs';
import {
  appendOperationalEvent,
  claimDueDefensePrograms,
  claimJobs,
  enqueueJob,
  enterpriseHealth,
  getDefenseTelemetry,
  getJob,
  listDefenseAssets,
  listDefenseCycles,
  listInventoryOrganizations,
  listSoftwareComponents,
  purgeExpiredEnterpriseData,
  requeueStaleJobs,
  saveArtifact,
  saveDefenseCycle,
  updateJob,
  upsertScanFindings,
  upsertVulnerabilityMatches,
} from './enterprise-db.mjs';
import { deliverIntegrationJob, queueIntegrationEvent, sendEmail } from './enterprise-integrations.mjs';
import { decryptSecret } from './enterprise-security.mjs';
import { buildDefenseCycle } from './continuous-defense.mjs';
import { createProgress, feedProgress } from './scan-progress.mjs';
import { buildVulnerabilityMatches, loadCisaKev, queryOsvComponents } from './vulnerability-management.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const WORKSPACES = process.env.SHANNON_WORKSPACES_DIR || join(ROOT, 'workspaces');
const SCAN_ENTRY = process.env.SHANNON_SCAN_ENTRY || join(ROOT, 'run-scan.mjs');
const INSTANCE = process.env.RAILWAY_REPLICA_ID || process.env.RAILWAY_DEPLOYMENT_ID || `worker-${randomUUID()}`;
const CONCURRENCY = Math.max(1, Math.min(10, Number(process.env.SHANNON_WORKER_CONCURRENCY || 2)));
const POLL_MS = Math.max(500, Number(process.env.SHANNON_WORKER_POLL_MS || 2500));
// Scans run for a long time, so they have their own limit and never take a slot that mail,
// alerts and scheduled checks need.
const SCAN_CONCURRENCY = Math.max(1, Math.min(5, Number(process.env.SHANNON_WORKER_SCAN_CONCURRENCY || 1)));
const HEARTBEAT_MS = Math.max(100, Number(process.env.SHANNON_WORKER_HEARTBEAT_MS || 5000));
const SCAN_WAIT_MS = 30_000;
const MAX_ARTIFACT_BYTES = Math.max(1024, Number(process.env.SHANNON_MAX_ARTIFACT_BYTES || 100 * 1024 * 1024));
let stopping = false;
const activeChildren = new Set();
// Jobs this worker is running now: job id -> { type, promise }.
const running = new Map();
const workerStatus = { ready: false, startedAt: Date.now(), lastPollAt: null, activeJobs: 0, database: null };
let healthServer = null;

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

function removeWorkspace(dir) {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {}
}

async function runChild(command, args, options, job) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    activeChildren.add(child);
    let tail = '';
    // How much the scanner has printed in total. The dashboard uses it to tell which part of the
    // tail it has not shown yet.
    let chars = 0;
    const progress = createProgress();
    let cancelRequested = false;
    const capture = (chunk) => {
      const text = String(chunk);
      chars += text.length;
      feedProgress(progress, text);
      tail = `${tail}${text}`.slice(-32_000);
    };
    child.stdout?.on('data', capture);
    child.stderr?.on('data', capture);
    const heartbeat = setInterval(() => {
      updateJob(job.id, {
        heartbeatAt: Date.now(),
        result: { outputTail: tail, outputChars: chars, phases: progress.phases },
      }).catch(() => {});
    }, HEARTBEAT_MS);
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
      if (code === 0) return resolve({ code, outputTail: tail, outputChars: chars, phases: progress.phases });
      const error = new Error(`scan process exited with code ${code}: ${tail.slice(-2000)}`);
      error.outputTail = tail;
      error.outputChars = chars;
      error.phases = progress.phases;
      reject(error);
    });
  });
}

async function executeScan(job) {
  const payload = job.payload || {};
  const secret = decryptSecret(job.secretEnc) || {};
  const scanId = payload.scanId;
  if (!scanId || !payload.config) throw new Error('scan job is missing its scan configuration');
  if (
    process.env.NODE_ENV === 'production' &&
    process.env.SHANNON_ALLOW_LOCAL_TARGETS !== '1' &&
    payload.targetUrl &&
    !(await publicOriginAllowed(payload.targetUrl).catch(() => false))
  ) {
    throw new Error('The target now points to a private or internal network, so the scan was not started.');
  }
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
  let failure = null;
  try {
    processResult = await runChild(
      'node',
      [SCAN_ENTRY, '--config', configPath],
      {
        cwd: ROOT,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
      job,
    );
  } catch (error) {
    failure = error;
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
  const workspace = join(WORKSPACES, scanId);
  const sessionPath = join(workspace, 'session.json');
  const readSession = () => {
    try {
      return existsSync(sessionPath) ? JSON.parse(readFileSync(sessionPath, 'utf8')) : {};
    } catch {
      return {};
    }
  };
  if (failure) {
    // The scanner stopped part-way. What it wrote so far is kept so the user can read it. While
    // the worker itself is shutting down there is no time for that, and the job is run again by
    // the next worker; a scan that failed on its own is not, because a second run costs the same
    // again and usually fails the same way.
    let artifacts = [];
    if (!stopping) artifacts = await uploadScanArtifacts(job, scanId).catch(() => []);
    const session = readSession();
    failure.retryable = stopping;
    failure.partial = {
      scanId,
      status: 'failed',
      target: session.target || payload.targetUrl,
      startedAt: session.startedAt || null,
      completedAt: new Date().toISOString(),
      artifactCount: artifacts.length,
      outputTail: failure.outputTail || '',
      outputChars: failure.outputChars || 0,
      phases: failure.phases || [],
    };
    if (artifacts.length) removeWorkspace(workspace);
    throw failure;
  }
  const artifacts = await uploadScanArtifacts(job, scanId);
  const session = readSession();
  const result = {
    scanId,
    status: session.status || 'completed',
    target: session.target || payload.targetUrl,
    startedAt: session.startedAt || null,
    completedAt: session.completedAt || new Date().toISOString(),
    artifactCount: artifacts.length,
    outputTail: processResult.outputTail,
    outputChars: processResult.outputChars,
    phases: processResult.phases,
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
  // Everything is stored now; the working copy would only fill the worker's disk.
  removeWorkspace(workspace);
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

export async function executeDefenseCycle(job) {
  const startedAt = Date.now();
  const cycleId = String(job.payload?.cycleId || `dcy_${randomUUID()}`);
  await saveDefenseCycle({ id: cycleId, orgId: job.orgId, jobId: job.id, status: 'running', startedAt, createdAt: startedAt });
  try {
    const [assets, previous, telemetry] = await Promise.all([
      listDefenseAssets(job.orgId),
      listDefenseCycles(job.orgId, 2),
      getDefenseTelemetry(job.orgId),
    ]);
    const priorCompleted = previous.find((item) => item.id !== cycleId && item.status === 'completed') || null;
    const result = buildDefenseCycle({ assets, previousCycle: priorCompleted, ...telemetry, now: Date.now() });
    const completed = await saveDefenseCycle({
      id: cycleId, orgId: job.orgId, jobId: job.id, status: 'completed', startedAt,
      completedAt: Date.now(), createdAt: startedAt, ...result,
    });
    const escalate = job.payload?.responseMode === 'bounded-auto' && result.actions.escalations.length > 0;
    await queueIntegrationEvent(job.orgId, {
      id: `defense-cycle:${cycleId}`,
      type: escalate ? 'defender.cycle.escalated' : 'defender.cycle.completed',
      at: new Date().toISOString(),
      data: { cycleId, ...result.snapshot, escalations: result.actions.escalations },
    }, job.userId || null);
    return completed;
  } catch (error) {
    await saveDefenseCycle({
      id: cycleId, orgId: job.orgId, jobId: job.id, status: 'failed', startedAt,
      completedAt: Date.now(), createdAt: startedAt, error: String(error?.message || error).slice(0, 2000),
    }).catch(() => {});
    throw error;
  }
}

export async function scheduleDueDefenseCycles(now = Date.now()) {
  const programs = await claimDueDefensePrograms(50, now);
  const jobs = [];
  for (const program of programs) {
    const slot = new Date(now).toISOString().slice(0, 13);
    jobs.push(await enqueueJob({
      orgId: program.orgId,
      userId: program.createdBy,
      type: 'defense-cycle',
      payload: { cycleId: `dcy_${randomUUID()}`, trigger: 'schedule', responseMode: program.responseMode },
      idempotencyKey: `defense-cycle:${slot}`,
      maxAttempts: 3,
    }));
  }
  return jobs;
}

export async function executeVulnerabilityRefresh(job) {
  const components = await listSoftwareComponents(job.orgId);
  if (!components.length) return { components: 0, matches: 0, created: 0, kev: 0 };
  const [osv, kev] = await Promise.all([queryOsvComponents(components), loadCisaKev()]);
  const matches = buildVulnerabilityMatches(components, osv, kev, Date.now());
  const saved = await upsertVulnerabilityMatches(job.orgId, matches);
  const newOpen = [...saved.created, ...saved.newKev].filter((item, index, rows) =>
    !['resolved', 'accepted'].includes(item.status) && rows.findIndex((row) => row.id === item.id) === index,
  );
  if (newOpen.length) {
    const rank = { low: 1, medium: 2, high: 3, critical: 4 };
    const severity = [...newOpen].sort((a, b) => rank[b.severity] - rank[a.severity])[0]?.severity || 'medium';
    const kevCount = newOpen.filter((item) => item.details?.kev).length;
    await queueIntegrationEvent(job.orgId, {
      id: `vulnerability-refresh:${job.id}`,
      type: kevCount ? 'vulnerability.kev.detected' : 'vulnerability.detected',
      at: new Date().toISOString(),
      data: {
        title: kevCount
          ? `${kevCount} newly relevant CISA KEV ${kevCount === 1 ? 'vulnerability' : 'vulnerabilities'}`
          : `${newOpen.length} new dependency ${newOpen.length === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        severity, count: newOpen.length, kevCount,
        vulnerabilities: newOpen.slice(0, 25).map((item) => ({
          id: item.vulnerabilityId, aliases: item.aliases, severity: item.severity, dueAt: item.dueAt,
        })),
      },
    }, job.userId || null);
  }
  return { components: components.length, matches: saved.matches.length, created: saved.created.length, newlyRelevantKev: saved.newKev.length, kev: saved.matches.filter((item) => item.details?.kev).length };
}

export async function scheduleDailyVulnerabilityRefreshes(now = Date.now()) {
  const organizations = await listInventoryOrganizations();
  const day = new Date(now).toISOString().slice(0, 10);
  return Promise.all(organizations.map((orgId) => enqueueJob({
    orgId, type: 'vulnerability-refresh', payload: { trigger: 'daily' },
    idempotencyKey: `vulnerability-refresh:daily:${day}`, maxAttempts: 4,
  })));
}

async function execute(job) {
  if (job.type === 'integration-delivery') return deliverIntegrationJob(job);
  if (job.type === 'email') return sendEmail(job.payload);
  if (job.type === 'scan') return executeScan(job);
  if (job.type === 'defense-cycle') return executeDefenseCycle(job);
  if (job.type === 'vulnerability-refresh') return executeVulnerabilityRefresh(job);
  if (job.type === 'retention')
    return { ok: true, note: 'retention is enforced by Supabase lifecycle and scheduled SQL policies' };
  throw new Error(`unsupported job type: ${job.type}`);
}

async function handle(job) {
  try {
    const result = await execute(job);
    await updateJob(job.id, {
      status: 'succeeded',
      // A sent email's text is not kept: it can hold a one-time link meant for its recipient only.
      ...(job.type === 'email' ? { payload: { to: job.payload?.to, subject: job.payload?.subject } } : {}),
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
    const exhausted = error?.retryable === false || job.attempts >= job.maxAttempts;
    const delay = Math.min(60 * 60_000, 15_000 * 2 ** Math.max(0, job.attempts - 1));
    const partial = error?.partial ? { result: error.partial } : {};
    await updateJob(
      job.id,
      exhausted
        ? { status: 'dead-letter', error: message, heartbeatAt: Date.now(), lockedBy: null, lockedAt: null, ...partial }
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

// Starts a claimed job without waiting for it, so the worker keeps polling while it runs.
function start(job) {
  // A scan reports in through its own heartbeat, which also carries its output.
  const beat =
    job.type === 'scan'
      ? null
      : setInterval(() => updateJob(job.id, { heartbeatAt: Date.now() }).catch(() => {}), HEARTBEAT_MS * 3);
  beat?.unref?.();
  const promise = handle(job)
    .catch((error) => console.error(`[worker] job ${job.id} (${job.type}) could not be recorded:`, error.message))
    .finally(() => {
      if (beat) clearInterval(beat);
      running.delete(job.id);
      workerStatus.activeJobs = running.size;
    });
  running.set(job.id, { type: job.type, promise });
  workerStatus.activeJobs = running.size;
}

/** Claims as many jobs as there is room for and starts them. Returns how many were started. */
export async function pollOnce() {
  let scans = 0;
  for (const item of running.values()) if (item.type === 'scan') scans += 1;
  const free = CONCURRENCY - (running.size - scans);
  if (free <= 0) return 0;
  let started = 0;
  for (const job of await claimJobs(INSTANCE, free)) {
    if (job.type === 'scan') {
      if (scans >= SCAN_CONCURRENCY) {
        // Hand it back for later. Being claimed counted as an attempt; waiting is not one.
        await updateJob(job.id, {
          status: 'queued',
          runAt: Date.now() + SCAN_WAIT_MS,
          lockedBy: null,
          lockedAt: null,
          attempts: Math.max(0, job.attempts - 1),
        });
        continue;
      }
      scans += 1;
    }
    start(job);
    started += 1;
  }
  return started;
}

/** Waits for every job this worker is running to finish. */
export async function drain() {
  while (running.size) await Promise.allSettled([...running.values()].map((item) => item.promise));
}

export async function runWorker() {
  workerStatus.database = await enterpriseHealth();
  await requeueStaleJobs(Date.now() - Number(process.env.SHANNON_JOB_STALE_MS || 120_000));
  await scheduleDueDefenseCycles().catch((error) => console.error('[worker] defense scheduling failed:', error.message));
  await scheduleDailyVulnerabilityRefreshes().catch((error) => console.error('[worker] vulnerability scheduling failed:', error.message));
  const retention = {
    authTokenDays: Number(process.env.SHANNON_AUTH_TOKEN_RETENTION_DAYS || 7),
    deliveryDays: Number(process.env.SHANNON_DELIVERY_RETENTION_DAYS || 90),
    operationalDays: Number(process.env.SHANNON_OPERATIONAL_RETENTION_DAYS || 30),
    completedJobDays: Number(process.env.SHANNON_JOB_RETENTION_DAYS || 30),
    artifactDays: Number(process.env.SHANNON_ARTIFACT_RETENTION_DAYS || 90),
  };
  purgeExpiredEnterpriseData(retention).catch((error) =>
    console.error('[worker] retention failed:', error.message),
  );
  await appendOperationalEvent({
    service: 'worker',
    instanceId: INSTANCE,
    level: 'info',
    event: 'worker.started',
    metadata: { concurrency: CONCURRENCY },
  }).catch(() => {});
  workerStatus.ready = true;
  let lastMaintenance = Date.now();
  let lastRetention = Date.now();
  let lastHeartbeat = 0;
  let pollFailures = 0;
  while (!stopping) {
    workerStatus.lastPollAt = Date.now();
    if (Date.now() - lastHeartbeat > 60_000) {
      await appendOperationalEvent({
        service: 'worker',
        instanceId: INSTANCE,
        level: 'info',
        event: 'worker.heartbeat',
        metadata: { concurrency: CONCURRENCY, scanConcurrency: SCAN_CONCURRENCY, activeJobs: running.size },
        createdAt: Date.now(),
      }).catch(() => {});
      lastHeartbeat = Date.now();
    }
    if (Date.now() - lastMaintenance > 60_000) {
      await requeueStaleJobs(Date.now() - Number(process.env.SHANNON_JOB_STALE_MS || 120_000)).catch(() => {});
      await scheduleDueDefenseCycles().catch((error) => console.error('[worker] defense scheduling failed:', error.message));
      await scheduleDailyVulnerabilityRefreshes().catch((error) => console.error('[worker] vulnerability scheduling failed:', error.message));
      lastMaintenance = Date.now();
    }
    if (Date.now() - lastRetention > 24 * 60 * 60_000) {
      await purgeExpiredEnterpriseData(retention).catch((error) =>
        console.error('[worker] retention failed:', error.message),
      );
      lastRetention = Date.now();
    }
    let started = 0;
    try {
      started = await pollOnce();
      pollFailures = 0;
    } catch (error) {
      // One failed poll is a blip; a database that stays away should restart the worker.
      pollFailures += 1;
      console.error('[worker] could not claim jobs:', error.message);
      if (pollFailures >= 20) throw error;
    }
    await sleep(started ? 250 : POLL_MS);
  }
  workerStatus.ready = false;
  await drain();
}

export function createWorkerHealthServer() {
  return http.createServer(async (req, res) => {
    if (!['/healthz', '/readyz'].includes(req.url || '')) {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: 'not found' }));
    }
    const stale = !workerStatus.lastPollAt || Date.now() - workerStatus.lastPollAt > Math.max(30_000, POLL_MS * 5);
    const ready = workerStatus.ready && !stale;
    res.writeHead(req.url === '/readyz' && !ready ? 503 : 200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      ok: req.url === '/healthz' ? true : ready,
      service: 'worker',
      instance: INSTANCE,
      uptime: Math.floor((Date.now() - workerStatus.startedAt) / 1000),
      lastPollAt: workerStatus.lastPollAt,
      activeJobs: workerStatus.activeJobs,
      database: workerStatus.database,
    }));
  });
}

function shutdown() {
  stopping = true;
  workerStatus.ready = false;
  healthServer?.close();
  for (const child of activeChildren) {
    try {
      child.kill('SIGTERM');
    } catch {}
  }
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

if (process.argv[1]?.endsWith('worker.mjs')) {
  const port = Number(process.env.PORT || 8080);
  healthServer = createWorkerHealthServer().listen(port, '0.0.0.0', () =>
    console.log(`[worker] health server listening on 0.0.0.0:${port}`),
  );
  healthServer.once('error', (error) => {
    console.error('[worker] health server failed:', error);
    process.exitCode = 1;
    shutdown();
  });
  runWorker().catch((error) => {
    console.error('[worker] fatal:', error);
    workerStatus.ready = false;
    healthServer?.close();
    process.exitCode = 1;
  });
}
