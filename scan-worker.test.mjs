// How the worker runs a scan: it must not hold up other work, must not run a failed scan again by
// itself, must keep what a stopped scan produced, and must report progress while it runs.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-scan-worker-test-'));
const workspaces = join(dataDir, 'workspaces');
mkdirSync(workspaces, { recursive: true });

// Stands in for run-scan.mjs. It reads what to do from the target URL in its config file:
// how long to run and which exit code to end with.
const fakeScanner = join(dataDir, 'fake-scan.mjs');
writeFileSync(
  fakeScanner,
  `
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const config = readFileSync(process.argv[process.argv.indexOf('--config') + 1], 'utf8');
const url = new URL(/url:\\s*(\\S+)/.exec(config)[1]);
const ms = Number(url.searchParams.get('ms') || 0);
const code = Number(url.searchParams.get('exit') || 0);
const dir = join(process.env.SHANNON_WORKSPACES_DIR, process.env.SHANNON_SCAN_ID);
mkdirSync(join(dir, 'broker', 'sqli'), { recursive: true });
const session = { scanId: process.env.SHANNON_SCAN_ID, target: url.href, startedAt: new Date().toISOString(), status: 'running' };
writeFileSync(join(dir, 'session.json'), JSON.stringify(session));
console.log('  [Phase 0] HTTP Recon');
console.log('    Done (0.1s, $0.00)');
console.log('  [Phase 1] Pre-Recon');
writeFileSync(join(dir, 'broker', 'sqli', 'findings.json'), JSON.stringify([{ title: 'Test finding', severity: 'high', url: url.href }]));
await new Promise((resolve) => setTimeout(resolve, ms));
if (code) { console.error('scanner stopped: simulated failure'); process.exit(code); }
writeFileSync(join(dir, 'report.md'), '# Report');
writeFileSync(join(dir, 'session.json'), JSON.stringify({ ...session, status: 'completed', completedAt: new Date().toISOString() }));
console.log('  Scan Complete');
`,
);

process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_ENCRYPTION_KEY = 'scan-worker-test-encryption-key';
process.env.NODE_ENV = 'test';
process.env.SHANNON_SCAN_ENTRY = fakeScanner;
process.env.SHANNON_WORKSPACES_DIR = workspaces;
process.env.SHANNON_WORKER_HEARTBEAT_MS = '150';
process.env.SHANNON_WORKER_CONCURRENCY = '2';
process.env.SHANNON_WORKER_SCAN_CONCURRENCY = '1';

const security = await import('./packages/dashboard/enterprise-security.mjs');
const database = await import('./packages/dashboard/enterprise-db.mjs');
const worker = await import('./packages/dashboard/worker.mjs');

after(async () => {
  await worker.drain();
  rmSync(dataDir, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let seq = 0;
async function queueScan(org, { ms = 0, exit = 0 } = {}) {
  seq += 1;
  const scanId = `scan${seq}`;
  const job = await database.enqueueJob({
    orgId: org,
    userId: 'user-1',
    type: 'scan',
    payload: {
      scanId,
      targetUrl: 'http://127.0.0.1:9/',
      config: { target: { url: `http://127.0.0.1:9/?ms=${ms}&exit=${exit}` } },
    },
    secretEnc: security.encryptSecret({ apiKey: 'test-key-not-real' }),
    maxAttempts: 3,
    idempotencyKey: `scan:${scanId}`,
  });
  return { job, scanId };
}
async function until(check, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error('timed out waiting');
    await sleep(40);
  }
}

test('other work is done while a scan is still running', async () => {
  const { job } = await queueScan('org-a', { ms: 1500 });
  assert.equal(await worker.pollOnce(), 1);
  const other = await database.enqueueJob({ orgId: 'org-a', type: 'retention', payload: {} });
  await worker.pollOnce();
  const done = await until(async () => {
    const current = await database.getJob(other.id);
    return current.status === 'succeeded' ? current : null;
  });
  assert.equal(done.status, 'succeeded');
  assert.equal((await database.getJob(job.id)).status, 'running', 'the scan is still going');
  await worker.drain();
  assert.equal((await database.getJob(job.id)).status, 'succeeded');
});

test('a scan reports its output while it runs, and its results are stored when it ends', async () => {
  const { job, scanId } = await queueScan('org-b', { ms: 900 });
  await worker.pollOnce();
  const mid = await until(async () => {
    const current = await database.getJob(job.id);
    return current.result?.outputChars > 0 ? current : null;
  });
  assert.equal(mid.status, 'running');
  assert.match(mid.result.outputTail, /\[Phase 1\] Pre-Recon/);
  await worker.drain();
  const finished = await database.getJob(job.id);
  assert.equal(finished.status, 'succeeded');
  assert.equal(finished.result.status, 'completed');
  assert.ok(finished.result.outputChars >= finished.result.outputTail.length);
  const paths = (await database.listArtifacts('org-b', scanId)).map((a) => a.metadata.relativePath).sort();
  assert.deepEqual(paths, ['broker/sqli/findings.json', 'report.md', 'session.json']);
  assert.equal(finished.result.findingsImported, 1);
  assert.equal(existsSync(join(workspaces, scanId)), false, 'the working folder is removed once it is stored');
});

test('a scan that fails is not run again by itself, and what it produced is kept', async () => {
  const { job, scanId } = await queueScan('org-c', { ms: 50, exit: 3 });
  await worker.pollOnce();
  await worker.drain();
  const failed = await database.getJob(job.id);
  assert.equal(failed.status, 'dead-letter');
  assert.equal(failed.attempts, 1);
  assert.match(failed.error, /simulated failure/);
  assert.equal(failed.result.status, 'failed');
  const paths = (await database.listArtifacts('org-c', scanId)).map((a) => a.metadata.relativePath).sort();
  assert.deepEqual(paths, ['broker/sqli/findings.json', 'session.json']);
  // Nothing is left to pick up.
  assert.equal(await worker.pollOnce(), 0);
});

test('a second scan waits its turn without using up one of its attempts', async () => {
  const first = await queueScan('org-d', { ms: 900 });
  await worker.pollOnce();
  const second = await queueScan('org-d', { ms: 0 });
  await worker.pollOnce();
  const waiting = await database.getJob(second.job.id);
  assert.equal(waiting.status, 'queued');
  assert.equal(waiting.attempts, 0);
  assert.ok(waiting.runAt > Date.now(), 'it is retried a little later, not in a tight loop');
  await worker.drain();
  assert.equal((await database.getJob(first.job.id)).status, 'succeeded');
  await database.updateJob(second.job.id, { runAt: Date.now() - 1 });
  assert.equal(await worker.pollOnce(), 1);
  await worker.drain();
  const ran = await database.getJob(second.job.id);
  assert.equal(ran.status, 'succeeded');
  assert.equal(ran.attempts, 1);
});

test('a cancelled scan stops and is not marked as failed', async () => {
  const { job } = await queueScan('org-e', { ms: 20_000 });
  await worker.pollOnce();
  await until(async () => (await database.getJob(job.id)).result?.outputChars > 0);
  await database.updateJob(job.id, { status: 'cancelled', error: 'Cancelled by user', lockedBy: null, lockedAt: null });
  const started = Date.now();
  await worker.drain();
  assert.ok(Date.now() - started < 12_000, 'the scanner process was stopped');
  assert.equal((await database.getJob(job.id)).status, 'cancelled');
});

test('storing the same result file twice keeps one record', async () => {
  const record = {
    orgId: 'org-f',
    scanId: 'dup',
    objectPath: 'org-f/dup/report.md',
    metadata: { relativePath: 'report.md' },
  };
  await database.saveArtifact(record, 'first');
  await database.saveArtifact(record, 'second');
  const stored = await database.listArtifacts('org-f', 'dup');
  assert.equal(stored.length, 1);
  assert.equal((await database.readArtifact(stored[0])).toString(), 'second');
});
