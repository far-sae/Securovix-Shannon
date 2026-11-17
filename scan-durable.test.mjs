// A scan that the worker runs (the live setup) must look the same in the dashboard as one the
// dashboard runs itself: progress while it runs, a clear end, and every result tab filled.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-scan-durable-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_SESSION_SECRET = 'scan-durable-test-secret-that-is-long-enough';
process.env.SHANNON_ENCRYPTION_KEY = 'scan-durable-test-encryption-key';
process.env.SHANNON_SIGNUP_RATE_LIMIT = '50';
process.env.SHANNON_SCAN_EVENTS_POLL_MS = '100';
process.env.NODE_ENV = 'test';
Reflect.deleteProperty(process.env, 'ANTHROPIC_API_KEY');

const { createProgress, createSeen, feedProgress, progressSince } = await import(
  './packages/dashboard/scan-progress.mjs'
);
const { startDashboard } = await import('./packages/dashboard/server.mjs');
const teamDb = await import('./packages/dashboard/db.mjs');
const jobsDb = await import('./packages/dashboard/enterprise-db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function request(path, { method = 'GET', cookie, body } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    response,
    json: await response.json().catch(() => ({})),
    setCookie: response.headers.get('set-cookie') || '',
  };
}

let people = 0;
async function account() {
  people += 1;
  const out = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      email: `scan-owner-${people}@example.test`,
      name: `Owner ${people}`,
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    },
  });
  assert.equal(out.response.status, 200);
  return {
    cookie: out.setCookie.split(';')[0],
    orgId: out.json.organizations[0].id,
    userId: out.json.user?.id || `user-${people}`,
  };
}

let scans = 0;
/** A scan as the worker leaves it in the database: a job, its owner, and stored result files. */
async function workerScan(who, { status = 'running', result = null, error = null, files = {} } = {}) {
  scans += 1;
  const scanId = `dur${String(scans).padStart(5, '0')}`;
  teamDb.saveScanOwner({ scanId, orgId: who.orgId, userId: who.userId, projectId: null, createdAt: Date.now() });
  const job = await jobsDb.enqueueJob({
    orgId: who.orgId,
    userId: who.userId,
    type: 'scan',
    payload: { scanId, targetUrl: 'https://shop.example.test' },
    idempotencyKey: `scan:${scanId}`,
  });
  await jobsDb.updateJob(job.id, { status, result, error });
  for (const [rel, content] of Object.entries(files))
    await jobsDb.saveArtifact(
      {
        orgId: who.orgId,
        scanId,
        jobId: job.id,
        objectPath: `${who.orgId}/${scanId}/${rel}`,
        metadata: { relativePath: rel },
      },
      typeof content === 'string' ? content : JSON.stringify(content),
    );
  return { scanId, jobId: job.id };
}

/** Reads a scan's event stream until it ends or `stop` says enough has arrived. */
async function events(path, cookie, stop = () => false, ms = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  const seen = [];
  try {
    const response = await fetch(base + path, { headers: { cookie }, signal: controller.signal });
    assert.equal(response.status, 200);
    const decoder = new TextDecoder();
    let buffer = '';
    for await (const chunk of response.body) {
      buffer += decoder.decode(chunk, { stream: true });
      let cut = buffer.indexOf('\n\n');
      while (cut >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        if (block.startsWith('data: ')) seen.push(JSON.parse(block.slice(6)));
        cut = buffer.indexOf('\n\n');
      }
      if (stop(seen)) break;
    }
  } catch (error) {
    if (error.name !== 'AbortError') throw error;
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  return seen;
}

test('scanner output becomes phases and lines, however it is cut into pieces', () => {
  const state = createProgress();
  const out = [
    ...feedProgress(state, '  [Phase 0] Live HTTP Recon'),
    ...feedProgress(state, 'naissance...\n           Done (1.5s) — 3 live\n  [Phase 1] Pre-Recon'),
    ...feedProgress(state, ' & Threat Modeling...\n      working\n           Done (12.25s, $0.031)\n'),
  ];
  assert.deepEqual(
    out.filter((e) => e.type !== 'output'),
    [
      { type: 'phase', phase: 'http-recon', name: 'HTTP Recon', status: 'running' },
      { type: 'phase-done', phase: 'http-recon', cost: undefined, duration: 1.5 },
      { type: 'phase', phase: 'pre-recon', name: 'Pre-Recon', status: 'running' },
      { type: 'phase-done', phase: 'pre-recon', cost: 0.031, duration: 12.25 },
    ],
  );
  assert.deepEqual(
    out.filter((e) => e.type === 'output').map((e) => e.line),
    [
      '[Phase 0] Live HTTP Reconnaissance...',
      'Done (1.5s) — 3 live',
      '[Phase 1] Pre-Recon & Threat Modeling...',
      'working',
      'Done (12.25s, $0.031)',
    ],
  );
  assert.deepEqual(
    state.phases.map((p) => `${p.id}:${p.status}`),
    ['http-recon:done', 'pre-recon:done'],
  );
});

test('a viewer is sent each phase and each line once, also when it joins late', () => {
  const seen = createSeen();
  const first = progressSince(seen, {
    phases: [
      { id: 'http-recon', name: 'HTTP Recon', status: 'done', duration: 2 },
      { id: 'pre-recon', name: 'Pre-Recon', status: 'running' },
    ],
    // The worker keeps only the end of the output: 1,000 characters were printed, 12 are left.
    outputTail: 'line nine\nli',
    outputChars: 1000,
  });
  assert.deepEqual(
    first.map((e) => e.type),
    ['phase', 'phase-done', 'phase', 'output'],
  );
  assert.equal(first.at(-1).line, 'line nine');
  const second = progressSince(seen, {
    phases: [
      { id: 'http-recon', name: 'HTTP Recon', status: 'done', duration: 2 },
      { id: 'pre-recon', name: 'Pre-Recon', status: 'done', cost: 0.5 },
    ],
    outputTail: 'line nine\nline ten\n',
    outputChars: 1007,
  });
  assert.deepEqual(second, [
    { type: 'phase-done', phase: 'pre-recon', cost: 0.5, duration: undefined },
    { type: 'output', line: 'line ten' },
  ]);
  assert.deepEqual(progressSince(seen, { phases: [], outputTail: 'line nine\nline ten\n', outputChars: 1007 }), []);
});

test('a scan run by the worker shows its progress and its end', async () => {
  const who = await account();
  const { scanId, jobId } = await workerScan(who, {
    result: {
      phases: [
        { id: 'http-recon', name: 'HTTP Recon', status: 'done', duration: 1.5 },
        { id: 'pre-recon', name: 'Pre-Recon', status: 'running' },
      ],
      outputTail: '[Phase 0] Live HTTP Reconnaissance...\nDone (1.5s)\n[Phase 1] Pre-Recon\n',
      outputChars: 68,
    },
  });
  const live = await request(`/api/scans/${scanId}/live`, { cookie: who.cookie });
  assert.equal(live.json.status, 'running');
  assert.deepEqual(
    live.json.phases.map((p) => p.id),
    ['http-recon', 'pre-recon'],
  );

  setTimeout(
    () =>
      jobsDb.updateJob(jobId, {
        status: 'succeeded',
        result: { status: 'completed', artifactCount: 3, phases: [], outputTail: '', outputChars: 68 },
      }),
    400,
  );
  const got = await events(`/api/scans/${scanId}/events`, who.cookie);
  const types = got.map((e) => e.type);
  assert.deepEqual(
    types.filter((t) => t === 'phase' || t === 'phase-done'),
    ['phase', 'phase-done', 'phase'],
  );
  assert.ok(got.some((e) => e.type === 'output' && e.line === '[Phase 1] Pre-Recon'));
  assert.equal(types.at(-1), 'complete');
});

test('a scan that failed or was stopped says so, with the reason', async () => {
  const who = await account();
  const failed = await workerScan(who, {
    status: 'dead-letter',
    error: 'scan process exited with code 1: ERROR: Set ANTHROPIC_API_KEY',
  });
  const failedEvents = await events(`/api/scans/${failed.scanId}/events`, who.cookie);
  assert.equal(failedEvents.at(-1).type, 'failed');
  assert.match(failedEvents.at(-1).error, /ANTHROPIC_API_KEY/);

  const stopped = await workerScan(who, { status: 'cancelled', error: 'Cancelled by user' });
  assert.equal((await events(`/api/scans/${stopped.scanId}/events`, who.cookie)).at(-1).type, 'stopped');

  const waiting = await workerScan(who, { status: 'queued' });
  const queued = await events(
    `/api/scans/${waiting.scanId}/events`,
    who.cookie,
    (seen) => seen.some((e) => e.type === 'output'),
    3000,
  );
  assert.match(queued.find((e) => e.type === 'output').line, /waiting/i);
});

test('verified results of a worker-run scan are read from storage', async () => {
  const who = await account();
  const { scanId } = await workerScan(who, {
    status: 'succeeded',
    result: { status: 'completed', artifactCount: 6 },
    files: {
      'session.json': {
        scanId: 'x',
        target: 'https://shop.example.test',
        status: 'completed',
        startedAt: '2026-11-17T00:00:00.000Z',
      },
      'report.md': '# Report',
      'broker/sqli/findings.json': [{ title: 'SQL injection in /search', severity: 'critical' }],
      'broker/sqli/compliance.json': {
        rows: [{ control: 'A03' }],
        owaspCoverage: { A03: 1 },
        cweCoverage: { 'CWE-89': 1 },
      },
      'broker/attack-chain/findings.json': { findings: [{ title: 'Chain to admin', severity: 'high' }] },
      'broker/monitoring.json': { newExposures: 1 },
      'broker/ai-leads.json': [{ lead: 'check /export' }],
      'defense/sqli/defense.json': { category: 'sqli', rule: 'block' },
    },
  });
  const broker = await request(`/api/scans/${scanId}/broker`, { cookie: who.cookie });
  assert.equal(broker.response.status, 200);
  assert.deepEqual(broker.json.findings.map((f) => `${f.category}:${f.title}`).sort(), [
    'attack-chain:Chain to admin',
    'sqli:SQL injection in /search',
  ]);
  assert.deepEqual(broker.json.rows, [{ control: 'A03' }]);
  assert.deepEqual(broker.json.owaspCoverage, { A03: 1 });
  assert.deepEqual(broker.json.defenses, [{ category: 'sqli', rule: 'block' }]);
  assert.deepEqual(broker.json.monitoring, { newExposures: 1 });
  assert.equal(broker.json.aiLeads.length, 1);
  assert.equal(broker.json.chains.length, 1);

  // Another organization cannot read it.
  const other = await account();
  assert.equal((await request(`/api/scans/${scanId}/broker`, { cookie: other.cookie })).response.status, 404);
});

test('a failed worker-run scan is listed as failed and its partial results can be opened', async () => {
  const who = await account();
  const { scanId } = await workerScan(who, {
    status: 'dead-letter',
    error: 'scan process exited with code 1: the target stopped answering',
    result: { status: 'failed', artifactCount: 2, completedAt: '2026-11-17T00:10:00.000Z' },
    files: {
      // The scanner never got to mark its own session as ended.
      'session.json': {
        scanId: 'x',
        target: 'https://shop.example.test',
        status: 'running',
        startedAt: '2026-11-17T00:00:00.000Z',
      },
      'pre-recon/analysis.md': '# What was found before it stopped',
    },
  });
  const list = await request('/api/scans', { cookie: who.cookie });
  const row = list.json.find((s) => s.id === scanId);
  assert.equal(row.status, 'failed');
  assert.equal(row.hasReport, true);
  assert.match(row.error, /stopped answering/);

  const detail = await request(`/api/scans/${scanId}`, { cookie: who.cookie });
  assert.equal(detail.json.session.status, 'failed');
  assert.match(detail.json.session.failReason, /stopped answering/);
  assert.equal(detail.json.session.completedAt, '2026-11-17T00:10:00.000Z');
  assert.match(detail.json.files.preRecon, /before it stopped/);
});

test('a scan stays in the history for as long as its results are kept', async () => {
  const day = 86_400_000;
  const make = async (type, ageDays, key) => {
    const job = await jobsDb.enqueueJob({ orgId: 'org-retention', type, payload: {}, idempotencyKey: key });
    await jobsDb.updateJob(job.id, { status: 'succeeded' });
    (await jobsDb.getJob(job.id)).updatedAt = Date.now() - ageDays * day;
    return job.id;
  };
  const mail = await make('email', 40, 'r-mail');
  const scan = await make('scan', 40, 'r-scan');
  const oldScan = await make('scan', 100, 'r-old-scan');
  await jobsDb.purgeExpiredEnterpriseData({ completedJobDays: 30, artifactDays: 90 });
  assert.equal(await jobsDb.getJob(mail), null);
  assert.ok(await jobsDb.getJob(scan), 'a 40-day-old scan is still listed');
  assert.equal(await jobsDb.getJob(oldScan), null);
});
