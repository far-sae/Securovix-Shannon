// What the worker does while the database is not answering. On 20 November 2026 the database
// was away for about fifteen minutes: the worker exited, was restarted ten times in under three
// minutes, failed its start-up check each time and was then left stopped for good. A database that
// is away must be waited for, at start-up and while running.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-worker-outage-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_ENCRYPTION_KEY = 'worker-outage-test-encryption-key';
process.env.NODE_ENV = 'test';
process.env.SHANNON_WORKER_POLL_MS = '2500';

const worker = await import('./packages/dashboard/worker.mjs');

after(async () => {
  await worker.drain();
  rmSync(dataDir, { recursive: true, force: true });
});

const timeout = () => new Error('The operation was aborted due to timeout');
const quiet = async (fn) => {
  const { error, log } = console;
  console.error = () => {};
  console.log = () => {};
  try {
    return await fn();
  } finally {
    console.error = error;
    console.log = log;
  }
};

test('the wait between tries grows from the poll interval to one minute and no further', () => {
  assert.equal(worker.retryDelay(1), 2500);
  assert.equal(worker.retryDelay(2), 5000);
  assert.equal(worker.retryDelay(3), 10_000);
  assert.equal(worker.retryDelay(6), 60_000);
  assert.equal(worker.retryDelay(500), 60_000);
  assert.equal(worker.retryDelay(0), 2500);
});

test('start-up waits for a database that is away instead of giving up', async () => {
  let calls = 0;
  const waits = [];
  const result = await quiet(() =>
    worker.untilItWorks(
      'database check',
      async () => {
        calls += 1;
        // More failures than the ten restarts the platform allowed before it stopped the worker.
        if (calls <= 40) throw timeout();
        return { ok: true, backend: 'supabase' };
      },
      { wait: async (ms) => waits.push(ms), stopped: () => false },
    ),
  );
  assert.deepEqual(result, { ok: true, backend: 'supabase' });
  assert.equal(calls, 41);
  assert.equal(waits.length, 40);
  assert.equal(waits[0], 2500);
  assert.equal(Math.max(...waits), 60_000);
});

test('start-up stops waiting when the worker is told to shut down', async () => {
  let calls = 0;
  const result = await quiet(() =>
    worker.untilItWorks(
      'database check',
      async () => {
        calls += 1;
        throw timeout();
      },
      { wait: async () => {}, stopped: () => calls >= 3 },
    ),
  );
  assert.equal(result, null);
  assert.equal(calls, 3);
});

test('a running worker outlasts a long outage and picks up again when the database is back', async () => {
  let away = true;
  const poll = async () => {
    if (away) throw timeout();
    return 0;
  };
  const delays = [];
  // The shutdown test above ended in the middle of an outage; start this one from a working database.
  await quiet(() => worker.pollStep(async () => 0));
  // Twenty failed polls in a row used to end the worker. Go well past that.
  await quiet(async () => {
    for (let i = 0; i < 60; i += 1) delays.push(await worker.pollStep(poll));
  });
  assert.equal(delays[0], 2500);
  assert.equal(delays.at(-1), 60_000);
  const during = worker.workerState().database;
  assert.equal(during.ok, false);
  assert.match(during.error, /timeout/);
  assert.equal(typeof during.since, 'number');

  away = false;
  const next = await quiet(() => worker.pollStep(poll));
  assert.equal(next, 2500, 'back to the normal poll interval');
  assert.equal(worker.workerState().database.ok, true);

  // A later blip starts the wait from the beginning again.
  away = true;
  assert.equal(await quiet(() => worker.pollStep(poll)), 2500);
  away = false;
  await quiet(() => worker.pollStep(poll));
});

test('a poll that started work is followed up quickly', async () => {
  assert.equal(await worker.pollStep(async () => 2), 250);
});
