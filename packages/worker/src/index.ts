import { NativeConnection, Worker } from '@temporalio/worker';
import type { ShannonConfig } from './config/schema.js';
import { createContainer } from './di/container.js';
import { startScan } from './scan/start-scan.js';
import { createActivities } from './workflows/activities/index.js';

async function main(): Promise<void> {
  const taskQueue = process.env.TEMPORAL_TASK_QUEUE;
  if (!taskQueue) {
    throw new Error('TEMPORAL_TASK_QUEUE environment variable is required');
  }

  const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'temporal:7233';
  const workspaceDir = process.env.SHANNON_WORKSPACE ?? '/workspace';

  const container = createContainer();
  const activities = createActivities(container);

  const connection = await NativeConnection.connect({ address: temporalAddress });

  const worker = await Worker.create({
    connection,
    taskQueue,
    workflowsPath: new URL('./workflows/scan.js', import.meta.url).pathname,
    activities,
  });

  console.log(`Shannon worker started on task queue: ${taskQueue}`);

  const rawConfig = process.env.SHANNON_CONFIG;
  if (!rawConfig) {
    // No scan handed to this worker — run as a plain long-lived poller.
    await worker.run();
    return;
  }

  // Ephemeral one-shot (the CLI runs `docker run --rm` per scan): poll in the background,
  // start exactly one scanWorkflow, await its result, then shut the worker down.
  const config = JSON.parse(rawConfig) as ShannonConfig;
  const resume = process.env.SHANNON_RESUME === 'true';
  const scopeKey = process.env.SHANNON_BROKER_SCOPE_KEY;

  const runPromise = worker.run();
  try {
    const result = await startScan({
      temporalAddress,
      taskQueue,
      workspaceDir,
      config,
      resume,
      scopeKey,
    });
    console.log(`Scan complete: ${result}`);
  } finally {
    worker.shutdown();
    await runPromise.catch(() => {});
    await connection.close();
  }
}

main().catch((err) => {
  console.error('Worker failed:', err);
  process.exit(1);
});
