import { NativeConnection, Worker } from '@temporalio/worker';
import { createActivities } from './workflows/activities/index.js';
import { createContainer } from './di/container.js';

async function main(): Promise<void> {
  const taskQueue = process.env.TEMPORAL_TASK_QUEUE;
  if (!taskQueue) {
    throw new Error('TEMPORAL_TASK_QUEUE environment variable is required');
  }

  const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'temporal:7233';

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
  await worker.run();
}

main().catch((err) => {
  console.error('Worker failed:', err);
  process.exit(1);
});
