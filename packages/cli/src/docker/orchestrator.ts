import { execaCommand, execa } from 'execa';
import { join } from 'node:path';
import { mkdirSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { RuntimeMode } from '../modes/detect.js';

export interface ScanOptions {
  mode: RuntimeMode;
  config: ScanConfig;
  resume: boolean;
  workspaceOverride?: string;
}

export interface ScanConfig {
  target: string;
  [key: string]: unknown;
}

const DOCKER_IMAGE = 'keygraph/shannon-worker:latest';
const COMPOSE_FILE = 'docker-compose.yml';
const COMPOSE_LOCAL_FILE = 'docker-compose.local.yml';

export async function runScan(opts: ScanOptions): Promise<void> {
  const scanId = randomUUID().slice(0, 8);
  const taskQueue = `shannon-scan-${scanId}`;
  const workspaceDir = opts.workspaceOverride ?? join(opts.mode.workspacesDir, scanId);

  mkdirSync(workspaceDir, { recursive: true });

  // Start Temporal server via Docker Compose
  await startTemporal(opts.mode);

  // Spin up ephemeral worker container
  await startWorker({
    mode: opts.mode,
    taskQueue,
    workspaceDir,
    config: opts.config,
    resume: opts.resume,
  });
}

async function startTemporal(mode: RuntimeMode): Promise<void> {
  const composeFiles = ['-f', COMPOSE_FILE];
  if (mode.type === 'local') {
    composeFiles.push('-f', COMPOSE_LOCAL_FILE);
  }

  await execaCommand(`docker compose ${composeFiles.join(' ')} up -d temporal`, {
    stdio: 'inherit',
  });
}

interface WorkerOpts {
  mode: RuntimeMode;
  taskQueue: string;
  workspaceDir: string;
  config: ScanConfig;
  resume: boolean;
}

const FORWARDED_ENV_VARS = [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_BASE_URL',
  'SHANNON_MODEL',
  'SHANNON_LLM_API_KEY',
  'SHANNON_LLM_BASE_URL',
  'AWS_BEDROCK_REGION',
  'VERTEX_PROJECT_ID',
  'OPENAI_API_KEY',
  'GEMINI_API_KEY',
];

async function startWorker(opts: WorkerOpts): Promise<void> {
  if (!process.env.ANTHROPIC_API_KEY && !process.env.SHANNON_LLM_API_KEY && !process.env.AWS_BEDROCK_REGION && !process.env.VERTEX_PROJECT_ID) {
    throw new Error(
      'No LLM provider configured. Set ANTHROPIC_API_KEY (get one at https://console.anthropic.com/settings/keys), or configure another provider via SHANNON_LLM_API_KEY, AWS_BEDROCK_REGION, or VERTEX_PROJECT_ID.',
    );
  }

  const args = ['run', '--rm', '--network', 'shannon_default',
    '-e', `TEMPORAL_TASK_QUEUE=${opts.taskQueue}`,
    '-e', `SHANNON_CONFIG=${JSON.stringify(opts.config)}`,
    '-e', `SHANNON_RESUME=${opts.resume}`,
    '-v', `${opts.workspaceDir}:/workspace`,
  ];

  for (const name of FORWARDED_ENV_VARS) {
    const value = process.env[name];
    if (value) {
      args.push('-e', `${name}=${value}`);
    }
  }

  if (opts.mode.type === 'local' && opts.mode.mountPrompts) {
    args.push('-v', `${join(process.cwd(), 'prompts')}:/app/prompts`);
  }

  const image = opts.mode.type === 'local' ? 'shannon-worker:local' : DOCKER_IMAGE;

  // Build locally if needed
  if (opts.mode.type === 'local') {
    await execaCommand('docker build -t shannon-worker:local .', { stdio: 'inherit' });
  }

  args.push(image);

  await execa('docker', args, { stdio: 'inherit' });
}
