import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import { hostname } from 'node:os';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Container } from '../../di/container.js';
import type { ForensicPackageInput } from './index.js';
import { unwrap } from '../../result.js';
import { ForensicPackageBuilder } from '../../forensic/package-builder.js';
import type { CustodyMetadata } from '../../forensic/types.js';
import { toTemporalError } from '../../temporal/error-classification.js';

export async function forensicPackageActivity(container: Container, input: ForensicPackageInput): Promise<void> {
  const config = unwrap(container.configLoader.load(input.configPath));

  try {
    heartbeat('Building forensic evidence package');

    const configContent = readFileSync(input.configPath, 'utf-8');
    const configHash = createHash('sha256').update(configContent).digest('hex');

    const custodyMetadata: CustodyMetadata = {
      scanId: input.workspaceDir.split('/').pop() ?? 'unknown',
      operatorId: process.env.SHANNON_OPERATOR ?? process.env.USER ?? 'automated',
      machineId: `${hostname()}-${process.platform}-${process.arch}`,
      shannonVersion: process.env.SHANNON_VERSION ?? '0.0.0-development',
      configHash,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    };

    if (!container.evidenceStore) {
      heartbeat('No evidence store configured, skipping forensic package');
      return;
    }

    const builder = new ForensicPackageBuilder(container.evidenceStore);
    const packageDir = builder.build(input.workspaceDir, custodyMetadata);

    heartbeat(`Forensic package built at ${packageDir}`);
  } catch (error) {
    throw toTemporalError(error);
  }
}
