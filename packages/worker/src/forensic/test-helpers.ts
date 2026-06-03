import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CustodyMetadata, ForensicPayload } from './types.js';

export function tmpWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'shannon-forensic-'));
}

export function makeMetadata(): CustodyMetadata {
  return {
    scanId: 'test-scan',
    operatorId: 'op-1',
    machineId: 'machine-1',
    shannonVersion: '0.0.0-test',
    configHash: 'deadbeef',
    timezone: 'UTC',
  };
}

export function makePayload(description: string): ForensicPayload {
  return { description };
}
