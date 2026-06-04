import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { InvocationRecord, ToolStatus } from '../types.js';

export interface InvocationInput {
  scanId: string;
  tool: string;
  argv: string[];
  status: ToolStatus;
  exitCode?: number;
  durationMs?: number;
  timestamp: string;
}

function bodyToSign(rec: Omit<InvocationRecord, 'signature'>): string {
  return JSON.stringify({
    scanId: rec.scanId,
    tool: rec.tool,
    argvHash: rec.argvHash,
    status: rec.status,
    exitCode: rec.exitCode ?? null,
    durationMs: rec.durationMs ?? null,
    timestamp: rec.timestamp,
  });
}

export function buildInvocationRecord(input: InvocationInput, key: string): InvocationRecord {
  const argvHash = createHash('sha256').update(JSON.stringify(input.argv)).digest('hex');
  const unsigned: Omit<InvocationRecord, 'signature'> = {
    scanId: input.scanId,
    tool: input.tool,
    argvHash,
    status: input.status,
    exitCode: input.exitCode,
    durationMs: input.durationMs,
    timestamp: input.timestamp,
  };
  const signature = createHmac('sha256', key).update(bodyToSign(unsigned)).digest('hex');
  return { ...unsigned, signature };
}

export function verifyInvocationRecord(rec: InvocationRecord, key: string): boolean {
  const expected = createHmac('sha256', key).update(bodyToSign(rec)).digest('hex');
  const a = Buffer.from(rec.signature, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
