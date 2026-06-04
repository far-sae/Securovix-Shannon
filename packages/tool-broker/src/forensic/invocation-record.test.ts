import { describe, expect, it } from 'vitest';
import { buildInvocationRecord, verifyInvocationRecord } from './invocation-record.js';

const KEY = 'scan-key';
const TS = '2026-06-04T00:00:00.000Z';

describe('InvocationRecord', () => {
  it('builds a signed record that verifies', () => {
    const rec = buildInvocationRecord(
      {
        scanId: 's1',
        tool: 'sqlmap',
        argv: ['sqlmap', '-u', 'https://x/y'],
        status: 'success',
        exitCode: 0,
        durationMs: 12,
        timestamp: TS,
      },
      KEY,
    );
    expect(rec.argvHash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyInvocationRecord(rec, KEY)).toBe(true);
  });
  it('fails verification if any field is tampered', () => {
    const rec = buildInvocationRecord(
      { scanId: 's1', tool: 'sqlmap', argv: ['sqlmap'], status: 'success', timestamp: TS },
      KEY,
    );
    expect(verifyInvocationRecord({ ...rec, status: 'blocked' }, KEY)).toBe(false);
  });
});
