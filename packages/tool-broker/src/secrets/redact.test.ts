import { describe, expect, it } from 'vitest';
import { redact } from './redact.js';

describe('redact', () => {
  it('masks AWS access keys and secret keys', () => {
    expect(redact('key=AKIAIOSFODNN7EXAMPLE')).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redact('AKIAIOSFODNN7EXAMPLE')).toContain('[REDACTED]');
  });
  it('masks bearer tokens and authorization headers', () => {
    const out = redact('Authorization: Bearer abcdef123456ghijkl');
    expect(out).not.toContain('abcdef123456ghijkl');
  });
  it('masks the cloud metadata credentials path marker', () => {
    expect(redact('GET /latest/meta-data/iam/security-credentials/role')).toContain('[REDACTED]');
  });
  it('leaves ordinary text untouched', () => {
    expect(redact('the quick brown fox')).toBe('the quick brown fox');
  });
});
