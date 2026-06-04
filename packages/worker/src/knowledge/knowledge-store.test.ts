import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KnowledgeStore } from './knowledge-store.js';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'shannon-knowledge-'));
}

const FP = 'flask-jinja2-werkzeug';

describe('KnowledgeStore findings', () => {
  it('recalls findings by fingerprint, newest first', () => {
    const s = new KnowledgeStore(tmp());
    s.recordFinding({
      fingerprint: FP,
      category: 'rce-ssti',
      endpoint: '/a',
      severity: 'critical',
      verified: true,
      scanId: 's1',
      timestamp: '2026-06-01T00:00:00Z',
    });
    s.recordFinding({
      fingerprint: FP,
      category: 'xss',
      endpoint: '/b',
      severity: 'medium',
      verified: false,
      scanId: 's2',
      timestamp: '2026-06-02T00:00:00Z',
    });
    s.recordFinding({
      fingerprint: 'other',
      category: 'sqli',
      endpoint: '/c',
      severity: 'high',
      verified: true,
      scanId: 's3',
      timestamp: '2026-06-03T00:00:00Z',
    });
    const recalled = s.recallFindings(FP);
    expect(recalled).toHaveLength(2);
    expect(recalled[0].category).toBe('xss'); // newest first
    expect(recalled[0].verified).toBe(false);
    expect(recalled.every((f) => f.fingerprint === FP)).toBe(true);
    s.close();
  });

  it('persists across reopen (compounding across scans)', () => {
    const dir = tmp();
    const s1 = new KnowledgeStore(dir);
    s1.recordFinding({
      fingerprint: FP,
      category: 'rce-ssti',
      endpoint: '/x',
      severity: 'critical',
      verified: true,
      scanId: 's1',
      timestamp: '2026-06-01T00:00:00Z',
    });
    s1.close();
    const s2 = new KnowledgeStore(dir);
    expect(s2.recallFindings(FP)).toHaveLength(1);
    s2.close();
  });
});

describe('KnowledgeStore evasions', () => {
  it('recalls winning evasion techniques ranked by win-rate', () => {
    const s = new KnowledgeStore(tmp());
    const e = (technique: string, success: boolean) =>
      s.recordEvasion({ fingerprint: FP, technique, wafVendor: 'cloudflare', success, scanId: 's1' });
    // unicode: 2/2 wins; double-encode: 1/3 wins; case-variation: 0/2 (never wins)
    e('unicode', true);
    e('unicode', true);
    e('double-encode', true);
    e('double-encode', false);
    e('double-encode', false);
    e('case-variation', false);
    e('case-variation', false);

    const winners = s.recallWinningEvasions(FP, 'cloudflare');
    expect(winners).toEqual(['unicode', 'double-encode']); // by win-rate; losers excluded
    expect(winners).not.toContain('case-variation');
    // wrong WAF vendor → nothing
    expect(s.recallWinningEvasions(FP, 'akamai')).toEqual([]);
    s.close();
  });
});
