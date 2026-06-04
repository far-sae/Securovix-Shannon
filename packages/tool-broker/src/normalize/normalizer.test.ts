import { describe, expect, it } from 'vitest';
import { normalizeFfufJson, normalizeNucleiJsonl, normalizeSqlmapCsv } from './normalizer.js';

describe('normalizeSqlmapCsv', () => {
  it('parses the results CSV into findings', () => {
    const csv = 'Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://app/v.php?id=1,GET,id,BEUST,\n';
    const f = normalizeSqlmapCsv(csv);
    expect(f).toHaveLength(1);
    expect(f[0].tool).toBe('sqlmap');
    expect(f[0].target).toBe('http://app/v.php?id=1');
    expect(f[0].detail).toContain('id');
  });
  it('returns [] for a header-only / empty CSV', () => {
    expect(normalizeSqlmapCsv('Target URL,Place,Parameter,Technique(s),Note(s)\n')).toEqual([]);
    expect(normalizeSqlmapCsv('')).toEqual([]);
  });
});

describe('normalizeNucleiJsonl', () => {
  it('parses JSONL lines and maps severity', () => {
    const jsonl =
      '{"template-id":"cve-x","info":{"severity":"high","name":"X"},"host":"http://app","matched-at":"http://app/x"}\n' +
      '\n' +
      '{"template-id":"cve-y","info":{"severity":"low","name":"Y"},"host":"http://app","matched-at":"http://app/y"}\n';
    const f = normalizeNucleiJsonl(jsonl);
    expect(f).toHaveLength(2);
    expect(f[0].severity).toBe('high');
    expect(f[0].target).toBe('http://app/x');
  });
  it('skips malformed lines without throwing', () => {
    expect(normalizeNucleiJsonl('not json\n{bad')).toEqual([]);
  });
});

describe('normalizeFfufJson', () => {
  it('parses the results array', () => {
    const json = JSON.stringify({ results: [{ url: 'http://app/admin', status: 200, length: 10 }] });
    const f = normalizeFfufJson(json);
    expect(f).toHaveLength(1);
    expect(f[0].target).toBe('http://app/admin');
    expect(f[0].detail).toContain('200');
  });
  it('returns [] for empty / malformed json', () => {
    expect(normalizeFfufJson('')).toEqual([]);
    expect(normalizeFfufJson('{')).toEqual([]);
  });
});
