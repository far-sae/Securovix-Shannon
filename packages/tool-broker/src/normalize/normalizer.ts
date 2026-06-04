export interface NormalizedToolFinding {
  tool: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  detail: string;
  raw: string;
}

// sqlmap --results-file CSV: "Target URL,Place,Parameter,Technique(s),Note(s)".
export function normalizeSqlmapCsv(csv: string): NormalizedToolFinding[] {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length <= 1) return [];
  const out: NormalizedToolFinding[] = [];
  for (const line of lines.slice(1)) {
    const cols = line.split(',');
    if (cols.length < 4) continue;
    const [target, place, parameter, technique] = cols;
    out.push({
      tool: 'sqlmap',
      severity: 'high',
      target,
      detail: `SQL injection in parameter '${parameter}' (${place}) via technique ${technique}`,
      raw: line,
    });
  }
  return out;
}

// nuclei -jsonl: one JSON object per line.
export function normalizeNucleiJsonl(jsonl: string): NormalizedToolFinding[] {
  const out: NormalizedToolFinding[] = [];
  for (const line of jsonl.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const o = JSON.parse(trimmed) as {
        'template-id'?: string;
        info?: { severity?: string; name?: string };
        host?: string;
        'matched-at'?: string;
      };
      const sev = o.info?.severity as NormalizedToolFinding['severity'] | undefined;
      out.push({
        tool: 'nuclei',
        severity: sev,
        target: o['matched-at'] ?? o.host ?? '',
        detail: `${o['template-id'] ?? 'template'}: ${o.info?.name ?? ''}`.trim(),
        raw: trimmed,
      });
    } catch {
      // malformed line — skip
    }
  }
  return out;
}

// ffuf -of json: { results: [{ url, status, length }] }.
export function normalizeFfufJson(json: string): NormalizedToolFinding[] {
  if (!json.trim()) return [];
  try {
    const o = JSON.parse(json) as { results?: Array<{ url?: string; status?: number; length?: number }> };
    return (o.results ?? []).map((r) => ({
      tool: 'ffuf',
      severity: 'info' as const,
      target: r.url ?? '',
      detail: `status=${r.status ?? '?'} length=${r.length ?? '?'}`,
      raw: JSON.stringify(r),
    }));
  } catch {
    return [];
  }
}
