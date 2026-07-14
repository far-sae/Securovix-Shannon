#!/usr/bin/env node
/**
 * Continuous monitoring — turns point-in-time scans into an always-on attack-surface watch. After a
 * scan, Shannon diffs the confirmed findings against the last stored BASELINE for that target and
 * reports what CHANGED: NEW exposures (a new subdomain, a cert now expiring, a newly-open port, a
 * fresh vuln) and RESOLVED ones. The scheduling itself is external (cron / the dashboard re-invoking
 * a scan with --monitor); this module is the intelligence: a stable finding identity, the diff, and
 * the baseline store.
 *
 * Finding identity is stable across scans: class | target | hash(detail with nonces/numbers
 * normalized), so the same underlying finding matches run-to-run while a genuinely new one stands out.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const MONITOR_DIR = join(homedir(), '.shannon', 'monitor');

function findingId(cls, f) {
  const sig = String(f.detail || '')
    .replace(/[0-9a-f]{6,}/gi, '') // strip nonces / hex tokens
    .replace(/\d+/g, '#') // collapse counts / ports-in-text
    .slice(0, 160);
  const h = createHash('sha1').update(sig).digest('hex').slice(0, 8);
  return `${cls}|${f.target}|${h}`;
}

// Map of stable-id → finding summary for every CONFIRMED finding in a report.
export function reportFindingIds(report) {
  const ids = new Map();
  for (const e of (report.exploits || []).filter((x) => x.confirmed > 0))
    for (const f of e.findings || [])
      ids.set(findingId(e.cls, f), { cls: e.cls, target: f.target, severity: f.severity, detail: f.detail });
  return ids;
}

export function diffReports(baselineFindings, currentReport) {
  const cur = reportFindingIds(currentReport);
  const base = baselineFindings || {};
  const added = [];
  const resolved = [];
  for (const [id, f] of cur) if (!(id in base)) added.push(f);
  for (const id of Object.keys(base)) if (!cur.has(id)) resolved.push(base[id]);
  return { new: added, resolved, total: cur.size };
}

function baselinePath(target) {
  return join(MONITOR_DIR, `${createHash('sha1').update(String(target)).digest('hex').slice(0, 16)}.json`);
}

export function loadBaseline(target) {
  try {
    return JSON.parse(readFileSync(baselinePath(target), 'utf-8'));
  } catch {
    return null;
  }
}

export function saveBaseline(target, report) {
  try {
    mkdirSync(MONITOR_DIR, { recursive: true });
    const findings = Object.fromEntries(reportFindingIds(report));
    writeFileSync(
      baselinePath(target),
      JSON.stringify({ target, savedAt: new Date().toISOString(), findings }, null, 2),
    );
  } catch {}
}

// Diff the report against the last baseline, then persist the new baseline. Returns the delta.
export function runMonitorDiff(target, report) {
  const base = loadBaseline(target);
  const diff = base
    ? diffReports(base.findings, report)
    : {
        new: [...reportFindingIds(report).values()],
        resolved: [],
        total: reportFindingIds(report).size,
        firstRun: true,
      };
  saveBaseline(target, report);
  return { ...diff, previousScanAt: base?.savedAt || null };
}
