import { join } from 'node:path';
import Database from 'better-sqlite3';

// Track A — the Learning Brain substrate. A persistent, cross-scan store keyed by a
// target FINGERPRINT (a hash of stack indicators). It lets a later scan recall what was
// found on similar targets and which evasion techniques actually beat which WAF — so
// Shannon compounds intelligence instead of starting cold every time.

export interface KnowledgeFinding {
  fingerprint: string;
  category: string;
  endpoint: string;
  severity: string;
  verified: boolean;
  scanId: string;
  timestamp: string;
}

export interface EvasionOutcome {
  fingerprint: string;
  technique: string;
  wafVendor: string;
  success: boolean;
  scanId: string;
}

interface FindingRow {
  fingerprint: string;
  category: string;
  endpoint: string;
  severity: string;
  verified: number;
  scan_id: string;
  ts: string;
}
interface EvasionRow {
  technique: string;
  wins: number;
  attempts: number;
}

export class KnowledgeStore {
  private db: Database.Database;

  constructor(dir: string) {
    this.db = new Database(join(dir, 'knowledge.db'));
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        fingerprint TEXT NOT NULL, category TEXT NOT NULL, endpoint TEXT NOT NULL,
        severity TEXT NOT NULL, verified INTEGER NOT NULL, scan_id TEXT NOT NULL, ts TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
      CREATE TABLE IF NOT EXISTS evasions (
        fingerprint TEXT NOT NULL, technique TEXT NOT NULL, waf_vendor TEXT NOT NULL,
        success INTEGER NOT NULL, scan_id TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_evasions_fp ON evasions(fingerprint, waf_vendor);
    `);
  }

  recordFinding(f: KnowledgeFinding): void {
    this.db
      .prepare(
        'INSERT INTO findings (fingerprint, category, endpoint, severity, verified, scan_id, ts) VALUES (?,?,?,?,?,?,?)',
      )
      .run(f.fingerprint, f.category, f.endpoint, f.severity, f.verified ? 1 : 0, f.scanId, f.timestamp);
  }

  // What has been found before on targets with this fingerprint — prioritises the next scan.
  recallFindings(fingerprint: string): KnowledgeFinding[] {
    const rows = this.db
      .prepare('SELECT * FROM findings WHERE fingerprint = ? ORDER BY ts DESC')
      .all(fingerprint) as FindingRow[];
    return rows.map((r) => ({
      fingerprint: r.fingerprint,
      category: r.category,
      endpoint: r.endpoint,
      severity: r.severity,
      verified: r.verified === 1,
      scanId: r.scan_id,
      timestamp: r.ts,
    }));
  }

  recordEvasion(e: EvasionOutcome): void {
    this.db
      .prepare('INSERT INTO evasions (fingerprint, technique, waf_vendor, success, scan_id) VALUES (?,?,?,?,?)')
      .run(e.fingerprint, e.technique, e.wafVendor, e.success ? 1 : 0, e.scanId);
  }

  // Techniques that have beaten this WAF on similar targets, best win-rate first — so the
  // evasion engine tries what worked before instead of rediscovering it.
  recallWinningEvasions(fingerprint: string, wafVendor: string): string[] {
    const rows = this.db
      .prepare(
        `SELECT technique, SUM(success) AS wins, COUNT(*) AS attempts
         FROM evasions WHERE fingerprint = ? AND waf_vendor = ?
         GROUP BY technique HAVING wins > 0
         ORDER BY (CAST(wins AS REAL) / attempts) DESC, wins DESC`,
      )
      .all(fingerprint, wafVendor) as EvasionRow[];
    return rows.map((r) => r.technique);
  }

  close(): void {
    this.db.close();
  }
}
