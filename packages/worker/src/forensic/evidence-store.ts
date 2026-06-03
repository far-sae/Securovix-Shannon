import Database from 'better-sqlite3';
import { join } from 'node:path';
import type { ForensicEntry, CustodyMetadata, EvidencePackage } from './types.js';
import { EvidenceChainHasher } from './hasher.js';
import { createHash } from 'node:crypto';

export class EvidenceStore {
  private db: Database.Database;
  private hasher: EvidenceChainHasher;

  constructor(workspaceDir: string) {
    const dbPath = join(workspaceDir, 'evidence.db');
    this.db = new Database(dbPath);
    this.hasher = new EvidenceChainHasher();
    this.initSchema();
    this.restoreHasherState();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS evidence_chain (
        sequence_number INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        metadata TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_agent ON evidence_chain(agent_name);
      CREATE INDEX IF NOT EXISTS idx_type ON evidence_chain(action_type);
    `);
  }

  private restoreHasherState(): void {
    const last = this.db
      .prepare('SELECT * FROM evidence_chain ORDER BY sequence_number DESC LIMIT 1')
      .get() as
      | {
          sequence_number: number;
          timestamp: string;
          previous_hash: string;
          current_hash: string;
          agent_name: string;
          action_type: string;
          payload: string;
          metadata: string;
        }
      | undefined;

    if (!last) return; // empty chain — hasher stays at genesis

    // Recompute the last entry's hash from its stored fields. A mismatch means the
    // evidence.db was corrupted or tampered with — fail loud rather than silently
    // resetting to genesis (which would fork the chain on the next append).
    const recomputed = createHash('sha256')
      .update(
        JSON.stringify({
          sequenceNumber: last.sequence_number,
          timestamp: last.timestamp,
          previousHash: last.previous_hash,
          agentName: last.agent_name,
          actionType: last.action_type,
          payload: JSON.parse(last.payload),
          metadata: JSON.parse(last.metadata),
        }),
      )
      .digest('hex');

    if (recomputed !== last.current_hash) {
      throw new Error(
        `Evidence chain integrity error: last entry (seq ${last.sequence_number}) hash ` +
          'does not recompute on restore. evidence.db may be corrupted or tampered with.',
      );
    }

    // Continue the chain from the last persisted entry.
    this.hasher.seedState(last.current_hash, last.sequence_number + 1);
  }

  private append(entry: ForensicEntry): void {
    this.db.prepare(`
      INSERT INTO evidence_chain (sequence_number, timestamp, previous_hash, current_hash, agent_name, action_type, payload, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.sequenceNumber,
      entry.timestamp,
      entry.previousHash,
      entry.currentHash,
      entry.agentName,
      entry.actionType,
      JSON.stringify(entry.payload),
      JSON.stringify(entry.metadata),
    );
  }

  record(
    agentName: string,
    actionType: ForensicEntry['actionType'],
    payload: ForensicEntry['payload'],
    metadata: CustodyMetadata,
  ): ForensicEntry {
    const entry = this.hasher.computeHash(agentName, actionType, payload, metadata);
    this.append(entry);
    return entry;
  }

  getAll(): ForensicEntry[] {
    const rows = this.db.prepare('SELECT * FROM evidence_chain ORDER BY sequence_number').all() as Array<{
      sequence_number: number;
      timestamp: string;
      previous_hash: string;
      current_hash: string;
      agent_name: string;
      action_type: string;
      payload: string;
      metadata: string;
    }>;

    return rows.map((row) => ({
      sequenceNumber: row.sequence_number,
      timestamp: row.timestamp,
      previousHash: row.previous_hash,
      currentHash: row.current_hash,
      agentName: row.agent_name,
      actionType: row.action_type as ForensicEntry['actionType'],
      payload: JSON.parse(row.payload),
      metadata: JSON.parse(row.metadata),
    }));
  }

  getByAgent(agentName: string): ForensicEntry[] {
    const rows = this.db.prepare('SELECT * FROM evidence_chain WHERE agent_name = ? ORDER BY sequence_number').all(agentName) as Array<{
      sequence_number: number;
      timestamp: string;
      previous_hash: string;
      current_hash: string;
      agent_name: string;
      action_type: string;
      payload: string;
      metadata: string;
    }>;

    return rows.map((row) => ({
      sequenceNumber: row.sequence_number,
      timestamp: row.timestamp,
      previousHash: row.previous_hash,
      currentHash: row.current_hash,
      agentName: row.agent_name,
      actionType: row.action_type as ForensicEntry['actionType'],
      payload: JSON.parse(row.payload),
      metadata: JSON.parse(row.metadata),
    }));
  }

  getByType(actionType: ForensicEntry['actionType']): ForensicEntry[] {
    const rows = this.db.prepare('SELECT * FROM evidence_chain WHERE action_type = ? ORDER BY sequence_number').all(actionType) as Array<{
      sequence_number: number;
      timestamp: string;
      previous_hash: string;
      current_hash: string;
      agent_name: string;
      action_type: string;
      payload: string;
      metadata: string;
    }>;

    return rows.map((row) => ({
      sequenceNumber: row.sequence_number,
      timestamp: row.timestamp,
      previousHash: row.previous_hash,
      currentHash: row.current_hash,
      agentName: row.agent_name,
      actionType: row.action_type as ForensicEntry['actionType'],
      payload: JSON.parse(row.payload),
      metadata: JSON.parse(row.metadata),
    }));
  }

  verifyIntegrity(): { valid: boolean; brokenAt?: number } {
    return EvidenceChainHasher.verifyChain(this.getAll());
  }

  buildPackage(custodyMetadata: CustodyMetadata): EvidencePackage {
    const entries = this.getAll();
    const integrity = this.verifyIntegrity();

    const manifestContent = JSON.stringify({ entries, custodyMetadata });
    const manifestHash = createHash('sha256').update(manifestContent).digest('hex');

    return {
      manifestHash,
      entryCount: entries.length,
      firstEntry: entries[0]?.timestamp ?? '',
      lastEntry: entries[entries.length - 1]?.timestamp ?? '',
      chainIntegrity: integrity.valid,
      custodyRecord: custodyMetadata,
      entries,
    };
  }

  close(): void {
    this.db.close();
  }
}
