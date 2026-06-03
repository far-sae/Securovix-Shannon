import { createHash } from 'node:crypto';
import type { ForensicEntry, ForensicPayload, CustodyMetadata } from './types.js';

export class EvidenceChainHasher {
  private previousHash: string = '0'.repeat(64);
  private sequenceNumber: number = 0;

  computeHash(
    agentName: string,
    actionType: ForensicEntry['actionType'],
    payload: ForensicPayload,
    metadata: CustodyMetadata,
  ): ForensicEntry {
    const timestamp = new Date().toISOString();
    const seq = this.sequenceNumber++;
    const prev = this.previousHash;

    const contentToHash = JSON.stringify({
      sequenceNumber: seq,
      timestamp,
      previousHash: prev,
      agentName,
      actionType,
      payload,
      metadata,
    });

    const currentHash = createHash('sha256').update(contentToHash).digest('hex');
    this.previousHash = currentHash;

    return {
      sequenceNumber: seq,
      timestamp,
      previousHash: prev,
      currentHash,
      agentName,
      actionType,
      payload,
      metadata,
    };
  }

  static verifyChain(entries: ForensicEntry[]): { valid: boolean; brokenAt?: number } {
    if (entries.length === 0) return { valid: true };

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Verify previous hash linkage
      if (i === 0) {
        if (entry.previousHash !== '0'.repeat(64)) {
          return { valid: false, brokenAt: 0 };
        }
      } else {
        if (entry.previousHash !== entries[i - 1].currentHash) {
          return { valid: false, brokenAt: i };
        }
      }

      // Verify current hash
      const contentToHash = JSON.stringify({
        sequenceNumber: entry.sequenceNumber,
        timestamp: entry.timestamp,
        previousHash: entry.previousHash,
        agentName: entry.agentName,
        actionType: entry.actionType,
        payload: entry.payload,
        metadata: entry.metadata,
      });

      const expectedHash = createHash('sha256').update(contentToHash).digest('hex');
      if (entry.currentHash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }

    return { valid: true };
  }

  getHead(): { hash: string; sequence: number } {
    return { hash: this.previousHash, sequence: this.sequenceNumber };
  }

  seedState(previousHash: string, sequenceNumber: number): void {
    this.previousHash = previousHash;
    this.sequenceNumber = sequenceNumber;
  }
}
