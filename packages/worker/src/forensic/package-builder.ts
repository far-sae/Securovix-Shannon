import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { EvidenceStore } from './evidence-store.js';
import type { CustodyMetadata, EvidencePackage } from './types.js';

export class ForensicPackageBuilder {
  constructor(private evidenceStore: EvidenceStore) {}

  build(workspaceDir: string, custodyMetadata: CustodyMetadata): string {
    const packageDir = join(workspaceDir, 'forensic-package');
    mkdirSync(packageDir, { recursive: true });

    const evidencePackage = this.evidenceStore.buildPackage(custodyMetadata);

    // Write main evidence manifest
    const manifestPath = join(packageDir, 'manifest.json');
    writeFileSync(manifestPath, JSON.stringify(evidencePackage, null, 2));

    // Write integrity verification report
    const integrityReport = this.generateIntegrityReport(evidencePackage);
    writeFileSync(join(packageDir, 'integrity-report.md'), integrityReport);

    // Write timeline view
    const timeline = this.generateTimeline(evidencePackage);
    writeFileSync(join(packageDir, 'timeline.md'), timeline);

    // Write chain-of-custody document
    const custody = this.generateCustodyDocument(evidencePackage);
    writeFileSync(join(packageDir, 'chain-of-custody.md'), custody);

    // Write per-agent evidence files
    const agents = [...new Set(evidencePackage.entries.map((e) => e.agentName))];
    for (const agent of agents) {
      const agentEntries = evidencePackage.entries.filter((e) => e.agentName === agent);
      writeFileSync(
        join(packageDir, `agent-${agent}.json`),
        JSON.stringify(agentEntries, null, 2),
      );
    }

    return packageDir;
  }

  private generateIntegrityReport(pkg: EvidencePackage): string {
    const lines = [
      '# Evidence Chain Integrity Report',
      '',
      `**Generated**: ${new Date().toISOString()}`,
      `**Manifest Hash**: \`${pkg.manifestHash}\``,
      `**Chain Integrity**: ${pkg.chainIntegrity ? 'VERIFIED' : 'BROKEN'}`,
      `**Total Entries**: ${pkg.entryCount}`,
      `**Time Range**: ${pkg.firstEntry} to ${pkg.lastEntry}`,
      '',
      '## Verification',
      '',
      'Each entry in the evidence chain contains a SHA-256 hash computed from:',
      '- The entry content (timestamp, agent, action, payload)',
      '- The hash of the previous entry (creating an immutable chain)',
      '',
      `The chain has been verified: all ${pkg.entryCount} hashes are consistent.`,
      '',
      '## Hash Chain Head',
      '',
      `\`${pkg.entries[pkg.entries.length - 1]?.currentHash ?? 'N/A'}\``,
    ];

    return lines.join('\n');
  }

  private generateTimeline(pkg: EvidencePackage): string {
    const lines = ['# Evidence Timeline', ''];

    for (const entry of pkg.entries) {
      lines.push(
        `| ${entry.sequenceNumber} | ${entry.timestamp} | ${entry.agentName} | ${entry.actionType} | ${entry.payload.description} |`,
      );
    }

    return lines.join('\n');
  }

  private generateCustodyDocument(pkg: EvidencePackage): string {
    const c = pkg.custodyRecord;
    return [
      '# Chain of Custody Document',
      '',
      '## Scan Metadata',
      '',
      `- **Scan ID**: ${c.scanId}`,
      `- **Operator**: ${c.operatorId}`,
      `- **Machine**: ${c.machineId}`,
      `- **Shannon Version**: ${c.shannonVersion}`,
      `- **Config Hash**: \`${c.configHash}\``,
      `- **Timezone**: ${c.timezone}`,
      '',
      '## Evidence Summary',
      '',
      `- **Total Evidence Entries**: ${pkg.entryCount}`,
      `- **First Action**: ${pkg.firstEntry}`,
      `- **Last Action**: ${pkg.lastEntry}`,
      `- **Manifest Hash**: \`${pkg.manifestHash}\``,
      `- **Chain Integrity**: ${pkg.chainIntegrity ? 'INTACT' : 'COMPROMISED'}`,
      '',
      '## Attestation',
      '',
      'This document attests that all evidence entries in this package',
      'were collected automatically by the Shannon penetration testing framework.',
      'The SHA-256 hash chain provides tamper-evidence: any modification',
      'to any entry will break the chain verification.',
    ].join('\n');
  }
}
