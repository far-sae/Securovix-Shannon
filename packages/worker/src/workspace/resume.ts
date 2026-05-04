import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { SessionManager } from './session.js';
import { GitCheckpoint } from './git-checkpoint.js';
import { type Result, ok, err } from '../result.js';

export class ResumeManager {
  private sessionMgr: SessionManager;
  private gitCheckpoint: GitCheckpoint;
  private workspaceDir: string;

  constructor(workspaceDir: string) {
    this.workspaceDir = workspaceDir;
    this.sessionMgr = new SessionManager(workspaceDir);
    this.gitCheckpoint = new GitCheckpoint(workspaceDir);
  }

  shouldSkipAgent(agentName: string): boolean {
    if (!this.sessionMgr.isAgentCompleted(agentName)) return false;

    // Validate deliverables still exist
    return this.validateDeliverables(agentName);
  }

  private validateDeliverables(agentName: string): boolean {
    const deliverablePaths = this.getExpectedDeliverables(agentName);
    return deliverablePaths.every((p) => existsSync(p));
  }

  private getExpectedDeliverables(agentName: string): string[] {
    if (agentName === 'pre-recon') {
      return [join(this.workspaceDir, 'pre-recon', 'nmap-raw.txt')];
    }
    if (agentName === 'recon') {
      return [join(this.workspaceDir, 'recon', 'exploration.md')];
    }
    if (agentName.startsWith('vuln-')) {
      const cat = agentName.replace('vuln-', '');
      return [
        join(this.workspaceDir, 'vuln', cat, 'analysis.md'),
        join(this.workspaceDir, 'vuln', cat, 'exploitation-queue.json'),
      ];
    }
    if (agentName.startsWith('exploit-')) {
      const cat = agentName.replace('exploit-', '');
      return [join(this.workspaceDir, 'exploit', cat, 'exploit-report.md')];
    }
    return [];
  }

  async restoreCheckpoint(agentName: string): Promise<Result<void>> {
    const checkpoint = await this.gitCheckpoint.getCheckpoint(`post-${agentName}`);
    if (checkpoint) {
      return this.gitCheckpoint.restoreTo(checkpoint);
    }
    return ok(undefined);
  }
}
