import { appendFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentMetrics } from '../workspace/session.js';
import { AuditMutex } from './mutex.js';

export class AuditSession {
  private agentName: string;
  private logDir: string;
  private agentLogPath: string;
  private workflowLogPath: string;
  private promptsDir: string;
  private mutex: AuditMutex;

  constructor(agentName: string, workspaceDir: string) {
    this.agentName = agentName;
    this.logDir = join(workspaceDir, 'audit');
    this.agentLogPath = join(this.logDir, `${agentName}.log`);
    this.workflowLogPath = join(this.logDir, 'workflow.log');
    this.promptsDir = join(this.logDir, 'prompts');
    this.mutex = AuditMutex.getInstance();

    mkdirSync(this.logDir, { recursive: true });
    mkdirSync(this.promptsDir, { recursive: true });
  }

  log(message: string): void {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] [${this.agentName}] ${message}\n`;

    // Agent-specific log (no mutex needed, one writer per agent)
    appendFileSync(this.agentLogPath, line);

    // Shared workflow log (needs mutex)
    this.mutex.acquire(() => {
      appendFileSync(this.workflowLogPath, line);
    });
  }

  logPromptSnapshot(prompt: string): void {
    const snapshotPath = join(this.promptsDir, `${this.agentName}-${Date.now()}.txt`);
    writeFileSync(snapshotPath, prompt);
  }

  trackMetrics(metrics: AgentMetrics): void {
    this.log(`Metrics: cost=$${metrics.cost.toFixed(6)} turns=${metrics.turns} duration=${metrics.duration}ms`);
  }

  close(): void {
    this.log('Agent session closed');
  }
}
