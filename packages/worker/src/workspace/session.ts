import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export interface SessionData {
  scanId: string;
  startedAt: string;
  completedAgents: string[];
  metrics: Record<string, AgentMetrics>;
  status: 'running' | 'completed' | 'failed';
}

export interface AgentMetrics {
  cost: number;
  turns: number;
  duration: number;
}

export class SessionManager {
  private sessionPath: string;
  private data: SessionData;

  constructor(workspaceDir: string) {
    this.sessionPath = join(workspaceDir, 'session.json');
    this.data = this.load();
  }

  private load(): SessionData {
    if (existsSync(this.sessionPath)) {
      return JSON.parse(readFileSync(this.sessionPath, 'utf-8'));
    }

    return {
      scanId: '',
      startedAt: new Date().toISOString(),
      completedAgents: [],
      metrics: {},
      status: 'running',
    };
  }

  private save(): void {
    writeFileSync(this.sessionPath, JSON.stringify(this.data, null, 2));
  }

  isAgentCompleted(agentName: string): boolean {
    return this.data.completedAgents.includes(agentName);
  }

  markAgentCompleted(agentName: string): void {
    if (!this.data.completedAgents.includes(agentName)) {
      this.data.completedAgents.push(agentName);
      this.save();
    }
  }

  updateMetrics(agentName: string, metrics: AgentMetrics): void {
    this.data.metrics[agentName] = metrics;
    this.save();
  }

  getAggregateMetrics(): AgentMetrics {
    const agents = Object.values(this.data.metrics);
    return {
      cost: agents.reduce((sum, m) => sum + m.cost, 0),
      turns: agents.reduce((sum, m) => sum + m.turns, 0),
      duration: agents.reduce((sum, m) => sum + m.duration, 0),
    };
  }

  setStatus(status: SessionData['status']): void {
    this.data.status = status;
    this.save();
  }
}
