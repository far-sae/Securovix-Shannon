import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export class AuditLogger {
  private logPath: string;

  constructor(workspaceDir: string, filename: string = 'audit.jsonl') {
    const logDir = join(workspaceDir, 'audit');
    mkdirSync(logDir, { recursive: true });
    this.logPath = join(logDir, filename);
  }

  log(level: LogLevel, agent: string, message: string, data?: Record<string, unknown>): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      agent,
      message,
      ...data,
    };

    appendFileSync(this.logPath, JSON.stringify(entry) + '\n');
  }
}
