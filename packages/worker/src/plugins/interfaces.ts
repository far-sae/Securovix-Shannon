import type { Result } from '../result.js';

export interface CheckpointPlugin {
  save(agentName: string, commitHash: string): Promise<Result<void>>;
  restore(agentName: string): Promise<Result<string | null>>;
}

export interface ExternalFinding {
  source: string;
  type: string;
  severity: string;
  description: string;
  evidence?: string;
}

export interface FindingsPlugin {
  inject(scanId: string): Promise<Result<ExternalFinding[]>>;
}

export interface ReportOutput {
  format: string;
  content: string;
}

export interface ReportPlugin {
  emit(scanId: string, report: ReportOutput): Promise<Result<void>>;
}
