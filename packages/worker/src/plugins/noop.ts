import { ok, type Result } from '../result.js';
import type { CheckpointPlugin, FindingsPlugin, ExternalFinding, ReportPlugin, ReportOutput } from './interfaces.js';

export class NoopCheckpointPlugin implements CheckpointPlugin {
  async save(_agentName: string, _commitHash: string): Promise<Result<void>> {
    return ok(undefined);
  }

  async restore(_agentName: string): Promise<Result<string | null>> {
    return ok(null);
  }
}

export class NoopFindingsPlugin implements FindingsPlugin {
  async inject(_scanId: string): Promise<Result<ExternalFinding[]>> {
    return ok([]);
  }
}

export class NoopReportPlugin implements ReportPlugin {
  async emit(_scanId: string, _report: ReportOutput): Promise<Result<void>> {
    return ok(undefined);
  }
}
