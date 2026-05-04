export interface ForensicEntry {
  sequenceNumber: number;
  timestamp: string;
  previousHash: string;
  currentHash: string;
  agentName: string;
  actionType:
    | 'http-request'
    | 'http-response'
    | 'llm-call'
    | 'file-write'
    | 'exploit-attempt'
    | 'finding-confirmed'
    | 'checkpoint'
    | 'browser-action';
  payload: ForensicPayload;
  metadata: CustodyMetadata;
}

export interface ForensicPayload {
  httpMethod?: string;
  httpUrl?: string;
  httpHeaders?: Record<string, string>;
  httpBody?: string;
  httpStatus?: number;
  httpResponseHeaders?: Record<string, string>;
  httpResponseBody?: string;
  httpDurationMs?: number;
  llmModel?: string;
  llmPromptHash?: string;
  llmResponseHash?: string;
  llmTokensIn?: number;
  llmTokensOut?: number;
  filePath?: string;
  fileContentHash?: string;
  browserAction?: string;
  screenshotPath?: string;
  description: string;
}

export interface CustodyMetadata {
  scanId: string;
  operatorId: string;
  machineId: string;
  shannonVersion: string;
  configHash: string;
  timezone: string;
}

export interface EvidencePackage {
  manifestHash: string;
  entryCount: number;
  firstEntry: string;
  lastEntry: string;
  chainIntegrity: boolean;
  custodyRecord: CustodyMetadata;
  entries: ForensicEntry[];
}
