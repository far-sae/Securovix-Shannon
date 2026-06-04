// The pure data contract shared across the broker core. No behavior here.

export type ScopeDecisionReason =
  | 'in-scope'
  | 'out-of-scope-host'
  | 'denied-private'
  | 'denied-metadata'
  | 'denied-loopback'
  | 'denied-link-local'
  | 'path-not-allowed'
  | 'path-avoided';

export interface ScopeDecision {
  allowed: boolean;
  reason: ScopeDecisionReason;
  detail?: string;
}

export interface ScopeConfig {
  targetHost: string;
  targetIps: string[];
  allowlistCidrs: string[];
  allowPrivateCidrs: string[];
  focusPaths: string[];
  avoidPaths: string[];
}

export interface ToolParamSpec {
  name: string;
  flag?: string;
  required?: boolean;
  pattern?: string;
  enumValues?: string[];
}

export interface ToolDescriptor {
  id: string;
  bin: string;
  params: ToolParamSpec[];
  blocklist: string[];
  oobRequired?: boolean;
}

export interface ToolRequest {
  tool: string;
  params: Record<string, string | number>;
  scanId: string;
  scopeToken: string;
}

export type ToolStatus =
  | 'success'
  | 'blocked'
  | 'rate-limited'
  | 'error'
  | 'timeout'
  | 'budget'
  | 'scope'
  | 'oob-blocked'
  | 'auth-expired';

export interface ToolResult {
  tool: string;
  status: ToolStatus;
  argv?: string[];
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  durationMs?: number;
  oobHits?: string[];
  rawArtifactRef?: string;
}

export interface InvocationRecord {
  scanId: string;
  tool: string;
  argvHash: string;
  status: ToolStatus;
  exitCode?: number;
  durationMs?: number;
  timestamp: string;
  signature: string;
}

export type BudgetKind = 'toolInvocations' | 'httpRequests' | 'wallClockMs' | 'costUsd';
