export type Team = 'red' | 'blue';

export type PurpleAgentRole =
  | 'red-strategist'
  | 'red-attacker'
  | 'blue-defender'
  | 'blue-ir'
  | 'moderator';

export type PurpleChannel = 'red-internal' | 'blue-internal' | 'cross-team';

export type PurpleMessageType =
  | 'plan'
  | 'exploit-step'
  | 'mitigation'
  | 'detection'
  | 'rebuttal'
  | 'concession'
  | 'final-position';

export interface PurpleMessage {
  id: string;
  round: number;
  channel: PurpleChannel;
  team: Team | 'cross';
  from: PurpleAgentRole;
  to: PurpleAgentRole | 'red-team' | 'blue-team' | 'all';
  type: PurpleMessageType;
  findingRef: string;
  content: string;
  timestamp: string;
}

export interface PurpleFinding {
  id: string;
  category: string;
  endpoint: string;
  severity: string;
  description: string;
  evidence: string;
  exploitPoc?: string;
}

export interface MitigationProposal {
  control: string;
  layer: 'code' | 'config' | 'network' | 'process' | 'monitoring';
  effort: 'low' | 'medium' | 'high';
  rationale: string;
}

export interface DetectionProposal {
  name: string;
  signal: string;
  source: string;
  query?: string;
  rationale: string;
}

export interface FindingConclusion {
  findingId: string;
  exploitable: boolean;
  attackChainSummary: string;
  mitigations: MitigationProposal[];
  detections: DetectionProposal[];
  residualRisk: 'low' | 'medium' | 'high' | 'critical';
  redFinalPosition: string;
  blueFinalPosition: string;
  agreement: boolean;
  rounds: number;
}

export interface PurpleTeamResult {
  conclusions: FindingConclusion[];
  transcript: PurpleMessage[];
  totalRounds: number;
  agreementRate: number;
}
