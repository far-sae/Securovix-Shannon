export type AgentRole = 'red-team-lead' | 'adversary-sim' | 'skeptic' | 'moderator';

export interface WarRoomMessage {
  id: string;
  from: AgentRole;
  to: AgentRole | 'all';
  timestamp: string;
  round: number;
  type: 'assertion' | 'challenge' | 'evidence' | 'concession' | 'verdict';
  findingRef: string;
  content: string;
  structuredData?: Record<string, unknown>;
}

export interface MitreMapping {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  subtechniqueId?: string;
  confidence: number;
}

export interface FindingVerdict {
  findingId: string;
  originalSeverity: string;
  adjustedSeverity: string;
  confirmedFalsePositive: boolean;
  mitreMappings: MitreMapping[];
  debateRounds: number;
  consensusReached: boolean;
  redTeamNotes: string;
  skepticChallenges: string[];
  finalAssessment: string;
}

export interface WarRoomResult {
  findings: FindingVerdict[];
  eliminatedCount: number;
  escalatedCount: number;
  totalDebateRounds: number;
  transcript: WarRoomMessage[];
}

export interface FindingInput {
  id: string;
  category: string;
  endpoint: string;
  severity: string;
  description: string;
  evidence: string;
  exploitPoc?: string;
}
