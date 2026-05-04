export type DeceptionType = 'honeypot' | 'canary-token' | 'decoy-credential' | 'deception-network' | 'tarpit';

export interface DeceptionSignal {
  type: DeceptionType;
  indicator: string;
  confidence: number;
  source: 'heuristic' | 'behavioral' | 'llm';
  details: string;
}

export interface DeceptionVerdict {
  endpoint: string;
  isDecoy: boolean;
  confidence: number;
  signals: DeceptionSignal[];
  recommendation: 'skip' | 'proceed-cautiously' | 'safe';
}

export interface HoneypotFingerprint {
  responseTimeMs: number;
  responseTimeDeviation: number;
  unusualHeaders: string[];
  missingExpectedHeaders: string[];
  serverBannerMismatch: boolean;
  overpermissiveAuth: boolean;
  fakeDataPatterns: boolean;
  canaryTokensFound: string[];
  acceptsAllInput: boolean;
  identicalErrorResponses: boolean;
  tarpitDetected: boolean;
}
