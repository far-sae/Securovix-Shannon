export type DetectionType =
  | 'waf-block'
  | 'rate-limit'
  | 'captcha'
  | 'ip-block'
  | 'session-invalidation'
  | 'tarpit'
  | 'fingerprint-challenge';

export interface DetectionSignal {
  type: DetectionType;
  timestamp: string;
  httpStatus: number;
  responseIndicators: string[];
  requestThatTriggered: string;
  confidence: number;
}

export type EvasionTechnique =
  | 'timing-jitter'
  | 'timing-slowdown'
  | 'payload-double-encode'
  | 'payload-unicode'
  | 'payload-case-variation'
  | 'payload-comment-inject'
  | 'payload-chunked'
  | 'header-rotation'
  | 'method-override'
  | 'path-normalization'
  | 'parameter-pollution'
  | 'session-rotation'
  | 'ip-rotation';

export interface EvasionStrategy {
  techniques: EvasionTechnique[];
  priority: number;
  effectiveness: number;
  lastUsed: string;
  successCount: number;
  failureCount: number;
}

export interface EvasionProfile {
  targetHost: string;
  detectedWAF: string | null;
  detectionHistory: DetectionSignal[];
  activeStrategies: EvasionStrategy[];
  failedStrategies: EvasionTechnique[];
  currentTimingMs: number;
  requestsSinceLastDetection: number;
}
