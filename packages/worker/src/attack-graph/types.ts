export type VulnCategory =
  | 'sqli'
  | 'xss'
  | 'ssrf'
  | 'auth-bypass'
  | 'authz-bypass'
  | 'rce'
  | 'credential-theft'
  | 'business-logic'
  // Track B classes (typed now; agents added in Phase 3+)
  | 'rce-ssti'
  | 'rce-deser'
  | 'token-forgery'
  | 'prompt-injection'
  | 'graphql-idor'
  | 'request-smuggling';

export interface VulnNode {
  id: string;
  category: VulnCategory;
  endpoint: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  preconditions: string[];
  postconditions: string[];
  feasibilityScore: number;
  evidence: string;
}

export interface Edge {
  from: string;
  to: string;
  transitionType: 'enables' | 'amplifies' | 'requires';
  confidence: number;
}

export interface AttackChain {
  id: string;
  nodes: VulnNode[];
  edges: Edge[];
  entryPoint: VulnNode;
  objective: string;
  compositeScore: number;
  estimatedImpact: 'critical' | 'high' | 'medium' | 'low';
  mitreTactics: string[];
}

export interface ChainAnalysisResult {
  graph: { nodes: VulnNode[]; edges: Edge[] };
  chains: AttackChain[];
  highestScoringChain: AttackChain | null;
  executionPlan: string[];
}
