import { ACTIVE_VULN_CATEGORIES } from '../workflows/categories.js';

export type ModelTier = 'small' | 'medium' | 'large';

const DEFAULT_MODELS: Record<ModelTier, string> = {
  small: 'claude-haiku-4-5-20251001',
  medium: 'claude-sonnet-4-6',
  large: 'claude-opus-4-6',
};

export function resolveModel(tier: ModelTier, overrides?: Partial<Record<ModelTier, string>>): string {
  // Environment variable overrides take highest priority
  const envKey = `SHANNON_MODEL_${tier.toUpperCase()}`;
  const envOverride = process.env[envKey];
  if (envOverride) return envOverride;

  // Config overrides
  if (overrides?.[tier]) return overrides[tier]!;

  return DEFAULT_MODELS[tier];
}

export const AGENT_TIERS: Record<string, ModelTier> = {
  'pre-recon': 'medium',
  'recon': 'large',
  'vuln-sqli': 'large',
  'vuln-xss': 'large',
  'vuln-auth-bypass': 'large',
  'vuln-authz-bypass': 'large',
  'vuln-ssrf': 'large',
  'exploit-sqli': 'large',
  'exploit-xss': 'large',
  'exploit-auth-bypass': 'large',
  'exploit-authz-bypass': 'large',
  'exploit-ssrf': 'large',
  'report': 'medium',

  // Module 1: Attack Chain Graph
  'chain-analysis': 'large',
  'chain-exploit': 'large',

  // Module 2: Counter-Deception
  'deception-scan': 'medium',

  // Module 3: Business Logic
  'vuln-business-logic': 'large',
  'exploit-business-logic': 'large',

  // Module 4: War Room
  'war-room-lead': 'large',
  'war-room-adversary': 'large',
  'war-room-skeptic': 'medium',
  'war-room-moderator': 'medium',

  // Module 4.7: Purple Team (Red x Blue)
  'purple-red-strategist': 'large',
  'purple-red-attacker': 'large',
  'purple-blue-defender': 'large',
  'purple-blue-ir': 'medium',
  'purple-moderator': 'medium',

  // Module 5: Forensic
  'forensic-summary': 'small',
};

// Fail loud at startup if an active category is missing a tier (avoids the silent
// 'medium' fallback in client.ts). Call once during worker bootstrap.
export function validateAgentTiers(): void {
  const missing: string[] = [];
  for (const c of ACTIVE_VULN_CATEGORIES) {
    if (!AGENT_TIERS[`vuln-${c}`]) missing.push(`vuln-${c}`);
    if (!AGENT_TIERS[`exploit-${c}`]) missing.push(`exploit-${c}`);
  }
  if (missing.length > 0) {
    throw new Error(`Missing model tier for agents: ${missing.join(', ')}. Add them to AGENT_TIERS in tiers.ts.`);
  }
}
