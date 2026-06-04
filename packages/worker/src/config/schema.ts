export type AuthType = 'form' | 'sso' | 'api-key' | 'http-basic';

export interface AuthConfig {
  type: AuthType;
  loginUrl?: string;
  username?: string;
  password?: string;
  apiKey?: string;
  totpSecret?: string;
  ssoProvider?: string;
  customHeaders?: Record<string, string>;
}

export interface UrlRules {
  focus?: string[];
  avoid?: string[];
}

export type RetryPreset = 'default' | 'fast' | 'subscription';

export interface PipelineConfig {
  retryPreset?: RetryPreset;
  maxConcurrentPipelines?: number;
}

export interface TargetConfig {
  url: string;
  repoPath?: string;
  urls?: UrlRules;
}

export interface ModelOverrides {
  small?: string;
  medium?: string;
  large?: string;
}

export interface ScopeConfig {
  // Extra in-scope IPv4 CIDRs beyond the target host (always implicitly in scope).
  allowlistCidrs?: string[];
  // Private/link-local CIDRs to explicitly re-allow (overrides the broker's baked-in
  // deny of RFC1918/metadata/localhost). Use with care; Phase 1 broker enforces this.
  allowPrivateCidrs?: string[];
}

export interface BudgetConfig {
  maxToolInvocations?: number;
  maxHttpRequests?: number;
  maxWallClockMs?: number;
  maxCostUsd?: number;
}

export type OOBMode = 'reflected-only' | 'self-hosted';

export interface OOBConfig {
  mode?: OOBMode; // default 'reflected-only' in Phase 1
  serverUrl?: string; // self-hosted interactsh server base URL
  // Auth token is a SECRET HANDLE (resolved by the broker), never a raw secret here.
  tokenHandle?: string;
}

export interface BrokerConfig {
  // Phase 1 wires runtime enforcement; Phase 0 only validates the shape.
  allowStateChanging?: boolean; // default false
  // PEM public key (or handle) used to verify the signed scope-lock token. Phase 1.
  scopeLockPublicKey?: string;
  scope?: ScopeConfig;
  budgets?: BudgetConfig;
  oob?: OOBConfig;
}

export interface ShannonConfig {
  target: TargetConfig;
  authentication?: AuthConfig;
  pipeline?: PipelineConfig;
  models?: ModelOverrides;
  loginInstructions?: string;
  broker?: BrokerConfig;
}
