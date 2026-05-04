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

export interface ShannonConfig {
  target: TargetConfig;
  authentication?: AuthConfig;
  pipeline?: PipelineConfig;
  models?: ModelOverrides;
  loginInstructions?: string;
}
