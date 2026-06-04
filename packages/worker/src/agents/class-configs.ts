import type { VulnCategory } from '../attack-graph/types.js';

// Per-vuln-class agent configuration: the system prompt and the Anthropic tool
// definitions the model may call. Tool `name` equals the broker descriptor id so the
// dispatch routes directly. (Broker descriptors + real tool images for the non-SSTI
// classes are wired during deployment, like the in-house SSTI prober.)
export interface VulnClassConfig {
  category: VulnCategory;
  system: string;
  tools: ReadonlyArray<{ name: string; description: string; input_schema: unknown }>;
}

const urlSchema = (desc: string) => ({
  type: 'object',
  properties: { url: { type: 'string', description: desc } },
  required: ['url'],
});

export const CLASS_CONFIGS: Partial<Record<VulnCategory, VulnClassConfig>> = {
  'rce-ssti': {
    category: 'rce-ssti',
    system:
      'You are an autonomous SSTI testing agent. Use the tool to test the target for server-side template injection (put the payload where the URL has the INJECT marker). Report only tool-CONFIRMED findings.',
    tools: [
      {
        name: 'sstimap',
        description: 'Detect/exploit SSTI at a URL (use the INJECT marker for the payload position).',
        input_schema: urlSchema('Target URL with the INJECT marker'),
      },
    ],
  },
  'token-forgery': {
    category: 'token-forgery',
    system:
      'You are an autonomous JWT/OAuth testing agent. Use the tool to test the target token/endpoint for alg-confusion, weak secrets, kid injection, and OAuth flow flaws. Report only tool-CONFIRMED findings (a forged token the target accepts).',
    tools: [
      {
        name: 'jwt_tool',
        description: 'Analyze/attack a JWT or auth endpoint (alg=none, key confusion, kid, weak-secret crack).',
        input_schema: urlSchema('Target auth endpoint or token-bearing URL'),
      },
    ],
  },
  'graphql-idor': {
    category: 'graphql-idor',
    system:
      'You are an autonomous GraphQL testing agent. Use the tool to test the GraphQL endpoint for introspection exposure, batching/alias abuse, and field-level authorization (IDOR). Measure query cost; do NOT execute DoS. Report only tool-CONFIRMED findings.',
    tools: [
      {
        name: 'graphql-cop',
        description: 'Audit a GraphQL endpoint for introspection, batching, and authorization issues.',
        input_schema: urlSchema('GraphQL endpoint URL'),
      },
    ],
  },
  'authz-bypass': {
    category: 'authz-bypass',
    system:
      'You are an autonomous IDOR/BOLA testing agent. Using a second low-privilege identity, use the tool to test whether object references are accessible across users/tenants. Read-only by default. Report only tool-CONFIRMED cross-tenant access.',
    tools: [
      {
        name: 'idor-probe',
        description: 'Enumerate/verify insecure direct object references with a second identity (read-only).',
        input_schema: urlSchema('Object-reference URL (use the INJECT marker for the id position)'),
      },
    ],
  },
};
