// Single source of truth for the ACTIVE vuln/exploit pipeline categories — the
// ones the workflow actually runs agents for. Adding a new class here (with its
// agents, prompts, and tier) is what activates it end to end.
// NOTE: this is a strict subset of the broader `VulnCategory` type union in
// attack-graph/types.ts (which also includes future, not-yet-active classes).
export const ACTIVE_VULN_CATEGORIES = [
  'sqli',
  'xss',
  'auth-bypass',
  'authz-bypass',
  'ssrf',
  'business-logic',
] as const;

export type ActiveVulnCategory = (typeof ACTIVE_VULN_CATEGORIES)[number];

export function isActiveCategory(value: string): value is ActiveVulnCategory {
  return (ACTIVE_VULN_CATEGORIES as readonly string[]).includes(value);
}
